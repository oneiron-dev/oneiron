//! The authorization clock's lease journal (FIX 12023 W0, review #4484 P1-B;
//! L02 11-04 13:53 = A).
//!
//! A decision past the committed lease judges without waiting for the writer
//! ([`crate::store::Store::authorization_now`]), and the lease's renewal
//! commits after it. Before such a decision's time is returned, a bound that
//! covers it, the time plus [`AUTHORIZATION_LEASE_SECS`], is appended to the
//! environment's `clock-lease.journal` and fdatasynced, off the LMDB writer:
//! the first lapsed decision pays one small sync, and the decisions its bound
//! covers pay none. The owned open replays the journal's highest bound into
//! the committed clock floor before any admission, so a crash before the
//! renewal commits, with the wall stepped back across it, never judges below
//! a time a decision already took. A renewal that commits a lease at or past
//! every bound journaled truncates the journal: the vault holds them all.
//!
//! Only the owned open, in its own process, appends, replays or truncates. A
//! store without the writer lease, or one whose journal fails, renews in its
//! writer, as before FIX 12023, and reads the journal's bound into the floor
//! it commits there, so a lease holder's crash leaves no journaled time
//! above it.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};

use super::AUTHORIZATION_LEASE_SECS;
use crate::error::{Error, Result};

/// The journal's file, in the environment's root beside the slip-spend
/// journal.
const LEASE_JOURNAL_FILE: &str = "clock-lease.journal";

/// One record: the bound (u64, little-endian), [`RECORD_MAGIC`], and an
/// xxh32 tag over the first 12 bytes.
const RECORD_LEN: usize = 16;
const RECORD_MAGIC: &[u8; 4] = b"OCL1";

/// The owned open's journal at one canonical root, in this process.
pub(crate) struct LeaseJournal {
    path: PathBuf,
    pid: u32,
    state: Mutex<JournalState>,
}

/// Holds no descriptor between appends (review #4484 P2, 11-04 16:05): a
/// host that opens many vaults keeps only this small state per root.
#[derive(Default)]
struct JournalState {
    /// The root directory was synced after this open first created or
    /// opened the journal.
    dir_synced: bool,
    /// The highest bound this open synced: a decision at or below it is
    /// durable, in the journal or, once truncated, in a committed lease.
    covered: u64,
    /// A record was appended since the last truncate.
    owed: bool,
}

/// The journals of this process's owned opens, by canonical root.
static JOURNALS: LazyLock<Mutex<HashMap<PathBuf, Arc<LeaseJournal>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

impl LeaseJournal {
    /// The journal `store`'s lapsed decisions append to: `None` unless its
    /// open took the writer lease in this process.
    pub(super) fn of(store: &crate::store::Store) -> Option<Arc<Self>> {
        if !store.opened_with_writer_lease() {
            return None;
        }
        let journals = JOURNALS.lock().unwrap_or_else(PoisonError::into_inner);
        journals
            .get(store.canonical_root())
            .filter(|journal| journal.pid == std::process::id())
            .cloned()
    }

    /// A fresh journal for the owned open at `root`, replacing any an
    /// earlier open in this process left.
    fn install(root: &Path) -> Arc<Self> {
        let journal = Arc::new(Self {
            path: root.join(LEASE_JOURNAL_FILE),
            pid: std::process::id(),
            state: Mutex::new(JournalState::default()),
        });
        JOURNALS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(root.to_path_buf(), Arc::clone(&journal));
        journal
    }

    /// Makes a decision at `now` durable before it is returned (condition
    /// 1): `true` when a synced bound already covers it, or once one is
    /// appended and fdatasynced. `false` on any failure, said in a warn: the
    /// caller renews the lease in its writer before it judges (condition 2;
    /// L02 11-04 15:16).
    pub(super) fn cover(&self, now: u64) -> bool {
        if self.pid != std::process::id() {
            return false;
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if now <= state.covered {
            return true;
        }
        let mut file = match open_for_append(&self.path, !state.dir_synced) {
            Ok(file) => file,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "the clock lease journal did not open; the decision renews the lease in its writer"
                );
                return false;
            }
        };
        state.dir_synced = true;
        let bound = now.saturating_add(AUTHORIZATION_LEASE_SECS);
        let record = record(bound);
        match file.write_all(&record).and_then(|()| file.sync_data()) {
            Ok(()) => {
                state.covered = bound;
                state.owed = true;
                true
            }
            Err(error) => {
                // The append may have torn: the next open trims it.
                tracing::warn!(
                    %error,
                    "the clock lease journal append failed; the decision renews the lease in its writer"
                );
                false
            }
        }
    }

    /// A renewal committed `leased`: once it covers every bound synced, the
    /// journal owes nothing and is truncated. A truncate a crash undoes
    /// leaves records at or below a committed lease, which replay harmlessly.
    pub(super) fn settle(&self, leased: u64) {
        if self.pid != std::process::id() {
            return;
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if !state.owed || leased < state.covered {
            return;
        }
        match truncate(&self.path) {
            Ok(()) => state.owed = false,
            Err(error) => tracing::warn!(
                %error,
                "the settled clock lease journal did not truncate; its records replay harmlessly"
            ),
        }
    }
}

/// Opens the journal for appends, creating it owner-only, without following
/// a link and leaking no descriptor to a child. The root directory is synced
/// so a journal a first decision created survives the power loss its
/// fdatasync guards against, and a torn tail is trimmed so every record
/// stays aligned. The directory syncs only on `sync_dir`: once per open of
/// the vault, not per append.
fn open_for_append(path: &Path, sync_dir: bool) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    // A directory opens as a file only on unix.
    #[cfg(unix)]
    {
        if sync_dir && let Some(root) = path.parent() {
            File::open(root)?.sync_all()?;
        }
    }
    #[cfg(not(unix))]
    let _ = sync_dir;
    let len = file.metadata()?.len();
    let torn = len % (RECORD_LEN as u64);
    if torn > 0 {
        file.set_len(len - torn)?;
    }
    Ok(file)
}

fn record(bound: u64) -> [u8; RECORD_LEN] {
    let mut record = [0_u8; RECORD_LEN];
    record[0..8].copy_from_slice(&bound.to_le_bytes());
    record[8..12].copy_from_slice(RECORD_MAGIC);
    let tag = xxhash_rust::xxh32::xxh32(&record[..12], 0);
    record[12..16].copy_from_slice(&tag.to_le_bytes());
    record
}

fn parse_record(bytes: &[u8]) -> Option<u64> {
    if bytes.len() != RECORD_LEN
        || &bytes[8..12] != RECORD_MAGIC
        || xxhash_rust::xxh32::xxh32(&bytes[..12], 0).to_le_bytes() != bytes[12..16]
    {
        return None;
    }
    bytes[0..8].try_into().ok().map(u64::from_le_bytes)
}

/// The file's last write time in Unix seconds, from its metadata, which
/// reads even when its records do not.
fn written_secs(path: &Path) -> Option<u64> {
    std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
}

/// The highest time a decision the journal at `root` covers may have taken:
/// 0 for an absent or empty journal. Every readable record names its bound;
/// a torn tail is an append whose sync never returned, so no decision took
/// its bound. A damaged record's bound is unknown: the decision it covered
/// judged at no more than the wall when it was written (the file's last
/// write time) or the committed floor and lease `committed`, so the bound
/// rises a lease past both. A journal whose bytes and metadata both fail
/// to read fails, closed.
pub(super) fn journaled_bound(root: &Path, committed: u64) -> Result<u64> {
    let path = root.join(LEASE_JOURNAL_FILE);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => {
            let Some(written) = written_secs(&path) else {
                return Err(Error::Io(error));
            };
            tracing::error!(
                %error,
                "the clock lease journal did not read; the clock floor rises a lease past its last write"
            );
            return Ok(written
                .max(committed)
                .saturating_add(AUTHORIZATION_LEASE_SECS));
        }
    };
    let mut bound = 0_u64;
    let mut damaged = false;
    for chunk in bytes.chunks_exact(RECORD_LEN) {
        match parse_record(chunk) {
            Some(record) => bound = bound.max(record),
            None => damaged = true,
        }
    }
    if damaged {
        let Some(written) = written_secs(&path) else {
            return Err(Error::CorruptedIndex("clock lease journal"));
        };
        tracing::warn!("a clock lease journal record is damaged; the clock floor rises a lease past its last write");
        bound = bound.max(
            written
                .max(committed)
                .saturating_add(AUTHORIZATION_LEASE_SECS),
        );
    }
    Ok(bound)
}

/// The owned open's replay (condition 3): installs this open's journal and
/// returns the bound its records hold, for the caller to commit into the
/// clock floor before any admission, and the journal to truncate once it
/// has.
pub(super) fn replay_at_open(root: &Path, committed: u64) -> Result<(Arc<LeaseJournal>, u64)> {
    let bound = journaled_bound(root, committed)?;
    Ok((LeaseJournal::install(root), bound))
}

/// Empties the journal after its bound committed. A failed truncate leaves
/// records at or below the committed floor, which replay harmlessly.
pub(super) fn truncate_after_replay(journal: &LeaseJournal) {
    if let Err(error) = truncate(&journal.path) {
        tracing::warn!(%error, "the replayed clock lease journal did not truncate");
    }
}

/// Empties the journal at `path`, without following a link; an absent one
/// is empty already.
fn truncate(path: &Path) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    match options.open(path) {
        Ok(file) => file.set_len(0),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}
