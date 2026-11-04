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
//! Only the owned open, in its own process, appends, replays or truncates, and
//! on unix it does so through the descriptor of the directory it opened, so a
//! late callback of an open a restore replaced never touches its
//! replacement's journal (review #4484 Astra P1, 11-04 16:2x). Every other
//! open reads the journal's bound into its clock floor before its first
//! decision; a store without the writer lease, or one whose journal fails,
//! renews in its writer, as before FIX 12023, at or past that bound.
//!
//! Bounds only rise through the file: one open appends a bound only past the
//! one before, and the next open's clock starts at or past the bound it
//! replayed. So a readable record bounds every record before it, and a record
//! that does not read with no readable record after it bounds nothing: the
//! journal then fails closed and stays for the owner. The owner's way back:
//! move the journal aside and open; until the wall passes the last decision
//! time it covered, a grant that expired before then may judge as live.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use super::AUTHORIZATION_LEASE_SECS;
use crate::error::{Error, Result};

/// The journal's file, in the environment's root beside the slip-spend
/// journal.
const LEASE_JOURNAL_FILE: &str = "clock-lease.journal";

/// One record: the bound (u64, little-endian), [`RECORD_MAGIC`], and an
/// xxh32 tag over the first 12 bytes.
const RECORD_LEN: usize = 16;
const RECORD_MAGIC: &[u8; 4] = b"OCL1";

/// The owned open's journal. Its store's clock holds it, so it lives and
/// closes with that store (review #4484 P2, 11-04 16:05): no registry, and no
/// descriptor beyond the directory's between appends.
pub(crate) struct LeaseJournal {
    path: PathBuf,
    /// The directory this open opened, which every open of the journal goes
    /// through on unix.
    #[cfg(unix)]
    dir: File,
    pid: u32,
    state: Mutex<JournalState>,
}

#[derive(Default)]
struct JournalState {
    /// The root directory was synced after this open first opened the
    /// journal.
    dir_synced: bool,
    /// The highest bound this open synced: a decision at or below it is
    /// durable, in the journal or, once truncated, in a committed lease.
    covered: u64,
    /// A record was appended since the last truncate.
    owed: bool,
}

impl LeaseJournal {
    /// The journal for the owned open at `root`.
    fn open(root: &Path) -> Result<Self> {
        Ok(Self {
            path: root.join(LEASE_JOURNAL_FILE),
            #[cfg(unix)]
            dir: File::open(root)?,
            pid: std::process::id(),
            state: Mutex::new(JournalState::default()),
        })
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
        let mut file = match self.open_for_append(!state.dir_synced) {
            Ok(file) => file,
            Err(error) => {
                tracing::warn!(
                    %error,
                    journal = %self.path.display(),
                    "the clock lease journal did not open; the decision renews the lease in its writer"
                );
                return false;
            }
        };
        state.dir_synced = true;
        let bound = now.saturating_add(AUTHORIZATION_LEASE_SECS);
        let l15_sync = crate::stage_timing::stage("server.lease_journal_sync");
        let synced = file.write_all(&record(bound)).and_then(|()| file.sync_data());
        drop(l15_sync);
        match synced {
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
        match self.truncate() {
            Ok(()) => state.owed = false,
            Err(error) => tracing::warn!(
                %error,
                "the settled clock lease journal did not truncate; its records replay harmlessly"
            ),
        }
    }

    /// Opens the journal for appends, creating it owner-only, without
    /// following a link and leaking no descriptor to a child. The directory
    /// syncs on `sync_dir` (once per open of the vault), so a journal a first
    /// decision created survives the power loss its fdatasync guards against,
    /// and a torn tail is trimmed so every record stays aligned.
    fn open_for_append(&self, sync_dir: bool) -> std::io::Result<File> {
        #[cfg(unix)]
        let file = {
            use rustix::fs::{Mode, OFlags, openat};
            let fd = openat(
                &self.dir,
                LEASE_JOURNAL_FILE,
                OFlags::RDWR | OFlags::APPEND | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )?;
            if sync_dir {
                self.dir.sync_all()?;
            }
            File::from(fd)
        };
        #[cfg(not(unix))]
        let file = {
            let _ = sync_dir;
            std::fs::OpenOptions::new()
                .read(true)
                .append(true)
                .create(true)
                .open(&self.path)?
        };
        let len = file.metadata()?.len();
        let torn = len % (RECORD_LEN as u64);
        if torn > 0 {
            file.set_len(len - torn)?;
        }
        Ok(file)
    }

    /// Empties the journal, through the directory this open opened; an
    /// absent one is empty already.
    fn truncate(&self) -> std::io::Result<()> {
        #[cfg(unix)]
        let opened = {
            use rustix::fs::{Mode, OFlags, openat};
            use rustix::io::Errno;
            match openat(
                &self.dir,
                LEASE_JOURNAL_FILE,
                OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(fd) => Some(File::from(fd)),
                Err(Errno::NOENT) => None,
                Err(error) => return Err(error.into()),
            }
        };
        #[cfg(not(unix))]
        let opened = match std::fs::OpenOptions::new().write(true).open(&self.path) {
            Ok(file) => Some(file),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        match opened {
            Some(file) => file.set_len(0),
            None => Ok(()),
        }
    }
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

/// The highest time a decision the journal at `root` covers may have taken:
/// 0 for an absent or empty journal. A torn tail is an append whose sync
/// never returned, so no decision took its bound. A complete record that does
/// not read, zeros included, is bounded by a readable record after it (bounds
/// only rise through the file); with none after it, or when the file does not
/// read, nothing bounds it and this fails, closed (review #4484 Astra P1,
/// 11-04 16:2x: a write time is no bound after a wall step back).
pub(super) fn journaled_bound(root: &Path) -> Result<u64> {
    let path = root.join(LEASE_JOURNAL_FILE);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => {
            tracing::error!(
                %error,
                journal = %path.display(),
                "the clock lease journal did not read; the open fails. To recover: move the journal aside and open"
            );
            return Err(Error::Io(error));
        }
    };
    let mut bound = 0_u64;
    let mut unbounded = false;
    for chunk in bytes.chunks_exact(RECORD_LEN) {
        match parse_record(chunk) {
            Some(record) => {
                bound = bound.max(record);
                unbounded = false;
            }
            None => unbounded = true,
        }
    }
    if unbounded {
        tracing::error!(
            journal = %path.display(),
            "the clock lease journal's last complete record does not read and no record bounds it; the open fails. To recover: move the journal aside and open"
        );
        return Err(Error::CorruptedIndex("clock lease journal"));
    }
    Ok(bound)
}

/// The owned open's replay (condition 3): the journal this open appends to,
/// and the bound its records hold, for the caller to commit into the clock
/// floor before any admission, and the journal to truncate once it has.
pub(super) fn replay_at_open(root: &Path) -> Result<(Arc<LeaseJournal>, u64)> {
    let bound = journaled_bound(root)?;
    Ok((Arc::new(LeaseJournal::open(root)?), bound))
}

/// Empties the journal after its bound committed. A failed truncate leaves
/// records at or below the committed floor, which replay harmlessly.
pub(super) fn truncate_after_replay(journal: &LeaseJournal) {
    if let Err(error) = journal.truncate() {
        tracing::warn!(%error, "the replayed clock lease journal did not truncate");
    }
}
