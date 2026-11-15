//! What this process last found to be the backup a marker names (FIX 6729;
//! Engine RULING FIX-PERF-6729-HELD-CHECK = A, Sun 15 Nov 20:00).
//!
//! [`super::BackupMarker::held`] reads the whole artifact, which on a large
//! vault outlasts the pre-idle preparation window. Each time it reads a
//! file whole and finds the marker's evidence, the file's identity is kept
//! here under the marker's commitment digest: its device, inode, size, and
//! modification and status-change times to the nanosecond. A later held
//! read of the same evidence at the same path whose file still has that
//! identity answers without the whole read. Any change in the identity,
//! other evidence or a restart takes the whole read again.
//!
//! Only a whole read seeds it: landing a backup does not, so bytes changed
//! between the landing and the marker are still read and refused. The
//! identity is trusted only where the file system keeps fine-grained times
//! (see [`FileIdentity::of`]); where it keeps coarse times, and off unix,
//! every held read is whole.
//!
//! A file's times do not prove its bytes: two writes inside one tick of the
//! kernel's coarse clock, or stores through a page already mapped writable,
//! change the bytes and leave the times (Astra review of #8317). So a read
//! seeds the memo only from a settled file: last changed at least
//! [`SETTLED_SECS`] before the read began (by then such a write's tick has
//! passed, and the page cache has written a dirtied mapped page back, so
//! the next store moves the times), and with its identity unchanged by the
//! read. An entry is trusted for [`TRUSTED_FOR`] at most; the next held read
//! after that is whole again.

use std::collections::BTreeMap;
use std::fs::{File, Metadata};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

/// The most files kept; a full memo starts again empty.
const HELD_MAX: usize = 64;

/// How long before a whole read began the file must have last changed for
/// the read to seed the memo, in seconds.
const SETTLED_SECS: i64 = 60;

/// How long an entry answers held reads before the next one is whole.
const TRUSTED_FOR: Duration = Duration::from_secs(60 * 60);

/// What a held read compares: the marker's commitment digest, the BLAKE3 of
/// the artifact's every byte (both hex) and its size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Evidence<'a> {
    pub(super) commitment_digest: &'a str,
    pub(super) outer_blake3: &'a str,
    pub(super) size: u64,
}

/// A file as the kernel names it at one moment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl FileIdentity {
    /// The identity of the open file `metadata` describes; `None` where the
    /// platform names none, or where either time names no finer time than a
    /// whole millisecond. A file system that keeps coarse times (FAT's two
    /// seconds, exFAT's ten milliseconds, HFS+'s second, an SFTP mount's
    /// second) can leave both times unchanged across a rewrite, so its files
    /// always take the whole read. A fine-grained time lands on a whole
    /// millisecond once in a million; that file is only read whole.
    #[cfg(unix)]
    pub(super) fn of(metadata: &Metadata) -> Option<Self> {
        use std::os::unix::fs::MetadataExt;
        let fine = |nanoseconds: i64| nanoseconds % 1_000_000 != 0;
        (fine(metadata.mtime_nsec()) && fine(metadata.ctime_nsec())).then(|| Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }

    #[cfg(not(unix))]
    pub(super) fn of(_: &Metadata) -> Option<Self> {
        None
    }

    /// Whether the file last changed at least [`SETTLED_SECS`] before
    /// `started`, by the wall clock; a clock before the epoch is not.
    fn settled_before(self, started: SystemTime) -> bool {
        let Some(started) = started
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .and_then(|since| i64::try_from(since.as_secs()).ok())
        else {
            return false;
        };
        let last = self.modified.0.max(self.changed.0);
        last.checked_add(SETTLED_SECS)
            .is_some_and(|settled| settled <= started)
    }
}

/// One file found whole: where, as what, with which evidence, and when.
struct Held {
    path: PathBuf,
    identity: FileIdentity,
    outer_blake3: String,
    size: u64,
    seeded: Instant,
}

/// By commitment digest.
static HELD: Mutex<BTreeMap<String, Held>> = Mutex::new(BTreeMap::new());

/// `path` opened for reading, never through a symlink, with its metadata
/// read from the open file: `None` unless it is a regular file.
pub(super) fn open_regular(path: &Path) -> Option<(File, Metadata)> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(
        &mut options,
        libc::O_NOFOLLOW | libc::O_NONBLOCK,
    );
    let file = options.open(path).ok()?;
    let metadata = file.metadata().ok()?;
    metadata.is_file().then_some((file, metadata))
}

/// Whether this process found the file at `path`, as `identity` names it
/// now, to be the backup `evidence` describes, within [`TRUSTED_FOR`].
pub(super) fn holds(evidence: &Evidence<'_>, path: &Path, identity: FileIdentity) -> bool {
    HELD.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(evidence.commitment_digest)
        .is_some_and(|held| {
            held.path == path
                && held.identity == identity
                && held.outer_blake3 == evidence.outer_blake3
                && held.size == evidence.size
                && held.seeded.elapsed() < TRUSTED_FOR
        })
}

/// Keeps that the file at `path`, as `identity` named it when a whole read
/// of `file` began at `started`, is the backup `evidence` describes, as that
/// read found: only when the file was settled then and the read left its
/// identity unchanged.
pub(super) fn remember_read(
    evidence: &Evidence<'_>,
    path: PathBuf,
    identity: FileIdentity,
    file: &File,
    started: SystemTime,
) {
    let after = file
        .metadata()
        .ok()
        .and_then(|after| FileIdentity::of(&after));
    if after != Some(identity) || !identity.settled_before(started) {
        return;
    }
    let mut held = HELD.lock().unwrap_or_else(PoisonError::into_inner);
    if held.len() >= HELD_MAX && !held.contains_key(evidence.commitment_digest) {
        held.clear();
    }
    held.insert(
        evidence.commitment_digest.to_owned(),
        Held {
            path,
            identity,
            outer_blake3: evidence.outer_blake3.to_owned(),
            size: evidence.size,
            seeded: Instant::now(),
        },
    );
}
