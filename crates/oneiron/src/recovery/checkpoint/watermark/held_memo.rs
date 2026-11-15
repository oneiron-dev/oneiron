//! What this process last found to be the backup a marker names (FIX 6729;
//! Engine RULING FIX-PERF-6729-HELD-CHECK = A, Sun 15 Nov 20:00).
//!
//! [`super::BackupMarker::held`] reads the whole artifact, which on a large
//! vault outlasts the pre-idle preparation window. Each time it reads a
//! file whole and finds the marker's evidence, and each time this process
//! lands a backup and records its marker, the file's identity is kept here
//! under the marker's commitment digest: its device, inode, size, and
//! modification and status-change times to the nanosecond. A later held
//! read of the same evidence at the same path whose file still has that
//! identity answers without the whole read. Any change in the identity, a
//! new marker or a restart takes the whole read again. An in-place rewrite
//! always moves the status-change time, which user space cannot set back.
//! Only on unix: elsewhere every held read is whole.

use std::collections::BTreeMap;
use std::fs::{File, Metadata};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

/// The most files kept; a full memo starts again empty.
const HELD_MAX: usize = 64;

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
    /// platform names none.
    #[cfg(unix)]
    pub(super) fn of(metadata: &Metadata) -> Option<Self> {
        use std::os::unix::fs::MetadataExt;
        Some(Self {
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
}

/// One file found whole: where, as what, with which evidence.
struct Held {
    path: PathBuf,
    identity: FileIdentity,
    outer_blake3: String,
    size: u64,
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
/// now, to be the backup `evidence` describes.
pub(super) fn holds(evidence: &Evidence<'_>, path: &Path, identity: FileIdentity) -> bool {
    HELD.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(evidence.commitment_digest)
        .is_some_and(|held| {
            held.path == path
                && held.identity == identity
                && held.outer_blake3 == evidence.outer_blake3
                && held.size == evidence.size
        })
}

/// Keeps that the file at `path`, as `identity` names it, is the backup
/// `evidence` describes.
pub(super) fn remember(evidence: &Evidence<'_>, path: PathBuf, identity: FileIdentity) {
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
        },
    );
}

/// Keeps the backup this process just landed at `path`, whose evidence it
/// computed as it wrote it: a regular file of the evidence's size.
pub(super) fn remember_landed(evidence: &Evidence<'_>, path: PathBuf) {
    let Some((_, metadata)) = open_regular(&path) else {
        return;
    };
    if metadata.len() != evidence.size {
        return;
    }
    if let Some(identity) = FileIdentity::of(&metadata) {
        remember(evidence, path, identity);
    }
}
