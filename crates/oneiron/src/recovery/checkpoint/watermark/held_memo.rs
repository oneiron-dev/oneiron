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
//! (see [`FileIdentity::of`]); where it keeps coarse times every held read
//! is whole.
//!
//! A file's times do not prove its bytes: two writes inside one tick of the
//! kernel's coarse clock, or stores through a page already mapped writable,
//! change the bytes and leave the times (Astra review of #8317). So a whole
//! read seeds the memo only through [`prepare_seed`], before the read, and
//! [`remember_read`], after it (Engine RULING
//! FIX-PERF-6729-IDENTITY-NOT-CONTENT = A, 21:39):
//! - the file last changed at least [`SETTLED_FOR`] before the read began,
//!   so a write in the same tick as its times has passed;
//! - it lies on a Linux file system that writes dirty pages back
//!   ([`WRITTEN_BACK`]): tmpfs and ramfs never do, so a page once mapped
//!   writable there takes stores that move no time (Astra round 2). Every
//!   other file system, and every file off Linux, is read whole each time;
//! - its dirty pages are written back through the open file before the read.
//!   Write-back write-protects every mapping of a page it cleans, so a store
//!   after it faults and moves the file's times, whatever the system's
//!   write-back tunables or laptop mode would have delayed;
//! - an fstat of the same open file after the read names the same identity.
//!
//! An entry answers for [`TRUSTED_FOR`] at most, by the monotonic clock and
//! by the wall clock both: the monotonic clock stops while the host is
//! suspended, the wall clock does not.
//!
//! What this does not see (named in #8317): acts that need root (stepping
//! the clock, writing the block device, XFS open-by-handle I/O that moves no
//! time), writes through a page pinned for writing before the read began (a
//! direct-I/O or io_uring pin takes no fault when it writes), and bitrot of
//! the stored blocks inside the hour (a whole read of a cached file reads
//! the cached pages too).

use std::collections::BTreeMap;
use std::fs::{File, Metadata};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

/// The most files kept; a full memo starts again empty.
const HELD_MAX: usize = 64;

/// How long before a whole read began the file must have last changed for
/// the read to seed the memo.
const SETTLED_FOR: Duration = Duration::from_secs(60);

/// How long an entry answers held reads before the next one is whole.
const TRUSTED_FOR: Duration = Duration::from_secs(60 * 60);

/// The file systems whose files may seed the memo, by their `statfs` magic:
/// ext2, ext3 and ext4 (one magic), XFS, Btrfs and F2FS. Each writes a dirty
/// page back, write-protects its mappings as it does, and moves the file's
/// times at the next store through one.
#[cfg(target_os = "linux")]
const WRITTEN_BACK: [u64; 4] = [0xEF53, 0x5846_5342, 0x9123_683E, 0xF2F5_2010];

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

    /// Whether the file last changed at least [`SETTLED_FOR`] before
    /// `started`, by the wall clock to the nanosecond; a time before the
    /// epoch is not.
    fn settled_before(self, started: SystemTime) -> bool {
        let since_epoch = |(seconds, nanoseconds): (i64, i64)| {
            Some(Duration::new(
                u64::try_from(seconds).ok()?,
                u32::try_from(nanoseconds).ok()?,
            ))
        };
        let (Some(modified), Some(changed), Ok(started)) = (
            since_epoch(self.modified),
            since_epoch(self.changed),
            started.duration_since(SystemTime::UNIX_EPOCH),
        ) else {
            return false;
        };
        modified
            .max(changed)
            .checked_add(SETTLED_FOR)
            .is_some_and(|settled| settled <= started)
    }
}

/// One file found whole: where, as what, with which evidence, and when by
/// the monotonic and the wall clock.
struct Held {
    path: PathBuf,
    identity: FileIdentity,
    outer_blake3: String,
    size: u64,
    seeded_monotonic: Instant,
    seeded_wall: SystemTime,
}

impl Held {
    /// Whether neither clock has passed [`TRUSTED_FOR`] since the seed and
    /// the wall clock has not gone back before it.
    fn trusted(&self) -> bool {
        self.seeded_monotonic.elapsed() < TRUSTED_FOR
            && SystemTime::now()
                .duration_since(self.seeded_wall)
                .is_ok_and(|since| since < TRUSTED_FOR)
    }
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
                && held.trusted()
        })
}

/// A whole read that may seed the memo, made ready by [`prepare_seed`].
pub(super) struct Seed {
    identity: FileIdentity,
}

/// Before a whole read of `file` that begins at `started`, with `identity`
/// read from the open file: a [`Seed`] when the file had settled by then
/// and lies on a file system in [`WRITTEN_BACK`], once its dirty pages are
/// written back through it (which write-protects every mapping of them);
/// `None` otherwise, and when the write-back fails.
pub(super) fn prepare_seed(
    file: &File,
    identity: FileIdentity,
    started: SystemTime,
) -> Option<Seed> {
    (identity.settled_before(started) && written_back(file) && file.sync_data().is_ok())
        .then_some(Seed { identity })
}

/// Whether the open `file` lies on a file system in [`WRITTEN_BACK`].
#[cfg(target_os = "linux")]
fn written_back(file: &File) -> bool {
    rustix::fs::fstatfs(file)
        .ok()
        .and_then(|stats| u64::try_from(stats.f_type).ok())
        .is_some_and(|magic| WRITTEN_BACK.contains(&(magic & 0xFFFF_FFFF)))
}

#[cfg(not(target_os = "linux"))]
fn written_back(_: &File) -> bool {
    false
}

/// Keeps that the file at `path` is the backup `evidence` describes, as the
/// whole read of `file` that `seed` readied found it: only when an fstat of
/// `file` after the read names the identity the seed was readied with.
pub(super) fn remember_read(evidence: &Evidence<'_>, path: PathBuf, seed: Seed, file: &File) {
    let after = file
        .metadata()
        .ok()
        .and_then(|after| FileIdentity::of(&after));
    if after != Some(seed.identity) {
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
            identity: seed.identity,
            outer_blake3: evidence.outer_blake3.to_owned(),
            size: evidence.size,
            seeded_monotonic: Instant::now(),
            seeded_wall: SystemTime::now(),
        },
    );
}
