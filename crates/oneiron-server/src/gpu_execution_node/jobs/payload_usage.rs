//! The size of a key's payload on disk (design pass 33, 7.9; FIX
//! EXEC-NODE-DISK-CHECK-UNBUILT): what the engine compares with the key's
//! disk request every `disk_check_secs`, and ends the key as `DiskLimit`
//! past it ([`super::NodeJobs::check_payload_disk`]).
//!
//! The walk opens each directory beneath the one before it and never
//! through a link. It counts the blocks each entry holds on disk, so a
//! sparse file counts what it holds and not its length, and each file once
//! by its inode, whatever its names. It stops as soon as the count passes
//! the bound it was given. A walk is no snapshot: a file a job renames from
//! a directory not yet read into one already read is missed until the next
//! check, and a name removed while it runs is skipped.
//!
//! A payload the walk cannot finish within its bounds ([`PayloadWalkBounds`]:
//! so many directory levels, so many entries; the node file's
//! `payload_depth_max` and `payload_entries_max`, policy with today's
//! defaults) is [`PayloadUsage::Unmeasurable`] and passes every request:
//! the node cannot show that it is within. A walk that runs out of time is
//! an error instead, and the next check measures again: a slow disk is not
//! the job's doing.

use std::collections::HashSet;
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::{Duration, Instant};

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat};

pub use crate::gpu_execution_node::node_settings::{
    PAYLOAD_DEPTH_MAX_CEILING, PAYLOAD_DEPTH_MAX_DEFAULT, PAYLOAD_ENTRIES_MAX_DEFAULT,
};

/// The longest one walk takes: within the job control handler's own limit
/// and the engine's wait for its answer.
pub const PAYLOAD_WALK_TIME_MAX: Duration = Duration::from_secs(15);

/// The unit of `st_blocks`.
const BLOCK_BYTES: u64 = 512;

/// The flags every directory of the walk opens with: a directory only,
/// never through a link.
fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

/// The bounds of one walk. A `depth_max` above
/// [`PAYLOAD_DEPTH_MAX_CEILING`] walks to the ceiling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadWalkBounds {
    pub depth_max: u32,
    pub entries_max: u64,
    pub time_max: Duration,
}

impl PayloadWalkBounds {
    /// The widest bounds a node file may set: the disk check's walk when
    /// the node file does not read (review r13 R13-09 of #10512).
    #[must_use]
    pub fn widest() -> Self {
        Self {
            depth_max: PAYLOAD_DEPTH_MAX_CEILING,
            entries_max: u64::MAX,
            time_max: PAYLOAD_WALK_TIME_MAX,
        }
    }
}

impl Default for PayloadWalkBounds {
    fn default() -> Self {
        Self {
            depth_max: PAYLOAD_DEPTH_MAX_DEFAULT,
            entries_max: PAYLOAD_ENTRIES_MAX_DEFAULT,
            time_max: PAYLOAD_WALK_TIME_MAX,
        }
    }
}

/// What one measure of a payload found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadUsage {
    /// The walk ended: the payload holds `bytes` on disk.
    Measured { bytes: u64 },
    /// The walk stopped once it had counted `bytes`, more than the bound
    /// it was given.
    Past { bytes: u64 },
    /// The payload is beyond what the walk measures (too deep or too many
    /// entries): it passes every request.
    Unmeasurable { why: String },
}

impl PayloadUsage {
    /// Whether the payload passes a request of `limit_bytes`. A walk that
    /// stopped past its bound passes it when the bound was `limit_bytes`,
    /// as the disk check asks.
    #[must_use]
    pub fn passes(&self, limit_bytes: u64) -> bool {
        match self {
            Self::Measured { bytes } => *bytes > limit_bytes,
            Self::Past { .. } | Self::Unmeasurable { .. } => true,
        }
    }

    /// The answer's one-line form, as the job control socket sends it:
    /// `bytes <n>`, `past <n>` or `unmeasurable <why>`.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::Measured { bytes } => format!("bytes {bytes}"),
            Self::Past { bytes } => format!("past {bytes}"),
            Self::Unmeasurable { why } => {
                format!("unmeasurable {}", why.replace(['\n', '\r'], " "))
            }
        }
    }

    /// Reads [`Self::render`]'s form; `None` for any other text.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let (word, rest) = text.split_once(' ')?;
        let count = || -> Option<u64> {
            (!rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit()))
                .then(|| rest.parse().ok())
                .flatten()
        };
        match word {
            "bytes" => count().map(|bytes| Self::Measured { bytes }),
            "past" => count().map(|bytes| Self::Past { bytes }),
            "unmeasurable" if !rest.is_empty() => Some(Self::Unmeasurable {
                why: rest.to_owned(),
            }),
            _ => None,
        }
    }
}

/// Measures the payload directory `dir` with the default bounds. A
/// directory that does not exist holds nothing yet.
///
/// # Errors
///
/// `dir` is a link or not a directory, an entry could not be read, or the
/// walk ran out of time.
pub fn measure_payload(dir: &Path, stop_past: u64) -> io::Result<PayloadUsage> {
    measure_payload_within(dir, stop_past, &PayloadWalkBounds::default())
}

/// [`measure_payload`] within `bounds`.
///
/// # Errors
///
/// As [`measure_payload`].
pub fn measure_payload_within(
    dir: &Path,
    stop_past: u64,
    bounds: &PayloadWalkBounds,
) -> io::Result<PayloadUsage> {
    match rustix::fs::open(dir, directory_flags(), Mode::empty()) {
        Ok(top) => measure_payload_fd(top, stop_past, bounds),
        Err(rustix::io::Errno::NOENT) => Ok(PayloadUsage::Measured { bytes: 0 }),
        Err(error) => Err(io::Error::new(
            io::Error::from(error).kind(),
            format!("{}: {error}", dir.display()),
        )),
    }
}

/// Measures the opened payload directory `top`: every entry beneath it,
/// itself included, until the count passes `stop_past`.
///
/// # Errors
///
/// `top` is not a directory, an entry could not be read, or the walk ran
/// out of time.
pub fn measure_payload_fd(
    top: OwnedFd,
    stop_past: u64,
    bounds: &PayloadWalkBounds,
) -> io::Result<PayloadUsage> {
    measure_payload_fd_counting(top, stop_past, bounds, &mut HashSet::new())
}

/// [`measure_payload_fd`], leaving in `counted` the (device, inode) of
/// every file it counted, directories included, so a later count (root's
/// held files, which counts a removed directory a task still holds) charges
/// none of them again (review r13 R13-01, r14 R14-01). A
/// [`PayloadUsage::Past`] or [`PayloadUsage::Unmeasurable`] stands even
/// when found after the time bound: it is no estimate (R13-04).
///
/// # Errors
///
/// As [`measure_payload_fd`].
pub fn measure_payload_fd_counting(
    top: OwnedFd,
    stop_past: u64,
    bounds: &PayloadWalkBounds,
    counted: &mut HashSet<(u64, u64)>,
) -> io::Result<PayloadUsage> {
    let started = Instant::now();
    let out_of_time = |entries: u64| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "not measured within {} s ({entries} entries)",
                bounds.time_max.as_secs()
            ),
        )
    };
    let depth_max = bounds.depth_max.min(PAYLOAD_DEPTH_MAX_CEILING);
    let deepest = usize::try_from(depth_max).unwrap_or(usize::MAX);
    // Every listed name is charged to the entry bound and reads the clock,
    // also one gone by the time of its stat (review r12 R12-06).
    let mut entries: u64 = 0;
    let mut charge = || -> io::Result<Option<PayloadUsage>> {
        entries = entries.saturating_add(1);
        if entries > bounds.entries_max {
            return Ok(Some(PayloadUsage::Unmeasurable {
                why: format!("more than {} entries", bounds.entries_max),
            }));
        }
        if started.elapsed() > bounds.time_max {
            return Err(out_of_time(entries));
        }
        Ok(None)
    };
    // Each file once by its inode, whatever its names now: a file whose
    // second name goes while the walk runs is not counted twice (review r12
    // R12-05), nor a directory the held files' count meets again (r14
    // R14-01).
    let mut bytes: u64 = 0;
    let mut add = |stat: &Stat| -> Option<PayloadUsage> {
        if !counted.insert(file_identity(stat)) {
            return None;
        }
        let blocks = u64::try_from(stat.st_blocks).unwrap_or(0);
        bytes = bytes.saturating_add(blocks.saturating_mul(BLOCK_BYTES));
        (bytes > stop_past).then_some(PayloadUsage::Past { bytes })
    };

    let top_stat = rustix::fs::fstat(&top)?;
    if !is_directory(&top_stat) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the payload is not a directory",
        ));
    }
    if let Some(done) = charge()? {
        return Ok(done);
    }
    if let Some(done) = add(&top_stat) {
        return Ok(done);
    }
    // One open directory per level: the payload's, then each directory on
    // the way down to the one being read.
    let mut open = vec![Dir::new(top)?];
    loop {
        let level = open.len();
        let Some(dir) = open.last_mut() else {
            break;
        };
        let Some(entry) = dir.read() else {
            open.pop();
            continue;
        };
        let entry = entry?;
        let name = entry.file_name();
        if name == c"." || name == c".." {
            continue;
        }
        if let Some(done) = charge()? {
            return Ok(done);
        }
        let parent = dir.fd()?;
        let stat = match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            // Removed since the listing: nothing to count.
            Err(rustix::io::Errno::NOENT) => continue,
            Err(error) => return Err(error.into()),
        };
        if let Some(done) = add(&stat) {
            return Ok(done);
        }
        if !is_directory(&stat) {
            continue;
        }
        // The entry is at level `level`: the payload's own entries are at
        // level 1.
        if level > deepest {
            return Ok(PayloadUsage::Unmeasurable {
                why: format!("deeper than {depth_max} directories"),
            });
        }
        let child = match rustix::fs::openat(parent, name, directory_flags(), Mode::empty()) {
            Ok(child) => child,
            // Removed, or replaced by a file or a link, since its stat: the
            // walk goes on, and the next check counts what replaced it
            // (review r12 R12-02).
            Err(rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR | rustix::io::Errno::LOOP) => {
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        open.push(Dir::new(child)?);
    }
    // The clock once more: a slow last read is no measure (review r12
    // R12-06). The bound is the walk's own; a caller that needs a hard
    // deadline keeps the walk in a process it can stop.
    if started.elapsed() > bounds.time_max {
        return Err(out_of_time(entries));
    }
    Ok(PayloadUsage::Measured { bytes })
}

/// The (device, inode) pair that names one file.
fn file_identity(stat: &Stat) -> (u64, u64) {
    (
        u64::try_from(stat.st_dev).unwrap_or(u64::MAX),
        u64::try_from(stat.st_ino).unwrap_or(u64::MAX),
    )
}

fn is_directory(stat: &Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::Directory
}
