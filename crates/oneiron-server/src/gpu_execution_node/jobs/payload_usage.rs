//! The size of a key's payload on disk (design pass 33, 7.9; FIX
//! EXEC-NODE-DISK-CHECK-UNBUILT): what the engine compares with the key's
//! disk request every `disk_check_secs`, and ends the key as `DiskLimit`
//! past it ([`super::NodeJobs::check_payload_disk`]).
//!
//! The walk opens each directory beneath the one before it and never
//! through a link. It counts the blocks each entry holds on disk, so a
//! sparse file counts what it holds and not its length, and a file with
//! more than one name once. It stops as soon as the count passes the bound
//! it was given.
//!
//! A payload the walk cannot finish within its bounds ([`PayloadWalkBounds`]:
//! so many directory levels, so many entries) is
//! [`PayloadUsage::Unmeasurable`] and passes every request: the node cannot
//! show that it is within. A walk that runs out of time is an error
//! instead, and the next check measures again: a slow disk is not the job's
//! doing.

use std::collections::HashSet;
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::{Duration, Instant};

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat};

/// The deepest directory the walk enters, counted from the payload
/// directory (its own entries are at level 1). The walk holds one open
/// directory per level.
pub const PAYLOAD_WALK_DEPTH_MAX: usize = 64;

/// The most entries the walk counts, the payload directory included.
pub const PAYLOAD_WALK_ENTRIES_MAX: u64 = 1_000_000;

/// The longest one walk takes: within the job control handler's own limit
/// and the engine's wait for its answer.
pub const PAYLOAD_WALK_TIME_MAX: Duration = Duration::from_secs(15);

/// How often, in entries, the walk reads the clock.
const CLOCK_EVERY_ENTRIES: u64 = 1_024;

/// The unit of `st_blocks`.
const BLOCK_BYTES: u64 = 512;

/// The flags every directory of the walk opens with: a directory only,
/// never through a link.
fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

/// The bounds of one walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadWalkBounds {
    pub depth_max: usize,
    pub entries_max: u64,
    pub time_max: Duration,
}

impl Default for PayloadWalkBounds {
    fn default() -> Self {
        Self {
            depth_max: PAYLOAD_WALK_DEPTH_MAX,
            entries_max: PAYLOAD_WALK_ENTRIES_MAX,
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
    let started = Instant::now();
    let mut bytes: u64 = 0;
    let mut entries: u64 = 0;
    // The files with more than one name counted so far.
    let mut linked = HashSet::new();
    let mut count = |stat: &Stat| -> io::Result<Option<PayloadUsage>> {
        entries = entries.saturating_add(1);
        if entries > bounds.entries_max {
            return Ok(Some(PayloadUsage::Unmeasurable {
                why: format!("more than {} entries", bounds.entries_max),
            }));
        }
        if entries.is_multiple_of(CLOCK_EVERY_ENTRIES) && started.elapsed() > bounds.time_max {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "not measured within {} s ({entries} entries)",
                    bounds.time_max.as_secs()
                ),
            ));
        }
        if !is_directory(stat) && stat.st_nlink > 1 && !linked.insert((stat.st_dev, stat.st_ino)) {
            return Ok(None);
        }
        let blocks = u64::try_from(stat.st_blocks).unwrap_or(0);
        bytes = bytes.saturating_add(blocks.saturating_mul(BLOCK_BYTES));
        Ok((bytes > stop_past).then_some(PayloadUsage::Past { bytes }))
    };

    let top_stat = rustix::fs::fstat(&top)?;
    if !is_directory(&top_stat) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the payload is not a directory",
        ));
    }
    if let Some(done) = count(&top_stat)? {
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
        let parent = dir.fd()?;
        let stat = match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            // Removed since the listing: nothing to count.
            Err(rustix::io::Errno::NOENT) => continue,
            Err(error) => return Err(error.into()),
        };
        if let Some(done) = count(&stat)? {
            return Ok(done);
        }
        if !is_directory(&stat) {
            continue;
        }
        // The entry is at level `level`: the payload's own entries are at
        // level 1.
        if level > bounds.depth_max {
            return Ok(PayloadUsage::Unmeasurable {
                why: format!("deeper than {} directories", bounds.depth_max),
            });
        }
        let child = match rustix::fs::openat(parent, name, directory_flags(), Mode::empty()) {
            Ok(child) => child,
            Err(rustix::io::Errno::NOENT) => continue,
            Err(error) => return Err(error.into()),
        };
        open.push(Dir::new(child)?);
    }
    Ok(PayloadUsage::Measured { bytes })
}

fn is_directory(stat: &Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::Directory
}
