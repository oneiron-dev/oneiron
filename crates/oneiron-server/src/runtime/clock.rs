//! Shared wall-clock time in Unix milliseconds, and `[runtime] clock`: the
//! clock this server's vault reads.
//!
//! `wall_clock_ms` returns zero before the epoch and saturates on overflow.
//! Runtime callers share this helper without owning a second clock.
//!
//! `[runtime] clock = "system"` (the default) leaves the vault on the host's
//! clock. `[runtime] clock = "manual"` gives the vault a [`ManualClockFile`]:
//! the time is the Unix milliseconds the file `[runtime] clock_file` holds,
//! and whoever runs the server moves it with [`ManualClockFile::set`]. A test
//! harness steps a stopped server's time this way instead of sleeping. The
//! vault's clock is also the clock the HTTP idempotency layer judges its
//! entries' age by; the server's other host timers stay on the host clock.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use oneiron::store::ports::{Clock, ManualClock, StoreClock};
use serde::Deserialize;

pub(crate) fn wall_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// `[runtime] clock`: where this server's vault reads the time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeClock {
    /// The host's clock.
    #[default]
    System,
    /// The time the file `[runtime] clock_file` holds, moved by whoever runs
    /// the server ([`ManualClockFile::set`]).
    Manual,
}

/// A clock whose time is the Unix milliseconds one regular file holds:
/// decimal digits, surrounding whitespace allowed. Each read reads the file.
/// A read that fails (the file is gone, is not a regular file, or holds
/// something else) keeps the last time read; a clock that has never read one
/// reads zero, which every proof window refuses. It never falls back to the
/// host's clock. Config validation refuses a file it cannot read before a
/// server starts ([`Self::read`]).
///
/// The file belongs on a local filesystem, writable only by whoever may set
/// the vault's time: the vault reads it inside its write transactions.
#[derive(Debug)]
pub struct ManualClockFile {
    path: PathBuf,
    last_ms: AtomicU64,
}

impl ManualClockFile {
    /// The clock `path` holds, read once now. A file that cannot be read is
    /// logged, and the clock reads zero until it can.
    pub fn new(path: PathBuf) -> Arc<Self> {
        let now = Self::read(&path).unwrap_or_else(|error| {
            tracing::error!(%error, "the manual clock reads 0 until its file holds Unix milliseconds");
            0
        });
        Arc::new(Self {
            path,
            last_ms: AtomicU64::new(now),
        })
    }

    /// Sets the time the file at `path` holds to `unix_ms`. The new value
    /// replaces the old one in a single rename, so a server reading the file
    /// sees one or the other, never a part.
    ///
    /// # Errors
    /// The file or its temporary sibling cannot be written.
    pub fn set(path: &Path, unix_ms: u64) -> io::Result<()> {
        let mut staged = path.as_os_str().to_owned();
        staged.push(".next");
        let staged = PathBuf::from(staged);
        std::fs::write(&staged, format!("{unix_ms}\n"))?;
        std::fs::rename(&staged, path)
    }

    /// The Unix milliseconds the regular file at `path` holds. A FIFO or a
    /// device is refused before it is opened, so a read never waits on a
    /// writer.
    ///
    /// # Errors
    /// The file is missing, is not a regular file, or does not hold Unix
    /// milliseconds. The error names the path, never the file's contents.
    pub fn read(path: &Path) -> io::Result<u64> {
        if !std::fs::metadata(path)?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a regular file", path.display()),
            ));
        }
        let text = std::fs::read_to_string(path)?;
        text.trim().parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} does not hold Unix milliseconds", path.display()),
            )
        })
    }

    /// The file's time now, or the last time read when the file cannot be
    /// read.
    pub fn now_ms(&self) -> u64 {
        match Self::read(&self.path) {
            Ok(now) => {
                self.last_ms.store(now, Ordering::Relaxed);
                now
            }
            Err(_) => self.last_ms.load(Ordering::Relaxed),
        }
    }

    /// The vault clock over this file. Entity ids come from a counter, as a
    /// [`ManualClock`]'s do: the vault keeps every id above the highest one
    /// it has persisted, so a restart never reuses one.
    pub fn store_clock(self: &Arc<Self>) -> StoreClock {
        StoreClock::new(self.clone(), ManualClock::new(0))
    }
}

impl Clock for ManualClockFile {
    fn now_recorded_at(&self) -> u64 {
        self.now_ms() / 1000
    }

    fn now_recorded_ms(&self) -> u64 {
        self.now_ms()
    }
}
