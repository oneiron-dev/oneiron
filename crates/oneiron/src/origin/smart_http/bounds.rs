//! What one served exchange may cost the machine: how long it may sit idle,
//! how long a push waits for its repository, and the memory and disk floors
//! its door scan keeps.

use std::time::Duration;

use crate::error::{Error, Result};

/// The per-blob bound when the machine's memory cannot be read.
const DOOR_SCAN_BLOB_BYTES_FALLBACK: u64 = 256 * 1024 * 1024;

/// The free disk the hook leaves when it frames a push's blobs, by default.
const DOOR_SCAN_DISK_FLOOR_BYTES: u64 = 1024 * 1024 * 1024;

/// The bounds a transport that admits exchanges by permit serves one under.
/// They come from trusted host configuration, never from the request, and
/// are fixed before the backend is spawned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExchangeBounds {
    /// How long the exchange may move no byte, in either direction, before
    /// its backend is ended.
    pub idle: Duration,
    /// How long a push waits for the repository another writer holds.
    pub repository_wait: Duration,
    /// The floors the door's scan keeps.
    pub scan: ScanBounds,
}

/// The floors a push's door scan keeps. The door holds one blob at a time, so
/// memory is bounded per blob, never per push; the hook frames every blob to
/// disk, so the disk keeps a floor of free space. Neither is a count: a push
/// of any size lands while each blob fits and the disk holds the push.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanBounds {
    blob_bytes: u64,
    disk_floor_bytes: u64,
}

impl ScanBounds {
    /// The largest value either bound takes: the hook compares in `awk`, whose
    /// numbers are doubles, exact to 2^53.
    pub const MAX_BYTES: u64 = 1 << 53;

    /// Bounds holding at most `blob_bytes` of one blob and leaving at least
    /// `disk_floor_bytes` of disk free. Zero, or past [`Self::MAX_BYTES`], is a
    /// config error.
    pub fn new(blob_bytes: u64, disk_floor_bytes: u64) -> Result<Self> {
        for value in [blob_bytes, disk_floor_bytes] {
            if !(1..=Self::MAX_BYTES).contains(&value) {
                return Err(Error::InvalidConfig(format!(
                    "a scan bound must be 1 to {} bytes",
                    Self::MAX_BYTES
                )));
            }
        }
        Ok(Self {
            blob_bytes,
            disk_floor_bytes,
        })
    }

    /// The most bytes one blob may hold for the door to scan it.
    #[must_use]
    pub fn blob_bytes(self) -> u64 {
        self.blob_bytes
    }

    /// The free disk the hook leaves when it frames a push's blobs.
    #[must_use]
    pub fn disk_floor_bytes(self) -> u64 {
        self.disk_floor_bytes
    }

    /// The per-blob default: a sixty-fourth of the machine's memory. A push
    /// holds its blob and the scanner's copies of the line it is reading,
    /// which come to at most three times that line, so eight pushes each
    /// holding a blob at the bound hold half of the memory. 256 MiB when the
    /// memory cannot be read.
    #[must_use]
    pub fn machine_blob_bytes() -> u64 {
        machine_memory_bytes()
            .map(|memory| (memory / 64).min(Self::MAX_BYTES))
            .filter(|bytes| *bytes > 0)
            .unwrap_or(DOOR_SCAN_BLOB_BYTES_FALLBACK)
    }

    /// The default disk floor.
    #[must_use]
    pub fn default_disk_floor_bytes() -> u64 {
        DOOR_SCAN_DISK_FLOOR_BYTES
    }
}

impl Default for ScanBounds {
    fn default() -> Self {
        Self {
            blob_bytes: Self::machine_blob_bytes(),
            disk_floor_bytes: DOOR_SCAN_DISK_FLOOR_BYTES,
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn machine_memory_bytes() -> Option<u64> {
    // SAFETY: `sysconf` reads a system constant: it takes no pointer and has
    // no precondition, and a negative answer is read as unknown below.
    let (pages, page_bytes) = unsafe {
        (
            libc::sysconf(libc::_SC_PHYS_PAGES),
            libc::sysconf(libc::_SC_PAGESIZE),
        )
    };
    u64::try_from(pages)
        .ok()?
        .checked_mul(u64::try_from(page_bytes).ok()?)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn machine_memory_bytes() -> Option<u64> {
    None
}
