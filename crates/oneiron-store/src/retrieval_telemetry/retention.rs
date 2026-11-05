//! Bounded, expirable base-ledger retrieval runs and crash-orphan reconciliation.

use heed::RwTxn;

use crate::side_table::codec::CodecError;
use crate::side_table::codec::RawValue;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::error::SideTableRowProblem;
use oneiron_base::error::StoreError;

/// [`RETRIEVAL_AGE_BY_RUN`]'s value: the capture time, u64 big-endian.
pub struct CapturedAt(pub u64);

impl RawValue for CapturedAt {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(self.0.to_be_bytes().to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let bytes = bytes
            .try_into()
            .map_err(|_| Error::CorruptedIndex("retrieval run retention"))?;
        Ok(Self(u64::from_be_bytes(bytes)))
    }
}

/// A key that does not spell its table's shape stays a corrupt-index error.
pub fn corrupt_key(context: &'static str) -> impl FnOnce(Error) -> Error {
    move |error| match error {
        Error::Store(StoreError::SideTableRow {
            problem: SideTableRowProblem::KeyShape,
            ..
        }) => Error::CorruptedIndex(context),
        other => other,
    }
}

/// On Linux every live Store holds a shared lock for its lifetime. The sole opener may
/// take an exclusive lock, sweep crashed provisional rows, then downgrade.
/// A second process with an active run keeps its shared lock, so an opener
/// cannot mistake that run for an orphan. The file is one stable inode per
/// vault, not one file per retrieval.
#[cfg(target_os = "linux")]
pub const RETRIEVAL_TELEMETRY_LOCK_FILE: &str = "oneiron.retrieval-telemetry.lock";

#[cfg(target_os = "linux")]
pub struct RetrievalTelemetryLease {
    pub file: std::fs::File,
    pub pid: u32,
}

#[cfg(target_os = "linux")]
impl RetrievalTelemetryLease {
    pub fn acquire(dir: &std::fs::File) -> Result<(Self, bool)> {
        use std::os::fd::AsRawFd;
        let lock_name = std::ffi::CString::new(RETRIEVAL_TELEMETRY_LOCK_FILE)
            .expect("static lock filename contains no NUL");
        // SAFETY: dir is a live directory fd; lock_name is NUL-terminated,
        // and openat returns a new fd adopted exactly once below. O_NOFOLLOW
        // refuses a hostile link at the lock filename.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                lock_name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        let file = crate::root_directory::adopt_descriptor(fd)?;
        // SAFETY: the descriptor remains owned by `file` for the whole call.
        let exclusive = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if exclusive == 0 {
            return Ok((
                Self {
                    file,
                    pid: std::process::id(),
                },
                true,
            ));
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(error.into());
        }
        // Another live Store holds SH. Join it without sweeping. An EX sweep
        // in progress refuses this opener rather than blocking on an unknown
        // amount of legacy data.
        // SAFETY: the same live file descriptor is still owned by `file`.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok((
            Self {
                file,
                pid: std::process::id(),
            },
            false,
        ))
    }

    pub fn downgrade(&self) -> Result<()> {
        use std::os::fd::AsRawFd;
        // SAFETY: `file` remains open through the returned Store lifetime.
        if unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_SH) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for RetrievalTelemetryLease {
    fn drop(&mut self) {
        if self.pid == std::process::id() {
            use std::os::fd::AsRawFd;
            // SAFETY: this process owns the live descriptor. Explicit unlock
            // prevents a forked child inheriting it from extending our hold.
            unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}
