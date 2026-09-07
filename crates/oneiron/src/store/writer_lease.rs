//! Process-owner writer lease, shared by the server and embedded SDK.

use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

use crate::{Error, Result, VaultConfig};

#[cfg(unix)]
use super::root_directory::{file_identity, named_directory_identity, open_root_directory};
use super::{DefaultPolicySeedMode, STORAGE_ABI_VERSION, Store};

#[cfg(test)]
mod tests;

/// Lock-file name for the process-owner single-writer lease (ONE-1441 WIRE-P1).
///
/// Deliberately its own file, NOT a reuse of the off-record sweep lock: that
/// one is dedicated to off-record recovery and pairs a different lifetime with
/// a different owner. Two unrelated exclusions sharing one inode would make
/// either feature's hold silently deny the other.
pub const VAULT_WRITER_LOCK_FILE: &str = "oneiron.writer.lock";

/// The `Error::ConcurrentWrite` message that means "another process holds this
/// vault directory's writer lease" (ONE-1441 WIRE-P1).
///
/// Load-bearing as an EXACT string: the SDK's embedded constructor maps
/// `Error::ConcurrentWrite(message)` to the typed
/// `VAULT_LOCKED_SINGLE_WRITER` binding code ONLY when
/// `message == VAULT_WRITER_LEASE_HELD`. Every other `ConcurrentWrite` keeps
/// the existing `From<Error>` mapping to `INVALID_STATE`, and that impl is not
/// amended.
pub const VAULT_WRITER_LEASE_HELD: &str = "vault writer lease is held by another process";

/// An exclusive, process-scoped hold on one vault directory's write side
/// (ONE-1441 WIRE-P1 single-writer ownership).
///
/// The AUTHORITY is the live OS lock held on the open file description, never
/// the file's contents. The bytes are diagnostics only — the acquiring PID and
/// a newline — so a stale pidfile left by a crashed owner blocks nothing: the
/// kernel dropped its lock when the process died, and the next acquirer
/// truncates and rewrites the line.
///
/// The guard OWNS the open file. Releasing is `Drop` and nothing else: there
/// is deliberately no public unlock method, because an explicit release could
/// run while another in-process handle still believed it held the lease. A
/// shared native vault keeps one lease value alive (behind an `Arc`) for its
/// whole lifetime, so the single drop that releases it is the last one.
///
/// [`Self::pid`] records the acquiring process. A post-`fork` child inherits
/// the descriptor — and therefore the kernel's lock — without ever having
/// acquired it, so the SDK dispatcher compares [`Self::pid`] against the
/// current PID before every verb and fails closed when they differ. That check
/// is [`Self::held_by_current_process`]; the lease does not enforce it itself,
/// because the enforcement point is the dispatcher, not the handle.
pub struct VaultWriterLease {
    /// Held for the lease's whole lifetime: dropping the file closes the
    /// descriptor, and closing the descriptor is what releases the OS lock.
    ///
    /// Stored as an option so Drop can close the descriptor explicitly.
    file: Option<std::fs::File>,
    pid: u32,
    #[cfg(unix)]
    directory: std::fs::File,
}

impl Store {
    pub(crate) fn open_with_writer_lease(
        path: &Path,
        config: &VaultConfig,
        lease: &VaultWriterLease,
    ) -> Result<Self> {
        Self::open_with_lease(
            path,
            config,
            STORAGE_ABI_VERSION,
            DefaultPolicySeedMode::Required,
            Some(lease),
        )
    }
}

impl VaultWriterLease {
    /// Acquires the exclusive writer lease on `vault_dir`, or refuses.
    ///
    /// Non-blocking: a directory already owned by another process fails
    /// immediately with `Error::ConcurrentWrite(VAULT_WRITER_LEASE_HELD)`
    /// rather than parking. Contention is a fact about the deployment, not a
    /// transient the caller should wait out.
    ///
    /// Non-contention failures — a missing directory, a permission denial, a
    /// read-only filesystem — keep their ordinary typed `Error::Io` and never
    /// masquerade as lock contention, so an operator's diagnosis is not
    /// redirected at a process that does not exist.
    ///
    /// Unix uses `flock`. Other targets refuse rather than claim exclusion
    /// without an OS locking primitive.
    pub fn acquire(vault_dir: &Path) -> Result<Self> {
        let pid = std::process::id();
        #[cfg(unix)]
        let directory = open_root_directory(vault_dir)?;
        #[cfg(target_os = "linux")]
        let lock_dir = {
            use std::os::fd::AsRawFd;
            PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()))
        };
        #[cfg(not(target_os = "linux"))]
        let lock_dir = vault_dir.to_path_buf();
        let file = Self::lock_exclusive_nonblocking(&lock_dir)?;
        let lease = Self {
            file,
            pid,
            #[cfg(unix)]
            directory,
        };
        lease.validate_directory(vault_dir)?;
        if let Some(file) = lease.file.as_ref() {
            Self::write_pid_line(file, pid)?;
        }
        Ok(lease)
    }

    /// Refuses reuse when the pathname no longer names the leased directory.
    /// The live descriptor pins the inode, so delete/recreate cannot recycle it.
    pub fn validate_directory(&self, vault_dir: &Path) -> Result<()> {
        if !self.held_by_current_process() {
            return Err(Error::ConcurrentWrite(VAULT_WRITER_LEASE_HELD));
        }
        #[cfg(unix)]
        if named_directory_identity(vault_dir)?.as_ref()
            == Some(&file_identity(&self.directory.metadata()?))
        {
            return Ok(());
        }
        #[cfg(not(unix))]
        let _ = vault_dir;
        Err(Error::InvalidConfig(
            "vault directory identity changed while its writer lease was held".to_owned(),
        ))
    }

    /// The same descriptor-bound path used by the existing-only store door.
    #[cfg(target_os = "linux")]
    pub(super) fn environment_path(&self) -> PathBuf {
        use std::os::fd::AsRawFd;
        PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
    }

    /// The process that acquired this lease.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// Whether the CALLING process is the one that acquired this lease.
    ///
    /// `false` in a post-`fork` child holding an inherited handle: the child
    /// never took the lock, so it must not write through it even though the
    /// inherited descriptor would let the kernel say yes.
    #[must_use]
    pub fn held_by_current_process(&self) -> bool {
        self.pid == std::process::id()
    }

    #[cfg(unix)]
    fn lock_exclusive_nonblocking(vault_dir: &Path) -> Result<Option<std::fs::File>> {
        use std::os::fd::AsRawFd;

        // `create(true)` + `truncate(false)`: the file is a rendezvous point,
        // not state. Truncating before the lock is granted would let a REFUSED
        // acquirer erase the live owner's diagnostics.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(vault_dir.join(VAULT_WRITER_LOCK_FILE))?;
        // SAFETY: `file` is a live, open `std::fs::File` owned by this frame
        // and closed nowhere within it, so `as_raw_fd()` yields a descriptor
        // valid for the whole call. `flock` reads only that descriptor and the
        // flag word, and writes nothing through a pointer.
        let granted = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if granted == 0 {
            return Ok(Some(file));
        }
        let error = std::io::Error::last_os_error();
        // EWOULDBLOCK (EAGAIN on Linux and macOS) is the ONLY contention
        // answer. Everything else is a real I/O failure and keeps its typed
        // error, so a permission problem is never reported as a busy vault.
        if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Err(Error::ConcurrentWrite(VAULT_WRITER_LEASE_HELD));
        }
        Err(error.into())
    }

    #[cfg(not(unix))]
    fn lock_exclusive_nonblocking(_vault_dir: &Path) -> Result<Option<std::fs::File>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "vault writer leases require a supported OS locking primitive",
        )
        .into())
    }

    /// Records the owning PID for humans reading the directory. Diagnostics
    /// only: nothing reads this back to decide who owns the lease.
    fn write_pid_line(mut file: &std::fs::File, pid: u32) -> Result<()> {
        use std::io::{Seek, SeekFrom, Write};

        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(format!("{pid}\n").as_bytes())?;
        file.flush()?;
        Ok(())
    }
}

impl Drop for VaultWriterLease {
    fn drop(&mut self) {
        // Never LOCK_UN: fork duplicates the SAME open file description.
        // Closing the child's duplicate cannot unlock the parent's hold.
        drop(self.file.take());
    }
}

impl std::fmt::Debug for VaultWriterLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultWriterLease")
            .field("pid", &self.pid)
            .finish_non_exhaustive()
    }
}
