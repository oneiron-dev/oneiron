//! `job-exec`'s check that the unit's system call filter holds for the job
//! (review r13 R13-06 of #10512): the plain ways to take disk with no write
//! are refused (design 7.9; a mitigation, the disk check's module doc).

use std::os::fd::{FromRawFd, OwnedFd};
use std::path::Path;

/// `Ok` when the job cannot take disk with no write: `fallocate` on a file
/// in its own `tmp` (`dir`) answers `EOPNOTSUPP`, and `io_uring_setup`
/// answers `ENOSYS` or `EPERM` (review r13 R13-06 of #10512). The unit's
/// system call filter gives the first two; a file system without
/// `fallocate`, a kernel without io_uring or one that disables it gives the
/// same answers, and serves the same end for good. Any other failure (no
/// space, no memory, no descriptor left) is no refusal, so the check is not
/// made (review r14 R14-05). The instance's effective filter is checked by
/// the prepare step; this shows that it holds for this process. Run as the
/// job's ids.
///
/// # Errors
///
/// What the job could do, or why the check could not be made.
pub(super) fn disk_allocation_refused(dir: &Path) -> Result<(), String> {
    use rustix::fs::{FallocateFlags, Mode, OFlags};
    let fail = |error: rustix::io::Errno| format!("{}: {error}", dir.display());
    let file = match rustix::fs::open(
        dir,
        OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(file) => file,
        // No unnamed files here: a named one, gone at once.
        Err(rustix::io::Errno::OPNOTSUPP | rustix::io::Errno::ISDIR) => {
            let directory = rustix::fs::open(
                dir,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(fail)?;
            let name = c".oneiron-allocation-check";
            let file = rustix::fs::openat(
                &directory,
                name,
                OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(fail)?;
            rustix::fs::unlinkat(&directory, name, rustix::fs::AtFlags::empty()).map_err(fail)?;
            file
        }
        Err(error) => return Err(fail(error)),
    };
    match rustix::fs::fallocate(&file, FallocateFlags::empty(), 0, ALLOCATION_CHECK_BYTES) {
        Ok(()) => return Err("fallocate took blocks with no write".to_owned()),
        Err(rustix::io::Errno::OPNOTSUPP) => {}
        Err(error) => return Err(format!("fallocate's refusal not shown: {error}")),
    }
    drop(file);
    let mut params = [0_u8; IO_URING_PARAMS_BYTES];
    let entries: libc::c_uint = 1;
    // SAFETY: io_uring_setup reads and writes `params`, which is valid for
    // its whole size (the kernel's `struct io_uring_params`), all zero.
    let ring = unsafe { libc::syscall(libc::SYS_io_uring_setup, entries, params.as_mut_ptr()) };
    let setup_error = std::io::Error::last_os_error();
    if ring >= 0 {
        if let Ok(ring) = libc::c_int::try_from(ring) {
            // SAFETY: the call just made this descriptor, and nothing else
            // holds it.
            drop(unsafe { OwnedFd::from_raw_fd(ring) });
        }
        return Err("an io_uring ring was made".to_owned());
    }
    match setup_error.raw_os_error() {
        Some(libc::ENOSYS | libc::EPERM) => Ok(()),
        _ => Err(format!("io_uring's refusal not shown: {setup_error}")),
    }
}

/// The bytes [`disk_allocation_refused`] asks `fallocate` for.
const ALLOCATION_CHECK_BYTES: u64 = 4_096;

/// The size of the kernel's `struct io_uring_params`.
const IO_URING_PARAMS_BYTES: usize = 120;
