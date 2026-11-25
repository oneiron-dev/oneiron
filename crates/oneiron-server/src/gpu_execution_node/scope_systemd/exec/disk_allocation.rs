//! `job-exec`'s check that the job cannot take disk with no write (review
//! r13 R13-06 of #10512): the disk check's bound rests on it (design 7.9).

use std::os::fd::{FromRawFd, OwnedFd};
use std::path::Path;

/// `Ok` when the job cannot take disk with no write: `fallocate` on a file
/// in its own `tmp` (`dir`) fails, and no io_uring ring can be made (review
/// r13 R13-06 of #10512). The unit's system call filter refuses both; a
/// file system without `fallocate` refuses it too, which serves the same
/// end. The instance's effective filter is checked by the prepare step; this
/// shows that it holds for this process. Run as the job's ids.
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
    if rustix::fs::fallocate(&file, FallocateFlags::empty(), 0, ALLOCATION_CHECK_BYTES).is_ok() {
        return Err("fallocate took blocks with no write".to_owned());
    }
    drop(file);
    let mut params = [0_u8; IO_URING_PARAMS_BYTES];
    let entries: libc::c_uint = 1;
    // SAFETY: io_uring_setup reads and writes `params`, which is valid for
    // its whole size (the kernel's `struct io_uring_params`), all zero.
    let ring = unsafe { libc::syscall(libc::SYS_io_uring_setup, entries, params.as_mut_ptr()) };
    if ring >= 0 {
        if let Ok(ring) = libc::c_int::try_from(ring) {
            // SAFETY: the call just made this descriptor, and nothing else
            // holds it.
            drop(unsafe { OwnedFd::from_raw_fd(ring) });
        }
        return Err("an io_uring ring was made".to_owned());
    }
    Ok(())
}

/// The bytes [`disk_allocation_refused`] asks `fallocate` for.
const ALLOCATION_CHECK_BYTES: u64 = 4_096;

/// The size of the kernel's `struct io_uring_params`.
const IO_URING_PARAMS_BYTES: usize = 120;
