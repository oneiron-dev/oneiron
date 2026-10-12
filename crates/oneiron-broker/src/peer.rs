//! Who this process is, and closing its memory to processes of its own uid.

use std::io;

/// The uid this process runs as.
pub(crate) fn own_uid() -> u32 {
    // SAFETY: getuid takes no arguments, cannot fail and touches no memory.
    unsafe { libc::getuid() }
}

/// Makes this process non-dumpable, so no other process of its uid can ptrace
/// it or read its `/proc/<pid>/{mem,environ}`.
#[cfg(target_os = "linux")]
pub(crate) fn harden() -> io::Result<()> {
    // SAFETY: prctl with constant arguments on this process.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Denies debugger attach to this process.
#[cfg(target_os = "macos")]
pub(crate) fn harden() -> io::Result<()> {
    // SAFETY: PT_DENY_ATTACH acts on this process only and reads nothing
    // through its null address.
    if unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// No way to close this process's memory is known here, so the broker does
/// not start.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn harden() -> io::Result<()> {
    Err(io::ErrorKind::Unsupported.into())
}
