//! Starting a subprocess with only the descriptors it is meant to have.
//!
//! A descriptor this process opens is not always close-on-exec from the
//! moment it exists. On macOS, std makes a socket pair or a pipe first and
//! marks it close-on-exec in a second call, so a subprocess another thread
//! starts in between keeps a copy across exec: for example the receiving end
//! of a call's socket, and with it the call's key. So every subprocess the
//! workspace's crates start comes from [`command`] or [`command_with_fds`] (or
//! their tokio forms); the workspace's clippy.toml refuses any other
//! `Command::new`, `fork` or `posix_spawn`.
//!
//! Between fork and exec, the process marks every descriptor above the
//! standard three close-on-exec, whatever its flag here, and then puts the
//! descriptors its caller names at the numbers it names. It finds every open
//! descriptor there, after the fork: with close_range on Linux 5.11 and later,
//! else from the list in /proc/self/fd; on macOS, by every slot of the
//! descriptor table the kernel reports. Where it cannot, the subprocess does
//! not start.

use std::ffi::OsStr;
#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::os::fd::RawFd;
use std::process::Command;

/// A command for `program` whose process starts with the standard three
/// descriptors and no other.
#[must_use]
#[cfg_attr(
    not(unix),
    expect(clippy::disallowed_methods, reason = "the one place a command is made")
)]
pub fn command(program: impl AsRef<OsStr>) -> Command {
    #[cfg(unix)]
    {
        command_with_fds(program, &[])
    }
    #[cfg(not(unix))]
    {
        Command::new(program)
    }
}

/// A command for `program` whose process starts with the standard three
/// descriptors and, for each `(ours, theirs)` in `fds`, this process's
/// descriptor `ours` at number `theirs`, open across exec. Each `ours` is
/// above the standard three: std sets up the child's standard descriptors
/// before this runs, so a lower one would already be replaced, and the spawn
/// fails with EBADF instead. No `theirs` may be another pair's `ours`. A
/// closure the caller adds with `pre_exec` runs after this, with the
/// descriptors in place.
#[cfg(unix)]
#[must_use]
pub fn command_with_fds(program: impl AsRef<OsStr>, fds: &[(RawFd, RawFd)]) -> Command {
    use std::os::unix::process::CommandExt as _;
    #[expect(clippy::disallowed_methods, reason = "the one place a command is made")]
    let mut command = Command::new(program);
    let fds = fds.to_vec();
    // SAFETY: the closure runs in the child between fork and exec. It only
    // makes async-signal-safe calls (close_range, open, getdents64, close,
    // the proc_info system call, fcntl, dup2) on numbers it holds or reads
    // there, takes no lock and allocates nothing.
    unsafe {
        command.pre_exec(move || inherit_only(&fds));
    }
    command
}

/// [`command`], for tokio.
#[cfg(feature = "tokio")]
#[must_use]
pub fn tokio_command(program: impl AsRef<OsStr>) -> tokio::process::Command {
    command(program).into()
}

/// [`command_with_fds`], for tokio.
#[cfg(all(unix, feature = "tokio"))]
#[must_use]
pub fn tokio_command_with_fds(
    program: impl AsRef<OsStr>,
    fds: &[(RawFd, RawFd)],
) -> tokio::process::Command {
    command_with_fds(program, fds).into()
}

/// Marks every descriptor above the standard three close-on-exec, then puts
/// each `(ours, theirs)` in place without the flag.
#[cfg(unix)]
fn inherit_only(fds: &[(RawFd, RawFd)]) -> io::Result<()> {
    if fds.iter().any(|&(ours, _)| ours < 3) {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }
    close_on_exec_from(3)?;
    for &(ours, theirs) in fds {
        let placed = if ours == theirs {
            // SAFETY: fcntl on a descriptor this process holds; clearing its
            // close-on-exec flag only keeps it across exec.
            unsafe { libc::fcntl(theirs, libc::F_SETFD, 0) == 0 }
        } else {
            // SAFETY: both descriptors are valid in the child; dup2 leaves the
            // copy on `theirs` without close-on-exec.
            unsafe { libc::dup2(ours, theirs) == theirs }
        };
        if !placed {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Marks every open descriptor from `first` up close-on-exec.
#[cfg(unix)]
fn close_on_exec_from(first: RawFd) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: close_range with CLOSE_RANGE_CLOEXEC only sets a flag on
        // this process's descriptors. Kernels before 5.11, and filters that
        // refuse the call, fail it, and the walk covers that.
        let done = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                first,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            )
        } == 0;
        if done {
            return Ok(());
        }
    }
    close_on_exec_walk(first)
}

/// Marks each descriptor from `first` up that /proc/self/fd lists.
#[cfg(target_os = "linux")]
fn close_on_exec_walk(first: RawFd) -> io::Result<()> {
    // SAFETY: open takes a NUL-terminated path from a literal.
    let listing = unsafe {
        libc::open(
            c"/proc/self/fd".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if listing < 0 {
        return Err(io::Error::last_os_error());
    }
    let walked = mark_listed(listing, first);
    // SAFETY: closes the descriptor opened above, which nothing else holds.
    unsafe { libc::close(listing) };
    walked
}

/// Marks each descriptor from `first` up that the open directory `listing`
/// names, other than `listing` itself.
#[cfg(target_os = "linux")]
fn mark_listed(listing: RawFd, first: RawFd) -> io::Result<()> {
    // Each entry: inode (8 bytes), offset (8), entry length (2), type (1),
    // then the name and a NUL.
    const NAME: usize = 19;
    let mut entries = [0_u8; 4096];
    loop {
        // SAFETY: getdents64 writes at most `entries.len()` bytes into the
        // buffer on the stack.
        let got = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                listing,
                entries.as_mut_ptr(),
                entries.len(),
            )
        };
        let got = usize::try_from(got).map_err(|_| io::Error::last_os_error())?;
        if got == 0 {
            return Ok(());
        }
        let mut at = 0;
        while at < got {
            let Some(&[low, high]) = entries.get(at + 16..at + 18) else {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            };
            let length = usize::from(u16::from_ne_bytes([low, high]));
            if length <= NAME {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            let name = entries.get(at + NAME..at + length).unwrap_or_default();
            if let Some(fd) = descriptor_named(name)
                && fd >= first
                && fd != listing
            {
                mark(fd)?;
            }
            at += length;
        }
    }
}

/// The descriptor number a /proc/self/fd entry names; `.` and `..` name none.
#[cfg(target_os = "linux")]
fn descriptor_named(name: &[u8]) -> Option<RawFd> {
    let mut number: RawFd = 0;
    let mut digits = 0;
    for &byte in name.iter().take_while(|&&byte| byte != 0) {
        if !byte.is_ascii_digit() {
            return None;
        }
        number = number.checked_mul(10)?.checked_add(RawFd::from(byte - b'0'))?;
        digits += 1;
    }
    (digits > 0).then_some(number)
}

/// Marks each descriptor from `first` up to the size of this process's
/// descriptor table: the kernel's count of its slots (xnu's `fd_nfiles`),
/// which every open descriptor's number is below.
#[cfg(target_vendor = "apple")]
fn close_on_exec_walk(first: RawFd) -> io::Result<()> {
    const SIZE: usize = size_of::<libc::proc_bsdinfo>();
    let size = libc::c_int::try_from(SIZE).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    // SAFETY: proc_pidinfo is libproc's wrapper for the proc_info system call:
    // it writes at most `size` bytes into the struct on the stack, takes no
    // lock and allocates nothing.
    let got = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if got != size {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call filled the whole struct.
    let slots = unsafe { info.assume_init() }.pbi_nfiles;
    for fd in first..RawFd::try_from(slots).unwrap_or(RawFd::MAX) {
        mark(fd)?;
    }
    Ok(())
}

/// No way to list this process's descriptors here, so no subprocess starts.
#[cfg(all(unix, not(any(target_os = "linux", target_vendor = "apple"))))]
fn close_on_exec_walk(_first: RawFd) -> io::Result<()> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// Sets close-on-exec on `fd`; a number that is not open is skipped.
#[cfg(unix)]
fn mark(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl on a descriptor number that may not be open; one that is
    // not fails with EBADF.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || flags & libc::FD_CLOEXEC != 0 {
        return Ok(());
    }
    // SAFETY: as above; this only sets the flag on an open descriptor.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests;
