//! The task that made a brokered call, and the descriptor table the
//! launcher copies from (FIX 6185).
//!
//! Threads of one process may hold separate descriptor tables: a thread
//! that unshares its table (unshare, or close_range with
//! CLOSE_RANGE_UNSHARE) keeps numbers of its own. So the launcher opens a
//! pidfd for the calling task itself (PIDFD_THREAD, Linux 6.9). On a kernel
//! that refuses that flag, the thread group's pidfd reads the leader's
//! table, and the launcher uses it only while kcmp proves that table is the
//! task's own: before it opens it, and after each copy. A table once
//! unshared is never shared again, so a proof after a copy covers the copy.
//! A task whose table is its own then answers ENOTSUP, and the launcher
//! keeps no copy from it.
//!
//! A thread may also have its own working directory. A relative pathname
//! the task names resolves against it, and the launcher reaches it as
//! /proc/<tid>/cwd.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// Linux's kcmp type that compares two tasks' descriptor tables
/// (linux/kcmp.h); libc names no Linux value for it.
const KCMP_FILES: i32 = 2;

/// The calling task: the launcher duplicates the descriptors a call names
/// from its table (the access process_vm_readv already has), and raises
/// in it the signals the call raises.
pub(super) struct Task {
    tid: i32,
    tgid: i32,
    pidfd: OwnedFd,
    /// The pidfd names the thread group, so each copy comes from the
    /// leader's table and is proved to be from the task's own.
    group: bool,
}

impl Task {
    pub(super) fn open(tid: u32) -> io::Result<Self> {
        let status = std::fs::read_to_string(format!("/proc/{tid}/status"))?;
        let tgid = status
            .lines()
            .find_map(|line| line.strip_prefix("Tgid:"))
            .and_then(|id| id.trim().parse::<i32>().ok())
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ESRCH))?;
        let tid = tid as i32;
        let (pidfd, group) = match pidfd_open(tid, libc::PIDFD_THREAD) {
            Ok(pidfd) => (pidfd, false),
            // A kernel before Linux 6.9 knows no PIDFD_THREAD.
            Err(error) if error.raw_os_error() == Some(libc::EINVAL) => {
                shared_table(tid, tgid)?;
                (pidfd_open(tgid, 0)?, true)
            }
            Err(error) => return Err(error),
        };
        Ok(Self {
            tid,
            tgid,
            pidfd,
            group,
        })
    }

    /// The task's descriptor `fd`, duplicated into the launcher.
    pub(super) fn duplicate(&self, fd: RawFd) -> io::Result<OwnedFd> {
        // SAFETY: pidfd_getfd takes three integers and passes no pointer.
        let copy = unsafe { libc::syscall(libc::SYS_pidfd_getfd, self.pidfd.as_raw_fd(), fd, 0) };
        if copy < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a successful pidfd_getfd returned a new close-on-exec
        // descriptor, owned once.
        let copy = unsafe { OwnedFd::from_raw_fd(copy as RawFd) };
        if self.group {
            // A copy from a table that is not the task's closes here.
            shared_table(self.tid, self.tgid)?;
        }
        Ok(copy)
    }

    /// The launcher's path to the task's own working directory, against
    /// which a relative pathname the task names resolves.
    pub(super) fn working_directory(&self) -> String {
        format!("/proc/{}/cwd", self.tid)
    }

    /// Raises `signal` in the task (tgkill).
    pub(super) fn raise(&self, signal: i32) {
        // SAFETY: tgkill takes three integers and passes no pointer.
        unsafe {
            libc::syscall(libc::SYS_tgkill, self.tgid, self.tid, signal);
        }
    }
}

/// A pidfd for `pid`, opened with `flags`.
fn pidfd_open(pid: i32, flags: libc::c_uint) -> io::Result<OwnedFd> {
    // SAFETY: pidfd_open takes two integers and passes no pointer.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, flags) };
    if pidfd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful pidfd_open returned a new descriptor, owned
    // once.
    Ok(unsafe { OwnedFd::from_raw_fd(pidfd as RawFd) })
}

/// Proves that the task `tid` shares the descriptor table of its thread
/// group's leader `tgid` (kcmp); ENOTSUP when it does not, or when the
/// kernel cannot tell.
fn shared_table(tid: i32, tgid: i32) -> io::Result<()> {
    if tid == tgid {
        return Ok(());
    }
    // SAFETY: kcmp takes five integers and passes no pointer; KCMP_FILES
    // reads neither index.
    let order = unsafe { libc::syscall(libc::SYS_kcmp, tid, tgid, KCMP_FILES, 0_u64, 0_u64) };
    if order == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(libc::ENOTSUP))
    }
}
