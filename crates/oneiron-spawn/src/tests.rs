//! The walk that stands in where close_range is missing or refused finds a
//! descriptor above the soft limit, opened before the limit dropped (Sol on
//! #1416: a bound read from the limit misses it).

use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};

use super::close_on_exec_walk;

#[test]
fn the_walk_marks_a_descriptor_above_a_limit_lowered_after_it_opened() {
    let null = std::fs::File::open("/dev/null").expect("/dev/null");
    let (high, _limit) = copy_above_a_lowered_limit(null.as_raw_fd());
    let high = high.as_raw_fd();

    #[expect(
        clippy::disallowed_methods,
        reason = "a bare fork runs the walk as the helper's child does"
    )]
    // SAFETY: until it exits, the child makes only async-signal-safe calls
    // (the walk, fcntl, _exit).
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let code = if close_on_exec_walk(3).is_err() {
            2
        } else {
            // SAFETY: fcntl on a descriptor this process holds.
            match unsafe { libc::fcntl(high, libc::F_GETFD) } {
                flags if flags < 0 => 3,
                flags if flags & libc::FD_CLOEXEC != 0 => 0,
                _ => 1,
            }
        };
        // SAFETY: _exit ends the child without this process's exit handlers.
        unsafe { libc::_exit(code) };
    }
    assert!(pid > 0, "fork: {}", io::Error::last_os_error());
    let mut status = 0;
    loop {
        // SAFETY: waitpid writes the child's status into the int on the stack.
        match unsafe { libc::waitpid(pid, &mut status, 0) } {
            done if done == pid => break,
            _ if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) => {}
            _ => panic!("waitpid: {}", io::Error::last_os_error()),
        }
    }
    assert!(libc::WIFEXITED(status), "the child did not exit: {status}");
    match libc::WEXITSTATUS(status) {
        0 => {}
        1 => panic!("descriptor {high}, above the soft limit, stays open across exec"),
        2 => panic!("the walk failed in the child"),
        code => panic!("the child could not read descriptor {high}'s flags ({code})"),
    }
}

/// A copy of `fd` at the lowest free number from 65,537 where the limits
/// allow it (else from a lower start that fits), with the soft limit then lowered
/// to that number, so the copy sits above it. The guard puts the soft limit
/// back when it drops.
fn copy_above_a_lowered_limit(fd: RawFd) -> (OwnedFd, SoftLimit) {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes the struct on the stack.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
        0
    );
    let guard = SoftLimit(limit);
    let raised = libc::rlimit {
        rlim_cur: limit.rlim_max.min(70_001),
        rlim_max: limit.rlim_max,
    };
    // SAFETY: setrlimit reads the struct; a soft limit up to the hard one
    // needs no privilege, and a refusal or a clamp leaves a lower one.
    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) };
    // SAFETY: getrlimit writes the struct on the stack.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
        0
    );
    let mut from = if limit.rlim_cur > 65_537 {
        65_537
    } else {
        limit.rlim_cur / 2
    };
    // macOS also caps descriptor numbers at its per-process maximum, which
    // can sit below the soft limit, and refuses a start at or above it with
    // EINVAL: halve the start until one fits.
    let high = loop {
        let start = libc::c_int::try_from(from).expect("a descriptor number");
        // SAFETY: F_DUPFD copies an open descriptor to the lowest free number
        // at or above `start`, without close-on-exec, and touches no other
        // slot.
        let high = unsafe { libc::fcntl(fd, libc::F_DUPFD, start) };
        if high >= 0 {
            break high;
        }
        let error = io::Error::last_os_error();
        assert!(
            error.raw_os_error() == Some(libc::EINVAL) && from > 64,
            "a copy from {from}: {error}"
        );
        from /= 2;
    };
    // SAFETY: F_DUPFD has just opened it, and nothing else owns it.
    let copy = unsafe { OwnedFd::from_raw_fd(high) };
    let lowered = libc::rlimit {
        rlim_cur: libc::rlim_t::try_from(high).expect("a limit"),
        rlim_max: limit.rlim_max,
    };
    // SAFETY: setrlimit reads the struct; lowering the soft limit leaves
    // descriptors already open above it.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lowered) }, 0);
    (copy, guard)
}

/// The soft limit to put back.
struct SoftLimit(libc::rlimit);

impl Drop for SoftLimit {
    fn drop(&mut self) {
        // SAFETY: setrlimit reads the struct.
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &self.0) };
    }
}
