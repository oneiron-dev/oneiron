//! The walk that stands in where close_range is missing or refused finds a
//! descriptor above the soft limit, opened before the limit dropped (Sol on
//! #1416: a bound read from the limit misses it).

use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};

use super::close_on_exec_walk;

#[test]
fn the_walk_marks_a_descriptor_above_a_limit_lowered_after_it_opened() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes the struct on the stack.
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) }, 0);
    let original = limit.rlim_cur;
    // Room above 65,536 where the hard limit allows it.
    let raised = libc::rlimit {
        rlim_cur: limit.rlim_max.min(70_001),
        rlim_max: limit.rlim_max,
    };
    // SAFETY: setrlimit reads the struct; a soft limit up to the hard one
    // needs no privilege, and a refusal leaves the old one.
    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) };
    // SAFETY: as above.
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) }, 0);
    let high = RawFd::try_from(limit.rlim_cur - 1).expect("a descriptor number");
    assert!(high > 1024, "no room above 1024 under this host's descriptor limit");
    let null = std::fs::File::open("/dev/null").expect("/dev/null");
    // SAFETY: dup2 copies an open descriptor to a number below the soft limit
    // that nothing here uses; the copy has no close-on-exec flag.
    assert_eq!(unsafe { libc::dup2(null.as_raw_fd(), high) }, high);
    // SAFETY: dup2 has just opened it, and nothing else owns it.
    let high_copy = unsafe { OwnedFd::from_raw_fd(high) };
    let lowered = libc::rlimit {
        rlim_cur: original.min(1024),
        rlim_max: limit.rlim_max,
    };
    // SAFETY: setrlimit reads the struct; lowering the soft limit leaves
    // descriptors already open above it.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lowered) }, 0);

    #[expect(
        clippy::disallowed_methods,
        reason = "a bare fork runs the walk as the helper's child does"
    )]
    // SAFETY: until it exits, the child makes only async-signal-safe calls
    // (the walk, fcntl, _exit).
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let code = match close_on_exec_walk(3) {
            Err(_) => 2,
            // SAFETY: fcntl on a descriptor this process holds.
            Ok(()) if unsafe { libc::fcntl(high, libc::F_GETFD) } & libc::FD_CLOEXEC != 0 => 0,
            Ok(()) => 1,
        };
        // SAFETY: _exit ends the child without this process's exit handlers.
        unsafe { libc::_exit(code) };
    }
    assert!(pid > 0, "fork: {}", io::Error::last_os_error());
    let mut status = 0;
    // SAFETY: waitpid writes the child's status into the int on the stack.
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    drop(high_copy);
    let restored = libc::rlimit {
        rlim_cur: original,
        rlim_max: limit.rlim_max,
    };
    // SAFETY: setrlimit reads the struct.
    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &restored) };
    assert!(libc::WIFEXITED(status), "the child did not exit: {status}");
    match libc::WEXITSTATUS(status) {
        0 => {}
        1 => panic!("descriptor {high}, above the soft limit, stays open across exec"),
        code => panic!("the walk failed in the child ({code})"),
    }
}
