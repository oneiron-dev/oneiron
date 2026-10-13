//! A subprocess started through the helper while a new socket pair is still
//! open across exec gets none of it. That is the moment std leaves on macOS,
//! where it makes a pair with plain socketpair and marks each end
//! close-on-exec in a second call; a subprocess another thread starts in that
//! moment would keep the receiving end of a call's socket. The far end is
//! also copied above the soft descriptor limit, opened before the limit
//! dropped, where a bound read from the limit would miss it.
#![cfg(unix)]

use std::io::Write as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::process::Stdio;

/// The descriptor numbers the runner checks. Unset, the runner is a no-op, as
/// it is in a normal test run.
const RUNNER: &str = "ONEIRON_SPAWN_RUNNER";
const SENTINEL: &str = "sentinel-frame-0000";

#[test]
fn a_subprocess_started_while_a_new_socket_pair_is_open_across_exec_gets_none_of_it() {
    // The moment: a pair made with plain socketpair, neither end close-on-exec.
    let mut pair = [0; 2];
    // SAFETY: socketpair writes two descriptors into the array on the stack.
    let made = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) };
    assert_eq!(made, 0, "socketpair: {}", std::io::Error::last_os_error());
    // SAFETY: socketpair has just opened both, and nothing else owns them.
    let (ours, theirs) = unsafe { (OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1])) };
    let (high, limit) = copy_above_a_lowered_limit(&theirs);
    let numbers = format!(
        "{} {} {}",
        ours.as_raw_fd(),
        theirs.as_raw_fd(),
        high.as_raw_fd()
    );
    // An unrelated subprocess starts in that moment.
    let runner = oneiron_spawn::command(std::env::current_exe().expect("test binary"))
        .args(["--exact", "runner", "--nocapture"])
        .env(RUNNER, &numbers)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("runner");
    // The pair then carries a call: this process lets its copies of the far
    // end go and writes the frame on its own.
    drop(theirs);
    drop(high);
    drop(limit);
    let mut ours = UnixStream::from(ours);
    // Refused once nothing holds the far end.
    let _ = ours.write_all(SENTINEL.as_bytes());
    let ran = runner.wait_with_output().expect("runner output");
    let report = String::from_utf8_lossy(&ran.stdout);
    assert!(ran.status.success(), "the runner failed: {report}");
    assert!(
        report.lines().any(|line| line == "HELD 0"),
        "the subprocess holds a socket at {numbers}: {report}"
    );
    assert!(
        !report.contains(SENTINEL),
        "the subprocess read the frame: {report}"
    );
}

/// A copy of `fd` at the lowest free number from 65,537 where the limits
/// allow it (else from half the soft limit), with the soft limit then lowered
/// to that number, so the copy sits above it. The guard puts the soft limit
/// back when it drops.
fn copy_above_a_lowered_limit(fd: &OwnedFd) -> (OwnedFd, SoftLimit) {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes the struct on the stack.
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) }, 0);
    let guard = SoftLimit(limit);
    let raised = libc::rlimit {
        rlim_cur: limit.rlim_max.min(70_001),
        rlim_max: limit.rlim_max,
    };
    // SAFETY: setrlimit reads the struct; a soft limit up to the hard one
    // needs no privilege, and a refusal or a clamp leaves a lower one.
    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) };
    // SAFETY: getrlimit writes the struct on the stack.
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) }, 0);
    let from = if limit.rlim_cur > 65_537 { 65_537 } else { limit.rlim_cur / 2 };
    let from = libc::c_int::try_from(from).expect("a descriptor number");
    // SAFETY: F_DUPFD copies an open descriptor to the lowest free number at
    // or above `from`, without close-on-exec, and touches no other slot.
    let high = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD, from) };
    assert!(high >= 0, "a copy from {from}: {}", std::io::Error::last_os_error());
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

/// The subprocess: says how many of the numbers it was given are sockets it
/// holds, and what it reads from each within 3 s.
#[test]
fn runner() {
    let Some(numbers) = std::env::var_os(RUNNER) else {
        return;
    };
    let mut held = 0;
    let mut read = Vec::new();
    for fd in numbers.to_string_lossy().split_whitespace() {
        let fd: RawFd = fd.parse().expect("a descriptor number");
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fstat writes a stat struct on the stack; a descriptor number
        // that is not open fails with EBADF.
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
            continue;
        }
        // SAFETY: fstat succeeded, so it filled the struct.
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFSOCK {
            continue;
        }
        held += 1;
        let mut ready = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll reads and writes one pollfd on the stack.
        if unsafe { libc::poll(&mut ready, 1, 3000) } == 1 {
            let mut bytes = [0_u8; 64];
            // SAFETY: read writes at most 64 bytes into the buffer on the stack.
            let got = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
            if let Ok(got) = usize::try_from(got) {
                read.extend_from_slice(&bytes[..got]);
            }
        }
    }
    println!("\nHELD {held}");
    println!("READ {}", String::from_utf8_lossy(&read));
}
