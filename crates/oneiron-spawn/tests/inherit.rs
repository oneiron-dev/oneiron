//! A subprocess started through the helper while a new socket pair is still
//! open across exec gets none of it. That is the moment std leaves on macOS,
//! where it makes a pair with plain socketpair and marks each end
//! close-on-exec in a second call; a subprocess another thread starts in that
//! moment would keep the receiving end of a call's socket.
#![cfg(unix)]

use std::io::Write as _;
use std::os::fd::{FromRawFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::process::Stdio;

/// What the runner reads its task from. Unset, the runner is a no-op, as it
/// is in a normal test run.
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
    // An unrelated subprocess starts in that moment.
    let runner = oneiron_spawn::command(std::env::current_exe().expect("test binary"))
        .args(["--exact", "runner", "--nocapture"])
        .env(RUNNER, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("runner");
    // The pair then carries a call: this process lets its copy of the far end
    // go and writes the frame on its own.
    drop(theirs);
    let mut ours = UnixStream::from(ours);
    // Refused once nothing holds the far end.
    let _ = ours.write_all(SENTINEL.as_bytes());
    let ran = runner.wait_with_output().expect("runner output");
    let report = String::from_utf8_lossy(&ran.stdout);
    assert!(ran.status.success(), "the runner failed: {report}");
    assert!(
        report.lines().any(|line| line == "SOCKETS 0"),
        "the subprocess holds a socket: {report}"
    );
    assert!(
        !report.contains(SENTINEL),
        "the subprocess read the frame: {report}"
    );
}

/// The subprocess: says how many sockets it holds beside the standard three,
/// and what it reads from each within 3 s.
#[test]
fn runner() {
    if std::env::var_os(RUNNER).is_none() {
        return;
    }
    let mut sockets = 0;
    let mut read = Vec::new();
    for fd in 3..1024 {
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
        sockets += 1;
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
    println!("\nSOCKETS {sockets}");
    println!("READ {}", String::from_utf8_lossy(&read));
}
