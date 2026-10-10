//! Spinning a moment before sleeping. A small call is answered in tens of
//! microseconds, about what a sleeping thread takes to wake, so a thread
//! that expects its next frame or job soon polls for it briefly first.

use std::os::unix::net::UnixStream;
use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;

const SPIN_US: u64 = 100;

/// How long a waiting thread polls before it sleeps.
pub const SPIN: Duration = Duration::from_micros(SPIN_US);

/// Polls `stream` for up to [`SPIN`] until a byte, the end or an error is
/// there to read, then returns; the caller's blocking read follows and
/// meets it. A zero-timeout poll reads nothing, so a pending socket error
/// is left for that read (a peek would clear it on Linux).
pub fn poll_readable(stream: &UnixStream) {
    let until = Instant::now() + SPIN;
    let now = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    while Instant::now() < until {
        let mut fds = [PollFd::new(stream, PollFlags::IN)];
        match poll(&mut fds, Some(&now)) {
            Ok(0) | Err(Errno::INTR) => std::hint::spin_loop(),
            _ => return,
        }
    }
}

/// Receives from `rx`, polling for up to [`SPIN`] (never past `deadline`)
/// before it blocks until `deadline` (or for as long as it takes).
///
/// # Errors
/// As [`Receiver::recv_timeout`].
pub fn recv_spinning<T>(
    rx: &Receiver<T>,
    deadline: Option<Instant>,
) -> Result<T, RecvTimeoutError> {
    let spun = Instant::now() + SPIN;
    let until = deadline.map_or(spun, |deadline| spun.min(deadline));
    while Instant::now() < until {
        match rx.try_recv() {
            Ok(value) => return Ok(value),
            Err(TryRecvError::Disconnected) => return Err(RecvTimeoutError::Disconnected),
            Err(TryRecvError::Empty) => std::hint::spin_loop(),
        }
    }
    match deadline {
        Some(deadline) => rx.recv_timeout(deadline.saturating_duration_since(Instant::now())),
        None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
    }
}
