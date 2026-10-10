//! Spinning a moment before sleeping. A small call is answered in tens of
//! microseconds, about what a sleeping thread takes to wake, so a thread
//! that expects its next frame or job soon polls for it briefly first.

use std::os::unix::net::UnixStream;
use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError};
use std::time::{Duration, Instant};

use rustix::io::Errno;
use rustix::net::{RecvFlags, recv};

const SPIN_US: u64 = 100;

/// How long a waiting thread polls before it sleeps.
pub const SPIN: Duration = Duration::from_micros(SPIN_US);

/// Polls `stream` for up to [`SPIN`] until a byte (or the end) is there to
/// read, then returns; the caller's blocking read follows.
pub fn poll_readable(stream: &UnixStream) {
    let until = Instant::now() + SPIN;
    let mut probe = [0u8; 1];
    while Instant::now() < until {
        match recv(stream, &mut probe, RecvFlags::PEEK | RecvFlags::DONTWAIT) {
            Err(Errno::AGAIN | Errno::INTR) => std::hint::spin_loop(),
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
