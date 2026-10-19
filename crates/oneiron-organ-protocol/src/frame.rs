//! Framing: `len: u32 LE | MessagePack body`, with descriptors riding as
//! `SCM_RIGHTS` on the send that carries the frame's first byte.
//!
//! A frame with a deadline is bounded as a whole, not per read or write: a
//! peer that stops reading, or drips one byte at a time, ends the frame at
//! the deadline with [`FrameError::TimedOut`]. A timed frame waits with
//! poll(2) and moves bytes without blocking; it never sets a socket timeout
//! or mode, which every clone of the socket would share. A timed send needs
//! a socket the caller made nonblocking: macOS ignores `MSG_DONTWAIT` while
//! a send waits for room, so only the socket's own mode keeps it from
//! blocking past the deadline. An untimed read on such a socket, or a
//! clone of it, waits in poll(2) through [`recv_frame_polled`].

use std::io::{self, IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::{OFlags, fcntl_getfl};
use rustix::io::Errno;
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recv, recvmsg, sendmsg,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::shape;
use crate::wire::MAX_FDS_PER_FRAME;

const HEADER: usize = 4;

/// The longest single poll(2). macOS has no ppoll: its poll takes the
/// timeout as an i32 of milliseconds (about 24.8 days) and fails a longer
/// one with EINVAL. A later deadline polls again.
const LONGEST_POLL: Duration = Duration::from_millis(i32::MAX as u64);

/// How often a gated frame waiting for room before its first byte asks
/// again whether it is still wanted ([`send_frame_if`]).
const RECHECK: Duration = Duration::from_millis(20);

/// Why a frame could not be sent or read. Any of them ends the connection,
/// except a refusal [`FrameError::is_local`] reports.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("the peer closed the connection")]
    Closed,
    #[error("frame of {len} bytes is over the {limit}-byte limit")]
    TooLarge { len: u64, limit: u32 },
    #[error("frame carries {0} descriptors; the limit is 16")]
    TooManyFds(usize),
    #[error("descriptors were cut off in transit")]
    FdsTruncated,
    #[error("protocol violation: {0}")]
    Protocol(&'static str),
    /// The frame's shape breaks the limits its receiver enforces
    /// ([`crate::MAX_FRAME_VALUES`], [`crate::MAX_FRAME_DEPTH`]).
    #[error("frame refused before sending: {0}")]
    Refused(&'static str),
    /// The deadline passed before the frame's first byte left.
    #[error("the deadline passed before the frame was sent")]
    Late,
    /// The caller withdrew the frame before its first byte left
    /// ([`send_frame_if`]).
    #[error("the frame was withdrawn before it was sent")]
    Withdrawn,
    /// A timed send on a socket in blocking mode, which could block past
    /// the deadline.
    #[error("a timed send needs a nonblocking socket")]
    Blocking,
    #[error("the frame missed its deadline")]
    TimedOut,
    #[error("frame encode: {0}")]
    Encode(#[from] rmp_serde::encode::Error),
    #[error("frame decode: {0}")]
    Decode(#[from] rmp_serde::decode::Error),
    #[error("frame io: {0}")]
    Io(#[from] io::Error),
}

impl FrameError {
    /// No byte of the frame left (it was refused or withdrawn, or its
    /// deadline came first), so the connection is still in step and the
    /// peer saw nothing.
    #[must_use]
    pub fn is_local(&self) -> bool {
        matches!(
            self,
            Self::TooLarge { .. }
                | Self::TooManyFds(_)
                | Self::Encode(_)
                | Self::Refused(_)
                | Self::Late
                | Self::Withdrawn
                | Self::Blocking
        )
    }
}

/// How a frame waits for its socket.
#[derive(Clone, Copy)]
enum Wait {
    /// In the syscall, which blocks, or ends where the caller's socket says.
    Syscall,
    /// In poll(2), until the deadline if there is one. The syscalls never
    /// block.
    Poll(Option<Instant>),
}

impl Wait {
    fn until(deadline: Option<Instant>) -> Self {
        deadline.map_or(Self::Syscall, |deadline| Self::Poll(Some(deadline)))
    }

    /// A frame that waits in [`ready`] never blocks in its syscalls.
    fn polls(self) -> bool {
        matches!(self, Self::Poll(_))
    }

    fn passed(self) -> bool {
        matches!(self, Self::Poll(Some(deadline)) if Instant::now() >= deadline)
    }

    /// The same wait, ending `span` from now if that is sooner.
    fn within(self, span: Duration) -> Self {
        let soon = Instant::now() + span;
        match self {
            Self::Syscall => Self::Syscall,
            Self::Poll(deadline) => Self::Poll(Some(deadline.map_or(soon, |at| at.min(soon)))),
        }
    }

    /// Whether a failed syscall is tried again. An interrupt always is.
    /// EAGAIN is only where [`ready`] waits first; a frame that waits in
    /// its syscall returns it, so a caller's own nonblocking mode or socket
    /// timeout still ends the read.
    fn retry(self, errno: Errno) -> bool {
        errno == Errno::INTR || (errno == Errno::AGAIN && self.polls())
    }
}

/// Waits until `stream` can be read (or written) or the deadline passes. A
/// frame that waits in its syscall does not wait here.
fn ready(stream: &UnixStream, wait: Wait, write: bool) -> Result<(), FrameError> {
    let Wait::Poll(deadline) = wait else {
        return Ok(());
    };
    let events = if write { PollFlags::OUT } else { PollFlags::IN };
    loop {
        let timeout = match deadline {
            None => None,
            Some(deadline) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(FrameError::TimedOut);
                }
                // At least a millisecond, so a poll that counts whole
                // milliseconds never spins.
                let span = left.clamp(Duration::from_millis(1), LONGEST_POLL);
                Some(Timespec {
                    tv_sec: span.as_secs() as i64,
                    tv_nsec: span.subsec_nanos() as _,
                })
            }
        };
        let mut fds = [PollFd::new(stream, events)];
        match poll(&mut fds, timeout.as_ref()) {
            // Readable, writable, hung up or in error: the syscall says which.
            Ok(n) if n > 0 => return Ok(()),
            Ok(_) | Err(Errno::INTR) => {}
            Err(errno) => return Err(io::Error::from(errno).into()),
        }
    }
}

/// A send to a closed peer fails with EPIPE rather than raising SIGPIPE in
/// a host that has not ignored it. rustix has no `MSG_NOSIGNAL` for macOS,
/// so there each frame sets the socket's `SO_NOSIGPIPE` instead: the one
/// option a frame sets, since no clone of the socket could want the
/// signal.
#[cfg(target_os = "linux")]
const SEND_FLAGS: SendFlags = SendFlags::NOSIGNAL;
#[cfg(not(target_os = "linux"))]
const SEND_FLAGS: SendFlags = SendFlags::empty();

/// Encodes `msg` and sends it with `fds` attached.
///
/// # Errors
/// Fails on encode, on a frame over `limit`, and on any socket error.
pub fn send_frame<T: Serialize>(
    stream: &UnixStream,
    msg: &T,
    fds: &[BorrowedFd<'_>],
    limit: u32,
) -> Result<(), FrameError> {
    send_frame_with(stream, msg, fds, limit, Wait::Syscall, Gate::open()).map(|_| ())
}

/// [`send_frame`], with the whole frame bounded by `deadline`, on a socket
/// the caller made nonblocking. A frame cut off by the deadline leaves the
/// stream out of step: close it. Returns the encoded body's length, the
/// four-byte header aside.
///
/// # Errors
/// As [`send_frame`], plus [`FrameError::Refused`] for a frame the receiver
/// would refuse, [`FrameError::Blocking`] for a timed send on a socket in
/// blocking mode, [`FrameError::Late`] when no byte left by the deadline,
/// and [`FrameError::TimedOut`] for a frame cut off part way.
pub fn send_frame_until<T: Serialize>(
    stream: &UnixStream,
    msg: &T,
    fds: &[BorrowedFd<'_>],
    limit: u32,
    deadline: Option<Instant>,
) -> Result<u32, FrameError> {
    send_frame_with(stream, msg, fds, limit, Wait::until(deadline), Gate::open())
}

/// [`send_frame_until`], sent only while `still` says so. Before each try
/// at the frame's first byte, `still` is asked again and the guard it
/// returns is held across that try; `started` runs with that guard as the
/// first byte leaves. So whatever `still` locks orders the frame's start
/// against the lock's other holders: once they have withdrawn the frame,
/// no byte of it leaves, and once a byte has left they see what `started`
/// did. While the frame waits for room before its first byte, `still` is
/// asked every 20 ms, so a frame withdrawn then ends at once, not at its
/// deadline. A frame that has started is finished. The deadline is checked
/// again once `still` returns, but not while it waits: it should take only
/// a lock its holders keep briefly. Returns the encoded body's length.
///
/// # Errors
/// As [`send_frame_until`], plus [`FrameError::Withdrawn`] when `still`
/// returned `None` before the first byte left.
pub fn send_frame_if<T: Serialize, G>(
    stream: &UnixStream,
    msg: &T,
    fds: &[BorrowedFd<'_>],
    limit: u32,
    deadline: Instant,
    still: impl FnMut() -> Option<G>,
    started: impl FnMut(&mut G),
) -> Result<u32, FrameError> {
    let gate = Gate {
        still,
        started,
        recheck: Some(RECHECK),
    };
    send_frame_with(stream, msg, fds, limit, Wait::Poll(Some(deadline)), gate)
}

/// What a frame's first byte waits for besides room ([`send_frame_if`]).
struct Gate<S, F> {
    still: S,
    started: F,
    /// How often a wait for room before the first byte asks `still` again.
    recheck: Option<Duration>,
}

impl Gate<fn() -> Option<()>, fn(&mut ())> {
    /// A frame no one can withdraw.
    fn open() -> Self {
        Self {
            still: || Some(()),
            started: |_| {},
            recheck: None,
        }
    }
}

fn send_frame_with<T: Serialize, G>(
    stream: &UnixStream,
    msg: &T,
    fds: &[BorrowedFd<'_>],
    limit: u32,
    wait: Wait,
    mut gate: Gate<impl FnMut() -> Option<G>, impl FnMut(&mut G)>,
) -> Result<u32, FrameError> {
    if wait.polls() && !fcntl_getfl(stream).is_ok_and(|mode| mode.contains(OFlags::NONBLOCK)) {
        return Err(FrameError::Blocking);
    }
    #[cfg(target_vendor = "apple")]
    rustix::net::sockopt::set_socket_nosigpipe(stream, true).map_err(io::Error::from)?;
    let body = rmp_serde::to_vec_named(msg)?;
    // Refused here, not by the receiver, which would end the connection.
    shape::check(&body).map_err(FrameError::Refused)?;
    let len = u32::try_from(body.len())
        .ok()
        .filter(|len| *len <= limit)
        .ok_or(FrameError::TooLarge {
            len: body.len() as u64,
            limit,
        })?;
    if fds.len() > MAX_FDS_PER_FRAME {
        return Err(FrameError::TooManyFds(fds.len()));
    }
    let header = len.to_le_bytes();
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS_PER_FRAME))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !fds.is_empty() && !control.push(SendAncillaryMessage::ScmRights(fds)) {
        return Err(FrameError::TooManyFds(fds.len()));
    }
    let total = HEADER + body.len();
    let mut sent = 0;
    let late = |sent: usize| {
        if sent == 0 {
            FrameError::Late
        } else {
            FrameError::TimedOut
        }
    };
    while sent < total {
        let room = match gate.recheck {
            Some(every) if sent == 0 => wait.within(every),
            _ => wait,
        };
        match ready(stream, room, true) {
            // Still no room before the first byte: is the frame wanted?
            // Asked at the deadline too, and held across the clock check as
            // on the first send, so a frame withdrawn before the deadline
            // is seen to pass ends withdrawn, not late.
            Err(FrameError::TimedOut) if sent == 0 && gate.recheck.is_some() => {
                let Some(_held) = (gate.still)() else {
                    return Err(FrameError::Withdrawn);
                };
                if wait.passed() {
                    return Err(FrameError::Late);
                }
                continue;
            }
            Err(FrameError::TimedOut) => return Err(late(sent)),
            waited => waited?,
        }
        let iov = if sent < HEADER {
            [IoSlice::new(&header[sent..]), IoSlice::new(&body)]
        } else {
            [IoSlice::new(&body[sent - HEADER..]), IoSlice::new(&[])]
        };
        // The descriptors ride on the first send only, which goes only
        // while `still` holds.
        let result = if sent == 0 {
            let Some(mut guard) = (gate.still)() else {
                return Err(FrameError::Withdrawn);
            };
            if wait.passed() {
                return Err(FrameError::Late);
            }
            let first = sendmsg(stream, &iov, &mut control, SEND_FLAGS);
            if matches!(first, Ok(written) if written > 0) {
                (gate.started)(&mut guard);
            }
            drop(guard);
            first
        } else if wait.passed() {
            // Room can come after the deadline (poll rounds its wait up, or
            // this thread runs late); the rest of the frame does not go then.
            return Err(FrameError::TimedOut);
        } else {
            sendmsg(
                stream,
                &iov,
                &mut SendAncillaryBuffer::default(),
                SEND_FLAGS,
            )
        };
        match result {
            Ok(written) => sent += written,
            // Interrupted, or the buffer filled again since poll: wait anew.
            Err(errno) if wait.retry(errno) => {}
            Err(errno) => return Err(io::Error::from(errno).into()),
        }
    }
    Ok(len)
}

/// Reads one frame and the descriptors that rode with it.
///
/// # Errors
/// [`FrameError::Closed`] at a clean end of stream; any other variant for a
/// broken, oversized or undecodable frame.
pub fn recv_frame<T: DeserializeOwned>(
    stream: &UnixStream,
    limit: u32,
) -> Result<(T, Vec<OwnedFd>), FrameError> {
    recv_frame_with(stream, limit, Wait::Syscall).map(|(msg, fds, _)| (msg, fds))
}

/// [`recv_frame`] for a socket in nonblocking mode: the frame waits in
/// poll(2), with no deadline, for as long as its peer takes.
///
/// # Errors
/// As [`recv_frame`].
pub fn recv_frame_polled<T: DeserializeOwned>(
    stream: &UnixStream,
    limit: u32,
) -> Result<(T, Vec<OwnedFd>), FrameError> {
    recv_frame_polled_len(stream, limit).map(|(msg, fds, _)| (msg, fds))
}

/// [`recv_frame_polled`], with the encoded body's length, the four-byte
/// header aside.
///
/// # Errors
/// As [`recv_frame`].
pub fn recv_frame_polled_len<T: DeserializeOwned>(
    stream: &UnixStream,
    limit: u32,
) -> Result<(T, Vec<OwnedFd>, u32), FrameError> {
    recv_frame_with(stream, limit, Wait::Poll(None))
}

/// Received descriptors are close-on-exec from the moment they exist, so no
/// process this one starts can inherit them.
#[cfg(target_os = "linux")]
const RECV_FLAGS: RecvFlags = RecvFlags::CMSG_CLOEXEC;
#[cfg(not(target_os = "linux"))]
const RECV_FLAGS: RecvFlags = RecvFlags::empty();

/// Linux set close-on-exec as the descriptors arrived (`RECV_FLAGS`).
/// Elsewhere there is no atomic flag: set it at once on each batch, before
/// the frame waits for more, so a peer that holds back the rest of its
/// header cannot hold the descriptors open to a process started meanwhile.
fn mark_cloexec(fds: &[OwnedFd]) -> io::Result<()> {
    if cfg!(target_os = "linux") {
        return Ok(());
    }
    for fd in fds {
        rustix::io::fcntl_setfd(fd, rustix::io::FdFlags::CLOEXEC)?;
    }
    Ok(())
}

/// [`recv_frame`], with the whole frame bounded by `deadline`.
///
/// # Errors
/// As [`recv_frame`], plus [`FrameError::TimedOut`].
pub fn recv_frame_until<T: DeserializeOwned>(
    stream: &UnixStream,
    limit: u32,
    deadline: Option<Instant>,
) -> Result<(T, Vec<OwnedFd>), FrameError> {
    recv_frame_with(stream, limit, Wait::until(deadline)).map(|(msg, fds, _)| (msg, fds))
}

fn recv_frame_with<T: DeserializeOwned>(
    stream: &UnixStream,
    limit: u32,
    wait: Wait,
) -> Result<(T, Vec<OwnedFd>, u32), FrameError> {
    let mut header = [0u8; HEADER];
    let mut got = 0;
    let mut fds = Vec::new();
    let flags = if wait.polls() {
        RECV_FLAGS | RecvFlags::DONTWAIT
    } else {
        RECV_FLAGS
    };
    while got < HEADER {
        ready(stream, wait, false)?;
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS_PER_FRAME))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let mut iov = [IoSliceMut::new(&mut header[got..])];
        let msg = match recvmsg(stream, &mut iov, &mut control, flags) {
            Ok(msg) => msg,
            Err(errno) if wait.retry(errno) => continue,
            Err(errno) => return Err(io::Error::from(errno).into()),
        };
        let before = fds.len();
        for message in control.drain() {
            if let RecvAncillaryMessage::ScmRights(received) = message {
                fds.extend(received);
            }
        }
        mark_cloexec(&fds[before..])?;
        if msg.flags.contains(ReturnFlags::CTRUNC) {
            return Err(FrameError::FdsTruncated);
        }
        if msg.bytes == 0 {
            return Err(FrameError::Closed);
        }
        got += msg.bytes;
    }
    if fds.len() > MAX_FDS_PER_FRAME {
        return Err(FrameError::TooManyFds(fds.len()));
    }
    let len = u32::from_le_bytes(header);
    if len > limit {
        return Err(FrameError::TooLarge {
            len: u64::from(len),
            limit,
        });
    }
    let mut body = vec![0u8; len as usize];
    let mut filled = 0;
    let body_flags = if wait.polls() {
        RecvFlags::DONTWAIT
    } else {
        RecvFlags::empty()
    };
    while filled < body.len() {
        ready(stream, wait, false)?;
        match recv(stream, &mut body[filled..], body_flags) {
            Ok((0, _)) => return Err(FrameError::Closed),
            Ok((read, _)) => filled += read,
            Err(errno) if wait.retry(errno) => {}
            Err(errno) => return Err(io::Error::from(errno).into()),
        }
    }
    shape::check(&body).map_err(FrameError::Protocol)?;
    Ok((rmp_serde::from_slice(&body)?, fds, len))
}
