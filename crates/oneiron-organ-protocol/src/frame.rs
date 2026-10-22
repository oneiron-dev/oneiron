//! Framing (protocol 2.0): a message is one or more frames back to back,
//! each `len: u32 LE | more: u8 | len bytes`, `more` 1 on every frame but
//! the message's last. The bytes of all its frames together are the
//! message's encoding ([`crate::codec`]). Descriptors ride as `SCM_RIGHTS`
//! on the send that carries a frame's first byte, at most
//! [`MAX_FDS_PER_FRAME`] on one frame: a message's descriptors are its
//! frames' in order, and the rest of a larger set rides the next frame. A
//! frame is at most its receiver's frame limit long, and a longer message
//! takes more frames. So neither the `u32` length nor the descriptor count
//! limits a message: each only paces its frames.
//!
//! A message with a deadline is bounded as a whole, not per read or write:
//! a peer that stops reading, or drips one byte at a time, ends it at the
//! deadline with [`FrameError::TimedOut`]. A timed message waits with
//! poll(2) and moves bytes without blocking; it never sets a socket timeout
//! or mode, which every clone of the socket would share. A timed send needs
//! a socket the caller made nonblocking: macOS ignores `MSG_DONTWAIT` while
//! a send waits for room, so only the socket's own mode keeps it from
//! blocking past the deadline. An untimed read on such a socket, or a
//! clone of it, waits in poll(2) through [`recv_frame_polled`].
//!
//! A booked message makes room before each allocation it makes (FIX 6195):
//! a sender counts the encoding's bytes with nothing allocated
//! ([`frame_body_len`]) and books them before it sends; a read books each
//! frame's declared length before reading it, then the value the message
//! decodes into before that is built ([`FrameBooking`]).

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

use crate::codec::{self, CodecError};
use crate::wire::{INITIAL_HANDSHAKE_FRAME_BYTES, MAX_FDS_PER_FRAME};

mod booked;

use booked::Unbooked;
pub use booked::{
    FrameBooking, frame_body_len, recv_frame_polled_booked, recv_frame_until_booked,
    recv_handshake, recv_handshake_until_booked,
};

/// `len: u32 LE | more: u8`.
const HEADER: usize = 5;

/// The longest single poll(2). macOS has no ppoll: its poll takes the
/// timeout as an i32 of milliseconds (about 24.8 days) and fails a longer
/// one with EINVAL. A later deadline polls again.
const LONGEST_POLL: Duration = Duration::from_millis(i32::MAX as u64);

/// How often a gated message waiting for room before its first byte asks
/// again whether it is still wanted ([`send_frame_if`]).
const RECHECK: Duration = Duration::from_millis(20);

/// Why a message could not be sent or read. Any of them ends the
/// connection, except a refusal [`FrameError::is_local`] reports.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("the peer closed the connection")]
    Closed,
    /// A frame past its receiver's frame limit, or a handshake message past
    /// the pre-session bound: the peer broke the framing.
    #[error("frame of {len} bytes is over the {limit}-byte limit")]
    TooLarge { len: u64, limit: u64 },
    #[error("descriptors were cut off in transit")]
    FdsTruncated,
    #[error("protocol violation: {0}")]
    Protocol(&'static str),
    /// The message was refused before a byte of it left, by the caller's
    /// own booking (the machine's memory floor).
    #[error("frame refused before sending: {0}")]
    Refused(&'static str),
    /// The deadline passed before the message's first byte left.
    #[error("the deadline passed before the frame was sent")]
    Late,
    /// The caller withdrew the message before its first byte left
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
    Encode(CodecError),
    #[error("frame decode: {0}")]
    Decode(CodecError),
    #[error("frame io: {0}")]
    Io(#[from] io::Error),
}

impl FrameError {
    /// No byte of the message left (it did not encode, or was refused or
    /// withdrawn, or its deadline came first), so the connection is still
    /// in step and the peer saw nothing.
    #[must_use]
    pub fn is_local(&self) -> bool {
        matches!(
            self,
            Self::Encode(_) | Self::Refused(_) | Self::Late | Self::Withdrawn | Self::Blocking
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

/// Encodes `msg` and sends it with `fds` attached, in as many frames of at
/// most `limit` bytes and [`MAX_FDS_PER_FRAME`] descriptors as it takes.
///
/// # Errors
/// Fails on encode and on any socket error.
pub fn send_frame<T: Serialize + ?Sized>(
    stream: &UnixStream,
    msg: &T,
    fds: &[BorrowedFd<'_>],
    limit: u32,
) -> Result<(), FrameError> {
    send_frame_with(stream, msg, fds, limit, Wait::Syscall, Gate::open()).map(|_| ())
}

/// [`send_frame`], with the whole message bounded by `deadline`, on a
/// socket the caller made nonblocking. A message cut off by the deadline
/// leaves the stream out of step: close it. Returns the message's encoded
/// length, every frame's header aside.
///
/// # Errors
/// As [`send_frame`], plus [`FrameError::Blocking`] for a timed send on a
/// socket in blocking mode, [`FrameError::Late`] when no byte left by the
/// deadline, and [`FrameError::TimedOut`] for a message cut off part way.
pub fn send_frame_until<T: Serialize + ?Sized>(
    stream: &UnixStream,
    msg: &T,
    fds: &[BorrowedFd<'_>],
    limit: u32,
    deadline: Option<Instant>,
) -> Result<u64, FrameError> {
    send_frame_with(stream, msg, fds, limit, Wait::until(deadline), Gate::open())
}

/// [`send_frame_until`], sent only while `still` says so. Before each try
/// at the message's first byte, `still` is asked again and the guard it
/// returns is held across that try; `started` runs with that guard as the
/// first byte leaves. So whatever `still` locks orders the message's start
/// against the lock's other holders: once they have withdrawn the message,
/// no byte of it leaves, and once a byte has left they see what `started`
/// did. While the message waits for room before its first byte, `still` is
/// asked every 20 ms, so a message withdrawn then ends at once, not at its
/// deadline. A message that has started is finished, every frame of it. The
/// deadline is checked again once `still` returns, but not while it waits:
/// it should take only a lock its holders keep briefly. Returns the
/// message's encoded length.
///
/// # Errors
/// As [`send_frame_until`], plus [`FrameError::Withdrawn`] when `still`
/// returned `None` before the first byte left.
pub fn send_frame_if<T: Serialize + ?Sized, G>(
    stream: &UnixStream,
    msg: &T,
    fds: &[BorrowedFd<'_>],
    limit: u32,
    deadline: Instant,
    still: impl FnMut() -> Option<G>,
    started: impl FnMut(&mut G),
) -> Result<u64, FrameError> {
    let gate = Gate {
        still,
        started,
        recheck: Some(RECHECK),
    };
    send_frame_with(stream, msg, fds, limit, Wait::Poll(Some(deadline)), gate)
}

/// What a message's first byte waits for besides room ([`send_frame_if`]).
struct Gate<S, F> {
    still: S,
    started: F,
    /// How often a wait for room before the first byte asks `still` again.
    recheck: Option<Duration>,
}

impl Gate<fn() -> Option<()>, fn(&mut ())> {
    /// A message no one can withdraw.
    fn open() -> Self {
        Self {
            still: || Some(()),
            started: |_| {},
            recheck: None,
        }
    }
}

fn send_frame_with<T: Serialize + ?Sized, G>(
    stream: &UnixStream,
    msg: &T,
    fds: &[BorrowedFd<'_>],
    limit: u32,
    wait: Wait,
    mut gate: Gate<impl FnMut() -> Option<G>, impl FnMut(&mut G)>,
) -> Result<u64, FrameError> {
    if wait.polls() && !fcntl_getfl(stream).is_ok_and(|mode| mode.contains(OFlags::NONBLOCK)) {
        return Err(FrameError::Blocking);
    }
    #[cfg(target_vendor = "apple")]
    rustix::net::sockopt::set_socket_nosigpipe(stream, true).map_err(io::Error::from)?;
    // The encoding's length first, with nothing allocated, so the buffer is
    // made whole, as the sender booked it.
    let len = codec::encoded_len(msg).map_err(FrameError::Encode)?;
    let capacity = usize::try_from(len).map_err(|_| {
        FrameError::Encode(CodecError::Invalid("a message past this address space"))
    })?;
    let mut body = Vec::with_capacity(capacity);
    codec::write_into(&mut body, msg).map_err(FrameError::Encode)?;
    let chunk = usize::try_from(limit.max(1)).unwrap_or(usize::MAX);
    let frames = body
        .len()
        .div_ceil(chunk)
        .max(fds.len().div_ceil(MAX_FDS_PER_FRAME))
        .max(1);
    for at in 0..frames {
        let bytes = piece(&body, at, chunk);
        let carried = piece(fds, at, MAX_FDS_PER_FRAME);
        let mut header = [0u8; HEADER];
        header[..4].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        header[4] = u8::from(at + 1 < frames);
        let frame = Frame {
            header: &header,
            bytes,
            fds: carried,
        };
        send_one(stream, &frame, wait, &mut gate, at == 0)?;
    }
    Ok(len)
}

/// The `at`th run of at most `size` items of `all`, empty past its end.
fn piece<T>(all: &[T], at: usize, size: usize) -> &[T] {
    let rest = all.get(at.saturating_mul(size)..).unwrap_or(&[]);
    &rest[..rest.len().min(size)]
}

/// One frame of a message, about to be sent.
struct Frame<'a> {
    header: &'a [u8; HEADER],
    bytes: &'a [u8],
    fds: &'a [BorrowedFd<'a>],
}

/// Sends one frame. Before the message's first byte, `first` and `gate`
/// decide whether it still goes; the frame's descriptors ride on its own
/// first byte.
fn send_one<G>(
    stream: &UnixStream,
    frame: &Frame<'_>,
    wait: Wait,
    gate: &mut Gate<impl FnMut() -> Option<G>, impl FnMut(&mut G)>,
    first: bool,
) -> Result<(), FrameError> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS_PER_FRAME))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !frame.fds.is_empty() && !control.push(SendAncillaryMessage::ScmRights(frame.fds)) {
        return Err(FrameError::Protocol(
            "a frame's descriptors did not fit its control buffer",
        ));
    }
    let header = frame.header.as_slice();
    let total = HEADER + frame.bytes.len();
    let mut sent = 0;
    // Before the message's first byte, the message is still the caller's.
    let opening = |sent: usize| first && sent == 0;
    while sent < total {
        let room = match gate.recheck {
            Some(every) if opening(sent) => wait.within(every),
            _ => wait,
        };
        match ready(stream, room, true) {
            // Still no room before the first byte: is the message wanted?
            // Asked at the deadline too, and held across the clock check as
            // on the first send, so a message withdrawn before the deadline
            // is seen to pass ends withdrawn, not late.
            Err(FrameError::TimedOut) if opening(sent) && gate.recheck.is_some() => {
                let Some(_held) = (gate.still)() else {
                    return Err(FrameError::Withdrawn);
                };
                if wait.passed() {
                    return Err(FrameError::Late);
                }
                continue;
            }
            Err(FrameError::TimedOut) if opening(sent) => return Err(FrameError::Late),
            waited => waited?,
        }
        let iov = if sent < HEADER {
            [IoSlice::new(&header[sent..]), IoSlice::new(frame.bytes)]
        } else {
            [
                IoSlice::new(&frame.bytes[sent - HEADER..]),
                IoSlice::new(&[]),
            ]
        };
        // The descriptors ride on the frame's first send, which for the
        // message's first frame goes only while `still` holds.
        let result = if opening(sent) {
            let Some(mut guard) = (gate.still)() else {
                return Err(FrameError::Withdrawn);
            };
            if wait.passed() {
                return Err(FrameError::Late);
            }
            let written = sendmsg(stream, &iov, &mut control, SEND_FLAGS);
            if matches!(written, Ok(written) if written > 0) {
                (gate.started)(&mut guard);
            }
            drop(guard);
            written
        } else if wait.passed() {
            // Room can come after the deadline (poll rounds its wait up, or
            // this thread runs late); the rest of the message does not go
            // then.
            return Err(FrameError::TimedOut);
        } else if sent == 0 {
            sendmsg(stream, &iov, &mut control, SEND_FLAGS)
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
    Ok(())
}

/// Reads one message and the descriptors that rode with it, each frame of
/// it at most `limit` bytes.
///
/// # Errors
/// [`FrameError::Closed`] at a clean end of stream; any other variant for a
/// broken, oversized or undecodable frame.
pub fn recv_frame<T: DeserializeOwned>(
    stream: &UnixStream,
    limit: u32,
) -> Result<(T, Vec<OwnedFd>), FrameError> {
    recv_frame_with(stream, Bound::frames(limit), Wait::Syscall, Unbooked)
        .map(|(msg, fds, ..)| (msg, fds))
}

/// [`recv_frame`] for a socket in nonblocking mode: the message waits in
/// poll(2), with no deadline, for as long as its peer takes.
///
/// # Errors
/// As [`recv_frame`].
pub fn recv_frame_polled<T: DeserializeOwned>(
    stream: &UnixStream,
    limit: u32,
) -> Result<(T, Vec<OwnedFd>), FrameError> {
    recv_frame_with(stream, Bound::frames(limit), Wait::Poll(None), Unbooked)
        .map(|(msg, fds, ..)| (msg, fds))
}

/// [`recv_frame`], with the whole message bounded by `deadline`.
///
/// # Errors
/// As [`recv_frame`], plus [`FrameError::TimedOut`].
pub fn recv_frame_until<T: DeserializeOwned>(
    stream: &UnixStream,
    limit: u32,
    deadline: Option<Instant>,
) -> Result<(T, Vec<OwnedFd>), FrameError> {
    recv_frame_with(
        stream,
        Bound::frames(limit),
        Wait::until(deadline),
        Unbooked,
    )
    .map(|(msg, fds, ..)| (msg, fds))
}

/// What a read lets a message be: each frame at most `frame` bytes, and the
/// whole at most `message` where a bound holds before a session exists
/// ([`INITIAL_HANDSHAKE_FRAME_BYTES`]).
#[derive(Debug, Clone, Copy)]
struct Bound {
    frame: u32,
    message: Option<u64>,
}

impl Bound {
    fn frames(limit: u32) -> Self {
        Self {
            frame: limit,
            message: None,
        }
    }

    /// The handshake's: one pre-session bound on the whole message.
    fn handshake() -> Self {
        Self {
            frame: INITIAL_HANDSHAKE_FRAME_BYTES,
            message: Some(u64::from(INITIAL_HANDSHAKE_FRAME_BYTES)),
        }
    }

    /// A frame of `len` bytes after `before` bytes of its message.
    fn check(self, len: u32, before: u64) -> Result<(), FrameError> {
        if len > self.frame {
            return Err(FrameError::TooLarge {
                len: u64::from(len),
                limit: u64::from(self.frame),
            });
        }
        let whole = before.saturating_add(u64::from(len));
        match self.message {
            Some(limit) if whole > limit => Err(FrameError::TooLarge { len: whole, limit }),
            _ => Ok(()),
        }
    }
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

fn recv_frame_with<T: DeserializeOwned, B: FrameBooking>(
    stream: &UnixStream,
    bound: Bound,
    wait: Wait,
    mut booking: B,
) -> Result<(T, Vec<OwnedFd>, u64, B::Held), FrameError> {
    let mut fds = Vec::new();
    let (len, mut more) = recv_header(stream, wait, &mut fds)?;
    bound.check(len, 0)?;
    // The room first, then the bytes: nothing is allocated for a frame its
    // receiver has not made room for.
    let mut held = booking.body(u64::from(len))?;
    let mut body = Vec::new();
    recv_body(stream, wait, &mut body, len)?;
    while more {
        let (len, next) = recv_header(stream, wait, &mut fds)?;
        bound.check(len, body.len() as u64)?;
        booking.more(&mut held, u64::from(len))?;
        recv_body(stream, wait, &mut body, len)?;
        more = next;
    }
    let total = body.len() as u64;
    let shape = codec::shape(&body).map_err(FrameError::Decode)?;
    // Room for the value before it is built, while the bytes still live;
    // theirs goes back once only the value is left.
    booking.value(&mut held, shape.decoded())?;
    let message = codec::from_slice(&body).map_err(FrameError::Decode)?;
    drop(body);
    booking.body_gone(&mut held, total);
    Ok((message, fds, total, held))
}

/// One frame's header, and the descriptors that rode on its first byte.
fn recv_header(
    stream: &UnixStream,
    wait: Wait,
    fds: &mut Vec<OwnedFd>,
) -> Result<(u32, bool), FrameError> {
    let mut header = [0u8; HEADER];
    let mut got = 0;
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
    let [a, b, c, d, more] = header;
    let more = match more {
        0 => false,
        1 => true,
        _ => {
            return Err(FrameError::Protocol(
                "a frame's more flag is neither 0 nor 1",
            ));
        }
    };
    Ok((u32::from_le_bytes([a, b, c, d]), more))
}

/// Appends one frame's `len` bytes to `body`, its room already made.
fn recv_body(
    stream: &UnixStream,
    wait: Wait,
    body: &mut Vec<u8>,
    len: u32,
) -> Result<(), FrameError> {
    let start = body.len();
    let len = len as usize;
    body.reserve_exact(len);
    body.resize(start + len, 0);
    let flags = if wait.polls() {
        RecvFlags::DONTWAIT
    } else {
        RecvFlags::empty()
    };
    let mut filled = start;
    while filled < body.len() {
        ready(stream, wait, false)?;
        match recv(stream, &mut body[filled..], flags) {
            Ok((0, _)) => return Err(FrameError::Closed),
            Ok((read, _)) => filled += read,
            Err(errno) if wait.retry(errno) => {}
            Err(errno) => return Err(io::Error::from(errno).into()),
        }
    }
    Ok(())
}
