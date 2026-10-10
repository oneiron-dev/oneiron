//! Framing: `len: u32 LE | MessagePack body`, with descriptors riding as
//! `SCM_RIGHTS` on the send that carries the frame's first byte.
//!
//! A frame with a deadline is bounded as a whole, not per read or write: a
//! peer that stops reading, or drips one byte at a time, ends the frame at
//! the deadline with [`FrameError::TimedOut`]. A timed frame waits with
//! poll(2) and moves bytes without blocking; it never sets a socket timeout,
//! which every clone of the socket would share.

use std::io::{self, IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
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
    /// No byte of the frame left (it was refused, or its deadline came
    /// first), so the connection is still in step and the peer saw nothing.
    #[must_use]
    pub fn is_local(&self) -> bool {
        matches!(
            self,
            Self::TooLarge { .. }
                | Self::TooManyFds(_)
                | Self::Encode(_)
                | Self::Refused(_)
                | Self::Late
        )
    }
}

/// Waits until `stream` can be read (or written) or `deadline` passes. An
/// untimed frame does not wait here: its syscall blocks instead.
fn ready(stream: &UnixStream, deadline: Option<Instant>, write: bool) -> Result<(), FrameError> {
    let Some(deadline) = deadline else {
        return Ok(());
    };
    let events = if write { PollFlags::OUT } else { PollFlags::IN };
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(FrameError::TimedOut);
        }
        // At least a millisecond, so a poll that counts whole milliseconds
        // never spins.
        let wait = Timespec::try_from(left.max(Duration::from_millis(1))).unwrap_or(Timespec {
            tv_sec: i64::MAX,
            tv_nsec: 0,
        });
        let mut fds = [PollFd::new(stream, events)];
        match poll(&mut fds, Some(&wait)) {
            // Readable, writable, hung up or in error: the syscall says which.
            Ok(n) if n > 0 => return Ok(()),
            Ok(_) | Err(Errno::INTR) => {}
            Err(errno) => return Err(io::Error::from(errno).into()),
        }
    }
}

/// A timed frame's syscalls never block; [`ready`] does the waiting.
fn no_wait(deadline: Option<Instant>) -> bool {
    deadline.is_some()
}

/// Whether a failed syscall is tried again. An interrupt always is. EAGAIN
/// is only for a timed frame, whose [`ready`] waits first; an untimed frame
/// returns it, so a caller's own nonblocking mode or socket timeout still
/// ends the read.
fn retry(errno: Errno, deadline: Option<Instant>) -> bool {
    errno == Errno::INTR || (errno == Errno::AGAIN && deadline.is_some())
}

/// A send to a closed peer fails with EPIPE rather than raising SIGPIPE in
/// a host that has not ignored it.
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
    send_frame_until(stream, msg, fds, limit, None)
}

/// [`send_frame`], with the whole frame bounded by `deadline`. A frame cut
/// off by the deadline leaves the stream out of step: close it.
///
/// # Errors
/// As [`send_frame`], plus [`FrameError::Refused`] for a frame the receiver
/// would refuse, [`FrameError::Late`] when no byte left by the deadline,
/// and [`FrameError::TimedOut`] for a frame cut off part way.
pub fn send_frame_until<T: Serialize>(
    stream: &UnixStream,
    msg: &T,
    fds: &[BorrowedFd<'_>],
    limit: u32,
    deadline: Option<Instant>,
) -> Result<(), FrameError> {
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
    let flags = if no_wait(deadline) {
        SEND_FLAGS | SendFlags::DONTWAIT
    } else {
        SEND_FLAGS
    };
    let late = |sent: usize| {
        if sent == 0 {
            FrameError::Late
        } else {
            FrameError::TimedOut
        }
    };
    while sent < total {
        match ready(stream, deadline, true) {
            Err(FrameError::TimedOut) => return Err(late(sent)),
            waited => waited?,
        }
        let iov = if sent < HEADER {
            [IoSlice::new(&header[sent..]), IoSlice::new(&body)]
        } else {
            [IoSlice::new(&body[sent - HEADER..]), IoSlice::new(&[])]
        };
        // The descriptors ride on the first send only.
        let result = if sent == 0 {
            sendmsg(stream, &iov, &mut control, flags)
        } else {
            sendmsg(stream, &iov, &mut SendAncillaryBuffer::default(), flags)
        };
        match result {
            Ok(written) => sent += written,
            // Interrupted, or the buffer filled again since poll: wait anew.
            Err(errno) if retry(errno, deadline) => {}
            Err(errno) => return Err(io::Error::from(errno).into()),
        }
    }
    Ok(())
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
    recv_frame_until(stream, limit, None)
}

/// Received descriptors are close-on-exec from the moment they exist, so no
/// process this one starts can inherit them.
#[cfg(target_os = "linux")]
const RECV_FLAGS: RecvFlags = RecvFlags::CMSG_CLOEXEC;
#[cfg(not(target_os = "linux"))]
const RECV_FLAGS: RecvFlags = RecvFlags::empty();

/// Linux set close-on-exec as the descriptors arrived (`RECV_FLAGS`).
/// Elsewhere there is no atomic flag: set it at once, before anything else.
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
    let mut header = [0u8; HEADER];
    let mut got = 0;
    let mut fds = Vec::new();
    let flags = if no_wait(deadline) {
        RECV_FLAGS | RecvFlags::DONTWAIT
    } else {
        RECV_FLAGS
    };
    while got < HEADER {
        ready(stream, deadline, false)?;
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS_PER_FRAME))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let mut iov = [IoSliceMut::new(&mut header[got..])];
        let msg = match recvmsg(stream, &mut iov, &mut control, flags) {
            Ok(msg) => msg,
            Err(errno) if retry(errno, deadline) => continue,
            Err(errno) => return Err(io::Error::from(errno).into()),
        };
        for message in control.drain() {
            if let RecvAncillaryMessage::ScmRights(received) = message {
                fds.extend(received);
            }
        }
        if msg.flags.contains(ReturnFlags::CTRUNC) {
            return Err(FrameError::FdsTruncated);
        }
        if msg.bytes == 0 {
            return Err(FrameError::Closed);
        }
        got += msg.bytes;
    }
    mark_cloexec(&fds)?;
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
    let body_flags = if no_wait(deadline) {
        RecvFlags::DONTWAIT
    } else {
        RecvFlags::empty()
    };
    while filled < body.len() {
        ready(stream, deadline, false)?;
        match recv(stream, &mut body[filled..], body_flags) {
            Ok((0, _)) => return Err(FrameError::Closed),
            Ok((read, _)) => filled += read,
            Err(errno) if retry(errno, deadline) => {}
            Err(errno) => return Err(io::Error::from(errno).into()),
        }
    }
    shape::check(&body).map_err(FrameError::Protocol)?;
    Ok((rmp_serde::from_slice(&body)?, fds))
}
