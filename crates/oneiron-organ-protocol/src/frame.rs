//! Framing: `len: u32 LE | MessagePack body`, with descriptors riding as
//! `SCM_RIGHTS` on the send that carries the frame's first byte.
//!
//! A frame with a deadline is bounded as a whole, not per read or write: a
//! peer that stops reading, or drips one byte at a time, ends the frame at
//! the deadline with [`FrameError::TimedOut`].

use std::io::{self, IoSlice, IoSliceMut, Read};
use std::mem::MaybeUninit;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::Instant;

use rustix::io::Errno;
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
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
    /// The frame was refused before any byte left, so the connection is
    /// still in step and the peer saw nothing.
    #[must_use]
    pub fn is_local(&self) -> bool {
        matches!(
            self,
            Self::TooLarge { .. } | Self::TooManyFds(_) | Self::Encode(_)
        )
    }
}

/// Sets the socket's timeout for the next read or write to what is left
/// before `deadline`.
fn arm(stream: &UnixStream, deadline: Option<Instant>, write: bool) -> Result<(), FrameError> {
    let Some(deadline) = deadline else {
        return Ok(());
    };
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(FrameError::TimedOut);
    }
    if write {
        stream.set_write_timeout(Some(left))?;
    } else {
        stream.set_read_timeout(Some(left))?;
    }
    Ok(())
}

/// A send to a closed peer fails with EPIPE rather than raising SIGPIPE in
/// a host that has not ignored it.
#[cfg(target_os = "linux")]
const SEND_FLAGS: SendFlags = SendFlags::NOSIGNAL;
#[cfg(not(target_os = "linux"))]
const SEND_FLAGS: SendFlags = SendFlags::empty();

fn timed_out(errno: Errno, deadline: Option<Instant>) -> bool {
    deadline.is_some() && (errno == Errno::AGAIN || errno == Errno::WOULDBLOCK)
}

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
/// As [`send_frame`], plus [`FrameError::TimedOut`].
pub fn send_frame_until<T: Serialize>(
    stream: &UnixStream,
    msg: &T,
    fds: &[BorrowedFd<'_>],
    limit: u32,
    deadline: Option<Instant>,
) -> Result<(), FrameError> {
    let body = rmp_serde::to_vec_named(msg)?;
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
    while sent < total {
        arm(stream, deadline, true)?;
        let iov = if sent < HEADER {
            [IoSlice::new(&header[sent..]), IoSlice::new(&body)]
        } else {
            [IoSlice::new(&body[sent - HEADER..]), IoSlice::new(&[])]
        };
        // The descriptors ride on the first send only.
        let result = if sent == 0 {
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
            Err(Errno::INTR) => {}
            Err(errno) if timed_out(errno, deadline) => return Err(FrameError::TimedOut),
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
    while got < HEADER {
        arm(stream, deadline, false)?;
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS_PER_FRAME))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let mut iov = [IoSliceMut::new(&mut header[got..])];
        let msg = match recvmsg(stream, &mut iov, &mut control, RECV_FLAGS) {
            Ok(msg) => msg,
            Err(Errno::INTR) => continue,
            Err(errno) if timed_out(errno, deadline) => return Err(FrameError::TimedOut),
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
    let mut reader = stream;
    while filled < body.len() {
        arm(stream, deadline, false)?;
        match reader.read(&mut body[filled..]) {
            Ok(0) => return Err(FrameError::Closed),
            Ok(read) => filled += read,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err)
                if deadline.is_some()
                    && matches!(
                        err.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
            {
                return Err(FrameError::TimedOut);
            }
            Err(err) => return Err(FrameError::Io(err)),
        }
    }
    shape::check(&body).map_err(FrameError::Protocol)?;
    Ok((rmp_serde::from_slice(&body)?, fds))
}
