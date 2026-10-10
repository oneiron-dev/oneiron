//! Framing: `len: u32 LE | MessagePack body`, with descriptors riding as
//! `SCM_RIGHTS` on the send that carries the frame's first byte.

use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;

use rustix::io::{Errno, FdFlags, fcntl_setfd};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::wire::MAX_FDS_PER_FRAME;

const HEADER: usize = 4;

/// Why a frame could not be sent or read. Any of them ends the connection.
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
    #[error("frame encode: {0}")]
    Encode(#[from] rmp_serde::encode::Error),
    #[error("frame decode: {0}")]
    Decode(#[from] rmp_serde::decode::Error),
    #[error("frame io: {0}")]
    Io(#[from] io::Error),
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
    let iov = [IoSlice::new(&header), IoSlice::new(&body)];
    let sent = loop {
        match sendmsg(stream, &iov, &mut control, SendFlags::empty()) {
            Ok(sent) => break sent,
            Err(Errno::INTR) => {}
            Err(err) => return Err(io::Error::from(err).into()),
        }
    };
    let mut writer = stream;
    if sent < HEADER {
        writer.write_all(&header[sent..])?;
        writer.write_all(&body)?;
    } else {
        writer.write_all(&body[sent - HEADER..])?;
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
    let mut header = [0u8; HEADER];
    let mut got = 0;
    let mut fds = Vec::new();
    while got < HEADER {
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS_PER_FRAME))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let mut iov = [IoSliceMut::new(&mut header[got..])];
        let msg = match recvmsg(stream, &mut iov, &mut control, RecvFlags::empty()) {
            Ok(msg) => msg,
            Err(Errno::INTR) => continue,
            Err(err) => return Err(io::Error::from(err).into()),
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
    for fd in &fds {
        fcntl_setfd(fd, FdFlags::CLOEXEC).map_err(io::Error::from)?;
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
    let mut reader = stream;
    reader.read_exact(&mut body).map_err(|err| {
        if err.kind() == io::ErrorKind::UnexpectedEof {
            FrameError::Closed
        } else {
            FrameError::Io(err)
        }
    })?;
    Ok((rmp_serde::from_slice(&body)?, fds))
}
