//! Private, bounded launcher/supervisor protocol.

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

const MAX_FRAME: usize = 2 * 1024 * 1024;

/// The inodes one inventory frame carries: a `u64` encodes in at most 21
/// bytes of JSON, so a full chunk stays well inside [`MAX_FRAME`].
pub(crate) const INVENTORY_CHUNK: usize = MAX_FRAME / 32;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Hello {
    pub generation: String,
    pub bootstrap_fd: i32,
    pub parent_pid: u32,
    pub ruleset_hash: String,
    pub seccomp_hash: String,
    pub landlock_abi: i32,
    pub routes: Vec<String>,
    pub no_new_privs: bool,
    pub capabilities: String,
}

/// What the launcher sends the supervisor: a system call it brokers, or one
/// chunk of its guest's socket inventory (FIX 5978), which is no system call:
/// it is never replayed and has no notification to check.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum Frame {
    Request(Request),
    Inventory(SocketInventory),
}

/// One chunk of one complete scan of the socket inodes the guest's
/// processes hold. A scan's chunks share its generation and the last one
/// closes it; a scan that did not complete is never sent.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SocketInventory {
    pub generation: u64,
    pub inodes: Vec<u64>,
    pub last: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Request {
    pub id: u64,
    pub notification: u64,
    pub op: Operation,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum Operation {
    Socket {
        family: i32,
        kind: i32,
        protocol: i32,
    },
    Connect {
        socket: u64,
        target: SocketAddr,
    },
    Send {
        socket: u64,
        target: Option<SocketAddr>,
        bytes: Vec<u8>,
    },
    Receive {
        socket: u64,
        max: usize,
        flags: i32,
    },
    Peer {
        socket: u64,
        local: bool,
    },
    Describe {
        socket: u64,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct Reply {
    pub id: u64,
    pub value: i64,
    pub errno: i32,
    pub bytes: Vec<u8>,
    pub address: Option<SocketAddr>,
}

pub(crate) fn write<T: Serialize>(stream: &mut impl Write, value: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(io::Error::other("fence frame size"));
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()
}

pub(crate) fn read<T: DeserializeOwned>(stream: &mut impl Read) -> io::Result<T> {
    let mut len = [0; 4];
    stream.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(io::Error::other("fence frame size"));
    }
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

pub(crate) fn send_fd(stream: &UnixStream, fd: RawFd) -> io::Result<()> {
    let mut byte = [0_u8];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0_usize; 8];
    // SAFETY: all pointers reference live, aligned storage for the syscall.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize;
        std::ptr::write(libc::CMSG_DATA(cmsg).cast::<RawFd>(), fd);
        if libc::sendmsg(stream.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) != 1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub(crate) fn receive_fd(stream: &UnixStream) -> io::Result<OwnedFd> {
    let mut byte = [0_u8];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0_usize; 8];
    // SAFETY: recvmsg writes only into the live buffers supplied here. A
    // received SCM_RIGHTS descriptor is newly owned by this process.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = std::mem::size_of_val(&control);
        if libc::recvmsg(stream.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) != 1
            || msg.msg_flags & libc::MSG_CTRUNC != 0
        {
            return Err(io::Error::other("missing fence listener descriptor"));
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null()
            || (*cmsg).cmsg_level != libc::SOL_SOCKET
            || (*cmsg).cmsg_type != libc::SCM_RIGHTS
            || (*cmsg).cmsg_len != libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize
        {
            return Err(io::Error::other("invalid fence listener descriptor"));
        }
        Ok(OwnedFd::from_raw_fd(std::ptr::read(
            libc::CMSG_DATA(cmsg).cast::<RawFd>(),
        )))
    }
}
