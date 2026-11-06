//! A brokered receive on a native Unix socket (FIX 6185).
//!
//! Once a transfer was made, a receive with a control buffer runs here, so
//! a witness never reaches the guest. The launcher takes the message on its
//! duplicate of the guest's socket, into its own buffers, with room for the
//! guest's control data and one witness besides. It then gives the guest
//! what the kernel would have: the data, the sender's name, and each
//! control message that fits the guest's buffer. Each descriptor that fits
//! is installed in the calling task (ADDFD) and the launcher's copy closes;
//! what does not fit closes, and the guest sees MSG_CTRUNC, as the kernel
//! does it. The witness is never installed.
//!
//! The message is taken, its descriptors installed and its witness closed
//! under the inventory lock, so a scan sees the transfer hold or the table
//! hold, never neither. A peek takes copies, installs them, and leaves the
//! message, its witness and its hold in the queue.
//!
//! A receive that may wait first peeks, without the lock and without taking
//! anything: the guest's mode and the socket's receive timeout apply, as to
//! the guest's own call. Only then, with the call still live, does it take
//! the message without waiting; a message another task took meanwhile
//! sends it back to wait. So a call that ended takes nothing.

use super::{
    Call, MESSAGE_BOUND, Rights, aligned, controls, fds_of, identity, poisoned, put_control,
    scatter, vectors,
};
use crate::launcher::{Bridge, load, remote, store};
use crate::linux;
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// A recvmsg (one header) or recvmmsg (`vector`) on a native socket. A
/// recvmmsg waits for each message as a blocking one does, or for the
/// first alone with MSG_WAITFORONE; its timeout does not apply.
pub(super) fn receive(
    listener: &OwnedFd,
    bridge: &Bridge,
    n: linux::Notification,
    pointers: &[u64],
    flags: i32,
    vector: bool,
) -> io::Result<()> {
    let call = Call::open(bridge, n)?;
    let nonblocking = flags & libc::MSG_DONTWAIT != 0 || in_nonblocking_mode(&call.socket);
    let mut completed = 0_i64;
    let mut value = 0_i64;
    for (index, &pointer) in pointers.iter().enumerate() {
        let wait = !nonblocking && (index == 0 || flags & libc::MSG_WAITFORONE == 0);
        let length = match call.take(listener, pointer, flags, wait) {
            Ok(length) => length,
            Err(error) if completed == 0 => {
                let code = error.raw_os_error().unwrap_or(libc::EIO);
                return linux::respond(listener.as_raw_fd(), n.id, 0, code, 0);
            }
            Err(_) => break,
        };
        if vector {
            store(
                n.pid,
                pointer + size_of::<libc::msghdr>() as u64,
                length as u32,
            )?;
        }
        value = length as i64;
        completed += 1;
    }
    let value = if vector { completed } else { value };
    linux::respond(listener.as_raw_fd(), n.id, value, 0, 0)
}

/// What one received message carried, in order.
enum Received {
    /// A rights message: the launcher's copies of its descriptors, the
    /// witness left out.
    Rights(Vec<OwnedFd>),
    /// Any other control message, as the kernel wrote it.
    Other {
        level: i32,
        kind: i32,
        data: Vec<u8>,
    },
}

/// The launcher's buffers for one message.
struct Incoming {
    bytes: Vec<u8>,
    name: libc::sockaddr_storage,
    /// The guest asked for the sender's name.
    named: bool,
    namelen: libc::socklen_t,
    control: Vec<u8>,
    /// The control bytes the kernel wrote.
    used: usize,
    /// The flags the kernel answered.
    flags: i32,
}

impl Call<'_> {
    /// Takes one message into the guest's header at `pointer`, with what
    /// it carries, and returns its length as the kernel does.
    fn take(&self, listener: &OwnedFd, pointer: u64, flags: i32, wait: bool) -> io::Result<usize> {
        let pid = self.n.pid;
        let mut header: libc::msghdr = load(pid, pointer)?;
        let (vectors, total) = vectors(pid, &header)?;
        let capacity = if header.msg_control.is_null() {
            0
        } else {
            (header.msg_controllen as usize).min(MESSAGE_BOUND)
        };
        let mut incoming = Incoming::new(&header, total, capacity);
        loop {
            if wait {
                peek(&self.socket)?;
            }
            // Like a socket() or an accept, an install holds off the
            // inventory (FIX 5978): the witness closes after it.
            let _shared = self.bridge.sockets.read().map_err(|_| poisoned())?;
            linux::valid(listener.as_raw_fd(), self.n.id)?;
            let received = match incoming.receive(&self.socket, flags) {
                Err(error) if wait && error.kind() == io::ErrorKind::WouldBlock => continue,
                received => received?,
            };
            // The message left the queue, unless peeked. From here the
            // guest has what it carried, or it closed; the witnesses close
            // last, still under the lock.
            let (contents, _witnesses) =
                carried(&incoming.control[..incoming.used], &self.bridge.rights);
            let length = received.min(incoming.bytes.len());
            scatter(pid, &vectors, &mut incoming.bytes[..length])?;
            let cloexec = flags & libc::MSG_CMSG_CLOEXEC != 0;
            let (mut control, truncated) = self.install(listener, contents, capacity, cloexec);
            if incoming.named {
                let mut name = incoming.name_bytes(header.msg_namelen);
                if !name.is_empty() {
                    remote(pid, header.msg_name as u64, &mut name, true)?;
                }
                header.msg_namelen = incoming.namelen;
            }
            if !control.is_empty() {
                remote(pid, header.msg_control as u64, &mut control, true)?;
            }
            header.msg_controllen = control.len() as _;
            let truncated = truncated || incoming.flags & libc::MSG_CTRUNC != 0;
            header.msg_flags = incoming.flags & !libc::MSG_CTRUNC;
            if truncated {
                header.msg_flags |= libc::MSG_CTRUNC;
            }
            store(pid, pointer, header)?;
            return Ok(received);
        }
    }

    /// The guest's control bytes for what a message carried, at most
    /// `capacity` long, and whether any of it did not fit. Each descriptor
    /// that fits is installed in the calling task (ADDFD); the launcher's
    /// copies close after, and so does what did not fit, as the kernel
    /// closes what a short buffer cannot take.
    fn install(
        &self,
        listener: &OwnedFd,
        carried: Vec<Received>,
        capacity: usize,
        cloexec: bool,
    ) -> (Vec<u8>, bool) {
        let offset = aligned(size_of::<libc::cmsghdr>());
        let mut control = Vec::new();
        let mut truncated = false;
        for received in carried {
            // Once one message did not fit, the kernel places no more.
            let room = if truncated {
                0
            } else {
                capacity.saturating_sub(control.len())
            };
            match received {
                Received::Other { level, kind, data } => {
                    if offset + data.len() <= room {
                        put_control(&mut control, level, kind, &data);
                    } else {
                        truncated = true;
                    }
                }
                Received::Rights(fds) => {
                    let fit = room.saturating_sub(offset) / size_of::<RawFd>();
                    let mut numbers = Vec::new();
                    for fd in fds.iter().take(fit) {
                        let added =
                            linux::add_fd(listener.as_raw_fd(), self.n.id, fd.as_raw_fd(), cloexec);
                        match added {
                            Ok(number) => numbers.extend_from_slice(&number.to_ne_bytes()),
                            Err(_) => break,
                        }
                    }
                    truncated |= numbers.len() < fds.len() * size_of::<RawFd>();
                    if !numbers.is_empty() {
                        put_control(&mut control, libc::SOL_SOCKET, libc::SCM_RIGHTS, &numbers);
                    }
                }
            }
        }
        control.truncate(capacity);
        (control, truncated)
    }
}

impl Incoming {
    fn new(header: &libc::msghdr, total: usize, capacity: usize) -> Self {
        let witness = aligned(size_of::<libc::cmsghdr>()) + aligned(size_of::<RawFd>());
        Self {
            bytes: vec![0; total.min(MESSAGE_BOUND)],
            // SAFETY: a zeroed sockaddr_storage is a valid empty address.
            name: unsafe { std::mem::zeroed() },
            named: !header.msg_name.is_null(),
            namelen: 0,
            // Room for the guest's control data and one witness besides: a
            // message whose descriptors all fit the guest's buffer brings
            // its witness to the launcher.
            control: vec![0; capacity + witness],
            used: 0,
            flags: 0,
        }
    }

    /// Takes the next message, never waiting, into these buffers; returns
    /// its length as the kernel does.
    fn receive(&mut self, socket: &OwnedFd, flags: i32) -> io::Result<usize> {
        let mut vector = libc::iovec {
            iov_base: self.bytes.as_mut_ptr().cast(),
            iov_len: self.bytes.len(),
        };
        // SAFETY: a zeroed msghdr is a valid empty header.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        if self.named {
            message.msg_name = (&mut self.name as *mut libc::sockaddr_storage).cast();
            message.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        }
        message.msg_control = self.control.as_mut_ptr().cast();
        message.msg_controllen = self.control.len() as _;
        // One message, never waiting: a recvmmsg's own flag is not a
        // recvmsg's.
        let flags = (flags & !libc::MSG_WAITFORONE) | libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC;
        // SAFETY: every pointer references live launcher storage of the
        // stated length; the kernel writes at most that much.
        let received = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, flags) };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        self.namelen = message.msg_namelen;
        self.used = message.msg_controllen as usize;
        self.flags = message.msg_flags;
        Ok(received as usize)
    }

    /// The sender's name as a guest buffer of `room` bytes takes it.
    fn name_bytes(&self, room: libc::socklen_t) -> Vec<u8> {
        let length = (self.namelen.min(room) as usize).min(size_of::<libc::sockaddr_storage>());
        // SAFETY: the storage is live and initialized, zeroed and then
        // written by the kernel, and `length` lies within it.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&self.name as *const libc::sockaddr_storage).cast::<u8>(),
                length,
            )
        };
        bytes.to_vec()
    }
}

/// What the launcher's received control bytes carried, in order, and the
/// witnesses apart. Each received descriptor is owned first, so none stays
/// open in the launcher.
fn carried(control: &[u8], rights: &Rights) -> (Vec<Received>, Vec<OwnedFd>) {
    let mut carried = Vec::new();
    let mut witnesses = Vec::new();
    for found in controls(control).0 {
        if !found.rights() {
            carried.push(Received::Other {
                level: found.level,
                kind: found.kind,
                data: found.data.to_vec(),
            });
            continue;
        }
        let mut fds = Vec::new();
        for fd in fds_of(found.data) {
            // SAFETY: the kernel installed each received descriptor in the
            // launcher; it is owned once from here on.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            match identity(&fd) {
                Ok((device, inode, _)) if rights.witness(device, inode) => witnesses.push(fd),
                _ => fds.push(fd),
            }
        }
        carried.push(Received::Rights(fds));
    }
    (carried, witnesses)
}

/// Waits as the guest's call would wait, until the socket has a message,
/// an end or an error to report, and takes nothing.
fn peek(socket: &OwnedFd) -> io::Result<()> {
    let mut byte = [0_u8];
    // SAFETY: recv writes at most one byte into live storage.
    let peeked = unsafe {
        libc::recv(
            socket.as_raw_fd(),
            byte.as_mut_ptr().cast(),
            1,
            libc::MSG_PEEK,
        )
    };
    if peeked < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Whether the guest put the socket in nonblocking mode. The launcher's
/// copy shares the guest's open file description, and with it its mode.
fn in_nonblocking_mode(socket: &OwnedFd) -> bool {
    // SAFETY: F_GETFL only reads the status flags of a live descriptor.
    let flags = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFL) };
    flags >= 0 && flags & libc::O_NONBLOCK != 0
}
