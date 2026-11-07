//! A brokered receive on a native Unix socket (FIX 6185).
//!
//! Once a transfer was made, a receive with a control buffer runs here, so
//! a witness never reaches the guest. The launcher takes the message on its
//! duplicate of the guest's socket, into its own buffers, with room for the
//! guest's control data and one witness besides. Its data buffer holds the
//! guest's iovec total, up to the socket's SO_RCVBUF; on a socket that
//! keeps message boundaries it holds at least the next message's own
//! length, which a peek finds. So a message that fits the guest's buffers
//! arrives whole, and a longer one is cut at the guest's total with
//! MSG_TRUNC, as the kernel cuts it. The launcher then gives the guest what
//! the kernel would have: the data, the sender's name, and each control
//! message that fits the guest's buffer. Each descriptor that fits is
//! installed in the calling task (ADDFD) and the launcher's copy closes;
//! what does not fit closes, and the guest sees MSG_CTRUNC, as the kernel
//! does it. The witness is never installed.
//!
//! Two control messages carry a descriptor: rights (SCM_RIGHTS), and the
//! sender's pidfd (SCM_PIDFD) on a socket with SO_PASSPIDFD. The kernel
//! installs that pidfd in the launcher, so the launcher passes it on as it
//! passes rights: it installs it in the calling task, close-on-exec as the
//! kernel makes every pidfd, and writes the guest's number into the
//! message. The same fit, truncation and replacement rules apply, and the
//! launcher's copy always closes. A negative value in a pidfd message is
//! the kernel's errno for a pidfd it could not make: it is data, and is
//! copied. The other control messages (SCM_CREDENTIALS, SCM_SECURITY)
//! carry data only, and are copied as they came.
//!
//! The message is taken, its descriptors installed and its witness closed
//! under the inventory lock, so a scan sees the transfer hold or the table
//! hold, never neither. A peek takes copies, installs them, and leaves the
//! message, its witness and its hold in the queue.
//!
//! The launcher takes a message only while the call is live, and never
//! waits to take it. When the socket has none and the guest's call may
//! wait, it waits without the lock, as that call would: in slices, with a
//! check of the call after each, and up to the socket's receive timeout. A
//! recvmmsg's own timeout is checked after each message, as the kernel
//! checks it, and also bounds each wait after the first message. A call
//! that ended takes nothing and returns.
//!
//! The launcher reads no region that the call only writes. Before it
//! installs a descriptor, it writes the control bytes in their final
//! layout, with each descriptor's slot zeroed, and the sender's name: those
//! writes prove the regions writable, and a fault answers the call with
//! nothing installed. After the install it writes the numbers into their
//! slots, then the header and a recvmmsg's length. When one of those writes
//! fails, or the answer does, each descriptor the call installed is
//! replaced at its number by the launcher's /dev/null (ADDFD with
//! SECCOMP_ADDFD_FLAG_SETFD): the descriptor leaves the guest's table, and
//! the guest keeps only a /dev/null at a number it never learned. A call
//! that ended keeps what it was given, because the kernel takes no ADDFD
//! for it.

use super::wait::{Wait, Waited, may_wait};
use super::{
    Call, MESSAGE_BOUND, Rights, aligned, controls, fds_of, identity, poisoned, put_control,
    scatter, socket_option, vectors,
};
use crate::launcher::{Bridge, load, remote, store};
use crate::linux;
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

/// Linux's control message type for the sender's pidfd (linux/socket.h),
/// which a socket with SO_PASSPIDFD receives; libc names no Linux value
/// for it.
const SCM_PIDFD: i32 = 4;

/// A recvmsg (one header) or recvmmsg (`vector`) on a native socket. A
/// recvmmsg waits for each message as a blocking one does, or for the
/// first alone with MSG_WAITFORONE. Its own timeout is checked after each
/// message, as the kernel checks it, and bounds each wait after the first.
pub(super) fn receive(
    listener: &OwnedFd,
    bridge: &Bridge,
    n: linux::Notification,
    pointers: &[u64],
    flags: i32,
    vector: bool,
) -> io::Result<()> {
    let deadline = if vector {
        recvmmsg_deadline(n.pid, n.data.args[4])?
    } else {
        None
    };
    let call = Call::open(bridge, n)?;
    let blocking = may_wait(&call.socket, flags);
    let mut installed = Vec::new();
    let mut completed = 0_i64;
    let mut value = 0_i64;
    for (index, &pointer) in pointers.iter().enumerate() {
        let waiting = if blocking && (index == 0 || flags & libc::MSG_WAITFORONE == 0) {
            let limit = deadline.filter(|_| index > 0);
            Wait::new(&call.socket, libc::POLLIN, libc::SO_RCVTIMEO, limit).map(Some)
        } else {
            Ok(None)
        };
        let taken = waiting
            .and_then(|waiting| call.take(listener, pointer, flags, waiting.as_ref(), vector));
        let (length, numbers) = match taken {
            Ok(Some(taken)) => taken,
            // A call that ended is answered no more.
            Ok(None) => {
                call.replace(listener, &installed);
                return Ok(());
            }
            Err(error) if completed == 0 => {
                let code = error.raw_os_error().unwrap_or(libc::EIO);
                return linux::respond(listener.as_raw_fd(), n.id, 0, code, 0);
            }
            Err(_) => break,
        };
        installed.extend(numbers);
        value = length as i64;
        completed += 1;
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            break;
        }
    }
    let value = if vector { completed } else { value };
    let answered = linux::respond(listener.as_raw_fd(), n.id, value, 0, 0);
    if answered.is_err() {
        call.replace(listener, &installed);
    }
    answered
}

/// What one received message carried, in order.
enum Received {
    /// A control message that carries descriptors, of type `kind`: rights
    /// (SCM_RIGHTS), the witness left out, or the sender's pidfd
    /// (SCM_PIDFD). The launcher's copies, in order.
    Descriptors { kind: i32, fds: Vec<OwnedFd> },
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
    /// The guest's iovec total.
    total: usize,
    /// The socket's SO_RCVBUF.
    buffer: usize,
    /// The socket keeps message boundaries: it is no stream.
    messages: bool,
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

/// The guest's control bytes for what one message carried, laid out before
/// any install, with a zeroed slot for each descriptor that fits.
struct Layout {
    control: Vec<u8>,
    /// The descriptor messages that fit, in order.
    descriptors: Vec<DescriptorMessage>,
    /// Some of what the message carried did not fit.
    truncated: bool,
}

/// One control message of a layout that carries descriptors.
struct DescriptorMessage {
    /// Where its header starts in the control bytes.
    at: usize,
    /// Its type: SCM_RIGHTS or SCM_PIDFD.
    kind: i32,
    /// The launcher's copies of the descriptors its slots name, in order.
    fds: Vec<OwnedFd>,
    /// How many of them the calling task holds.
    installed: usize,
}

impl Call<'_> {
    /// Takes one message into the guest's header at `pointer` (of a
    /// recvmmsg when `vector`), with what it carries, waiting when
    /// `waiting` is given. Returns its length as the kernel does, and the
    /// numbers it installed: `None` once the call ended, with nothing
    /// taken.
    fn take(
        &self,
        listener: &OwnedFd,
        pointer: u64,
        flags: i32,
        waiting: Option<&Wait>,
        vector: bool,
    ) -> io::Result<Option<(usize, Vec<i32>)>> {
        let pid = self.n.pid;
        let mut header: libc::msghdr = load(pid, pointer)?;
        let (vectors, total) = vectors(pid, &header)?;
        let capacity = if header.msg_control.is_null() {
            0
        } else {
            header.msg_controllen.min(MESSAGE_BOUND)
        };
        let mut incoming = Incoming::new(&self.socket, &header, total, capacity)?;
        loop {
            // Like a socket() or an accept, an install holds off the
            // inventory (FIX 5978): the witness closes after it.
            let shared = self.bridge.sockets.read().map_err(|_| poisoned())?;
            if linux::valid(listener.as_raw_fd(), self.n.id).is_err() {
                return Ok(None);
            }
            let received = match (incoming.receive(&self.socket, flags), waiting) {
                (Err(error), Some(waiting)) if error.kind() == io::ErrorKind::WouldBlock => {
                    // The wait holds no lock: an inventory may run meanwhile.
                    drop(shared);
                    match waiting.ready(listener, self.n.id, &self.socket)? {
                        Waited::Ready => continue,
                        Waited::Ended => return Ok(None),
                    }
                }
                (received, _) => received?,
            };
            // The message left the queue, unless peeked. From here the
            // guest has what it carried, or it closed; the witnesses close
            // last, still under the lock.
            let (contents, _witnesses) =
                carried(&incoming.control[..incoming.used], &self.bridge.rights);
            let copied = received.min(incoming.bytes.len());
            scatter(pid, &vectors, &mut incoming.bytes[..copied])?;
            let mut layout = Layout::new(contents, capacity);
            let mut name = if incoming.named {
                incoming.name_bytes(header.msg_namelen)
            } else {
                Vec::new()
            };
            // These writes prove their regions writable, reading none,
            // before anything is installed.
            write_guest(pid, header.msg_control as u64, &mut layout.control)?;
            write_guest(pid, header.msg_name as u64, &mut name)?;
            let numbers = self.install(listener, &mut layout, flags & libc::MSG_CMSG_CLOEXEC != 0);
            if incoming.named {
                header.msg_namelen = incoming.namelen;
            }
            header.msg_controllen = layout.control.len();
            header.msg_flags = incoming.flags & !libc::MSG_CTRUNC;
            if layout.truncated || incoming.flags & libc::MSG_CTRUNC != 0 {
                header.msg_flags |= libc::MSG_CTRUNC;
            }
            let length = vector.then_some(received as u32);
            if let Err(error) = self.finish(pointer, &header, &mut layout, length) {
                self.replace(listener, &numbers);
                return Err(error);
            }
            return Ok(Some((received, numbers)));
        }
    }

    /// Installs the descriptors of `layout` in the calling task (ADDFD), in
    /// order, and puts each number in its slot. A table that takes no more
    /// ends the control bytes after the numbers installed, as the kernel
    /// ends them, and the guest sees MSG_CTRUNC. Returns the numbers
    /// installed.
    fn install(&self, listener: &OwnedFd, layout: &mut Layout, cloexec: bool) -> Vec<i32> {
        let offset = aligned(size_of::<libc::cmsghdr>());
        let mut numbers = Vec::new();
        for message in &mut layout.descriptors {
            // The kernel makes every pidfd close-on-exec, whatever the
            // receive's flags.
            let cloexec = cloexec || message.kind == SCM_PIDFD;
            for fd in &message.fds {
                let added = linux::add_fd(listener.as_raw_fd(), self.n.id, fd.as_raw_fd(), cloexec);
                let Ok(number) = added else {
                    break;
                };
                let slot = message.at + offset + message.installed * size_of::<RawFd>();
                layout.control[slot..slot + size_of::<RawFd>()]
                    .copy_from_slice(&number.to_ne_bytes());
                numbers.push(number);
                message.installed += 1;
            }
            if message.installed < message.fds.len() {
                let data = message.at + offset;
                let installed =
                    layout.control[data..data + message.installed * size_of::<RawFd>()].to_vec();
                let limit = layout.control.len();
                layout.control.truncate(message.at);
                if !installed.is_empty() {
                    put_control(
                        &mut layout.control,
                        libc::SOL_SOCKET,
                        message.kind,
                        &installed,
                    );
                }
                layout.control.truncate(limit);
                layout.truncated = true;
                break;
            }
        }
        numbers
    }

    /// The writes after an install, none of which reads the guest: each
    /// descriptor message's header and numbers, then the message header at
    /// `pointer`, then a recvmmsg's `length`.
    fn finish(
        &self,
        pointer: u64,
        header: &libc::msghdr,
        layout: &mut Layout,
        length: Option<u32>,
    ) -> io::Result<()> {
        let pid = self.n.pid;
        let offset = aligned(size_of::<libc::cmsghdr>());
        for message in layout
            .descriptors
            .iter()
            .filter(|message| message.installed > 0)
        {
            let end = message.at + offset + message.installed * size_of::<RawFd>();
            let address = header.msg_control as u64 + message.at as u64;
            remote(pid, address, &mut layout.control[message.at..end], true)?;
        }
        store(pid, pointer, *header)?;
        if let Some(length) = length {
            store(pid, pointer + size_of::<libc::msghdr>() as u64, length)?;
        }
        Ok(())
    }

    /// Replaces each descriptor in `numbers`, which this call installed,
    /// by the launcher's /dev/null at the same number (ADDFD with
    /// SECCOMP_ADDFD_FLAG_SETFD), so the socket or pidfd leaves the
    /// guest's table.
    fn replace(&self, listener: &OwnedFd, numbers: &[i32]) {
        if numbers.is_empty() {
            return;
        }
        let Ok(null) = std::fs::File::open("/dev/null") else {
            return;
        };
        for &number in numbers {
            let _ = linux::replace_fd(listener.as_raw_fd(), self.n.id, null.as_raw_fd(), number);
        }
    }
}

impl Layout {
    /// Lays out what a message `carried` in a guest buffer of `capacity`
    /// bytes, as the kernel places it: what does not fit closes, as the
    /// kernel closes what a short buffer cannot take, and once one control
    /// message did not fit, no more is placed.
    fn new(carried: Vec<Received>, capacity: usize) -> Self {
        let offset = aligned(size_of::<libc::cmsghdr>());
        let mut layout = Self {
            control: Vec::new(),
            descriptors: Vec::new(),
            truncated: false,
        };
        for received in carried {
            let room = if layout.truncated {
                0
            } else {
                capacity.saturating_sub(layout.control.len())
            };
            match received {
                Received::Other { level, kind, data } => {
                    if offset + data.len() <= room {
                        put_control(&mut layout.control, level, kind, &data);
                    } else {
                        layout.truncated = true;
                    }
                }
                // A pidfd message fits as a rights message of one
                // descriptor does: the kernel places it only whole.
                Received::Descriptors { kind, mut fds } => {
                    let fit = room.saturating_sub(offset) / size_of::<RawFd>();
                    if fds.len() > fit {
                        fds.truncate(fit);
                        layout.truncated = true;
                    }
                    if !fds.is_empty() {
                        let at = layout.control.len();
                        let slots = vec![0; fds.len() * size_of::<RawFd>()];
                        put_control(&mut layout.control, libc::SOL_SOCKET, kind, &slots);
                        layout.descriptors.push(DescriptorMessage {
                            at,
                            kind,
                            fds,
                            installed: 0,
                        });
                    }
                }
            }
        }
        layout.control.truncate(capacity);
        layout
    }
}

impl Incoming {
    fn new(
        socket: &OwnedFd,
        header: &libc::msghdr,
        total: usize,
        capacity: usize,
    ) -> io::Result<Self> {
        let witness = aligned(size_of::<libc::cmsghdr>()) + aligned(size_of::<RawFd>());
        Ok(Self {
            bytes: Vec::new(),
            total,
            buffer: usize::try_from(socket_option(socket, libc::SO_RCVBUF)?).unwrap_or(0),
            messages: socket_option(socket, libc::SO_TYPE)? != libc::SOCK_STREAM,
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
        })
    }

    /// Takes the next message, never waiting, into these buffers; returns
    /// its length as the kernel does. The data buffer holds the guest's
    /// total up to the socket's SO_RCVBUF, and on a socket that keeps
    /// message boundaries up to at least the next message's own length: a
    /// peek with MSG_TRUNC finds it and leaves the message queued.
    fn receive(&mut self, socket: &OwnedFd, flags: i32) -> io::Result<usize> {
        let mut room = self.total.min(self.buffer);
        if self.messages {
            let peek = libc::MSG_PEEK | libc::MSG_TRUNC | libc::MSG_DONTWAIT;
            // SAFETY: recv writes nothing into a buffer of length zero.
            let next = unsafe { libc::recv(socket.as_raw_fd(), std::ptr::null_mut(), 0, peek) };
            if next < 0 {
                return Err(io::Error::last_os_error());
            }
            room = room.max(self.total.min(next as usize));
        }
        self.bytes.resize(room, 0);
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
        message.msg_controllen = self.control.len();
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
        self.used = message.msg_controllen;
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
/// witnesses apart. Each received descriptor, of a rights message or a
/// pidfd, is owned first, so none stays open in the launcher.
fn carried(control: &[u8], rights: &Rights) -> (Vec<Received>, Vec<OwnedFd>) {
    let mut carried = Vec::new();
    let mut witnesses = Vec::new();
    for found in controls(control).0 {
        // A pidfd message names one descriptor, or holds the negative
        // errno of a pidfd the kernel could not make: then it is data.
        let pidfd = found.level == libc::SOL_SOCKET
            && found.kind == SCM_PIDFD
            && fds_of(found.data).next().is_some_and(|fd| fd >= 0);
        if !found.rights() && !pidfd {
            carried.push(Received::Other {
                level: found.level,
                kind: found.kind,
                data: found.data.to_vec(),
            });
            continue;
        }
        let count = if pidfd { 1 } else { usize::MAX };
        let mut fds = Vec::new();
        for fd in fds_of(found.data).take(count) {
            // SAFETY: the kernel installed each received descriptor in the
            // launcher; it is owned once from here on.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            match identity(&fd) {
                Ok((device, inode, _)) if !pidfd && rights.witness(device, inode) => {
                    witnesses.push(fd);
                }
                _ => fds.push(fd),
            }
        }
        carried.push(Received::Descriptors {
            kind: found.kind,
            fds,
        });
    }
    (carried, witnesses)
}

/// Writes `bytes` to the guest at `address`; nothing when there are none.
fn write_guest(pid: u32, address: u64, bytes: &mut [u8]) -> io::Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    remote(pid, address, bytes, true)
}

/// The deadline of a recvmmsg's timeout, a `struct timespec *` at `pointer`
/// (NULL for none), counted from now. An unreadable timespec fails EFAULT
/// and an invalid one EINVAL, before anything is received, as the kernel
/// fails them; a deadline past the clock's range is none.
fn recvmmsg_deadline(pid: u32, pointer: u64) -> io::Result<Option<Instant>> {
    if pointer == 0 {
        return Ok(None);
    }
    let timeout: libc::timespec =
        load(pid, pointer).map_err(|_| io::Error::from_raw_os_error(libc::EFAULT))?;
    let seconds = u64::try_from(timeout.tv_sec);
    let nanoseconds = u64::try_from(timeout.tv_nsec).map(Duration::from_nanos);
    match (seconds, nanoseconds) {
        (Ok(seconds), Ok(nanoseconds)) if nanoseconds < Duration::from_secs(1) => {
            Ok(Duration::from_secs(seconds)
                .checked_add(nanoseconds)
                .and_then(|timeout| Instant::now().checked_add(timeout)))
        }
        _ => Err(io::Error::from_raw_os_error(libc::EINVAL)),
    }
}
