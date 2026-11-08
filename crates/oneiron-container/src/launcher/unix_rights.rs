//! Brokered sockets a guest sends over its own Unix sockets (FIX 6185).
//!
//! A guest may pass a brokered socket to another task in a message on a
//! native Unix socket (SCM_RIGHTS), and then close its own descriptor. While
//! the message waits in the kernel's queue, no descriptor table holds the
//! socket, so two inventories would miss it and its host entry would end.
//!
//! So once a socket was brokered, the launcher sends every message of a
//! native sendmsg or sendmmsg itself, and no such call continues to the
//! kernel: another guest thread could rewrite a message between the
//! launcher's read and the kernel's. Before that, the calls continue. The
//! launcher copies each message once, just before it sends it, with the
//! exact descriptors it names, duplicated from the calling task's own
//! table ([`task`]), and asks the supervisor which are brokered sockets.
//! Under the inventory lock it records a transfer hold for them: the write
//! end of a fresh pipe, the message's witness. It then sends the copy
//! itself, on a duplicate of the guest's socket, with the witness as the
//! last descriptor. The kernel moves a message's descriptors together, so
//! the witness leaves the queue with the brokered sockets. The entry keeps
//! its original room on the host floor; the launcher keeps no host
//! descriptor. The kernel takes the launcher as the sender: a receiver with
//! SO_PASSCRED sees the launcher's credentials, and credentials a message
//! names (SCM_CREDENTIALS) must be the launcher's. In the same way, a
//! receiver with SO_PASSPIDFD gets a pidfd of the launcher. The kernel
//! would also resolve a relative pathname destination against the
//! launcher's working directory, so the launcher sends a datagram to that
//! path in the calling task's (/proc/<tid>/cwd/<path>). When that path
//! does not fit sun_path, the send fails ENAMETOOLONG and nothing is sent.
//!
//! The launcher judges each message as the kernel does: a buffer it cannot
//! read fails EFAULT, a control buffer longer than [`MESSAGE_BOUND`]
//! ENOBUFS, a malformed control length EINVAL, and a datagram or seqpacket
//! message longer than the socket's SO_SNDBUF EMSGSIZE. A stream takes at
//! most [`MESSAGE_BOUND`] bytes of one message, a short write. A sendmmsg
//! sends its messages in order, up to the first that fails.
//!
//! A hold ends when the last copy of its witness closes, and only then:
//! - the message was never sent: its send failed, or its call ended while
//!   it waited. Nothing enqueued, and the launcher closes its copy;
//! - a brokered receive took the message ([`receive`]): it installs the
//!   guest's descriptors first, and closes the witness after, under the
//!   same inventory lock a socket() or accept install takes, so the table
//!   hold and the transfer hold overlap;
//! - the kernel discarded the message: a read with no control buffer, a
//!   receive with a short one, the teardown of the receiving socket, or the
//!   guest's exit. The witness's read end hangs up ([`Rights::watch`]).
//!
//! A peek leaves the message, its witness and its hold in the queue. Each
//! complete inventory reports the table holds and every transfer hold
//! together, and the supervisor's two-miss reclaim applies as before.
//!
//! The launcher never blocks in a send or a receive. When the guest's call
//! may wait, it polls the socket and checks the call between polls ([`wait`]);
//! the socket's SO_SNDTIMEO or SO_RCVTIMEO ends the wait with EAGAIN, as
//! the kernel ends it. A call that ended is answered no more: its unsent
//! messages close their copies and witnesses, so their holds end, and a
//! receive takes nothing.

// A native receive once a transfer was made: it installs what a message
// carried, and keeps the witness from the guest (FIX 6185).
mod receive;
// The calling task, whose own descriptor table a brokered call reads
// (FIX 6185).
mod task;
// A brokered call's wait on its socket, which ends with the call, and the
// send that waits (FIX 6185).
mod wait;

use super::{Bridge, load, remote, store};
use crate::{linux, wire};
use std::collections::{BTreeSet, HashMap};
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use task::Task;
use wait::may_wait;

/// The most control bytes one brokered message copies, and the most data
/// bytes a stream takes of one brokered message.
const MESSAGE_BOUND: usize = 65536;
/// The most buffers one message, and the most messages one call, holds:
/// the kernel's bound, which a brokered socket's calls have too.
const VECTOR_BOUND: usize = 1024;

/// The transfer holds of the brokered sockets queued on native Unix
/// sockets, by the inode of each message's witness pipe (FIX 6185).
pub(super) struct Rights {
    transfers: Mutex<HashMap<u64, Transfer>>,
    /// The epoll set that waits for each witness to hang up.
    watch: OwnedFd,
    /// A transfer was made: from then on a native receive with a control
    /// buffer is brokered, so no witness reaches the guest.
    transferred: AtomicBool,
}

/// One queued message's transfer hold.
struct Transfer {
    /// The witness pipe's device: with its inode, it names the witness.
    device: u64,
    /// The brokered sockets the message carries.
    sockets: Vec<u64>,
    /// The witness's read end, in the epoll set. It hangs up once no queue
    /// and no descriptor holds the write end.
    _end: OwnedFd,
}

impl Rights {
    pub(super) fn new() -> io::Result<Self> {
        // SAFETY: epoll_create1 takes one flag and passes no pointer.
        let watch = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if watch < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            transfers: Mutex::default(),
            // SAFETY: a successful epoll_create1 returned a new descriptor,
            // owned once.
            watch: unsafe { OwnedFd::from_raw_fd(watch) },
            transferred: AtomicBool::new(false),
        })
    }

    /// Adds every socket a transfer holds to an inventory's `inodes`.
    pub(super) fn extend_held(&self, inodes: &mut BTreeSet<u64>) -> io::Result<()> {
        let transfers = self.transfers.lock().map_err(|_| poisoned())?;
        inodes.extend(
            transfers
                .values()
                .flat_map(|held| held.sockets.iter().copied()),
        );
        Ok(())
    }

    /// Holds `sockets` for one message, before it can enqueue, and returns
    /// its witness's write end. The hold ends when the last copy of that
    /// end closes.
    fn hold(&self, sockets: Vec<u64>) -> io::Result<OwnedFd> {
        let mut ends = [0; 2];
        // SAFETY: pipe2 writes two descriptors into the live array.
        if unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a successful pipe2 returned two new descriptors, each
        // owned once.
        let (end, write) =
            unsafe { (OwnedFd::from_raw_fd(ends[0]), OwnedFd::from_raw_fd(ends[1])) };
        let (device, inode, _) = identity(&end)?;
        let mut event = libc::epoll_event {
            events: libc::EPOLLHUP as u32,
            u64: inode,
        };
        // SAFETY: event is live storage of the epoll_event layout, and both
        // descriptors are live.
        let added = unsafe {
            libc::epoll_ctl(
                self.watch.as_raw_fd(),
                libc::EPOLL_CTL_ADD,
                end.as_raw_fd(),
                &mut event,
            )
        };
        if added < 0 {
            return Err(io::Error::last_os_error());
        }
        self.transferred.store(true, Ordering::Release);
        self.transfers.lock().map_err(|_| poisoned())?.insert(
            inode,
            Transfer {
                device,
                sockets,
                _end: end,
            },
        );
        Ok(write)
    }

    /// Whether the file `(device, inode)` is a witness that still holds.
    fn witness(&self, device: u64, inode: u64) -> bool {
        self.transfers.lock().is_ok_and(|transfers| {
            transfers
                .get(&inode)
                .is_some_and(|held| held.device == device)
        })
    }

    /// Ends each transfer whose witness hung up, for the session's life:
    /// the last copy of its write end closed.
    pub(super) fn watch(&self) {
        let mut event = libc::epoll_event { events: 0, u64: 0 };
        loop {
            // SAFETY: epoll_wait writes at most one event into live storage.
            let ready = unsafe { libc::epoll_wait(self.watch.as_raw_fd(), &mut event, 1, -1) };
            if ready == 1 {
                let inode = event.u64;
                // The read end closes with its transfer and leaves the set.
                let Ok(mut transfers) = self.transfers.lock() else {
                    return;
                };
                transfers.remove(&inode);
            } else if ready < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return;
            }
        }
    }
}

/// Answers a call on a native socket (FIX 6185). Once a socket was
/// brokered, every send is brokered, and so is a receive with a control
/// buffer once a transfer was made; every other call continues to the
/// kernel as before.
pub(super) fn dispatch(
    listener: &OwnedFd,
    bridge: &Bridge,
    n: linux::Notification,
) -> io::Result<()> {
    let a = n.data.args;
    let nr = i64::from(n.data.nr);
    let vector = nr == libc::SYS_sendmmsg || nr == libc::SYS_recvmmsg;
    let (pointers, flags): (Vec<u64>, i32) = if nr == libc::SYS_sendmsg || nr == libc::SYS_recvmsg {
        (vec![a[1]], a[2] as i32)
    } else if vector {
        let count = (a[2] as usize).min(VECTOR_BOUND);
        let step = size_of::<libc::mmsghdr>() as u64;
        (
            (0..count as u64).map(|index| a[1] + index * step).collect(),
            a[3] as i32,
        )
    } else {
        return proceed(listener, n);
    };
    if nr == libc::SYS_sendmsg || nr == libc::SYS_sendmmsg {
        send(listener, bridge, n, &pointers, flags, vector)
    } else if bridge.rights.transferred.load(Ordering::Acquire)
        && pointers.iter().any(|&pointer| has_control(n.pid, pointer))
    {
        receive::receive(listener, bridge, n, &pointers, flags, vector)
    } else {
        proceed(listener, n)
    }
}

/// Continues the call to the kernel.
fn proceed(listener: &OwnedFd, n: linux::Notification) -> io::Result<()> {
    linux::respond(listener.as_raw_fd(), n.id, 0, 0, linux::CONTINUE)
}

/// Whether the guest's message header at `pointer` has a control buffer.
/// A header the launcher cannot read has none: the kernel answers it.
fn has_control(pid: u32, pointer: u64) -> bool {
    load::<libc::msghdr>(pid, pointer)
        .is_ok_and(|header| !header.msg_control.is_null() && header.msg_controllen > 0)
}

/// One message of a brokered send, copied into the launcher.
struct Outgoing {
    bytes: Vec<u8>,
    name: Vec<u8>,
    /// The guest's control bytes; their rights messages name `copies`.
    control: Vec<u8>,
    /// The launcher's copies of the descriptors the message names, in
    /// order. They close once the send has returned.
    copies: Vec<OwnedFd>,
    /// The witness's write end, once the message holds a brokered socket.
    witness: Option<OwnedFd>,
}

/// A brokered call: its notification, and the launcher's handles on the
/// calling task and on the socket the call names.
struct Call<'b> {
    bridge: &'b Bridge,
    n: linux::Notification,
    task: Task,
    socket: OwnedFd,
}

impl<'b> Call<'b> {
    fn open(bridge: &'b Bridge, n: linux::Notification) -> io::Result<Self> {
        let task = Task::open(n.pid)?;
        let socket = task.duplicate(n.data.args[0] as RawFd)?;
        Ok(Self {
            bridge,
            n,
            task,
            socket,
        })
    }
}

/// A sendmsg (one header) or sendmmsg (`vector`) on a native socket. Before
/// a socket was brokered, no message can carry one, and the call continues
/// to the kernel. After, the launcher sends each message from its own copy.
fn send(
    listener: &OwnedFd,
    bridge: &Bridge,
    n: linux::Notification,
    pointers: &[u64],
    flags: i32,
    vector: bool,
) -> io::Result<()> {
    if !bridge.brokered.load(Ordering::Acquire) {
        return proceed(listener, n);
    }
    Call::open(bridge, n)?.send_all(listener, pointers, flags, vector)
}

impl Call<'_> {
    /// Sends each message in order, each copied just before it is sent, up
    /// to the first that fails, and answers the call as the kernel would:
    /// the count a sendmmsg sent, the length a sendmsg sent, or the first
    /// failure's errno. A message never sent closes its witness, and its
    /// hold ends. A call that ended sends nothing more and is answered no
    /// more.
    fn send_all(
        &self,
        listener: &OwnedFd,
        pointers: &[u64],
        flags: i32,
        vector: bool,
    ) -> io::Result<()> {
        let blocking = may_wait(&self.socket, flags);
        let mut completed = 0_i64;
        let mut value = 0_i64;
        for &pointer in pointers {
            if linux::valid(listener.as_raw_fd(), self.n.id).is_err() {
                return Ok(());
            }
            let sent = self
                .outgoing(pointer)
                .and_then(|message| message.transmit(self, listener, flags, blocking));
            let length = match sent {
                Ok(Some(length)) => length,
                Ok(None) => return Ok(()),
                Err(error) if completed == 0 => return self.fail(listener, &error, flags),
                Err(_) => break,
            };
            let at = pointer + size_of::<libc::msghdr>() as u64;
            // A message whose length the guest cannot take was sent but is
            // not counted, as the kernel counts it.
            if vector && store(self.n.pid, at, length as u32).is_err() {
                if completed == 0 {
                    let error = io::Error::from_raw_os_error(libc::EFAULT);
                    return self.fail(listener, &error, flags);
                }
                break;
            }
            value = length as i64;
            completed += 1;
        }
        let value = if vector { completed } else { value };
        linux::respond(listener.as_raw_fd(), self.n.id, value, 0, 0)
    }

    /// Copies the guest's message at `pointer` with the launcher's copies
    /// of the descriptors it names, and holds the brokered sockets among
    /// them. The copies and the hold are made under the inventory lock: a
    /// copy proves the guest held its descriptor, and its hold is recorded
    /// before a scan can miss it (FIX 5978).
    fn outgoing(&self, pointer: u64) -> io::Result<Outgoing> {
        let pid = self.n.pid;
        let header = load::<libc::msghdr>(pid, pointer)?;
        let (control, fds) = descriptors(pid, &header)?;
        let (vectors, total) = vectors(pid, &header)?;
        let _shared = self.bridge.sockets.read().map_err(|_| poisoned())?;
        let copies = fds
            .iter()
            .map(|&fd| self.task.duplicate(fd))
            .collect::<io::Result<Vec<_>>>()?;
        let mut brokered = Vec::new();
        for copy in &copies {
            let (_, inode, kind) = identity(copy)?;
            let describe = wire::Operation::Describe { socket: inode };
            if kind == libc::S_IFSOCK && self.bridge.call(self.n.id, describe)?.errno == 0 {
                brokered.push(inode);
            }
        }
        let (bytes, name) = self.payload(&header, &vectors, total)?;
        let witness = if brokered.is_empty() {
            None
        } else {
            Some(self.bridge.rights.hold(brokered)?)
        };
        Ok(Outgoing {
            bytes,
            name,
            control,
            copies,
            witness,
        })
    }

    /// The message's data and destination name, as the kernel takes them:
    /// a stream may take part of a long write, and a datagram or seqpacket
    /// message no longer than the socket's SO_SNDBUF must fit whole. A Unix
    /// datagram's relative pathname names the calling task's working
    /// directory ([`resolved`]).
    fn payload(
        &self,
        header: &libc::msghdr,
        vectors: &[libc::iovec],
        total: usize,
    ) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let pid = self.n.pid;
        let kind = socket_option(&self.socket, libc::SO_TYPE)?;
        let mut destination = name(pid, header)?;
        // Only a datagram goes to the name it gives: a stream refuses a
        // name, and a seqpacket socket ignores it.
        if kind == libc::SOCK_DGRAM
            && socket_option(&self.socket, libc::SO_DOMAIN)? == libc::AF_UNIX
        {
            destination = resolved(&self.task, destination)?;
        }
        let length = if kind == libc::SOCK_STREAM {
            total.min(MESSAGE_BOUND)
        } else if usize::try_from(socket_option(&self.socket, libc::SO_SNDBUF)?)
            .is_ok_and(|bound| total <= bound)
        {
            total
        } else {
            return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
        };
        Ok((gather(pid, vectors, length)?, destination))
    }

    /// Answers the call with `error`. A send to a closed peer raises
    /// SIGPIPE in the sending task, as the kernel does, unless the call
    /// asked not to.
    fn fail(&self, listener: &OwnedFd, error: &io::Error, flags: i32) -> io::Result<()> {
        let code = error.raw_os_error().unwrap_or(libc::EIO);
        linux::respond(listener.as_raw_fd(), self.n.id, 0, code, 0)?;
        if code == libc::EPIPE && flags & libc::MSG_NOSIGNAL == 0 {
            self.task.raise(libc::SIGPIPE);
        }
        Ok(())
    }
}

/// The guest's control bytes of `header` and the descriptors its rights
/// messages name, judged as the kernel judges them: a buffer the launcher
/// cannot read fails EFAULT, one longer than [`MESSAGE_BOUND`] ENOBUFS, and
/// a control message whose length the kernel refuses EINVAL.
fn descriptors(pid: u32, header: &libc::msghdr) -> io::Result<(Vec<u8>, Vec<RawFd>)> {
    let length = header.msg_controllen;
    if length == 0 {
        return Ok((Vec::new(), Vec::new()));
    }
    if length > MESSAGE_BOUND {
        return Err(io::Error::from_raw_os_error(libc::ENOBUFS));
    }
    let mut control = vec![0; length];
    remote(pid, header.msg_control as u64, &mut control, false)
        .map_err(|_| io::Error::from_raw_os_error(libc::EFAULT))?;
    let fds = {
        let (found, whole) = controls(&control);
        if !whole {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        found
            .iter()
            .filter(|found| found.rights())
            .flat_map(|found| fds_of(found.data))
            .collect()
    };
    Ok((control, fds))
}

/// `control` with each rights message naming the launcher's `copies` in
/// turn, and with the witness, when there is one, as the last descriptor.
fn rebuild(control: &[u8], copies: &[OwnedFd], witness: Option<RawFd>) -> Vec<u8> {
    let mut rebuilt = Vec::new();
    let mut next = copies.iter();
    for found in controls(control).0 {
        if found.rights() {
            let data: Vec<u8> = fds_of(found.data)
                .filter_map(|_| next.next())
                .flat_map(|copy| copy.as_raw_fd().to_ne_bytes())
                .collect();
            put_control(&mut rebuilt, found.level, found.kind, &data);
        } else {
            put_control(&mut rebuilt, found.level, found.kind, found.data);
        }
    }
    if let Some(witness) = witness {
        put_control(
            &mut rebuilt,
            libc::SOL_SOCKET,
            libc::SCM_RIGHTS,
            &witness.to_ne_bytes(),
        );
    }
    rebuilt
}

/// One control message of a buffer.
struct Control<'b> {
    level: i32,
    kind: i32,
    data: &'b [u8],
}

impl Control<'_> {
    fn rights(&self) -> bool {
        self.level == libc::SOL_SOCKET && self.kind == libc::SCM_RIGHTS
    }
}

/// The control messages of `buffer` as the kernel walks them, and whether
/// the walk ended cleanly: `false` at a length the kernel refuses.
fn controls(buffer: &[u8]) -> (Vec<Control<'_>>, bool) {
    let header = size_of::<libc::cmsghdr>();
    let offset = aligned(header);
    let mut found = Vec::new();
    let mut at = 0;
    while at + header <= buffer.len() {
        // SAFETY: the header's bytes lie inside the buffer, and
        // read_unaligned takes them at any alignment.
        let control: libc::cmsghdr =
            unsafe { std::ptr::read_unaligned(buffer[at..].as_ptr().cast::<libc::cmsghdr>()) };
        let length = control.cmsg_len;
        if length < header || length > buffer.len() - at {
            return (found, false);
        }
        found.push(Control {
            level: control.cmsg_level,
            kind: control.cmsg_type,
            data: &buffer[at + offset.min(length)..at + length],
        });
        at += aligned(length);
    }
    (found, true)
}

/// Appends one control message to `buffer`, padded as the kernel pads it.
fn put_control(buffer: &mut Vec<u8>, level: i32, kind: i32, data: &[u8]) {
    let start = buffer.len();
    let offset = aligned(size_of::<libc::cmsghdr>());
    // SAFETY: a zeroed cmsghdr is a valid value; its fields are set next.
    let mut header: libc::cmsghdr = unsafe { std::mem::zeroed() };
    header.cmsg_len = (offset + data.len()) as _;
    header.cmsg_level = level;
    header.cmsg_type = kind;
    buffer.resize(start + offset + aligned(data.len()), 0);
    // SAFETY: the header's bytes lie inside the resized buffer, and
    // write_unaligned puts them at any alignment.
    unsafe {
        std::ptr::write_unaligned(buffer[start..].as_mut_ptr().cast::<libc::cmsghdr>(), header);
    }
    buffer[start + offset..start + offset + data.len()].copy_from_slice(data);
}

/// The descriptors a rights message's data names; a short tail names none,
/// as the kernel reads it.
fn fds_of(data: &[u8]) -> impl Iterator<Item = RawFd> + '_ {
    data.chunks_exact(size_of::<RawFd>())
        .map(|bytes| RawFd::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// `length` rounded up as the kernel aligns a control message.
fn aligned(length: usize) -> usize {
    let word = size_of::<usize>();
    (length + word - 1) & !(word - 1)
}

/// The buffers of the guest's message header, and their total length.
fn vectors(pid: u32, header: &libc::msghdr) -> io::Result<(Vec<libc::iovec>, usize)> {
    let count = header.msg_iovlen;
    if count > VECTOR_BOUND {
        return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
    }
    let mut vectors = Vec::with_capacity(count);
    let mut total = 0_usize;
    for index in 0..count {
        let at = header.msg_iov as u64 + (index * size_of::<libc::iovec>()) as u64;
        let vector: libc::iovec = load(pid, at)?;
        total = total.saturating_add(vector.iov_len);
        vectors.push(vector);
    }
    Ok((vectors, total))
}

/// The first `length` bytes of the guest's buffers.
fn gather(pid: u32, vectors: &[libc::iovec], length: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0; length];
    let mut at = 0;
    for vector in vectors {
        let take = vector.iov_len.min(length - at);
        remote(
            pid,
            vector.iov_base as u64,
            &mut bytes[at..at + take],
            false,
        )?;
        at += take;
    }
    Ok(bytes)
}

/// Writes `bytes` into the guest's buffers, in order.
fn scatter(pid: u32, vectors: &[libc::iovec], bytes: &mut [u8]) -> io::Result<()> {
    let mut at = 0;
    for vector in vectors {
        let take = vector.iov_len.min(bytes.len() - at);
        remote(pid, vector.iov_base as u64, &mut bytes[at..at + take], true)?;
        at += take;
    }
    Ok(())
}

/// The guest's destination name, copied: at most a sockaddr_storage, as
/// the kernel takes one.
fn name(pid: u32, header: &libc::msghdr) -> io::Result<Vec<u8>> {
    if header.msg_name.is_null() || header.msg_namelen == 0 {
        return Ok(Vec::new());
    }
    let length = header.msg_namelen as usize;
    if length > size_of::<libc::sockaddr_storage>() {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let mut name = vec![0; length];
    remote(pid, header.msg_name as u64, &mut name, false)?;
    Ok(name)
}

/// A Unix datagram's destination `name`, as the launcher sends it for
/// `task` (FIX 6185). A pathname whose sun_path is relative names the
/// task's working directory through /proc/<tid>/cwd, with the length to
/// match: the launcher's own working directory is not the task's. A path
/// that then does not fit sun_path with its NUL fails ENAMETOOLONG, and
/// nothing is sent. An absolute or abstract name, or one the kernel
/// refuses, is sent unchanged.
fn resolved(task: &Task, name: Vec<u8>) -> io::Result<Vec<u8>> {
    let offset = std::mem::offset_of!(libc::sockaddr_un, sun_path);
    let family = (libc::AF_UNIX as libc::sa_family_t).to_ne_bytes();
    if name.len() <= offset || name.len() > size_of::<libc::sockaddr_un>() {
        return Ok(name);
    }
    // The kernel reads sun_path up to its first NUL; an abstract name
    // starts with one.
    let path = &name[offset..];
    let end = path.iter().position(|&byte| byte == 0);
    let path = &path[..end.unwrap_or(path.len())];
    if name[..offset] != family[..] || path.first().is_none_or(|&byte| byte == b'/') {
        return Ok(name);
    }
    let mut anchored = name[..offset].to_vec();
    anchored.extend_from_slice(task.working_directory().as_bytes());
    anchored.push(b'/');
    anchored.extend_from_slice(path);
    anchored.push(0);
    if anchored.len() > size_of::<libc::sockaddr_un>() {
        return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
    }
    Ok(anchored)
}

/// A descriptor's device, inode and file type.
fn identity(fd: &impl AsRawFd) -> io::Result<(u64, u64, libc::mode_t)> {
    // SAFETY: fstat fills a live stat value for a borrowed descriptor.
    unsafe {
        let mut stat: libc::stat = std::mem::zeroed();
        if libc::fstat(fd.as_raw_fd(), &mut stat) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((stat.st_dev, stat.st_ino, stat.st_mode & libc::S_IFMT))
    }
}

/// The socket's integer option `option` at SOL_SOCKET: its type
/// (SO_TYPE), or the size of its send or receive buffer (SO_SNDBUF,
/// SO_RCVBUF).
fn socket_option(socket: &OwnedFd, option: i32) -> io::Result<i32> {
    let mut value = 0_i32;
    let mut size = size_of::<i32>() as libc::socklen_t;
    // SAFETY: getsockopt writes one int into live storage of its size.
    let read = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            (&mut value as *mut i32).cast(),
            &mut size,
        )
    };
    if read < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

fn poisoned() -> io::Error {
    io::Error::other("fence state poisoned")
}
