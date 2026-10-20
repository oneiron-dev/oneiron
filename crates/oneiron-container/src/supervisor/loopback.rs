//! The guest's virtual loopback (FIX 6680): stream listeners a guest binds
//! on its own loopback, inside its own session.
//!
//! No kernel INET listener exists anywhere. A bind records its address in
//! this session's registry; a listen makes the socket a listener with a
//! bounded queue; a connect from this session to a loopback address one of
//! its listeners holds queues the client's host end, and an accept installs
//! that end in the guest, so the two guest ends talk over one Unix pair.
//! Nothing on the host or in another session can reach a listener: only
//! this session's own connect calls look in its registry, and a connect to
//! any other address goes to the host egress proxy as it always did.
//!
//! Only 127.0.0.0/8 and ::1 hold listeners ([`loopback_admits`]); any other
//! address is a typed refusal the host records ([`refuse`]). So is a
//! loopback connect no listener holds, except on port 53, which keeps the
//! fence's DNS.
//!
//! A listener is readable while its queue is not empty: each queued
//! connection writes one byte (a token) to the listener's guest end, and
//! each dequeue reads one back, under the queue's lock, through the copy of
//! that end the listener keeps.

use super::{Socket, State, get, inode};
use crate::{
    HostNetPermit, LoopbackOperation, LoopbackRefusal, LoopbackRefusalReason, linux, wire,
};
use std::collections::{HashMap, VecDeque};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// The longest accept queue a listener keeps: a larger backlog is cut to
/// it, and a connect to a full queue answers `EAGAIN`.
const LOOPBACK_BACKLOG: usize = 128;
/// The virtual ports a bind to port 0 and a client's own end take.
const LOOPBACK_PORTS: RangeInclusive<u16> = 49152..=65535;
/// What a listener holds of the host floor while it lives, as (descriptors,
/// workers): its copy of the guest's end. Its host end is its entry's.
const LISTENER: (usize, usize) = (1, 0);
/// What a queued connection holds until the guest accepts it: the client's
/// host end, whose entry may end first.
const QUEUED: (usize, usize) = (1, 0);
/// How long a blocking accept sleeps before it looks at its call, its
/// listener and the session again: a cadence, not a bound.
const ACCEPT_POLL: Duration = Duration::from_millis(250);

/// One session's virtual loopback.
#[derive(Default)]
pub(super) struct Registry {
    /// Each socket's virtual local address: bound, listening, accepted, or
    /// a client's own end.
    local: HashMap<u64, SocketAddr>,
    /// Every bound address, and the socket that holds it.
    bound: HashMap<SocketAddr, u64>,
    listeners: HashMap<u64, Arc<Listener>>,
    /// Where the next search for a free virtual port starts.
    next: u16,
}

struct Listener {
    address: SocketAddr,
    family: i32,
    /// The listener's guest end: it reads tokens back and shows the
    /// guest's mode.
    guest: OwnedFd,
    /// The listener's host end: it writes the tokens.
    host: UnixStream,
    queue: Mutex<Queue>,
    ready: Condvar,
    _charge: HostNetPermit,
}

#[derive(Default)]
struct Queue {
    waiting: VecDeque<Queued>,
    /// Connections an accept took, until its address is written.
    reserved: HashMap<u64, Queued>,
    next: u64,
    backlog: usize,
    closed: bool,
}

struct Queued {
    /// The client's host end: the guest's accepted socket.
    stream: UnixStream,
    /// The client's virtual address.
    peer: SocketAddr,
    _charge: HostNetPermit,
}

/// The loopback set: whether `address` may hold a listener, or why not.
/// 127.0.0.0/8 and ::1 may; the wildcard, a mapped IPv6 form and every
/// other address may not.
fn loopback_admits(address: SocketAddr) -> Result<(), LoopbackRefusalReason> {
    match address.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => Err(LoopbackRefusalReason::Wildcard),
        IpAddr::V4(ip) if ip.is_loopback() => Ok(()),
        IpAddr::V6(ip) if ip.is_unspecified() => Err(LoopbackRefusalReason::Wildcard),
        IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some() => {
            Err(LoopbackRefusalReason::MappedAddress)
        }
        IpAddr::V6(ip) if ip.is_loopback() => Ok(()),
        _ => Err(LoopbackRefusalReason::NotLoopback),
    }
}

/// The refusal shape: the errno a refusal answers. A connect no listener
/// holds is `ECONNREFUSED` and an accept on a socket that is not listening
/// is `EINVAL`, as Linux answers them; an address the fence keeps no
/// listener on is `EACCES`.
fn refusal_errno(reason: LoopbackRefusalReason) -> i32 {
    match reason {
        LoopbackRefusalReason::NoListener => libc::ECONNREFUSED,
        LoopbackRefusalReason::NotListening => libc::EINVAL,
        LoopbackRefusalReason::Wildcard
        | LoopbackRefusalReason::NotLoopback
        | LoopbackRefusalReason::MappedAddress
        | LoopbackRefusalReason::Datagram => libc::EACCES,
    }
}

/// Answers a refusal, typed, and has the host record it. A record that
/// fails changes nothing the guest is answered.
fn refuse(
    state: &State,
    operation: LoopbackOperation,
    address: SocketAddr,
    reason: LoopbackRefusalReason,
) -> wire::Reply {
    let refusal = LoopbackRefusal {
        operation,
        address,
        reason,
    };
    let _ = state.relay.record_refusal(&refusal);
    wire::Reply {
        errno: refusal_errno(reason),
        refusal: Some(refusal),
        ..Default::default()
    }
}

fn poisoned() -> io::Error {
    io::Error::other("fence state poisoned")
}

fn errno(code: i32) -> io::Error {
    io::Error::from_raw_os_error(code)
}

/// The address a socket of `family` bound to nothing has.
fn wildcard(family: i32) -> SocketAddr {
    if family == libc::AF_INET6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    }
}

impl Registry {
    /// A port of [`LOOPBACK_PORTS`] no bind holds at `ip`, in turn.
    fn free(&mut self, ip: IpAddr) -> Option<SocketAddr> {
        let first = *LOOPBACK_PORTS.start();
        let span = LOOPBACK_PORTS.end() - first + 1;
        (0..span).find_map(|_| {
            let address = SocketAddr::new(ip, first + self.next % span);
            self.next = self.next.wrapping_add(1);
            (!self.bound.contains_key(&address)).then_some(address)
        })
    }
}

/// A bind of a stream socket to a loopback address of its family, once and
/// before any connect. Port 0 takes a free virtual port.
pub(super) fn bind(state: &State, id: u64, address: SocketAddr) -> io::Result<wire::Reply> {
    let socket = get(state, id)?;
    // The address alone: no flow label or scope names another listener.
    let address = SocketAddr::new(address.ip(), address.port());
    if socket.kind == libc::SOCK_DGRAM {
        let reason = LoopbackRefusalReason::Datagram;
        return Ok(refuse(state, LoopbackOperation::Bind, address, reason));
    }
    if address.is_ipv6() != (socket.family == libc::AF_INET6) {
        return Err(errno(libc::EAFNOSUPPORT));
    }
    if let Err(reason) = loopback_admits(address) {
        return Ok(refuse(state, LoopbackOperation::Bind, address, reason));
    }
    let mut registry = state.loopback.lock().map_err(|_| poisoned())?;
    let connected = socket.stream.lock().map_err(|_| poisoned())?.is_none();
    if connected || registry.local.contains_key(&id) {
        return Err(errno(libc::EINVAL));
    }
    let address = if address.port() == 0 {
        registry
            .free(address.ip())
            .ok_or_else(|| errno(libc::EADDRINUSE))?
    } else if registry.bound.contains_key(&address) {
        return Err(errno(libc::EADDRINUSE));
    } else {
        address
    };
    registry.bound.insert(address, id);
    registry.local.insert(id, address);
    Ok(wire::Reply::default())
}

/// A listen on a socket that holds a loopback bind. A listen with no bind
/// would take the wildcard: it is refused. The listener keeps `guest`, the
/// socket's guest end, and takes its room on the host floor first.
pub(super) fn listen(
    state: &State,
    id: u64,
    backlog: i32,
    guest: Option<OwnedFd>,
) -> io::Result<wire::Reply> {
    let socket = get(state, id)?;
    let backlog = usize::try_from(backlog)
        .unwrap_or(0)
        .clamp(1, LOOPBACK_BACKLOG);
    let unbound = {
        let mut registry = state.loopback.lock().map_err(|_| poisoned())?;
        if let Some(listener) = registry.listeners.get(&id) {
            listener.queue.lock().map_err(|_| poisoned())?.backlog = backlog;
            return Ok(wire::Reply::default());
        }
        let mut host = socket.stream.lock().map_err(|_| poisoned())?;
        let address = registry
            .local
            .get(&id)
            .copied()
            .filter(|address| registry.bound.get(address) == Some(&id));
        match (host.is_some(), address) {
            (false, _) => return Err(errno(libc::EINVAL)),
            (true, None) => true,
            (true, Some(address)) => {
                let guest = guest
                    .filter(|guest| inode(guest).is_ok_and(|found| found == id))
                    .ok_or_else(|| errno(libc::EBADF))?;
                let (fds, workers) = LISTENER;
                let charge = state.relay.host_net_floor().acquire(fds, workers)?;
                let host = host.take().ok_or_else(|| errno(libc::EINVAL))?;
                let queue = Queue {
                    backlog,
                    ..Queue::default()
                };
                let listener = Listener {
                    address,
                    family: socket.family,
                    guest,
                    host,
                    queue: Mutex::new(queue),
                    ready: Condvar::new(),
                    _charge: charge,
                };
                registry.listeners.insert(id, Arc::new(listener));
                false
            }
        }
    };
    if unbound {
        let address = wildcard(socket.family);
        let reason = LoopbackRefusalReason::Wildcard;
        return Ok(refuse(state, LoopbackOperation::Listen, address, reason));
    }
    Ok(wire::Reply::default())
}

/// Takes the next queued connection under a ticket (the reply's value),
/// with its peer address. A listener in nonblocking mode answers `EAGAIN`
/// on an empty queue; a blocking one waits until `waiting` (the call), the
/// listener or the session ends.
pub(super) fn accept(
    state: &State,
    id: u64,
    waiting: impl Fn() -> bool,
) -> io::Result<wire::Reply> {
    let Some(listener) = listening(state, id)? else {
        let family = get(state, id)?.family;
        let address = local(state, id).unwrap_or_else(|| wildcard(family));
        let reason = LoopbackRefusalReason::NotListening;
        return Ok(refuse(state, LoopbackOperation::Accept, address, reason));
    };
    let nonblocking = in_nonblocking_mode(&listener.guest);
    let mut queue = listener.queue.lock().map_err(|_| poisoned())?;
    loop {
        if let Some(queued) = queue.waiting.pop_front() {
            listener.untoken();
            queue.next += 1;
            let ticket = queue.next;
            let peer = queued.peer;
            queue.reserved.insert(ticket, queued);
            return Ok(wire::Reply {
                value: ticket as i64,
                address: Some(peer),
                ..Default::default()
            });
        }
        if nonblocking {
            return Err(errno(libc::EAGAIN));
        }
        if queue.closed || !state.alive.load(Ordering::Acquire) || !waiting() {
            return Err(errno(libc::EINVAL));
        }
        queue = listener
            .ready
            .wait_timeout(queue, ACCEPT_POLL)
            .map_err(|_| poisoned())?
            .0;
    }
}

/// Installs a reserved connection as the result of the guest's accept,
/// with `flags` (accept4's SOCK_NONBLOCK and SOCK_CLOEXEC), or puts it back
/// first in its queue. Its entry, with its virtual local and peer
/// addresses, exists before the guest holds it.
pub(super) fn finish(
    request: &wire::Request,
    notify: &OwnedFd,
    state: &State,
    id: u64,
    ticket: u64,
    commit: bool,
    flags: i32,
) -> io::Result<wire::Reply> {
    let listener = listening(state, id)?.ok_or_else(|| errno(libc::ECONNABORTED))?;
    let reserved = listener
        .queue
        .lock()
        .map_err(|_| poisoned())?
        .reserved
        .remove(&ticket);
    let queued = reserved.ok_or_else(|| errno(libc::ECONNABORTED))?;
    if !commit {
        listener.requeue(queued)?;
        return Ok(wire::Reply::default());
    }
    let made = queued
        .stream
        .set_nonblocking(flags & libc::SOCK_NONBLOCK != 0)
        .and_then(|()| inode(&queued.stream));
    let accepted = match made {
        Ok(accepted) => accepted,
        Err(error) => {
            listener.requeue(queued)?;
            return Err(error);
        }
    };
    let socket = Arc::new(Socket {
        family: listener.family,
        kind: libc::SOCK_STREAM,
        target: Mutex::new(Some(queued.peer)),
        stream: Mutex::new(None),
        datagram: None,
        closed: AtomicBool::new(false),
        // The guest holds both ends; the host holds nothing of it.
        _charge: HostNetPermit::new(()),
    });
    state
        .sockets
        .lock()
        .map_err(|_| poisoned())?
        .insert(accepted, Arc::clone(&socket));
    state
        .loopback
        .lock()
        .map_err(|_| poisoned())?
        .local
        .insert(accepted, listener.address);
    let injected = linux::inject(
        notify.as_raw_fd(),
        request.notification,
        queued.stream.as_raw_fd(),
        flags & libc::SOCK_CLOEXEC != 0,
    );
    match injected {
        Ok(fd) => Ok(wire::Reply {
            value: i64::from(fd),
            ..Default::default()
        }),
        // A connection the guest never received has no entry and goes back.
        Err(error) => {
            if let Ok(mut sockets) = state.sockets.lock()
                && sockets
                    .get(&accepted)
                    .is_some_and(|held| Arc::ptr_eq(held, &socket))
            {
                sockets.remove(&accepted);
            }
            if let Ok(mut registry) = state.loopback.lock() {
                registry.local.remove(&accepted);
            }
            listener.requeue(queued)?;
            Err(error)
        }
    }
}

/// A stream connect to a loopback `target`. A listener of this session at
/// `target` queues the client's host end for its accept, and the client is
/// connected; with none there, the connect is refused (`ECONNREFUSED`),
/// except on port 53, whose DNS goes on as before. `None` is every connect
/// that goes on as before: any other target, port 53 with no listener, and
/// a socket already connected.
pub(super) fn connect(
    state: &State,
    id: u64,
    socket: &Socket,
    target: SocketAddr,
) -> Option<io::Result<wire::Reply>> {
    if !target.ip().is_loopback() {
        return None;
    }
    let target = SocketAddr::new(target.ip(), target.port());
    let found = state.loopback.lock().map(|mut registry| {
        let listener = registry
            .bound
            .get(&target)
            .and_then(|holder| registry.listeners.get(holder))
            .cloned()?;
        let own = registry.local.get(&id).copied();
        let own = own.or_else(|| registry.free(target.ip()))?;
        Some((listener, own))
    });
    match found {
        Err(_) => Some(Err(poisoned())),
        Ok(Some((listener, own))) => Some(enqueue(state, id, socket, &listener, own, target)),
        Ok(None) if target.port() == 53 => None,
        // A socket already connected answers as it always did.
        Ok(None) if !socket.stream.lock().is_ok_and(|peer| peer.is_some()) => None,
        Ok(None) => {
            let reason = LoopbackRefusalReason::NoListener;
            let reply = refuse(state, LoopbackOperation::Connect, target, reason);
            Some(Ok(reply))
        }
    }
}

/// Queues the client's host end on `listener`, with the client's own
/// virtual address `own`, and its token. The room it holds is taken first.
fn enqueue(
    state: &State,
    id: u64,
    socket: &Socket,
    listener: &Listener,
    own: SocketAddr,
    target: SocketAddr,
) -> io::Result<wire::Reply> {
    let mut peer = socket.stream.lock().map_err(|_| poisoned())?;
    if peer.is_none() {
        return Err(errno(libc::EISCONN));
    }
    let (fds, workers) = QUEUED;
    let charge = state.relay.host_net_floor().acquire(fds, workers)?;
    {
        let mut queue = listener.queue.lock().map_err(|_| poisoned())?;
        if queue.closed {
            return Err(errno(libc::ECONNREFUSED));
        }
        if queue.waiting.len() >= queue.backlog {
            return Err(errno(libc::EAGAIN));
        }
        let stream = peer.take().ok_or_else(|| errno(libc::EISCONN))?;
        listener.token();
        queue.waiting.push_back(Queued {
            stream,
            peer: own,
            _charge: charge,
        });
        listener.ready.notify_one();
    }
    *socket.target.lock().map_err(|_| poisoned())? = Some(target);
    drop(peer);
    state
        .loopback
        .lock()
        .map_err(|_| poisoned())?
        .local
        .insert(id, own);
    Ok(wire::Reply::default())
}

/// The virtual local address of socket `id`, when it has one: getsockname
/// answers it.
pub(super) fn local(state: &State, id: u64) -> Option<SocketAddr> {
    state.loopback.lock().ok()?.local.get(&id).copied()
}

fn listening(state: &State, id: u64) -> io::Result<Option<Arc<Listener>>> {
    let registry = state.loopback.lock().map_err(|_| poisoned())?;
    Ok(registry.listeners.get(&id).cloned())
}

/// Socket `id` has no guest hold left: its address, its listener, the
/// listener's queue and its waits end with it.
pub(super) fn release(state: &State, id: u64) {
    let Ok(mut registry) = state.loopback.lock() else {
        return;
    };
    if let Some(address) = registry.local.remove(&id)
        && registry.bound.get(&address) == Some(&id)
    {
        registry.bound.remove(&address);
    }
    if let Some(listener) = registry.listeners.remove(&id) {
        listener.close();
    }
}

impl Listener {
    /// One token: the listener's guest end is readable while one waits.
    fn token(&self) {
        let _ = (&self.host).write_all(&[0]);
    }

    /// Takes one token back, never waiting: a guest that read its own
    /// listener took it already.
    fn untoken(&self) {
        let mut byte = [0_u8];
        // SAFETY: recv writes at most one byte into live storage, and
        // MSG_DONTWAIT keeps it from waiting whatever the guest's mode.
        let _ = unsafe {
            libc::recv(
                self.guest.as_raw_fd(),
                byte.as_mut_ptr().cast(),
                1,
                libc::MSG_DONTWAIT,
            )
        };
    }

    /// Puts a connection back first in the queue, with its token. A closed
    /// listener drops it, and its client reads the end.
    fn requeue(&self, queued: Queued) -> io::Result<()> {
        let mut queue = self.queue.lock().map_err(|_| poisoned())?;
        if !queue.closed {
            self.token();
            queue.waiting.push_front(queued);
            self.ready.notify_one();
        }
        Ok(())
    }

    /// Ends the listener: its queued connections close, and its waits end.
    fn close(&self) {
        if let Ok(mut queue) = self.queue.lock() {
            queue.closed = true;
            queue.waiting.clear();
            queue.reserved.clear();
        }
        self.ready.notify_all();
    }
}

/// Whether the guest put the listener in nonblocking mode. The kept copy
/// shares the guest end's open file description, and with it its mode.
fn in_nonblocking_mode(guest: &OwnedFd) -> bool {
    // SAFETY: F_GETFL only reads the status flags of a live descriptor.
    let flags = unsafe { libc::fcntl(guest.as_raw_fd(), libc::F_GETFL) };
    flags >= 0 && flags & libc::O_NONBLOCK != 0
}
