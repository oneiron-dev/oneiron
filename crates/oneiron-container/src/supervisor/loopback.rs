//! The guest's virtual loopback (FIX 6680): stream listeners a guest binds
//! on its own loopback, inside its own session.
//!
//! No kernel INET listener exists anywhere. A bind records its address in
//! this session's registry; a listen makes the socket a listener with a
//! bounded queue; a connect from this session to a loopback address one of
//! its listeners holds queues the client's host end, and an accept installs
//! that end in the guest, so the two guest ends talk over one Unix pair.
//! The trusted holder of this session's fence may also connect to an exact
//! loopback listener, keeping the host peer. No kernel listener or route to
//! another session is opened. Guest connects to any other address still
//! go to the host egress proxy.
//!
//! Only 127.0.0.0/8 and ::1 hold listeners ([`loopback_admits`]); any other
//! address is a typed refusal the host records ([`refuse`]). So is a
//! loopback connect no listener holds, except on port 53, which keeps the
//! fence's DNS.
//!
//! An IPv4-mapped address (::ffff:127.x.y.z) on an AF_INET6 socket is its
//! IPv4 address (FIX 6787): the registry keys every address by
//! [`canonical`], so it shares IPv4's ports, and an AF_INET6 socket shows
//! an IPv4 address in its mapped form ([`presented`]). A socket with
//! IPV6_V6ONLY takes no mapped address. ::1 stays IPv6.
//!
//! A listener is readable while its queue is not empty: each queued
//! connection writes one byte (a token) to the listener's guest end, and
//! each dequeue reads one back, under the queue's lock, through the copy of
//! that end the socket kept since `socket()` (FIX 6788).
//!
//! A connect to a full queue waits its turn ([`connect()`], FIX 6785).

use super::control::Control;
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

// Connects that wait their turn for a slot (FIX 6785, FIX 8015).
mod connect;
/// The trusted session holder's exact loopback dial. No guest socket id or
/// egress authority is manufactured for the host peer.
pub(super) fn connect_host(
    state: &State,
    target: SocketAddr,
    waiting: impl Fn() -> bool,
) -> io::Result<super::LoopbackConnection> {
    if !state.alive.load(Ordering::Acquire) || !waiting() {
        return Err(errno(libc::EINTR));
    }
    let target = canonical(target);
    if loopback_admits(target).is_err() {
        return Err(errno(libc::EACCES));
    }
    let (listener, own) = {
        let mut registry = state.loopback.lock().map_err(|_| poisoned())?;
        let listener = registry
            .bound
            .get(&target)
            .and_then(|id| registry.listeners.get(id))
            .cloned()
            .ok_or_else(|| errno(libc::ECONNREFUSED))?;
        let own = registry
            .free(target.ip())
            .ok_or_else(|| errno(libc::EADDRINUSE))?;
        (listener, own)
    };
    connect::enqueue_host(state, &listener, own, waiting)
}

pub(super) use connect::Connecting;
// SO_ACCEPTCONN and IPV6_V6ONLY, kept by the fence (FIX 6784, FIX 6787).
mod options;

pub(super) use options::{get_option, set_option};

/// The longest accept queue a listener keeps: a larger backlog is cut to
/// it, and a connect to a full queue waits its turn or, nonblocking,
/// answers `EAGAIN` ([`connect()`]). A connection an accept has reserved
/// still counts until it is installed or back in its queue, so putting it
/// back never overfills the queue (FIX 6791).
const LOOPBACK_BACKLOG: usize = 128;
/// The virtual ports a bind to port 0 and a client's own end take.
const LOOPBACK_PORTS: RangeInclusive<u16> = 49152..=65535;
/// What a queued connection holds until the guest accepts it: the client's
/// host end, whose entry may end first.
const QUEUED: (usize, usize) = (1, 0);
/// How long a blocking accept or connect sleeps before it looks at its
/// call, its listener and the session again: a cadence, not a bound.
const BLOCKED_CALL_POLL: Duration = Duration::from_millis(250);

/// One session's virtual loopback.
#[derive(Default)]
pub(super) struct Registry {
    /// Each socket's virtual local address, by its [`canonical`] key:
    /// bound, listening, accepted, or a client's own end.
    local: HashMap<u64, SocketAddr>,
    /// Every bound [`canonical`] address, and the socket that holds it.
    bound: HashMap<SocketAddr, u64>,
    listeners: HashMap<u64, Arc<Listener>>,
    /// Where the next search for a free virtual port starts.
    next: u16,
}

struct Listener {
    /// The listener's [`canonical`] address.
    address: SocketAddr,
    family: i32,
    /// The listener's IPV6_V6ONLY, which its accepted sockets take.
    ipv6_only: bool,
    /// The socket's copy of its guest end, with that copy's room on the
    /// host floor: it reads tokens back and shows the guest's mode.
    control: Control,
    /// The listener's host end: it writes the tokens. Its room on the host
    /// floor is its socket entry's.
    host: UnixStream,
    queue: Mutex<Queue>,
    /// An accept may find a connection.
    ready: Condvar,
    /// A connect waiting its turn may find a slot.
    space: Condvar,
}

#[derive(Default)]
struct Queue {
    waiting: VecDeque<Queued>,
    /// Connections an accept took, until its address is written.
    reserved: HashMap<u64, Queued>,
    /// Reserved connections a finish is installing: each holds its slot
    /// until it is installed or back in `waiting`.
    installing: usize,
    next: u64,
    backlog: usize,
    closed: bool,
    /// The connects waiting for a slot, in arrival order.
    pending: connect::PendingConnects,
}

impl Queue {
    /// The slots the queue's connections hold.
    fn occupied(&self) -> usize {
        self.waiting.len() + self.reserved.len() + self.installing
    }
}

struct Queued {
    /// The client's host end: the guest's accepted socket.
    stream: UnixStream,
    /// The client's virtual address, by its [`canonical`] key.
    peer: SocketAddr,
    _charge: HostNetPermit,
}

/// The loopback set: whether the [`canonical`] `address` may hold a
/// listener, or why not. 127.0.0.0/8 and ::1 may; the wildcard and every
/// other address may not.
fn loopback_admits(address: SocketAddr) -> Result<(), LoopbackRefusalReason> {
    match address.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => Err(LoopbackRefusalReason::Wildcard),
        IpAddr::V4(ip) if ip.is_loopback() => Ok(()),
        IpAddr::V6(ip) if ip.is_unspecified() => Err(LoopbackRefusalReason::Wildcard),
        IpAddr::V6(ip) if ip.is_loopback() => Ok(()),
        _ => Err(LoopbackRefusalReason::NotLoopback),
    }
}

/// The registry's key for `address`: an IPv4-mapped IPv6 address is its
/// IPv4 address, and no scope or flow label names another endpoint.
fn canonical(address: SocketAddr) -> SocketAddr {
    let ip = match address.ip() {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        ip => ip,
    };
    SocketAddr::new(ip, address.port())
}

/// The address a socket of `family` shows for the key `address`: an
/// AF_INET6 socket shows an IPv4 address in its mapped form.
fn presented(address: SocketAddr, family: i32) -> SocketAddr {
    match address.ip() {
        IpAddr::V4(ip) if family == libc::AF_INET6 => {
            SocketAddr::new(IpAddr::V6(ip.to_ipv6_mapped()), address.port())
        }
        _ => address,
    }
}

/// Whether `named`, as the guest named it, is an IPv4-mapped address.
fn mapped(named: SocketAddr) -> bool {
    matches!(named.ip(), IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some())
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
/// before any connect. Port 0 takes a free virtual port. An IPv4-mapped
/// address binds its IPv4 address, unless the socket has IPV6_V6ONLY:
/// then it is `EINVAL`, as on Linux.
pub(super) fn bind(state: &State, id: u64, address: SocketAddr) -> io::Result<wire::Reply> {
    let socket = get(state, id)?;
    // The address alone: no flow label or scope names another listener.
    let named = SocketAddr::new(address.ip(), address.port());
    if socket.kind == libc::SOCK_DGRAM {
        let reason = LoopbackRefusalReason::Datagram;
        return Ok(refuse(state, LoopbackOperation::Bind, named, reason));
    }
    if named.is_ipv6() != (socket.family == libc::AF_INET6) {
        return Err(errno(libc::EAFNOSUPPORT));
    }
    if mapped(named) && socket.ipv6_only.load(Ordering::Acquire) {
        return Err(errno(libc::EINVAL));
    }
    let key = canonical(named);
    if let Err(reason) = loopback_admits(key) {
        return Ok(refuse(state, LoopbackOperation::Bind, named, reason));
    }
    let mut registry = state.loopback.lock().map_err(|_| poisoned())?;
    let connected = socket.stream.lock().map_err(|_| poisoned())?.is_none();
    // Looked at again under the registry's lock, which a setsockopt of
    // IPV6_V6ONLY also holds ([`set_option`]).
    let v6_only_mapped = mapped(named) && socket.ipv6_only.load(Ordering::Acquire);
    if connected
        || v6_only_mapped
        || registry.local.contains_key(&id)
        || socket.connecting.load(Ordering::Acquire)
    {
        return Err(errno(libc::EINVAL));
    }
    let key = if key.port() == 0 {
        registry
            .free(key.ip())
            .ok_or_else(|| errno(libc::EADDRINUSE))?
    } else if registry.bound.contains_key(&key) {
        return Err(errno(libc::EADDRINUSE));
    } else {
        key
    };
    registry.bound.insert(key, id);
    registry.local.insert(id, key);
    Ok(wire::Reply::default())
}

/// A listen on a socket that holds a loopback bind. A listen with no bind
/// would take the wildcard: it is refused. The listener takes the socket's
/// copy of its guest end, with that copy's room on the host floor. A
/// repeated listen sets the backlog again: a larger one may let waiting
/// connects in.
pub(super) fn listen(state: &State, id: u64, backlog: i32) -> io::Result<wire::Reply> {
    let socket = get(state, id)?;
    let backlog = usize::try_from(backlog)
        .unwrap_or(0)
        .clamp(1, LOOPBACK_BACKLOG);
    let unbound = {
        let mut registry = state.loopback.lock().map_err(|_| poisoned())?;
        if let Some(listener) = registry.listeners.get(&id) {
            listener.queue.lock().map_err(|_| poisoned())?.backlog = backlog;
            listener.space.notify_all();
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
            _ if socket.connecting.load(Ordering::Acquire) => return Err(errno(libc::EINVAL)),
            (true, None) => true,
            (true, Some(address)) => {
                let control = socket
                    .control
                    .lock()
                    .map_err(|_| poisoned())?
                    .take()
                    .ok_or_else(|| errno(libc::EBADF))?;
                let host = host.take().ok_or_else(|| errno(libc::EINVAL))?;
                let queue = Queue {
                    backlog,
                    ..Queue::default()
                };
                let listener = Listener {
                    address,
                    family: socket.family,
                    ipv6_only: socket.ipv6_only.load(Ordering::Acquire),
                    control,
                    host,
                    queue: Mutex::new(queue),
                    ready: Condvar::new(),
                    space: Condvar::new(),
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
/// with its peer address as the listener's family shows it. A listener in
/// nonblocking mode answers `EAGAIN` on an empty queue; a blocking one
/// waits until `waiting` (the call), the listener or the session ends.
pub(super) fn accept(
    state: &State,
    id: u64,
    waiting: impl Fn() -> bool,
) -> io::Result<wire::Reply> {
    let Some(listener) = listening(state, id)? else {
        let family = get(state, id)?.family;
        let address = local(state, id, family).unwrap_or_else(|| wildcard(family));
        let reason = LoopbackRefusalReason::NotListening;
        return Ok(refuse(state, LoopbackOperation::Accept, address, reason));
    };
    let nonblocking = listener.control.nonblocking();
    let mut queue = listener.queue.lock().map_err(|_| poisoned())?;
    loop {
        if let Some(queued) = queue.waiting.pop_front() {
            listener.untoken();
            queue.next += 1;
            let ticket = queue.next;
            let peer = presented(queued.peer, listener.family);
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
            .wait_timeout(queue, BLOCKED_CALL_POLL)
            .map_err(|_| poisoned())?
            .0;
    }
}

/// Installs a reserved connection as the result of the guest's accept,
/// with `flags` (accept4's SOCK_NONBLOCK and SOCK_CLOEXEC), or puts it back
/// first in its queue. Its entry, with its virtual local and peer
/// addresses, exists before the guest holds it. The connection holds its
/// slot until it is installed or back: only an install frees the slot for
/// a waiting connect.
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
    let queued = {
        let mut queue = listener.queue.lock().map_err(|_| poisoned())?;
        let queued = queue
            .reserved
            .remove(&ticket)
            .ok_or_else(|| errno(libc::ECONNABORTED))?;
        queue.installing += 1;
        queued
    };
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
        target: Mutex::new(Some(presented(queued.peer, listener.family))),
        stream: Mutex::new(None),
        datagram: None,
        control: Mutex::new(None),
        ipv6_only: AtomicBool::new(listener.ipv6_only),
        connecting: AtomicBool::new(false),
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
        Ok(fd) => {
            listener.installed();
            Ok(wire::Reply {
                value: i64::from(fd),
                ..Default::default()
            })
        }
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

/// A stream connect to a loopback `target`, an IPv4-mapped one included. A
/// listener of this session at `target` queues the client's host end for
/// its accept once a slot is free and the connect's turn has come
/// ([`connect::enqueue`]), and the client is connected; with none there,
/// the connect is refused (`ECONNREFUSED`), except on port 53, whose DNS
/// goes on as before. `None` is every connect that goes on as before: any
/// other target, port 53 with no listener, and a socket already connected.
/// `waiting` is whether the call still waits for its answer.
pub(super) fn connect(
    state: &State,
    id: u64,
    socket: &Socket,
    target: SocketAddr,
    waiting: impl Fn() -> bool,
) -> Option<io::Result<wire::Reply>> {
    let named = SocketAddr::new(target.ip(), target.port());
    let key = canonical(named);
    if !key.ip().is_loopback() {
        return None;
    }
    if named.is_ipv6() != (socket.family == libc::AF_INET6) {
        return Some(Err(errno(libc::EAFNOSUPPORT)));
    }
    // A v6-only socket reaches no IPv4 address, as on Linux.
    if mapped(named) && socket.ipv6_only.load(Ordering::Acquire) {
        return Some(Err(errno(libc::ENETUNREACH)));
    }
    let found = state.loopback.lock().map(|mut registry| {
        let listener = registry
            .bound
            .get(&key)
            .and_then(|holder| registry.listeners.get(holder))
            .cloned()?;
        let own = registry.local.get(&id).copied();
        let own = own.or_else(|| registry.free(key.ip()))?;
        Some((listener, own))
    });
    match found {
        Err(_) => Some(Err(poisoned())),
        // A client bound to ::1 reaches no IPv4 listener.
        Ok(Some((_, own))) if own.is_ipv4() != key.is_ipv4() => Some(Err(errno(libc::EINVAL))),
        Ok(Some((listener, own))) => {
            let target = presented(key, socket.family);
            let enqueued = connect::enqueue(state, id, socket, &listener, own, target, waiting);
            Some(enqueued)
        }
        Ok(None) if key.port() == 53 => None,
        // A socket already connected answers as it always did.
        Ok(None) if !socket.stream.lock().is_ok_and(|peer| peer.is_some()) => None,
        Ok(None) => {
            let reason = LoopbackRefusalReason::NoListener;
            let reply = refuse(state, LoopbackOperation::Connect, named, reason);
            Some(Ok(reply))
        }
    }
}

/// The virtual local address of socket `id`, of `family`, when it has one:
/// getsockname answers it.
pub(super) fn local(state: &State, id: u64, family: i32) -> Option<SocketAddr> {
    let key = state.loopback.lock().ok()?.local.get(&id).copied()?;
    Some(presented(key, family))
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
                self.control.as_raw_fd(),
                byte.as_mut_ptr().cast(),
                1,
                libc::MSG_DONTWAIT,
            )
        };
    }

    /// Puts a connection a finish took back first in the queue, with its
    /// token. It held its slot throughout. A closed listener drops it, and
    /// its client reads the end.
    fn requeue(&self, queued: Queued) -> io::Result<()> {
        let mut queue = self.queue.lock().map_err(|_| poisoned())?;
        queue.installing = queue.installing.saturating_sub(1);
        if !queue.closed {
            self.token();
            queue.waiting.push_front(queued);
            self.ready.notify_one();
        }
        Ok(())
    }

    /// An accept installed a connection: its slot is free for the connect
    /// whose turn it is.
    fn installed(&self) {
        if let Ok(mut queue) = self.queue.lock() {
            queue.installing = queue.installing.saturating_sub(1);
        }
        self.space.notify_all();
    }

    /// Ends the listener: its queued connections close, and its waits end.
    fn close(&self) {
        if let Ok(mut queue) = self.queue.lock() {
            queue.closed = true;
            queue.waiting.clear();
            queue.reserved.clear();
        }
        self.ready.notify_all();
        self.space.notify_all();
    }
}
