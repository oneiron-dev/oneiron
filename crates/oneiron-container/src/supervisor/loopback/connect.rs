//! A connect to a full listener queue waits its turn (FIX 6785; the
//! blocking half of FIX 8015).
//!
//! Each connect to a virtual listener takes a ticket in the listener's line
//! of pending connects ([`PendingConnects`]). The line is apart from the
//! accept queue and the accepts' reservations, and counts in no backlog.
//! Only the line's head may take a free slot, so no later connect overtakes
//! an earlier one. The client's host end stays in its socket entry while it
//! waits, charged as the entry: the queued connection's own room on the
//! host floor is taken only with its slot.
//!
//! A blocking connect that finds the queue full waits in the request worker
//! that already carries its call, and holds no lock while it waits. It
//! looks again when an accept installs a connection, the head leaves the
//! line, the backlog grows or the listener closes, and every
//! [`BLOCKED_CALL_POLL`] for its call, its socket and the session.
//!
//! The wait ends at the deadline the socket's send timeout (`SO_SNDTIMEO`)
//! sets when the call starts; zero is no deadline. Linux answers
//! `EINPROGRESS` at that deadline and keeps the connect pending. This fence
//! keeps no pending connect yet: it withdraws the connect and answers
//! `EAGAIN`. A nonblocking connect to a full queue also answers `EAGAIN`,
//! never `EINPROGRESS`. Both need the readiness work of FIX 6786 and the
//! rest of FIX 8015.

use super::{BLOCKED_CALL_POLL, Listener, QUEUED, Queued, errno, poisoned};
use crate::supervisor::{Socket, State};
use crate::wire;
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Instant;

/// The connects waiting for a slot on one listener's queue, by ticket,
/// oldest first.
#[derive(Default)]
pub(super) struct PendingConnects {
    tickets: VecDeque<u64>,
    next: u64,
}

impl PendingConnects {
    /// A new ticket at the end of the line.
    fn join(&mut self) -> u64 {
        self.next += 1;
        self.tickets.push_back(self.next);
        self.next
    }

    /// Whether `ticket` is the head of the line.
    fn heads(&self, ticket: u64) -> bool {
        self.tickets.front() == Some(&ticket)
    }

    /// Takes `ticket` out of the line: whether it was the head.
    fn leave(&mut self, ticket: u64) -> bool {
        let head = self.heads(ticket);
        self.tickets.retain(|held| *held != ticket);
        head
    }
}

/// The one connect in progress on a socket. Dropping it ends it.
pub(in crate::supervisor) struct Connecting<'a>(&'a Socket);

impl<'a> Connecting<'a> {
    /// Marks a connect in progress on `socket`: `None` if one already is.
    pub(in crate::supervisor) fn begin(socket: &'a Socket) -> Option<Self> {
        // Built only when this call set the flag: a guard built and dropped
        // for a refused call would clear the flag of the connect in progress.
        (!socket.connecting.swap(true, Ordering::AcqRel)).then(|| Self(socket))
    }
}

impl Drop for Connecting<'_> {
    fn drop(&mut self) {
        self.0.connecting.store(false, Ordering::Release);
    }
}

/// A connect's ticket in its listener's line. Dropping it leaves the line;
/// a head that leaves wakes the connects behind it.
struct Ticket<'a> {
    listener: &'a Listener,
    number: u64,
}

impl Drop for Ticket<'_> {
    fn drop(&mut self) {
        if let Ok(mut queue) = self.listener.queue.lock()
            && queue.pending.leave(self.number)
        {
            self.listener.space.notify_all();
        }
    }
}

/// Queues the client's host end on `listener`, with its token, once the
/// connect's turn has come and a slot is free. `own` is the client's own
/// virtual address (a key), and `target` the address getpeername answers.
/// A nonblocking connect looks once. A blocking one waits while `waiting`
/// (the call), its socket, the listener and the session hold, until its
/// deadline; each look checks them before it takes a slot. A connected
/// client drops its copy of its guest end.
pub(super) fn enqueue(
    state: &State,
    id: u64,
    socket: &Socket,
    listener: &Listener,
    own: SocketAddr,
    target: SocketAddr,
    waiting: impl Fn() -> bool,
) -> io::Result<wire::Reply> {
    let (nonblocking, deadline) = socket.connect_mode()?;
    let number = listener
        .queue
        .lock()
        .map_err(|_| poisoned())?
        .pending
        .join();
    let ticket = Ticket { listener, number };
    loop {
        // A call that ended, a socket the guest let go and a session that
        // ended take no slot, so no queued connection outlives its caller.
        if !state.alive.load(Ordering::Acquire)
            || socket.closed.load(Ordering::Acquire)
            || !waiting()
        {
            return Err(errno(libc::EINTR));
        }
        let mut peer = socket.stream.lock().map_err(|_| poisoned())?;
        if peer.is_none() {
            return Err(errno(libc::EISCONN));
        }
        let mut queue = listener.queue.lock().map_err(|_| poisoned())?;
        if queue.closed {
            return Err(errno(libc::ECONNREFUSED));
        }
        if queue.pending.heads(number) && queue.occupied() < queue.backlog {
            let (fds, workers) = QUEUED;
            let charge = state.relay.host_net_floor().acquire(fds, workers)?;
            let stream = peer.take().ok_or_else(|| errno(libc::EISCONN))?;
            listener.token();
            queue.waiting.push_back(Queued {
                stream,
                peer: own,
                _charge: charge,
            });
            listener.ready.notify_one();
            queue.pending.leave(number);
            // The next connect in line may find a slot too.
            listener.space.notify_all();
            break;
        }
        drop(peer);
        let now = Instant::now();
        if nonblocking || deadline.is_some_and(|deadline| now >= deadline) {
            return Err(errno(libc::EAGAIN));
        }
        let pause = deadline.map_or(BLOCKED_CALL_POLL, |deadline| {
            deadline
                .saturating_duration_since(now)
                .min(BLOCKED_CALL_POLL)
        });
        // The socket's lock comes before the queue's: let both go.
        let (queue, _) = listener
            .space
            .wait_timeout(queue, pause)
            .map_err(|_| poisoned())?;
        drop(queue);
    }
    drop(ticket);
    *socket.target.lock().map_err(|_| poisoned())? = Some(target);
    state
        .loopback
        .lock()
        .map_err(|_| poisoned())?
        .local
        .insert(id, own);
    socket.release_control();
    Ok(wire::Reply::default())
}
