//! Bounded relay workers for a guest's datagrams (FIX 5979).
//!
//! A relayed datagram takes its room on the host floor before anything
//! starts for it and before the guest's send is acknowledged: the relay's
//! own UDP socket and the worker that waits for its answer ([`SEND`]). The
//! worker holds that room until the relay's blocking receive has ended,
//! whatever became of the session or the socket meanwhile, so no room comes
//! back while a receive still blocks. At low load nothing waits for an
//! answer: the send is acknowledged once its worker has started. An answer
//! the guest's socket has no room for waits only while the session and the
//! socket live ([`deliver`], FIX 8016).
//!
//! A full floor back-pressures the guest. A blocking send waits for room in
//! the request thread that already carries it (one per guest task blocked in
//! a call, never a queue of its own); a send that asked not to wait, or on a
//! socket in nonblocking mode, fails with `EAGAIN` naming the floor.
//!
//! A socket's writer relays what the guest writes without a send call. It
//! is its socket entry's worker, charged with the entry, so before each
//! relay it takes only the relay's socket ([`EXCHANGE`]), waiting for it
//! while the floor is full; the guest's next writes wait in its socket
//! meanwhile. A stream's DNS relay takes each exchange's socket the same
//! way: its thread is charged with its connect (FIX 6301).

use super::{Socket, State};
use crate::{HOST_NET_WORKER_FLOOR, HostNetPermit, floor_saturated, saturated_floor, wire};
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// What one relayed datagram holds of the host floor until its receive
/// ends, as (descriptors, workers): the relay's UDP socket, and the worker
/// that waits on it.
const SEND: (usize, usize) = (1, 1);
/// What one exchange of an already charged worker holds, as (descriptors,
/// workers): its transport's one socket. A writer is charged with its socket
/// entry, a stream's DNS relay with its connect (FIX 6301).
const EXCHANGE: (usize, usize) = (1, 0);
/// How long a waiting send or writer sleeps before it looks at the floor
/// again: a cadence, not a bound.
const FLOOR_RETRY: Duration = Duration::from_millis(10);
/// How long an answer waiting for room in the guest's socket sleeps before
/// it tries again: a cadence, not a bound.
const DELIVERY_RETRY: Duration = Duration::from_millis(10);

/// Relays `bytes` to `target` on a worker of its own, which hands the answer
/// to `socket`. Returns once the worker has started; while the floor is
/// full, a blocking send waits as long as `waiting` and the socket hold.
pub(super) fn send(
    state: &Arc<State>,
    socket: &Arc<Socket>,
    target: SocketAddr,
    bytes: &[u8],
    dontwait: bool,
    waiting: impl Fn() -> bool,
) -> io::Result<()> {
    let nonblocking = dontwait || in_nonblocking_mode(socket);
    let (fds, workers) = SEND;
    loop {
        let started = state
            .relay
            .host_net_floor()
            .acquire(fds, workers)
            .and_then(|permit| {
                let (state, socket, bytes) =
                    (Arc::clone(state), Arc::clone(socket), bytes.to_vec());
                start(permit, move || {
                    if let Ok(answer) = state.relay.datagram(target, &bytes)
                        && let Some((_, host)) = &socket.datagram
                    {
                        deliver(&state, &socket, host, &answer);
                    }
                })
            });
        match started {
            Err(error)
                if !nonblocking
                    && saturated_floor(&error).is_some()
                    && waiting()
                    && live(state, socket) =>
            {
                std::thread::sleep(FLOOR_RETRY);
            }
            started => return started,
        }
    }
}

/// Room for one exchange of a writer or a stream's DNS relay, waited for
/// while the floor is full; `None` once the session or the socket has
/// ended, or the floor failed.
pub(super) fn reserve(state: &State, socket: &Socket) -> Option<HostNetPermit> {
    let (fds, workers) = EXCHANGE;
    loop {
        match state.relay.host_net_floor().acquire(fds, workers) {
            Ok(permit) => return Some(permit),
            Err(error) if saturated_floor(&error).is_some() && live(state, socket) => {
                std::thread::sleep(FLOOR_RETRY);
            }
            Err(_) => return None,
        }
    }
}

/// Hands `answer` to the guest through `host`, its socket's host end (FIX
/// 8016). A guest whose socket has no room makes the answer wait, but only
/// while the session and the socket live: a guest that never reads frees
/// the worker, its descriptors and its room once either ends. Any other
/// send failure drops the answer, as a lost datagram.
pub(super) fn deliver(state: &State, socket: &Socket, host: &UnixDatagram, answer: &[u8]) {
    loop {
        // SAFETY: `send` reads `answer.len()` bytes from `answer`, a live
        // buffer, on `host`'s live descriptor; MSG_DONTWAIT makes it return
        // instead of blocking, without changing the descriptor's own mode.
        let sent = unsafe {
            libc::send(
                host.as_raw_fd(),
                answer.as_ptr().cast(),
                answer.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if sent >= 0 {
            return;
        }
        match io::Error::last_os_error().kind() {
            io::ErrorKind::Interrupted => continue,
            io::ErrorKind::WouldBlock if live(state, socket) => std::thread::sleep(DELIVERY_RETRY),
            _ => return,
        }
    }
}

/// The reply to a call that failed. A floor's back-pressure is `EAGAIN`,
/// carrying the floor's name.
pub(super) fn failed(id: u64, error: &io::Error) -> wire::Reply {
    let floor = saturated_floor(error);
    wire::Reply {
        id,
        errno: match floor {
            Some(_) => libc::EAGAIN,
            None => error.raw_os_error().unwrap_or(libc::EIO),
        },
        floor: floor.map(str::to_owned),
        ..Default::default()
    }
}

/// Starts `job` on a thread that holds `permit` until the job has returned.
/// A thread the host cannot start is the worker floor's back-pressure; its
/// room goes back with the job.
fn start(permit: HostNetPermit, job: impl FnOnce() + Send + 'static) -> io::Result<()> {
    let worker = std::thread::Builder::new().spawn(move || {
        job();
        drop(permit);
    });
    match worker {
        Ok(_detached) => Ok(()),
        Err(_) => Err(floor_saturated(HOST_NET_WORKER_FLOOR)),
    }
}

fn live(state: &State, socket: &Socket) -> bool {
    state.alive.load(Ordering::Acquire) && !socket.closed.load(Ordering::Acquire)
}

/// Whether the guest's datagram socket is in nonblocking mode. The host's
/// copy of the guest's end shares its open file description, and with it
/// the mode the guest set.
fn in_nonblocking_mode(socket: &Socket) -> bool {
    socket.datagram.as_ref().is_some_and(|(guest, _)| {
        // SAFETY: F_GETFL only reads the status flags of a live descriptor.
        let flags = unsafe { libc::fcntl(guest.as_raw_fd(), libc::F_GETFL) };
        flags >= 0 && flags & libc::O_NONBLOCK != 0
    })
}
