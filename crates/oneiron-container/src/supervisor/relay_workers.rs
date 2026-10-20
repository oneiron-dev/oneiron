//! Bounded relay workers for a guest's datagrams (FIX 5979).
//!
//! A relayed datagram takes its room on the host floor before anything
//! starts for it and before the guest's send is acknowledged: the relay's
//! own UDP socket and the worker that waits for its answer ([`SEND`]). The
//! worker holds that room until the relay's blocking receive has ended,
//! whatever became of the session or the socket meanwhile, so no room comes
//! back while a receive still blocks. At low load nothing waits for an
//! answer: the send is acknowledged once its worker has started.
//!
//! A full floor back-pressures the guest. A blocking send waits for room in
//! the request thread that already carries it (one per guest task blocked in
//! a call, never a queue of its own); a send that asked not to wait, or on a
//! socket in nonblocking mode, fails with `EAGAIN` naming the floor.
//!
//! A socket's writer relays what the guest writes without a send call. It
//! is its socket entry's worker, charged with the entry, so before each
//! relay it takes only the relay's socket ([`WRITER`]), waiting for it while
//! the floor is full; the guest's next writes wait in its socket meanwhile.

use super::{Socket, State};
use crate::{HOST_NET_WORKER_FLOOR, HostNetPermit, floor_saturated, saturated_floor, wire};
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// What one relayed datagram holds of the host floor until its receive
/// ends, as (descriptors, workers): the relay's UDP socket, and the worker
/// that waits on it.
const SEND: (usize, usize) = (1, 1);
/// What one of a writer's relays holds, as (descriptors, workers): the
/// relay's UDP socket. The writer itself is charged with its socket entry.
const WRITER: (usize, usize) = (1, 0);
/// How long a waiting send or writer sleeps before it looks at the floor
/// again: a cadence, not a bound.
const FLOOR_RETRY: Duration = Duration::from_millis(10);

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
                        let _ = host.send(&answer);
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

/// Room for one of a writer's relays, waited for while the floor is full;
/// `None` once the session or the socket has ended, or the floor failed.
pub(super) fn reserve(state: &State, socket: &Socket) -> Option<HostNetPermit> {
    let (fds, workers) = WRITER;
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
