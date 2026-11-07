//! A guest stream's relay to its remote, and its relay to the host's DNS
//! (FIX 6301).
//!
//! A relay charges its host work to the host floor before any of it starts.
//! This room is beside the room the socket's entry holds for its host end
//! ([`super::lifetime::STREAM_ENTRY`]). A stream to a remote takes its room
//! before the relay connects: the remote socket, the copies of it and of the
//! host end, and the download and upload threads ([`REMOTE_STREAM`]). A gated
//! stream also holds its name gate's DNS socket until the gate passes
//! ([`NAME_GATE`]). A
//! stream to DNS takes its one thread ([`DNS_RELAY`]). Each of its exchanges
//! then takes the transport's one socket inside that thread
//! ([`super::relay_workers::reserve`]).
//!
//! A full floor answers the guest's connect `EAGAIN` naming the floor. The
//! entry stays as it was, so the guest can connect again. A thread the host
//! cannot start is the worker floor's back-pressure in the same way: each
//! relay thread starts, parked, before the guest's end leaves its entry. A
//! socket copy that fails fails the connect. So no connect is answered whose
//! relay did not start.
//!
//! A relay holds its socket's entry until its threads end. So an entry that
//! two inventories missed gives its room back only once the relay no longer
//! uses its host end. The download thread joins the upload thread before the
//! stream's room goes back.
//!
//! While the floor is full, a DNS query waits in its relay's thread, as a
//! datagram writer's relay does. The guest's next query waits in its socket.
//! No query is dropped, and nothing else waits.

use super::{Socket, State, relay_workers};
use crate::{EgressRelay, HOST_NET_WORKER_FLOOR, HostNetPermit, floor_saturated};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SendError, SyncSender};
use std::thread::JoinHandle;
use std::time::Duration;

/// What a stream to a remote holds of the host floor besides its entry, as
/// (descriptors, workers): the remote socket, its copy and the copy of the
/// entry's host end, and the download and upload threads.
const REMOTE_STREAM: (usize, usize) = (3, 2);
/// What a stream to DNS holds of the host floor besides its entry: its one
/// thread. Each exchange takes its transport's socket when it starts.
const DNS_RELAY: (usize, usize) = (0, 1);
/// What a gated stream holds besides [`REMOTE_STREAM`] while its name gate
/// reads the opening: the transport socket the gate's DNS refresh may open
/// (review P1 #5938).
const NAME_GATE: (usize, usize) = (1, 0);
/// How long a relay's read waits before it looks at the session again: a
/// cadence, not a bound.
const READ_POLL: Duration = Duration::from_millis(250);

/// A relay thread that started before its work: it waits for what its job
/// owns, and ends without the job when its handoff is dropped unsent.
struct Parked<T> {
    handoff: SyncSender<T>,
    thread: JoinHandle<()>,
}

/// Starts a thread for `job`, parked until its handoff. A thread the host
/// cannot start is the worker floor's back-pressure, as a datagram worker's
/// is.
fn park<T: Send + 'static>(job: impl FnOnce(T) + Send + 'static) -> io::Result<Parked<T>> {
    let (handoff, work) = mpsc::sync_channel(1);
    let thread = std::thread::Builder::new()
        .spawn(move || {
            if let Ok(owned) = work.recv() {
                job(owned);
            }
        })
        .map_err(|_| floor_saturated(HOST_NET_WORKER_FLOOR))?;
    Ok(Parked { handoff, thread })
}

/// What a stream's download thread owns: all the stream holds, and the
/// parked upload thread it gives the guest's end and the remote to.
struct RemoteStream {
    /// The entry's host end, which the upload thread reads.
    guest: UnixStream,
    /// The remote socket, which the upload thread writes.
    remote: TcpStream,
    incoming: TcpStream,
    outgoing: UnixStream,
    upload: Parked<(UnixStream, TcpStream)>,
    target: SocketAddr,
    state: Arc<State>,
    entry: Arc<Socket>,
    room: HostNetPermit,
}

/// Connects socket `entry`'s stream to `target`, and starts its relay. The
/// relay's room is taken before the relay connects. Both relay threads start
/// before the guest's end leaves `peer`, its entry's.
///
/// # Errors
/// A full floor, or a thread the host cannot start, is `WouldBlock` naming
/// the floor, with the entry as it was. The relay's refusal, and a failed
/// connect or socket copy, fail the connect as they are.
pub(super) fn connect_remote(
    state: &Arc<State>,
    entry: &Arc<Socket>,
    peer: &mut Option<UnixStream>,
    target: SocketAddr,
) -> io::Result<()> {
    let (fds, workers) = REMOTE_STREAM;
    let room = state.relay.host_net_floor().acquire(fds, workers)?;
    let host = peer
        .as_ref()
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EISCONN))?;
    let (remote, gated) = state.relay.connect_stream(target)?;
    // A gated stream's name gate may refresh its DNS binding before the
    // opening reaches the remote: it takes that socket's room now, and holds
    // it until the gate has passed.
    let (gate_fds, gate_workers) = NAME_GATE;
    let gate = gated
        .then(|| state.relay.host_net_floor().acquire(gate_fds, gate_workers))
        .transpose()?;
    let incoming = remote.try_clone()?;
    let outgoing = host.try_clone()?;
    incoming.set_read_timeout(Some(READ_POLL))?;
    let (alive, relay) = (Arc::clone(&state.alive), Arc::clone(&state.relay));
    let upload = park(move |(guest, remote): (UnixStream, TcpStream)| {
        relay_upload(guest, remote, target, gate, &*relay, &alive);
    })?;
    let download = park(RemoteStream::download)?;
    let guest = peer
        .take()
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EISCONN))?;
    let stream = RemoteStream {
        guest,
        remote,
        incoming,
        outgoing,
        upload,
        target,
        state: Arc::clone(state),
        entry: Arc::clone(entry),
        room,
    };
    // A parked thread that ended unhanded is one the host could not start.
    download.handoff.send(stream).map_err(|SendError(stream)| {
        *peer = Some(stream.guest);
        floor_saturated(HOST_NET_WORKER_FLOOR)
    })
}

impl RemoteStream {
    /// Gives the upload thread its part, relays the remote's bytes to the
    /// guest, and gives the stream's room and entry back once both threads
    /// ended.
    fn download(self) {
        let Self {
            guest,
            remote,
            mut incoming,
            mut outgoing,
            upload,
            target,
            state,
            entry,
            room,
        } = self;
        // A parked thread takes its handoff: it waits for nothing else.
        if upload.handoff.send((guest, remote)).is_err() {
            return;
        }
        let mut hash = blake3::Hasher::new();
        let mut total = 0;
        let mut bytes = [0; 32768];
        while state.alive.load(Ordering::Acquire) {
            match incoming.read(&mut bytes) {
                Ok(0) => break,
                Ok(n) => {
                    hash.update(&bytes[..n]);
                    total += n as u64;
                    if outgoing.write_all(&bytes[..n]).is_err() {
                        break;
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(_) => break,
            }
        }
        let _ = incoming.shutdown(Shutdown::Both);
        let _ = outgoing.shutdown(Shutdown::Both);
        let _ = upload.thread.join();
        state
            .relay
            .transferred(target, *hash.finalize().as_bytes(), total);
        // The descriptors close before their room and their entry go back.
        drop((incoming, outgoing));
        drop(room);
        drop(entry);
    }
}

/// Relays the guest's bytes to the remote. A gated stream's opening bytes
/// pass the relay's name gate after the guest's connect was answered and
/// before any reaches the remote; a refused one ends with nothing sent
/// (FIX 7652). `gate` is the room the gate's DNS refresh takes
/// ([`NAME_GATE`]); it goes back once the gate has passed.
fn relay_upload(
    mut guest: UnixStream,
    mut remote: TcpStream,
    target: SocketAddr,
    gate: Option<HostNetPermit>,
    relay: &dyn EgressRelay,
    alive: &AtomicBool,
) {
    // The host end takes its read timeout only here, once it has left its
    // entry: a connect that failed leaves the end as the guest made it.
    let _ = guest.set_read_timeout(Some(READ_POLL));
    if let Some(gate) = gate {
        let opening = relay.open_upload(target, &mut guest, alive);
        drop(gate);
        if opening.and_then(|bytes| remote.write_all(&bytes)).is_err() {
            let _ = remote.shutdown(Shutdown::Both);
            return;
        }
    }
    let mut bytes = [0; 32768];
    while alive.load(Ordering::Acquire) {
        match guest.read(&mut bytes) {
            Ok(0) => break,
            Ok(n) => {
                if remote.write_all(&bytes[..n]).is_err() {
                    break;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(_) => break,
        }
    }
    let _ = remote.shutdown(Shutdown::Write);
}

/// What a stream's DNS relay thread owns: the entry's host end, and the
/// entry and room it holds until the thread ends.
struct DnsStream {
    guest: UnixStream,
    target: SocketAddr,
    state: Arc<State>,
    entry: Arc<Socket>,
    room: HostNetPermit,
}

/// Connects socket `entry`'s stream to the DNS at `target`, and starts its
/// relay. The relay's thread takes its room and starts, parked, before the
/// guest's end leaves `peer`, its entry's.
///
/// # Errors
/// A full floor, or a thread the host cannot start, is `WouldBlock` naming
/// the floor, with the entry as it was. The relay's refusal fails the
/// connect as it is.
pub(super) fn connect_dns(
    state: &Arc<State>,
    entry: &Arc<Socket>,
    peer: &mut Option<UnixStream>,
    target: SocketAddr,
) -> io::Result<()> {
    let (fds, workers) = DNS_RELAY;
    let room = state.relay.host_net_floor().acquire(fds, workers)?;
    state.relay.authorize_datagram(target)?;
    let parked = park(DnsStream::answer_queries)?;
    let guest = peer
        .take()
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EISCONN))?;
    let stream = DnsStream {
        guest,
        target,
        state: Arc::clone(state),
        entry: Arc::clone(entry),
        room,
    };
    // A parked thread that ended unhanded is one the host could not start.
    parked.handoff.send(stream).map_err(|SendError(stream)| {
        *peer = Some(stream.guest);
        floor_saturated(HOST_NET_WORKER_FLOOR)
    })
}

impl DnsStream {
    /// Answers the guest's length-prefixed queries in turn. Each exchange
    /// holds its transport's socket on the host floor while it lasts; while
    /// the floor is full, the query waits for it here.
    fn answer_queries(self) {
        let Self {
            mut guest,
            target,
            state,
            entry,
            room,
        } = self;
        while state.alive.load(Ordering::Acquire) {
            let mut len = [0; 2];
            if guest.read_exact(&mut len).is_err() {
                break;
            }
            let mut query = vec![0; u16::from_be_bytes(len) as usize];
            if guest.read_exact(&mut query).is_err() {
                break;
            }
            let answered = relay_workers::reserve(&state, &entry)
                .map(|_exchange| state.relay.datagram(target, &query));
            let Some(Ok(answer)) = answered else {
                break;
            };
            if guest
                .write_all(&(answer.len() as u16).to_be_bytes())
                .and_then(|()| guest.write_all(&answer))
                .is_err()
            {
                break;
            }
        }
        let _ = guest.shutdown(Shutdown::Both);
        // The host end closes before its thread's room and its entry go back.
        drop(guest);
        drop(room);
        drop(entry);
    }
}
