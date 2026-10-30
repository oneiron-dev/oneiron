//! The home's live relay of custody carrier leaf keys (FIX 11785).
//!
//! An executor's request goes to the newest live socket of the machine that
//! holds the key; the holder's answer, sealed to the executor's machine key,
//! or its failure comes back to the executor's newest live socket. The home
//! answers in place a request for a key it holds itself, and offers its own
//! requests to each holder's socket. Everything here is in memory: no payload
//! is written, queued past a live socket, cached or logged. A log line names
//! the tag, the request id, the two machines and the outcome. A request whose
//! holder has no live socket, or whose expiry passed, fails by name and its
//! executor asks again; one answer goes per request id.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron::authority::PeerMachine;
use oneiron::secret_custody::{LeafKeyFailureCause, LeafKeyRequest};
use oneiron::sync::TransportError;
use oneiron::sync::transport::{
    LEAF_KEY_RETRY, TAG_LEAF_KEY_ANSWER, TAG_LEAF_KEY_FAILURE, TAG_LEAF_KEY_REQUEST,
    decode_leaf_key_answer, decode_leaf_key_failure, decode_leaf_key_request,
    encode_leaf_key_answer, encode_leaf_key_failure, encode_leaf_key_request, leaf_key_request_hex,
};
use tokio::sync::mpsc::UnboundedSender;

use super::conn_state::ConnState;
use crate::protocol::{self, ProtocolError};
use crate::server::SyncServer;

/// How often a holder's socket is offered the home's own pending requests
/// (a call, FIX 11785).
pub(super) const LEAF_KEY_TICK: Duration = Duration::from_secs(1);

/// A socket's direct lane: what it is sent there leaves through its guarded
/// door, as every reply does.
type Lane = UnboundedSender<Vec<u8>>;

/// The relay's state on the home: each live socket of a proven machine and
/// the requests between them. In memory only.
#[derive(Default)]
pub(crate) struct LeafKeyRelay {
    state: Mutex<RelayState>,
}

impl LeafKeyRelay {
    fn state(&self) -> MutexGuard<'_, RelayState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[derive(Default)]
struct RelayState {
    /// Rises with each socket registered: the highest is a machine's newest.
    next_seq: u64,
    /// Each live socket of a proven machine, by connection id.
    sockets: HashMap<u32, LiveSocket>,
    /// Requests relayed or answered here and not yet ended, by request id.
    in_flight: HashMap<[u8; 32], InFlight>,
    /// Ids answered, each until its expiry, so a replay is refused.
    completed: HashMap<[u8; 32], u64>,
    /// The home's own requests that failed, each held until it may go again.
    home_retry: HashMap<[u8; 32], Instant>,
}

struct LiveSocket {
    seq: u64,
    machine: EntityId,
    /// The machine as its upgrade proved it, judged again at each send.
    peer: PeerMachine,
    lane: Lane,
}

struct InFlight {
    executor: EntityId,
    holder: EntityId,
    /// The holder's socket the request went to; `None` where the home holds
    /// the key.
    holder_conn: Option<u32>,
    expires_at_ms: u64,
    /// The request itself where the home is its executor: the answer is
    /// taken against it. Never kept for another executor's request.
    home_request: Option<LeafKeyRequest>,
}

/// A live socket a frame goes to.
struct Target {
    peer: PeerMachine,
    lane: Lane,
}

/// What the relay does with a request.
enum Admission {
    /// It is already on its way: nothing more.
    InFlight,
    /// It was answered before.
    Replayed,
    /// Its holder has no live socket.
    HolderOffline,
    /// The home holds the key: answer it here.
    AnswerHere,
    /// Push it to the holder's newest live socket.
    Relay(Target),
}

/// How an answer from a holder ends its request.
enum Answered {
    Delivered(InFlight),
    Expired(InFlight),
}

impl RelayState {
    /// `machine`'s newest live socket.
    fn newest(&self, machine: EntityId) -> Option<(u32, Target)> {
        self.sockets
            .iter()
            .filter(|(_, socket)| socket.machine == machine)
            .max_by_key(|(_, socket)| socket.seq)
            .map(|(conn_id, socket)| {
                let target = Target {
                    peer: socket.peer,
                    lane: socket.lane.clone(),
                };
                (*conn_id, target)
            })
    }

    fn is_newest(&self, conn_id: u32, machine: EntityId) -> bool {
        self.newest(machine)
            .is_some_and(|(newest, _)| newest == conn_id)
    }

    /// Takes request `id` into the relay, `home` being the home's own
    /// machine, after dropping every entry past its expiry. The home's own
    /// request is kept with its entry.
    fn admit(
        &mut self,
        id: [u8; 32],
        request: &LeafKeyRequest,
        home: Option<EntityId>,
        now_ms: u64,
    ) -> Admission {
        self.in_flight
            .retain(|_, entry| entry.expires_at_ms > now_ms);
        self.completed
            .retain(|_, expires_at_ms| *expires_at_ms > now_ms);
        if self.completed.contains_key(&id) {
            return Admission::Replayed;
        }
        if self.in_flight.contains_key(&id) {
            return Admission::InFlight;
        }
        let holder = request.holder_machine();
        let (holder_conn, admission) = if Some(holder) == home {
            (None, Admission::AnswerHere)
        } else {
            let Some((conn_id, target)) = self.newest(holder) else {
                return Admission::HolderOffline;
            };
            (Some(conn_id), Admission::Relay(target))
        };
        self.in_flight.insert(
            id,
            InFlight {
                executor: request.executor_machine(),
                holder,
                holder_conn,
                expires_at_ms: request.expires_at_ms(),
                home_request: (Some(request.executor_machine()) == home).then(|| request.clone()),
            },
        );
        admission
    }

    /// Ends request `id` with the answer `holder` sent for `executor`:
    /// `None` where no such request is on its way.
    fn answer(
        &mut self,
        id: [u8; 32],
        holder: EntityId,
        executor: EntityId,
        now_ms: u64,
    ) -> Option<Answered> {
        let entry = self.in_flight.get(&id)?;
        if entry.holder != holder || entry.executor != executor {
            return None;
        }
        let entry = self.in_flight.remove(&id)?;
        if entry.expires_at_ms <= now_ms {
            return Some(Answered::Expired(entry));
        }
        self.completed.insert(id, entry.expires_at_ms);
        Some(Answered::Delivered(entry))
    }

    /// Ends request `id` with the failure `holder` sent: `None` where no
    /// request of that holder is on its way.
    fn fail(&mut self, id: [u8; 32], holder: EntityId) -> Option<InFlight> {
        if self.in_flight.get(&id)?.holder != holder {
            return None;
        }
        self.in_flight.remove(&id)
    }
}

/// A proven machine's socket in the relay for as long as its connection
/// lives. Dropped, it leaves the relay, and each request relayed to it and
/// still unanswered fails `HolderOffline` back to its executor.
pub(super) struct LeafKeySocket<'s> {
    server: &'s SyncServer,
    conn_id: u32,
}

impl<'s> LeafKeySocket<'s> {
    /// Registers connection `conn_id`, whose direct lane is `lane`, for the
    /// machine its upgrade proved. A socket with no proven machine carries
    /// no leaf key and is not registered.
    pub(super) fn register(
        server: &'s SyncServer,
        conn_id: u32,
        machine: PeerMachine,
        lane: &Lane,
    ) -> Self {
        if let PeerMachine::Proven { machine: id, .. } = machine {
            let mut state = server.leaf_keys.state();
            state.next_seq += 1;
            let seq = state.next_seq;
            state.sockets.insert(
                conn_id,
                LiveSocket {
                    seq,
                    machine: id,
                    peer: machine,
                    lane: lane.clone(),
                },
            );
        }
        Self { server, conn_id }
    }
}

impl Drop for LeafKeySocket<'_> {
    fn drop(&mut self) {
        let conn_id = self.conn_id;
        let mut state = self.server.leaf_keys.state();
        if state.sockets.remove(&conn_id).is_none() {
            return;
        }
        let orphaned: Vec<([u8; 32], InFlight)> = state
            .in_flight
            .extract_if(|_, entry| entry.holder_conn == Some(conn_id))
            .collect();
        drop(state);
        if orphaned.is_empty() {
            return;
        }
        let home = home_machine(self.server);
        for (id, entry) in orphaned {
            fail_executor(
                self.server,
                home,
                id,
                &entry,
                &LeafKeyFailureCause::HolderOffline,
            );
        }
    }
}

/// Who asked: an executor's socket, failed on its own lane, or the home,
/// failed in its own vault.
enum Asker<'a> {
    Socket { peer: PeerMachine, lane: &'a Lane },
    Home,
}

/// One leaf-key frame from this socket, `tag` and the bytes after it. A frame
/// from a socket with no proven machine, or one its machine may not send, is
/// dropped and logged, and the socket stays up.
///
/// # Errors
///
/// [`ProtocolError::InvalidPayload`] for a frame that does not decode.
pub(super) fn handle(
    server: &SyncServer,
    conn_id: u32,
    state: &ConnState,
    tag: u8,
    payload: &[u8],
    direct_tx: &Lane,
) -> Result<(), ProtocolError> {
    let peer = state.peer_machine(server.vault());
    let PeerMachine::Proven { machine, .. } = peer else {
        tracing::warn!(
            conn_id,
            tag,
            outcome = "no_proven_machine",
            "leaf key frame dropped"
        );
        return Ok(());
    };
    let invalid =
        |error: TransportError| ProtocolError::InvalidPayload(protocol::transport_err_msg(error));
    let frame = [&[tag][..], payload].concat();
    let now_ms = crate::owner::stamp::now_unix_ms();
    match tag {
        TAG_LEAF_KEY_REQUEST => {
            let request = decode_leaf_key_request(payload).map_err(invalid)?;
            if request.executor_machine() != machine {
                refused(
                    tag,
                    &request.request_id(),
                    machine,
                    "executor_not_this_machine",
                );
                return Ok(());
            }
            let asker = Asker::Socket {
                peer,
                lane: direct_tx,
            };
            route(
                server,
                &asker,
                &request,
                frame,
                home_machine(server),
                now_ms,
            );
        }
        TAG_LEAF_KEY_ANSWER => {
            let answer = decode_leaf_key_answer(payload).map_err(invalid)?;
            let (id, holder, executor) = (
                answer.request_id(),
                answer.holder_machine(),
                answer.executor_machine(),
            );
            if holder != machine {
                refused(tag, &id, machine, "holder_not_this_machine");
                return Ok(());
            }
            let answered = server
                .leaf_keys
                .state()
                .answer(id, holder, executor, now_ms);
            let home = home_machine(server);
            match answered {
                None => refused(tag, &id, machine, "no_matching_request"),
                Some(Answered::Expired(entry)) => {
                    logged(tag, &id, holder, executor, "expired");
                    fail_executor(server, home, id, &entry, &LeafKeyFailureCause::Expired);
                }
                Some(Answered::Delivered(entry)) if Some(executor) == home => {
                    let accepted = entry
                        .home_request
                        .as_ref()
                        .map(|request| server.vault().accept_leaf_key_answer(request, &answer));
                    let outcome = match accepted {
                        Some(Ok(())) => "accepted_here",
                        Some(Err(_)) => "accept_failed_here",
                        None => "no_request_kept_here",
                    };
                    logged(tag, &id, holder, executor, outcome);
                }
                Some(Answered::Delivered(_)) => {
                    let outcome = if push(server, newest(server, executor), frame) {
                        "relayed"
                    } else {
                        "executor_offline_dropped"
                    };
                    logged(tag, &id, holder, executor, outcome);
                }
            }
        }
        TAG_LEAF_KEY_FAILURE => {
            let (id, cause) = decode_leaf_key_failure(payload).map_err(invalid)?;
            let Some(entry) = server.leaf_keys.state().fail(id, machine) else {
                refused(tag, &id, machine, "no_matching_request");
                return Ok(());
            };
            if Some(entry.executor) == home_machine(server) {
                fail_home(server, id, entry.holder, entry.executor, &cause);
            } else {
                let outcome = if push(server, newest(server, entry.executor), frame) {
                    "relayed"
                } else {
                    "executor_offline_dropped"
                };
                logged(tag, &id, entry.holder, entry.executor, outcome);
            }
        }
        _ => return Err(ProtocolError::UnknownTag(tag)),
    }
    Ok(())
}

/// The home as executor: offers this socket the home's own pending requests
/// whose key its machine holds and which are not on their way, when it is
/// that machine's newest live socket. A failed read is logged and the socket
/// stays up.
pub(super) fn offer_home_requests(server: &SyncServer, conn_id: u32, state: &ConnState) {
    let PeerMachine::Proven { machine, .. } = state.peer_machine(server.vault()) else {
        return;
    };
    if !server.leaf_keys.state().is_newest(conn_id, machine) {
        return;
    }
    let pending = match server.vault().pending_leaf_key_requests() {
        Ok(pending) => pending,
        Err(_) => {
            tracing::warn!(
                conn_id,
                outcome = "pending_read_failed",
                "leaf key offer skipped"
            );
            return;
        }
    };
    let mut held = pending
        .into_iter()
        .filter(|request| request.holder_machine() == machine)
        .peekable();
    if held.peek().is_none() {
        return;
    }
    let home = home_machine(server);
    if home.is_none_or(|home| home == machine) {
        return;
    }
    let now = Instant::now();
    let now_ms = crate::owner::stamp::now_unix_ms();
    for request in held {
        if Some(request.executor_machine()) != home {
            continue;
        }
        let id = request.request_id();
        {
            let mut relay = server.leaf_keys.state();
            relay.home_retry.retain(|_, at| *at > now);
            if relay.home_retry.contains_key(&id) {
                continue;
            }
        }
        let Ok(frame) = encode_leaf_key_request(&request).into_result() else {
            logged(
                TAG_LEAF_KEY_REQUEST,
                &id,
                machine,
                request.executor_machine(),
                "too_large",
            );
            continue;
        };
        route(server, &Asker::Home, &request, frame, home, now_ms);
    }
}

/// Sends `request`, whose frame is `frame`, on to its holder, answers it
/// here where the home holds the key, or fails it to `asker` by name.
fn route(
    server: &SyncServer,
    asker: &Asker<'_>,
    request: &LeafKeyRequest,
    frame: Vec<u8>,
    home: Option<EntityId>,
    now_ms: u64,
) {
    let id = request.request_id();
    let (holder, executor) = (request.holder_machine(), request.executor_machine());
    let tag = TAG_LEAF_KEY_REQUEST;
    let cause = if request.expires_at_ms() <= now_ms {
        LeafKeyFailureCause::Expired
    } else {
        let admission = server.leaf_keys.state().admit(id, request, home, now_ms);
        match admission {
            // The home asks again each tick while its request is on its way.
            Admission::InFlight => {
                if matches!(asker, Asker::Socket { .. }) {
                    logged(tag, &id, holder, executor, "in_flight");
                }
                return;
            }
            Admission::Replayed => LeafKeyFailureCause::Replayed,
            Admission::HolderOffline => LeafKeyFailureCause::HolderOffline,
            Admission::AnswerHere => match asker {
                Asker::Socket { peer, lane } => {
                    return answer_here(server, request, *peer, lane);
                }
                Asker::Home => {
                    server.leaf_keys.state().in_flight.remove(&id);
                    return;
                }
            },
            Admission::Relay(target) => {
                if push(server, Some(target), frame) {
                    return logged(tag, &id, holder, executor, "relayed");
                }
                server.leaf_keys.state().in_flight.remove(&id);
                LeafKeyFailureCause::HolderOffline
            }
        }
    };
    match asker {
        Asker::Socket { lane, .. } => {
            reply_failure(lane, &id, &cause);
            logged(tag, &id, holder, executor, cause_outcome(&cause));
        }
        Asker::Home => fail_home(server, id, holder, executor, &cause),
    }
}

/// The home holds the key `request` asks for: its answer, or its refusal by
/// cause, goes back on the executor's socket `lane`, whose machine is `peer`.
fn answer_here(server: &SyncServer, request: &LeafKeyRequest, peer: PeerMachine, lane: &Lane) {
    let id = request.request_id();
    let (holder, executor) = (request.holder_machine(), request.executor_machine());
    let answered = match server.vault().answer_leaf_key_request(request, peer) {
        Ok(answer) => encode_leaf_key_answer(&answer)
            .into_result()
            .map_err(|error| LeafKeyFailureCause::HolderRefused(error.to_string())),
        Err(error) => Err(LeafKeyFailureCause::of_refusal(&error)
            .unwrap_or_else(|| LeafKeyFailureCause::HolderRefused(error.to_string()))),
    };
    let mut state = server.leaf_keys.state();
    let entry = state.in_flight.remove(&id);
    match answered {
        Ok(frame) => {
            if let Some(entry) = entry {
                state.completed.insert(id, entry.expires_at_ms);
            }
            drop(state);
            let _ = lane.send(frame);
            logged(TAG_LEAF_KEY_ANSWER, &id, holder, executor, "answered_here");
        }
        Err(cause) => {
            drop(state);
            reply_failure(lane, &id, &cause);
            logged(
                TAG_LEAF_KEY_FAILURE,
                &id,
                holder,
                executor,
                cause_outcome(&cause),
            );
        }
    }
}

/// Ends request `id`, whose relay entry was `entry`, with `cause` at its
/// executor: the home's own vault, or the executor's newest live socket. An
/// executor with neither is logged and the failure dropped.
fn fail_executor(
    server: &SyncServer,
    home: Option<EntityId>,
    id: [u8; 32],
    entry: &InFlight,
    cause: &LeafKeyFailureCause,
) {
    if Some(entry.executor) == home {
        return fail_home(server, id, entry.holder, entry.executor, cause);
    }
    let sent = encode_leaf_key_failure(&id, cause)
        .into_result()
        .is_ok_and(|frame| push(server, newest(server, entry.executor), frame));
    let outcome = if sent {
        cause_outcome(cause)
    } else {
        "executor_offline_dropped"
    };
    logged(
        TAG_LEAF_KEY_FAILURE,
        &id,
        entry.holder,
        entry.executor,
        outcome,
    );
}

/// Ends the home's own request `id`, from `holder` to `executor`, with
/// `cause` in its vault, and holds it back for [`LEAF_KEY_RETRY`].
fn fail_home(
    server: &SyncServer,
    id: [u8; 32],
    holder: EntityId,
    executor: EntityId,
    cause: &LeafKeyFailureCause,
) {
    server
        .leaf_keys
        .state()
        .home_retry
        .insert(id, Instant::now() + LEAF_KEY_RETRY);
    let outcome = match server.vault().leaf_key_request_failed(id, cause) {
        Ok(()) => cause_outcome(cause),
        Err(_) => "failure_record_failed_here",
    };
    logged(TAG_LEAF_KEY_FAILURE, &id, holder, executor, outcome);
}

/// Queues a failure frame for request `id` on `lane`.
fn reply_failure(lane: &Lane, id: &[u8; 32], cause: &LeafKeyFailureCause) {
    if let Ok(frame) = encode_leaf_key_failure(id, cause).into_result() {
        let _ = lane.send(frame);
    }
}

/// `machine`'s newest live socket.
fn newest(server: &SyncServer, machine: EntityId) -> Option<Target> {
    server
        .leaf_keys
        .state()
        .newest(machine)
        .map(|(_, target)| target)
}

/// Queues `frame` on `target`'s lane while its machine still stands here on
/// the key it proved; `false` where there is no such live socket.
fn push(server: &SyncServer, target: Option<Target>, frame: Vec<u8>) -> bool {
    target.is_some_and(|target| {
        matches!(
            server.vault().peer_machine_stands(target.peer),
            PeerMachine::Proven { .. }
        ) && target.lane.send(frame).is_ok()
    })
}

/// This install's own machine, or `None` before it has one.
fn home_machine(server: &SyncServer) -> Option<EntityId> {
    match server.vault().local_machine() {
        Ok(machine) => machine.map(|machine| machine.id),
        Err(_) => {
            tracing::warn!(outcome = "local_machine_read_failed", "leaf key relay");
            None
        }
    }
}

/// The outcome a failure's cause is logged as.
fn cause_outcome(cause: &LeafKeyFailureCause) -> &'static str {
    match cause {
        LeafKeyFailureCause::HolderOffline => "holder_offline",
        LeafKeyFailureCause::ExecutorOffline => "executor_offline",
        LeafKeyFailureCause::Expired => "expired",
        LeafKeyFailureCause::Replayed => "replayed",
        LeafKeyFailureCause::HolderRefused(_) => "holder_refused",
    }
}

fn logged(tag: u8, id: &[u8; 32], holder: EntityId, executor: EntityId, outcome: &'static str) {
    tracing::info!(
        tag,
        request = %leaf_key_request_hex(id),
        holder = %holder.to_hex(),
        executor = %executor.to_hex(),
        outcome,
        "leaf key relay"
    );
}

/// A frame the machine `socket` proved may not send for request `id`, or
/// one that answers no request on its way: dropped (a security check).
fn refused(tag: u8, id: &[u8; 32], socket: EntityId, outcome: &'static str) {
    tracing::warn!(
        tag,
        request = %leaf_key_request_hex(id),
        socket = %socket.to_hex(),
        outcome,
        "leaf key frame dropped"
    );
}
