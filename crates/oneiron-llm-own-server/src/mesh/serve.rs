//! The serving side: the node that has the model runs another owner node's
//! call under its own admission, and hands a stream's events back in
//! batches as the asking node pulls them.
//!
//! What a connection holds is booked on the node's [`StagingBudget`] for
//! its whole life (FIX 8618): each body staged in, from its first piece
//! (its entry too, an empty one included) until a call takes it; each reply
//! out, from before it is written until it is sent or its last piece is
//! read; each stream's entry, and the batch a pull fills, from before the
//! stream is read. A full budget pauses the work that waits on it, in
//! arrival order; nothing made is dropped, and the connection's end drops
//! what it held.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_core::Stream;
use oneiron::{
    LlmCatalogEntry, LlmGenerateFuture, LlmRequest, LlmResult, LlmStream, LlmStreamEvent, ModelId,
};
use oneiron_mesh_transport::{
    MachineId, MeshConnection, MeshError, MeshFuture, MeshService, MeshStream,
};
use serde::Serialize;

use super::staging::{BookedBody, Booking, OUTGOING_ENTRY, Staging, StagingBudget};
use super::{Batch, LLM_ALPN, Reply, Request, encode, lock, seal, unseal};

/// How long a pull waits for the first event before it answers with none.
const PULL_WAIT: Duration = Duration::from_secs(20);
/// The most event bytes one batch carries before it goes back.
const BATCH_BYTES: usize = 256 * 1024;

/// What runs a model call for one of the owner's machines on this node: the
/// node's own admission and offer ladder, as its HTTP routes run them.
pub trait LlmMeshHandler: Send + Sync + 'static {
    /// Whether this node runs `model`; a call for one it does not is
    /// refused, so the asking node tries another.
    fn serves(&self, model: &ModelId) -> bool;
    /// One generate for `peer`, an owner's machine the mesh admitted.
    fn generate(&self, peer: MachineId, request: LlmRequest) -> LlmGenerateFuture<'static>;
    /// One stream for `peer`.
    ///
    /// # Errors
    /// The call was refused before it started.
    fn stream(&self, peer: MachineId, request: LlmRequest) -> LlmResult<LlmStream<'static>>;
    /// The models this node offers the owner's other nodes, so they can
    /// route to them: its own models only ([`super::advertises`]).
    fn catalog(&self) -> Vec<LlmCatalogEntry> {
        Vec::new()
    }
}

/// Serves `oneiron/llm/1`: the owner's other nodes use this node's models.
#[derive(Clone)]
pub struct LlmMeshService {
    handler: Arc<dyn LlmMeshHandler>,
    /// The bytes every connection's calls hold at once.
    budget: StagingBudget,
}

impl std::fmt::Debug for LlmMeshService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LlmMeshService")
    }
}

type Running = Arc<tokio::sync::Mutex<LlmStream<'static>>>;

/// One running stream, its entry booked.
struct Held {
    running: Running,
    _entry: Booking,
}

/// One connection's staged bodies and running streams. Dropping it drops
/// the streams, which ends their calls, and frees all it booked.
struct Session {
    staging: Staging,
    streams: Mutex<HashMap<u64, Held>>,
    next: AtomicU64,
}

impl Session {
    fn new(budget: StagingBudget) -> Self {
        Self {
            staging: Staging::new(budget),
            streams: Mutex::default(),
            next: AtomicU64::default(),
        }
    }
}

impl LlmMeshService {
    /// Serves `handler`'s calls, every connection's holding at most
    /// `budget`'s bytes at once: the host's, or [`StagingBudget::default`].
    #[must_use]
    pub fn new(handler: Arc<dyn LlmMeshHandler>, budget: StagingBudget) -> Self {
        Self { handler, budget }
    }

    /// Serves one admitted connection until it closes. A connection on
    /// another ALPN is closed at once.
    pub async fn serve_connection(&self, conn: Box<dyn MeshConnection>) {
        if conn.alpn() != LLM_ALPN {
            conn.close();
            return;
        }
        let peer = conn.machine();
        let conn: Arc<dyn MeshConnection> = Arc::from(conn);
        let session = Arc::new(Session::new(self.budget.clone()));
        let mut tasks = Vec::new();
        while let Ok(stream) = conn.accept_stream().await {
            let service = self.clone();
            let task_session = Arc::clone(&session);
            let serve = async move {
                // A stream that breaks leaves the asker without a reply; it
                // tries again or another node.
                drop(service.serve_stream(peer, &task_session, stream).await);
            };
            // Each accepted stream's task and its entry here are charged
            // before it is spawned, never waited for, so a control or a Get
            // that frees held bytes always runs; the charge goes when the
            // task ends, is cancelled, or the connection closes (FIX 9323).
            let entry = session
                .staging
                .budget
                .charged(size_of_val(&serve).saturating_add(TASK_ENTRY));
            tasks.push(tokio::spawn(async move {
                let _entry = entry;
                serve.await;
            }));
            tasks.retain(|task| !task.is_finished());
        }
        for task in tasks {
            task.abort();
        }
        conn.close();
    }

    async fn serve_stream(
        &self,
        peer: MachineId,
        session: &Session,
        mut stream: Box<dyn MeshStream>,
    ) -> Result<(), MeshError> {
        let request: Request = unseal(&stream.recv().await?)?;
        // The reply's bytes stay booked until it is sent.
        let (reply, _held) = self.answer(peer, session, request).await;
        stream.send(&seal(&reply)?).await
    }

    /// The reply to `request`, and the booking of its inline body, if any.
    async fn answer(
        &self,
        peer: MachineId,
        session: &Session,
        request: Request,
    ) -> (Reply, Option<Booking>) {
        let refused = |why: String| (Reply::Refused(why), None);
        match request {
            Request::Put {
                hash,
                total,
                offset,
                bytes,
            } => match session.staging.put(hash, total, offset, &bytes).await {
                Ok(()) => (Reply::Put, None),
                Err(why) => refused(why),
            },
            Request::Get { hash, offset } => match session.staging.piece(hash, offset) {
                Ok(BookedBody { bytes, booking }) => (Reply::Piece(bytes), Some(booking)),
                Err(why) => refused(why),
            },
            Request::Generate { request } => match self.request(session, request) {
                Ok(request) => {
                    // The answer's room is booked before the model runs, so
                    // a finished answer never waits unbooked (FIX 9323).
                    let budget = &session.staging.budget;
                    let booking = budget.reserve(BATCH_BYTES + OUTGOING_ENTRY).await;
                    match self.handler.generate(peer, request).await {
                        Ok(response) => match charged_json(budget, booking, response) {
                            Ok(body) => {
                                let (carried, held) = session.staging.offer(body);
                                (Reply::Generated(Ok(carried)), held)
                            }
                            Err(why) => refused(why),
                        },
                        Err(error) => (Reply::Generated(Err(error)), None),
                    }
                }
                Err(why) => refused(why),
            },
            Request::Stream { request } => match self.request(session, request) {
                Ok(request) => match self.handler.stream(peer, request) {
                    Ok(running) => {
                        let id = session.next.fetch_add(1, Ordering::Relaxed);
                        let entry = session.staging.budget.charged(STREAM_ENTRY);
                        let held = Held {
                            running: Arc::new(tokio::sync::Mutex::new(running)),
                            _entry: entry,
                        };
                        lock(&session.streams).insert(id, held);
                        (Reply::Started(Ok(id)), None)
                    }
                    Err(error) => (Reply::Started(Err(error)), None),
                },
                Err(why) => refused(why),
            },
            Request::Next { stream: id } => pull(session, id).await,
            Request::Cancel { stream: id } => {
                lock(&session.streams).remove(&id);
                (Reply::Cancelled, None)
            }
            Request::Catalog => {
                let offered: Vec<LlmCatalogEntry> = self
                    .handler
                    .catalog()
                    .into_iter()
                    .filter(|entry| super::advertises(entry.locality))
                    .collect();
                match booked_json(&session.staging.budget, &offered).await {
                    Ok(body) => {
                        let (carried, held) = session.staging.offer(body);
                        (Reply::Catalog(carried), held)
                    }
                    Err(why) => refused(why),
                }
            }
        }
    }

    /// The request a body names, refused when this node does not run its
    /// model. The body's booking goes once it is decoded.
    fn request(&self, session: &Session, body: super::Carried) -> Result<LlmRequest, String> {
        let body = session.staging.take(body)?;
        let request: LlmRequest = serde_json::from_slice(&body.bytes)
            .map_err(|_| "the request does not decode".to_owned())?;
        drop(body);
        if !self.handler.serves(&request.model) {
            return Err(format!("this node does not run {}", request.model));
        }
        Ok(request)
    }
}

impl MeshService for LlmMeshService {
    fn serve(&self, connection: Box<dyn MeshConnection>) -> MeshFuture<'_, ()> {
        Box::pin(async move {
            self.serve_connection(connection).await;
            Ok(())
        })
    }
}

/// What a running stream's entry costs past its stream.
const STREAM_ENTRY: usize = 2 * (size_of::<u64>() + size_of::<Held>());

/// What an accepted stream's task costs past its future: its handle and its
/// slot in the connection's list.
const TASK_ENTRY: usize = 2 * size_of::<tokio::task::JoinHandle<()>>();

/// `value`, an answer the model already made, as JSON on `booking`, which
/// was booked before it ran: the answer and its encoding are charged at once
/// while both live, never waited for, and the answer goes once it is
/// written, leaving its encoding and its reply entry charged.
fn charged_json<T: Serialize>(
    budget: &StagingBudget,
    mut booking: Booking,
    value: T,
) -> Result<BookedBody, String> {
    let mut counted = Counted(0);
    serde_json::to_writer(&mut counted, &value).map_err(|err| err.to_string())?;
    let len = counted.0;
    budget.charge(
        &mut booking,
        len.saturating_mul(2).saturating_add(OUTGOING_ENTRY),
    );
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| "this node has no memory for the answer".to_owned())?;
    serde_json::to_writer(&mut bytes, &value).map_err(|err| err.to_string())?;
    drop(value);
    budget.charge(
        &mut booking,
        bytes.capacity().saturating_add(OUTGOING_ENTRY),
    );
    Ok(BookedBody { bytes, booking })
}

/// `value` as JSON, in room booked for it first: its length is counted, its
/// room and its reply entry booked, waiting its turn, and only then is it
/// written.
async fn booked_json<T: Serialize>(
    budget: &StagingBudget,
    value: &T,
) -> Result<BookedBody, String> {
    let mut counted = Counted(0);
    serde_json::to_writer(&mut counted, value).map_err(|err| err.to_string())?;
    let mut body = BookedBody::room(budget, counted.0, OUTGOING_ENTRY).await?;
    serde_json::to_writer(&mut body.bytes, value).map_err(|err| err.to_string())?;
    Ok(body)
}

/// A writer that only counts what it is given.
struct Counted(usize);

impl std::io::Write for Counted {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The stream's next events: waits for the first, then takes what is ready.
/// Room for the batch, its events and their encoding both, is booked before
/// the stream is read, so a full budget pauses the stream here and drops
/// nothing it made; an event past that room is charged as it comes.
async fn pull(session: &Session, id: u64) -> (Reply, Option<Booking>) {
    let Some(running) = lock(&session.streams)
        .get(&id)
        .map(|held| Arc::clone(&held.running))
    else {
        return (Reply::Refused("no such stream".into()), None);
    };
    let budget = &session.staging.budget;
    let mut booking = budget.reserve(2 * BATCH_BYTES + OUTGOING_ENTRY).await;
    let mut running = running.lock().await;
    let mut events = Vec::new();
    let mut bytes = 0;
    let mut end = false;
    let mut wait = PULL_WAIT;
    while bytes < BATCH_BYTES {
        let next = std::future::poll_fn(|cx| Pin::new(&mut *running).poll_next(cx));
        let Ok(item) = tokio::time::timeout(wait, next).await else {
            break;
        };
        wait = Duration::ZERO;
        match item {
            None => {
                end = true;
                break;
            }
            Some(Err(error)) => {
                events.push(Err(error));
                end = true;
                break;
            }
            Some(Ok(event)) => {
                let done = matches!(event, LlmStreamEvent::Done { .. });
                match serde_json::to_string(&event) {
                    Ok(json) => {
                        bytes += json.len();
                        events.push(Ok(json));
                        if bytes > BATCH_BYTES {
                            budget.charge(&mut booking, 2 * bytes + OUTGOING_ENTRY);
                        }
                    }
                    Err(_) => {
                        events.push(Err(oneiron::FatalLlmError::InvalidRequest.into()));
                        end = true;
                        break;
                    }
                }
                if done {
                    end = true;
                    break;
                }
            }
        }
    }
    drop(running);
    if end {
        lock(&session.streams).remove(&id);
    }
    match encode(&Batch { events }) {
        Ok(batch) => {
            budget.charge(&mut booking, batch.len() + OUTGOING_ENTRY);
            let (carried, held) = session.staging.offer(BookedBody {
                bytes: batch,
                booking,
            });
            (
                Reply::Events {
                    events: carried,
                    end,
                },
                held,
            )
        }
        Err(err) => (Reply::Refused(err.to_string()), None),
    }
}
