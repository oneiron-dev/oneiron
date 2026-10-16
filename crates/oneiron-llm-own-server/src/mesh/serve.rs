//! The serving side: the node that has the model runs another owner node's
//! call under its own admission, and hands a stream's events back in
//! batches as the asking node pulls them.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_core::Stream;
use oneiron::{LlmGenerateFuture, LlmRequest, LlmResult, LlmStream, LlmStreamEvent, ModelId};
use oneiron_mesh_transport::{
    MachineId, MeshConnection, MeshError, MeshFuture, MeshService, MeshStream,
};

use super::{Batch, LLM_ALPN, Reply, Request, Staging, decode, encode, lock};

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
}

/// Serves `oneiron/llm/1`: the owner's other nodes use this node's models.
#[derive(Clone)]
pub struct LlmMeshService {
    handler: Arc<dyn LlmMeshHandler>,
}

impl std::fmt::Debug for LlmMeshService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LlmMeshService")
    }
}

type Running = Arc<tokio::sync::Mutex<LlmStream<'static>>>;

/// One connection's staged bodies and running streams. Dropping it drops
/// the streams, which ends their calls.
#[derive(Default)]
struct Session {
    staging: Staging,
    streams: Mutex<HashMap<u64, Running>>,
    next: AtomicU64,
}

impl LlmMeshService {
    #[must_use]
    pub fn new(handler: Arc<dyn LlmMeshHandler>) -> Self {
        Self { handler }
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
        let session = Arc::new(Session::default());
        let mut tasks = Vec::new();
        while let Ok(stream) = conn.accept_stream().await {
            let service = self.clone();
            let session = Arc::clone(&session);
            tasks.push(tokio::spawn(async move {
                // A stream that breaks leaves the asker without a reply; it
                // tries again or another node.
                drop(service.serve_stream(peer, &session, stream).await);
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
        let request: Request = decode(&stream.recv().await?)?;
        let reply = match request {
            Request::Put {
                hash,
                total,
                offset,
                bytes,
            } => match session.staging.put(hash, total, offset, &bytes) {
                Ok(()) => Reply::Put,
                Err(why) => Reply::Refused(why),
            },
            Request::Get { hash, offset } => match session.staging.piece(hash, offset) {
                Ok(piece) => Reply::Piece(piece),
                Err(why) => Reply::Refused(why),
            },
            Request::Generate { request } => match self.request(session, request) {
                Ok(request) => match self.handler.generate(peer, request).await {
                    Ok(response) => match serde_json::to_vec(&response) {
                        Ok(bytes) => Reply::Generated(Ok(session.staging.offer(bytes))),
                        Err(err) => Reply::Refused(err.to_string()),
                    },
                    Err(error) => Reply::Generated(Err(error)),
                },
                Err(why) => Reply::Refused(why),
            },
            Request::Stream { request } => match self.request(session, request) {
                Ok(request) => match self.handler.stream(peer, request) {
                    Ok(running) => {
                        let id = session.next.fetch_add(1, Ordering::Relaxed);
                        lock(&session.streams)
                            .insert(id, Arc::new(tokio::sync::Mutex::new(running)));
                        Reply::Started(Ok(id))
                    }
                    Err(error) => Reply::Started(Err(error)),
                },
                Err(why) => Reply::Refused(why),
            },
            Request::Next { stream: id } => pull(session, id).await,
            Request::Cancel { stream: id } => {
                lock(&session.streams).remove(&id);
                Reply::Cancelled
            }
        };
        stream.send(&encode(&reply)?).await
    }

    /// The request a body names, refused when this node does not run its
    /// model.
    fn request(&self, session: &Session, body: super::Carried) -> Result<LlmRequest, String> {
        let bytes = session.staging.take(body)?;
        let request: LlmRequest =
            serde_json::from_slice(&bytes).map_err(|_| "the request does not decode".to_owned())?;
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

/// The stream's next events: waits for the first, then takes what is ready.
async fn pull(session: &Session, id: u64) -> Reply {
    let Some(running) = lock(&session.streams).get(&id).cloned() else {
        return Reply::Refused("no such stream".into());
    };
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
        Ok(batch) => Reply::Events {
            events: session.staging.offer(batch),
            end,
        },
        Err(err) => Reply::Refused(err.to_string()),
    }
}
