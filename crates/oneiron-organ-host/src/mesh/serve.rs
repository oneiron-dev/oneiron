//! The serving side of a mesh organ call: this node's host runs another
//! owner node's call as its own, and sends the organ's asks back to it,
//! all but a fetch and the organ's memory, which this node answers itself.

use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::limit_ask::EngineLimit;
use oneiron::{EntityId, Vault};
use oneiron_mesh_transport::{MeshConnection, MeshError, MeshFuture, MeshService, MeshStream};
use oneiron_organ_protocol::{ASK_MEMORY_GROW, ASK_NET_FETCH, AskCode, AskRefusal};
use tokio::runtime::Handle;
use tokio::task::JoinSet;

use super::staging::Staging;
use super::{
    Carried, FailureKind, ORGAN_ALPN, Offer, PeerAnswer, PeerAsk, PeerCall, PeerFailure,
    PeerOutcome, PeerOutput, PeerResult, Reply, Request, decode, encode,
};
use crate::error::HostError;
use crate::fetch::GuardedFetch;
use crate::handlers::{Answered, AskHandler, AskHandlers, AskRequest};
use crate::host::OrganHost;
use crate::outcome::OrganOutcome;
use crate::receipt::AskReceipt;
use crate::resource_memory::MemoryGrow;
use crate::shutdown::MeshCancel;
use crate::spec::{LentInput, OrganCall, OrganInput};

/// Serves `oneiron/organ/1`: the owner's other nodes run organ calls on this
/// node's host. The transport has already admitted the peer (its MACHINE
/// row and its grant for this ALPN), and that node read every input under
/// its own actor's authority before it sent the bytes.
///
/// Its host's mesh stop ([`Self::with_cancel`], FIX 4756): once it begins,
/// no new call is admitted, and the calls admitted run on, their outputs
/// still there to take; at its deadline each call still running is
/// cancelled, and its thread is awaited before the connection ends.
#[derive(Clone)]
pub struct OrganService {
    host: Arc<OrganHost>,
    vault: Arc<Vault>,
    cancel: MeshCancel,
}

impl std::fmt::Debug for OrganService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrganService")
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

impl OrganService {
    #[must_use]
    pub fn new(host: Arc<OrganHost>, vault: Arc<Vault>) -> Self {
        Self {
            host,
            vault,
            cancel: MeshCancel::new(),
        }
    }

    /// The service under its host's mesh stop.
    #[must_use]
    pub fn with_cancel(mut self, cancel: MeshCancel) -> Self {
        self.cancel = cancel;
        self
    }

    /// Serves one admitted connection until it closes, or until the stop
    /// cancels its work. Each stream the peer opens is one request, a task
    /// of the connection's own set; a call's asks go back on streams this
    /// side opens. Every request it took is awaited before it returns, its
    /// call's thread included. A connection on another ALPN is closed at
    /// once.
    pub async fn serve_connection(&self, conn: Box<dyn MeshConnection>) {
        if conn.alpn() != ORGAN_ALPN {
            conn.close();
            return;
        }
        let conn: Arc<dyn MeshConnection> = Arc::from(conn);
        let staging = Arc::new(self.staging());
        let mut streams = JoinSet::new();
        loop {
            let stream = tokio::select! {
                biased;
                () = self.cancel.cancelled() => break,
                Some(_) = streams.join_next(), if !streams.is_empty() => continue,
                accepted = conn.accept_stream() => match accepted {
                    Ok(stream) => stream,
                    Err(_) => break,
                },
            };
            let service = self.clone();
            let conn = Arc::clone(&conn);
            let staging = Arc::clone(&staging);
            streams.spawn(async move {
                // A stream that breaks leaves the peer without a reply; it
                // retries or tries another node.
                drop(service.serve_stream(conn, staging, stream).await);
            });
        }
        // Never aborted: a call the cancel cut short ends on its thread, and
        // its reply says so.
        while streams.join_next().await.is_some() {}
        conn.close();
    }

    /// A connection's staging (FIX 6193): it spills to the host's measured
    /// spool disk, each write admitted on its floor, when its vault was lent
    /// one, else to the system's temporary directory.
    fn staging(&self) -> Staging {
        let spool = self
            .vault
            .proposal_spool()
            .and_then(|spool| Some((spool.spool_dir().ok()?, spool)));
        match spool {
            Some((dir, floor)) => Staging::new(dir, Some(floor)),
            None => Staging::new(std::env::temp_dir(), None),
        }
    }

    /// Asks the staged row what the connection holds spilled now: nothing is
    /// refused for it (FIX 6193).
    fn measure_staged(&self, staging: &Staging) {
        self.vault
            .measure_limit(EngineLimit::OrganMeshStagedBytes, staging.staged());
    }

    async fn serve_stream(
        &self,
        conn: Arc<dyn MeshConnection>,
        staging: Arc<Staging>,
        mut stream: Box<dyn MeshStream>,
    ) -> Result<(), MeshError> {
        let request: Request = decode(&stream.recv().await?)?;
        let reply = match request {
            // A stopping host admits no new call: the asking node tries
            // another, or holds the call.
            Request::Offers | Request::Call { .. } if self.cancel.is_stopping() => {
                Reply::Refused("this node is stopping".into())
            }
            // What this host can start now, never an install it refuses.
            Request::Offers => Reply::Offers(
                self.host
                    .offered()
                    .into_iter()
                    .map(|(organ, verbs)| Offer { organ, verbs })
                    .collect(),
            ),
            Request::Put {
                hash,
                total,
                offset,
                bytes,
            } => {
                // One object's size, at its first piece: it is staged whole.
                if offset == 0 {
                    self.vault
                        .measure_limit(EngineLimit::OrganMeshObjectBytes, total);
                }
                match staging.put(hash, total, offset, &bytes) {
                    Ok(()) => {
                        self.measure_staged(&staging);
                        Reply::Put
                    }
                    Err(why) => Reply::Refused(why),
                }
            }
            Request::Get { hash, offset } => match staging.piece(hash, offset) {
                Ok(piece) => Reply::Piece(piece),
                Err(why) => Reply::Refused(why),
            },
            Request::Call { call } => {
                let result = match self.call(conn, &staging, &call).await {
                    Ok(result) => result,
                    Err(detail) => PeerResult::Failed(PeerFailure {
                        kind: FailureKind::Failed,
                        detail,
                        organ: None,
                        asks: Vec::new(),
                    }),
                };
                match encode(&result) {
                    Ok(bytes) => match staging.offer(&bytes) {
                        Ok(carried) => {
                            self.measure_staged(&staging);
                            Reply::Call(carried)
                        }
                        Err(why) => Reply::Refused(why),
                    },
                    Err(err) => Reply::Refused(err.to_string()),
                }
            }
        };
        stream.send(&encode(&reply)?).await
    }

    async fn call(
        &self,
        conn: Arc<dyn MeshConnection>,
        staging: &Arc<Staging>,
        carried: &Carried,
    ) -> Result<PeerResult, String> {
        let peer: PeerCall = decode(&staging.take(carried)?).map_err(|err| err.to_string())?;
        let deadline =
            Instant::now() + Duration::from_millis(peer.deadline_ms.min(u64::from(u32::MAX)));
        let mut inputs = Vec::with_capacity(peer.inputs.len());
        // Each staged input read back into memory leases this machine's
        // floor first, and holds it until the call ends (FIX 6193).
        let mut held = Vec::new();
        for input in &peer.inputs {
            let read = match &input.read {
                Some((artifact, version)) => Some(OrganInput {
                    artifact: EntityId::from_hex(artifact)
                        .map_err(|_| "an input names no artifact".to_owned())?,
                    version: *version,
                }),
                None => None,
            };
            if let Some(lease) = self.hold_taken(&input.bytes, deadline)? {
                held.push(lease);
            }
            let bytes = staging.take(&input.bytes)?;
            inputs.push((
                read,
                LentInput {
                    media_type: input.media_type.clone(),
                    bytes,
                },
            ));
        }
        let call = OrganCall {
            organ: peer.organ,
            verb: peer.verb,
            schema: peer.schema,
            args: peer.args,
            body: peer.body,
            inputs: Vec::new(),
            class: peer.class,
            deadline: Duration::from_millis(peer.deadline_ms),
            grant: peer.grant,
        };
        let host = Arc::clone(&self.host);
        let vault = Arc::clone(&self.vault);
        let forward = Forward {
            conn,
            staging: Arc::clone(staging),
            runtime: Handle::current(),
            cancel: self.cancel.clone(),
        };
        let cancel = self.cancel.clone();
        let answers = peer.answers;
        let (outcome, asked) = tokio::task::spawn_blocking(move || {
            let fetch = GuardedFetch;
            let memory = MemoryGrow;
            let mut handlers = AskHandlers::none();
            for verb in answers {
                // A fetch runs here, where the organ runs, under this
                // install's allowlist; the organ's memory is reserved here,
                // from this machine's floor and in this call's room, never
                // forwarded (FIX 7654); every other ask goes back.
                let handler: &dyn AskHandler = if verb == ASK_NET_FETCH {
                    &fetch
                } else if verb == ASK_MEMORY_GROW {
                    &memory
                } else {
                    &forward
                };
                handlers = handlers.with(verb, handler);
            }
            let outcome = host.call_for_peer(&vault, call, inputs, &handlers, &cancel);
            (outcome, handlers.asked())
        })
        .await
        .map_err(|err| format!("the call's thread: {err}"))?;
        drop(held);
        Ok(match outcome {
            Ok(outcome) => PeerResult::Done(offered(outcome, staging)?),
            Err(err) => PeerResult::Failed(failure(err, asked)),
        })
    }

    /// A lease of this machine's memory for staged bytes about to be read
    /// back, within the call's deadline; none for bytes that rode inline, or
    /// on a host with no floor.
    fn hold_taken(
        &self,
        carried: &Carried,
        deadline: Instant,
    ) -> Result<Option<Box<dyn Send>>, String> {
        let (Carried::Staged { len, .. }, Some(floor)) = (carried, self.host.floor()) else {
            return Ok(None);
        };
        floor
            .0
            .lease(*len, deadline, &|| false)
            .map(Some)
            .map_err(|refused| format!("this node's memory floor: {refused:?}"))
    }
}

impl MeshService for OrganService {
    fn serve(&self, connection: Box<dyn MeshConnection>) -> MeshFuture<'_, ()> {
        Box::pin(async move {
            self.serve_connection(connection).await;
            Ok(())
        })
    }
}

/// The outcome as it crosses back: each output's bytes offered by hash.
fn offered(outcome: OrganOutcome, staging: &Staging) -> Result<PeerOutcome, String> {
    let outputs = outcome
        .outputs
        .iter()
        .map(|output| {
            Ok(PeerOutput {
                name: output.name.clone(),
                media_type: output.media_type.clone(),
                content_hash: output.content_hash,
                bytes: staging.offer(output)?,
            })
        })
        .collect::<Result<_, String>>()?;
    Ok(PeerOutcome {
        body: outcome.body,
        report: outcome.report,
        receipt: outcome.receipt,
        outputs,
    })
}

/// What the asking node needs of a failure: whether another node may serve
/// the call, and this host's word.
fn failure(err: HostError, asks: Vec<AskReceipt>) -> PeerFailure {
    let kind = match &err {
        HostError::NotInstalled(_)
        | HostError::Unavailable { .. }
        | HostError::Backoff { .. }
        | HostError::UnknownVerb { .. }
        | HostError::Handshake(_)
        | HostError::StartFailed { .. }
        | HostError::BudgetTimeout
        | HostError::OverBudget
        | HostError::MediaTypeNotGranted(_)
        | HostError::KindNotGranted(_)
        // This node's stop cut it short (FIX 4756): another node may run it.
        | HostError::Interrupted => FailureKind::Absent,
        HostError::Organ(_) => FailureKind::Organ,
        HostError::DeadlineExceeded => FailureKind::Deadline,
        HostError::Revoked => FailureKind::Revoked,
        _ => FailureKind::Failed,
    };
    let organ = match &err {
        HostError::Organ(error) => Some(error.clone()),
        _ => None,
    };
    PeerFailure {
        kind,
        detail: err.to_string(),
        organ,
        asks,
    }
}

/// Sends an organ's ask back to the asking node and waits for its answer,
/// inside the call's deadline. It runs on the call's blocking thread.
struct Forward {
    conn: Arc<dyn MeshConnection>,
    staging: Arc<Staging>,
    runtime: Handle,
    /// The stop's cancel ends a wait for the asking node.
    cancel: MeshCancel,
}

impl Forward {
    async fn ask(&self, peer: &PeerAsk) -> Result<PeerAnswer, MeshError> {
        let mut stream = self.conn.open_stream().await?;
        stream.send(&encode(peer)?).await?;
        decode(&stream.recv().await?)
    }
}

impl AskHandler for Forward {
    fn answer(&self, ask: &AskRequest<'_>) -> Result<Answered, AskRefusal> {
        let remaining = ask.deadline.saturating_duration_since(Instant::now());
        let peer = PeerAsk {
            organ: ask.organ.to_owned(),
            verb: ask.verb.to_owned(),
            value: ask.value.clone(),
            call_verb: ask.call_verb.to_owned(),
            grant: ask.grant.to_owned(),
            deadline_ms: u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX),
            max_bytes: ask.max_bytes,
        };
        let failed = |detail: String| AskRefusal::new(AskCode::Failed, detail).retryable();
        let asked = async {
            tokio::select! {
                answered = tokio::time::timeout(remaining, self.ask(&peer)) => Some(answered),
                () = self.cancel.cancelled() => None,
            }
        };
        let answer = match self.runtime.block_on(asked) {
            Some(Ok(Ok(answer))) => answer,
            Some(Ok(Err(err))) => return Err(failed(format!("the asking node: {err}"))),
            Some(Err(_)) => return Err(failed("the asking node did not answer in time".into())),
            None => return Err(failed("this node is stopping".into())),
        };
        if let Some(signed) = answer.signed {
            ask.record_signing(signed);
        }
        let answered = answer.answered?;
        let data = match &answered.data {
            Some(carried) => Some(self.staging.take(carried).map_err(failed)?),
            None => None,
        };
        Ok(Answered {
            value: answered.value,
            data,
            fetch: answered.fetch,
        })
    }
}
