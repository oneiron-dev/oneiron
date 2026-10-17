//! The serving side of a mesh organ call: this node's host runs another
//! owner node's call as its own, and sends the organ's asks back to it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::{EntityId, Vault};
use oneiron_mesh_transport::{MeshConnection, MeshError, MeshFuture, MeshService, MeshStream};
use oneiron_organ_protocol::{ASK_NET_FETCH, AskCode, AskRefusal};
use tokio::runtime::Handle;

use super::{
    Carried, FailureKind, ORGAN_ALPN, Offer, PeerAnswer, PeerAsk, PeerCall, PeerFailure,
    PeerOutcome, PeerOutput, PeerResult, Reply, Request, Staging, decode, encode,
};
use crate::error::HostError;
use crate::fetch::GuardedFetch;
use crate::handlers::{Answered, AskHandler, AskHandlers, AskRequest};
use crate::host::OrganHost;
use crate::outcome::OrganOutcome;
use crate::receipt::AskReceipt;
use crate::spec::{LentInput, OrganCall, OrganInput};

/// Serves `oneiron/organ/1`: the owner's other nodes run organ calls on this
/// node's host. The transport has already admitted the peer (its MACHINE
/// row and its grant for this ALPN), and that node read every input under
/// its own actor's authority before it sent the bytes.
#[derive(Clone)]
pub struct OrganService {
    host: Arc<OrganHost>,
    vault: Arc<Vault>,
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
        Self { host, vault }
    }

    /// Serves one admitted connection until it closes. Each stream the peer
    /// opens is one request; a call's asks go back on streams this side
    /// opens. A connection on another ALPN is closed at once.
    pub async fn serve_connection(&self, conn: Box<dyn MeshConnection>) {
        if conn.alpn() != ORGAN_ALPN {
            conn.close();
            return;
        }
        let conn: Arc<dyn MeshConnection> = Arc::from(conn);
        let staging = Arc::new(Staging::default());
        while let Ok(stream) = conn.accept_stream().await {
            let service = self.clone();
            let conn = Arc::clone(&conn);
            let staging = Arc::clone(&staging);
            tokio::spawn(async move {
                // A stream that breaks leaves the peer without a reply; it
                // retries or tries another node.
                drop(service.serve_stream(conn, staging, stream).await);
            });
        }
        conn.close();
    }

    async fn serve_stream(
        &self,
        conn: Arc<dyn MeshConnection>,
        staging: Arc<Staging>,
        mut stream: Box<dyn MeshStream>,
    ) -> Result<(), MeshError> {
        let request: Request = decode(&stream.recv().await?)?;
        let reply = match request {
            Request::Offers => Reply::Offers(
                self.host
                    .installed()
                    .into_iter()
                    .map(|(organ, verbs)| Offer { organ, verbs })
                    .collect(),
            ),
            Request::Put {
                hash,
                total,
                offset,
                bytes,
            } => match staging.put(hash, total, offset, &bytes) {
                Ok(()) => Reply::Put,
                Err(why) => Reply::Refused(why),
            },
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
                    Ok(bytes) => Reply::Call(staging.offer(bytes)),
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
        let mut inputs = Vec::with_capacity(peer.inputs.len());
        for input in &peer.inputs {
            let read = match &input.read {
                Some((artifact, version)) => Some(OrganInput {
                    artifact: EntityId::from_hex(artifact)
                        .map_err(|_| "an input names no artifact".to_owned())?,
                    version: *version,
                }),
                None => None,
            };
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
        };
        let answers = peer.answers;
        let (outcome, asked) = tokio::task::spawn_blocking(move || {
            let fetch = GuardedFetch;
            let mut handlers = AskHandlers::none();
            for verb in answers {
                // A fetch runs here, where the organ runs, under this
                // install's allowlist; every other ask goes back.
                let handler: &dyn AskHandler = if verb == ASK_NET_FETCH {
                    &fetch
                } else {
                    &forward
                };
                handlers = handlers.with(verb, handler);
            }
            let outcome = host.call_for_peer(&vault, call, inputs, &handlers);
            (outcome, handlers.asked())
        })
        .await
        .map_err(|err| format!("the call's thread: {err}"))?;
        Ok(match outcome {
            Ok(outcome) => PeerResult::Done(offered(outcome, staging)),
            Err(err) => PeerResult::Failed(failure(err, asked)),
        })
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
fn offered(outcome: OrganOutcome, staging: &Staging) -> PeerOutcome {
    let outputs = outcome
        .outputs
        .iter()
        .map(|output| PeerOutput {
            name: output.name.clone(),
            media_type: output.media_type.clone(),
            content_hash: output.content_hash,
            bytes: staging.offer(output.to_vec()),
        })
        .collect();
    PeerOutcome {
        body: outcome.body,
        report: outcome.report,
        receipt: outcome.receipt,
        outputs,
    }
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
        | HostError::MediaTypeNotGranted(_) => FailureKind::Absent,
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
        let answer = match self
            .runtime
            .block_on(tokio::time::timeout(remaining, self.ask(&peer)))
        {
            Ok(Ok(answer)) => answer,
            Ok(Err(err)) => return Err(failed(format!("the asking node: {err}"))),
            Err(_) => return Err(failed("the asking node did not answer in time".into())),
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
