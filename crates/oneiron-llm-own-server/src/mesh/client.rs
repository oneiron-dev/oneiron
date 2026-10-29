//! The asking side: the first of the owner's nodes that takes the call runs
//! it; with none, the call waits and says why, trying again until one does.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use oneiron::authority::PeerMachine;
use oneiron::{
    BudgetLease, FatalLlmError, LlmCatalogEntry, LlmError, LlmGenerateFuture, LlmRequest,
    LlmResponse, LlmResult, LlmStream, LlmStreamEvent, LlmStreamResult, RetryableLlmError, Vault,
};
use oneiron_mesh_transport::{MachineId, MeshConnection, MeshTransport};
use tokio::runtime::Handle;

use super::catalog::{CatalogRefresh, merge, mesh_row, prune};
use super::pump::{AbortOnDrop, Demand, demand};
use super::staging::{BookedBody, Booking, StagingBudget};
use super::{Batch, LLM_ALPN, Reply, Request, exchange, lock, put, take};
use crate::OwnServerTransport;

/// How long a node has to answer the dial.
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a dialled node has to send its whole catalog.
const CATALOG_TIMEOUT: Duration = Duration::from_secs(10);
/// The first pause before trying the nodes again, doubling up to the last.
const PAUSE_FIRST: Duration = Duration::from_secs(1);
const PAUSE_MOST: Duration = Duration::from_secs(30);

/// The owner's other nodes a model call may go to.
pub trait LlmNodes: Send + Sync {
    /// The machines to try, best first; never this one.
    ///
    /// # Errors
    /// The roster could not be read; the call waits and says so.
    fn nodes(&self) -> Result<Vec<MachineId>, String>;

    /// The machine behind a dialled node's authenticated endpoint key, as
    /// the vault proves it now (FIX 4938); unproved by default.
    fn proved(&self, _endpoint_key: [u8; 32]) -> PeerMachine {
        PeerMachine::Unknown
    }
}

/// The vault's MACHINE rows whose grant admits model calls, without this
/// machine.
#[derive(Clone)]
pub struct VaultLlmNodes(pub Arc<Vault>);

impl std::fmt::Debug for VaultLlmNodes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultLlmNodes")
    }
}

impl LlmNodes for VaultLlmNodes {
    fn nodes(&self) -> Result<Vec<MachineId>, String> {
        let here = self
            .0
            .local_machine()
            .map_err(|err| err.to_string())?
            .map(|local| local.id);
        Ok(self
            .0
            .mesh_machines_granted(LLM_ALPN)
            .map_err(|err| err.to_string())?
            .into_iter()
            .filter(|machine| Some(*machine) != here)
            .collect())
    }

    /// The machine the vault's binding, grant and authority proof name for
    /// `endpoint_key` on the model-call protocol, in one snapshot; unproved
    /// when any fails or cannot be read.
    fn proved(&self, endpoint_key: [u8; 32]) -> PeerMachine {
        self.0
            .mesh_peer_machine(endpoint_key, LLM_ALPN)
            .unwrap_or(PeerMachine::Unknown)
    }
}

/// An own-server transport over the owner's mesh.
pub struct MeshLlmTransport {
    leg: Arc<Leg>,
    runtime: Handle,
}

impl std::fmt::Debug for MeshLlmTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshLlmTransport")
            .field("waiting", &self.waiting())
            .finish_non_exhaustive()
    }
}

struct Leg {
    transport: Arc<dyn MeshTransport>,
    nodes: Arc<dyn LlmNodes>,
    /// The bytes this transport's calls hold at once: replies taken and
    /// stream batches not yet read (FIX 8619).
    budget: StagingBudget,
    /// Why calls wait now; `None` while a node takes them.
    waiting: Mutex<Option<String>>,
    /// The machine each node's last authenticated handshake proved.
    proofs: Mutex<BTreeMap<MachineId, PeerMachine>>,
}

/// Why one node did not take a call: another may.
type Absent = String;

impl MeshLlmTransport {
    /// Calls go out on `runtime`, which drives `transport`, holding at most
    /// `budget`'s bytes at once: the host's, or [`StagingBudget::default`].
    #[must_use]
    pub fn new(
        transport: Arc<dyn MeshTransport>,
        nodes: Arc<dyn LlmNodes>,
        runtime: Handle,
        budget: StagingBudget,
    ) -> Self {
        Self {
            leg: Arc::new(Leg {
                transport,
                nodes,
                budget,
                waiting: Mutex::new(None),
                proofs: Mutex::default(),
            }),
            runtime,
        }
    }

    /// Why calls are waiting now, in the transport's words (every node it
    /// tried and what each said); `None` while a node takes them.
    #[must_use]
    pub fn waiting(&self) -> Option<String> {
        lock(&self.leg.waiting).clone()
    }

    /// Asks each of the owner's nodes granted model calls which models it
    /// offers, and writes an own-server row for each one the vault does not
    /// already route another way. A node that answers drops the rows of the
    /// models it no longer offers. A node that does not answer keeps the
    /// rows it had: its models wait for it, as any call to it does.
    ///
    /// # Errors
    /// A row could not be read or written.
    pub async fn refresh_catalog(&self, vault: &Vault) -> oneiron::Result<CatalogRefresh> {
        let leg = Arc::clone(&self.leg);
        let (answers, mut unreached) = self
            .runtime
            .spawn(async move { leg.catalogs().await })
            .await
            .unwrap_or_else(|_| (Vec::new(), vec!["the catalog task stopped".to_owned()]));
        let mut refresh = CatalogRefresh::default();
        for (machine, answer) in answers {
            match answer {
                Ok(entries) => {
                    let mut offered = Vec::new();
                    for entry in entries {
                        let model = entry.model.clone();
                        let Some(row) = mesh_row(machine, entry) else {
                            continue;
                        };
                        offered.push(model.clone());
                        if merge(vault, row)? {
                            refresh.written.push(model);
                        } else {
                            refresh.conflicts.push(model);
                        }
                    }
                    refresh.withdrawn.extend(prune(vault, machine, &offered)?);
                }
                Err(why) => unreached.push(format!("node {}: {why}", machine.to_hex())),
            }
        }
        refresh.unreached = unreached;
        Ok(refresh)
    }
}

impl OwnServerTransport for MeshLlmTransport {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let leg = Arc::clone(&self.leg);
        let task = self
            .runtime
            .spawn(async move { leg.generate(request).await });
        let guard = AbortOnDrop(task.abort_handle());
        Box::pin(async move {
            let _guard = guard;
            task.await.unwrap_or_else(|error| {
                Err(RetryableLlmError::io_after_send("generate", error.to_string()).into())
            })
        })
    }

    fn stream<'a>(&'a self, request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        let leg = Arc::clone(&self.leg);
        let (pump, end) = demand();
        let task = self
            .runtime
            .spawn(async move { leg.stream(request, &pump).await });
        Ok(LlmStream::new(
            end.guarded(AbortOnDrop(task.abort_handle())),
        ))
    }
}

impl Leg {
    /// Each granted node's offered models, and why any was not asked.
    async fn catalogs(
        &self,
    ) -> (
        Vec<(MachineId, Result<Vec<LlmCatalogEntry>, Absent>)>,
        Vec<String>,
    ) {
        let mut tried = Vec::new();
        let mut answers = Vec::new();
        for machine in self.nodes(&mut tried) {
            answers.push((machine, self.catalog_on(machine).await));
        }
        (answers, tried)
    }

    /// The models `machine` offers, sent within [`CATALOG_TIMEOUT`] of the
    /// dial, so a node that hangs mid-reply holds no refresh.
    async fn catalog_on(&self, machine: MachineId) -> Result<Vec<LlmCatalogEntry>, Absent> {
        let conn = self.dial(machine).await?;
        let asked = tokio::time::timeout(CATALOG_TIMEOUT, async {
            match exchange(&*conn, &Request::Catalog)
                .await
                .map_err(|err| err.to_string())?
            {
                Reply::Catalog(carried) => {
                    let body = take(&*conn, carried, &self.budget)
                        .await
                        .map_err(|err| err.to_string())?;
                    serde_json::from_slice(&body.bytes)
                        .map_err(|_| "its catalog does not decode".to_owned())
                }
                Reply::Refused(why) => Err(why),
                _ => Err("an unexpected reply".into()),
            }
        })
        .await
        .unwrap_or_else(|_| Err("did not send its catalog in time".into()));
        conn.close();
        asked
    }

    fn nodes(&self, tried: &mut Vec<String>) -> Vec<MachineId> {
        let nodes = self.nodes.nodes().unwrap_or_else(|err| {
            tried.push(format!("the node roster: {err}"));
            Vec::new()
        });
        if nodes.is_empty() {
            tried.push("no other node of yours is granted model calls".into());
        }
        nodes
    }

    /// No node took the call: say why, pause, and try again.
    async fn wait(&self, model: &str, tried: &[String], pause: &mut Duration) {
        *lock(&self.waiting) = Some(format!(
            "waiting for a node that can run {model}: {}",
            tried.join("; ")
        ));
        tokio::time::sleep(*pause).await;
        *pause = (*pause * 2).min(PAUSE_MOST);
    }

    fn taken(&self) {
        *lock(&self.waiting) = None;
    }

    /// Notes the machine `conn`'s authenticated handshake proved for the
    /// node dialled as `machine` (FIX 4938): a proof naming another machine
    /// proves none.
    fn note_proof(&self, machine: MachineId, conn: &dyn MeshConnection) {
        let proved = self.nodes.proved(conn.endpoint_key());
        let peer = match proved {
            PeerMachine::Proven { machine: named, .. } if named == machine => proved,
            _ => PeerMachine::Unknown,
        };
        lock(&self.proofs).insert(machine, peer);
    }

    async fn dial(&self, machine: MachineId) -> Result<Box<dyn MeshConnection>, Absent> {
        match tokio::time::timeout(DIAL_TIMEOUT, self.transport.dial(machine, LLM_ALPN)).await {
            Ok(Ok(conn)) => {
                self.note_proof(machine, &*conn);
                Ok(conn)
            }
            Ok(Err(err)) => Err(format!("unreachable: {err}")),
            Err(_) => Err("did not answer".into()),
        }
    }

    async fn generate(&self, request: LlmRequest) -> LlmResult<LlmResponse> {
        let body = serde_json::to_vec(&request).map_err(|_| FatalLlmError::InvalidRequest)?;
        let model = request.model.to_string();
        let mut pause = PAUSE_FIRST;
        loop {
            let mut tried = Vec::new();
            for machine in self.nodes(&mut tried) {
                match self.generate_on(machine, &body).await {
                    Ok(answer) => {
                        self.taken();
                        return answer;
                    }
                    Err(why) => tried.push(format!("node {}: {why}", machine.to_hex())),
                }
            }
            self.wait(&model, &tried, &mut pause).await;
        }
    }

    /// The node's answer, or why it did not take the call.
    async fn generate_on(
        &self,
        machine: MachineId,
        body: &[u8],
    ) -> Result<LlmResult<LlmResponse>, Absent> {
        let conn = self.dial(machine).await?;
        let answer = async {
            let request = put(&*conn, body.to_vec())
                .await
                .map_err(|err| err.to_string())?;
            match exchange(&*conn, &Request::Generate { request })
                .await
                .map_err(|err| err.to_string())?
            {
                Reply::Generated(Ok(carried)) => {
                    let body = take(&*conn, carried, &self.budget)
                        .await
                        .map_err(|err| err.to_string())?;
                    Ok(serde_json::from_slice(&body.bytes)
                        .map_err(|_| FatalLlmError::InvalidRequest.into()))
                }
                Reply::Generated(Err(error)) => Ok(Err(error)),
                Reply::Refused(why) => Err(why),
                _ => Err("an unexpected reply".into()),
            }
        }
        .await;
        conn.close();
        answer
    }

    async fn stream(&self, request: LlmRequest, pump: &Demand) {
        let body = match serde_json::to_vec(&request) {
            Ok(body) => body,
            Err(_) => {
                pump.hand(Err(FatalLlmError::InvalidRequest.into()), None)
                    .await;
                return;
            }
        };
        let model = request.model.to_string();
        let mut pause = PAUSE_FIRST;
        loop {
            let mut tried = Vec::new();
            for machine in self.nodes(&mut tried) {
                match self.stream_on(machine, &body, pump).await {
                    Ok(()) => return,
                    Err(why) => tried.push(format!("node {}: {why}", machine.to_hex())),
                }
            }
            if pump.is_closed() {
                return;
            }
            self.wait(&model, &tried, &mut pause).await;
        }
    }

    /// Runs the stream on one node, passing its events on as the caller
    /// takes them (FIX 8619): the node is asked for its next batch only once
    /// the caller has taken every event handed so far. `Err` when the node
    /// did not take it, or broke before any event went out: the next node
    /// runs it from the start.
    async fn stream_on(
        &self,
        machine: MachineId,
        body: &[u8],
        pump: &Demand,
    ) -> Result<(), Absent> {
        let conn = self.dial(machine).await?;
        let ran = async {
            let request = put(&*conn, body.to_vec())
                .await
                .map_err(|err| err.to_string())?;
            let id = match exchange(&*conn, &Request::Stream { request })
                .await
                .map_err(|err| err.to_string())?
            {
                Reply::Started(Ok(id)) => id,
                Reply::Started(Err(error)) => {
                    pump.hand(Err(error), None).await;
                    return Ok(());
                }
                Reply::Refused(why) => return Err(why),
                _ => return Err("an unexpected reply".into()),
            };
            self.taken();
            let mut flowed = false;
            loop {
                let Some(room) = pump.room().await else {
                    let _ = exchange(&*conn, &Request::Cancel { stream: id }).await;
                    return Ok(());
                };
                // Once events flow, a broken node ends the stream: its
                // events cannot be taken back. Before, another node can run it.
                let Some((events, end, booking)) = self.next_batch(&*conn, id).await else {
                    if !flowed {
                        return Err("broke before its first event".to_owned());
                    }
                    room.hand(
                        Err(RetryableLlmError::io_after_send(
                            "stream",
                            "broke after its first event",
                        )
                        .into()),
                        None,
                    );
                    return Ok(());
                };
                let (mut room, mut booking, last) = (Some(room), Some(booking), events.len());
                for (n, event) in events.into_iter().enumerate() {
                    let event = event.and_then(|json| {
                        serde_json::from_str::<LlmStreamEvent>(&json)
                            .map_err(|_| FatalLlmError::InvalidRequest.into())
                    });
                    let failed = event.is_err();
                    // The batch's bytes stay booked until its last event, or
                    // the error that ends it, is taken.
                    let closes = if failed || n + 1 == last {
                        booking.take()
                    } else {
                        None
                    };
                    let handed = match room.take() {
                        Some(room) => {
                            room.hand(event, closes);
                            true
                        }
                        None => pump.hand(event, closes).await,
                    };
                    if !handed || failed {
                        return Ok(());
                    }
                    flowed = true;
                }
                if end {
                    return Ok(());
                }
            }
        }
        .await;
        conn.close();
        ran
    }

    /// The node's next batch of stream `id`'s events, whether it is the
    /// last, and the booking of its bytes; `None` when the node broke.
    async fn next_batch(
        &self,
        conn: &dyn MeshConnection,
        id: u64,
    ) -> Option<(Vec<Result<String, LlmError>>, bool, Booking)> {
        let Ok(Reply::Events { events, end }) = exchange(conn, &Request::Next { stream: id }).await
        else {
            return None;
        };
        let BookedBody { bytes, booking } = take(conn, events, &self.budget).await.ok()?;
        let batch = rmp_serde::from_slice::<Batch>(&bytes).ok()?;
        Some((batch.events, end, booking))
    }
}

/// One of the owner's nodes, sent each call once (FIX 3229): the transport
/// under a model the router learned from that node's catalog. It never tries
/// another node and never sends a call again, so it may sit under a run's
/// gate; a node that does not take the call fails it, and the ladder above
/// decides whether the call waits.
pub struct MeshPeerTransport {
    leg: Arc<Leg>,
    machine: MachineId,
    runtime: Handle,
}

impl std::fmt::Debug for MeshPeerTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshPeerTransport")
            .field("machine", &self.machine.to_hex())
            .finish_non_exhaustive()
    }
}

impl MeshLlmTransport {
    /// This transport's mesh, sending each call once to `machine` alone.
    #[must_use]
    pub fn peer(&self, machine: MachineId) -> MeshPeerTransport {
        MeshPeerTransport {
            leg: Arc::clone(&self.leg),
            machine,
            runtime: self.runtime.clone(),
        }
    }
}

/// The machine a node's last authenticated mesh handshake proved (FIX
/// 4938): what a call to it is judged as, each judge revalidating the proof
/// in its own snapshot. Unproved until a handshake proved it.
#[derive(Clone)]
pub struct MeshPeerProof {
    leg: Arc<Leg>,
    machine: MachineId,
}

impl std::fmt::Debug for MeshPeerProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshPeerProof")
            .field("machine", &self.machine.to_hex())
            .finish_non_exhaustive()
    }
}

impl MeshPeerProof {
    /// The proved machine, or `Unknown`.
    #[must_use]
    pub fn peer(&self) -> PeerMachine {
        lock(&self.leg.proofs)
            .get(&self.machine)
            .copied()
            .unwrap_or(PeerMachine::Unknown)
    }
}

impl MeshPeerTransport {
    /// What the handshakes with this transport's node proved.
    #[must_use]
    pub fn proof(&self) -> MeshPeerProof {
        MeshPeerProof {
            leg: Arc::clone(&self.leg),
            machine: self.machine,
        }
    }
}

impl oneiron::llm::SingleSend for MeshPeerTransport {}

impl OwnServerTransport for MeshPeerTransport {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let (leg, machine) = (Arc::clone(&self.leg), self.machine);
        let task = self.runtime.spawn(async move {
            match serde_json::to_vec(&request) {
                // A node that does not take the call fails it; no other
                // node runs it.
                Ok(body) => leg
                    .generate_on(machine, &body)
                    .await
                    .unwrap_or_else(|_| Err(RetryableLlmError::ServerError.into())),
                Err(_) => Err(FatalLlmError::InvalidRequest.into()),
            }
        });
        let guard = AbortOnDrop(task.abort_handle());
        Box::pin(async move {
            let _guard = guard;
            task.await.unwrap_or_else(|error| {
                Err(RetryableLlmError::io_after_send("generate", error.to_string()).into())
            })
        })
    }

    fn stream<'a>(&'a self, request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        let body = serde_json::to_vec(&request).map_err(|_| FatalLlmError::InvalidRequest)?;
        let (leg, machine) = (Arc::clone(&self.leg), self.machine);
        let (pump, end) = demand();
        let task = self.runtime.spawn(async move {
            // The node did not take the stream, or broke before its first
            // event: nothing went out, and no other node runs it.
            if leg.stream_on(machine, &body, &pump).await.is_err() {
                pump.hand(Err(RetryableLlmError::ServerError.into()), None)
                    .await;
            }
        });
        Ok(LlmStream::new(
            end.guarded(AbortOnDrop(task.abort_handle())),
        ))
    }
}
