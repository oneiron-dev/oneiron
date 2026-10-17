//! The asking side: the first of the owner's nodes that takes the call runs
//! it; with none, the call waits and says why, trying again until one does.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use oneiron::{
    BudgetLease, FatalLlmError, LlmCatalogEntry, LlmGenerateFuture, LlmRequest, LlmResponse,
    LlmResult, LlmStream, LlmStreamEvent, LlmStreamResult, RetryableLlmError, Vault,
};
use oneiron_mesh_transport::{MachineId, MeshConnection, MeshTransport};
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

use super::catalog::{CatalogRefresh, merge, mesh_row};
use super::{Batch, LLM_ALPN, Reply, Request, exchange, lock, put, take};
use crate::OwnServerTransport;

/// How long a node has to answer the dial.
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
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
    /// Why calls wait now; `None` while a node takes them.
    waiting: Mutex<Option<String>>,
}

/// Why one node did not take a call: another may.
type Absent = String;

impl MeshLlmTransport {
    /// Calls go out on `runtime`, which drives `transport`.
    #[must_use]
    pub fn new(
        transport: Arc<dyn MeshTransport>,
        nodes: Arc<dyn LlmNodes>,
        runtime: Handle,
    ) -> Self {
        Self {
            leg: Arc::new(Leg {
                transport,
                nodes,
                waiting: Mutex::new(None),
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
    /// already route another way. A node that does not answer keeps the
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
                    for entry in entries {
                        let model = entry.model.clone();
                        let Some(row) = mesh_row(machine, entry) else {
                            continue;
                        };
                        if merge(vault, row)? {
                            refresh.written.push(model);
                        } else {
                            refresh.conflicts.push(model);
                        }
                    }
                }
                Err(why) => unreached.push(format!("node {}: {why}", machine.to_hex())),
            }
        }
        refresh.unreached = unreached;
        Ok(refresh)
    }
}

/// Stops the spawned call when the caller lets it go.
struct AbortOnDrop(AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
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
            task.await
                .unwrap_or_else(|_| Err(RetryableLlmError::StreamCut.into()))
        })
    }

    fn stream<'a>(&'a self, request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        let leg = Arc::clone(&self.leg);
        let (send, receive) = mpsc::unbounded_channel();
        let task = self
            .runtime
            .spawn(async move { leg.stream(request, send).await });
        Ok(LlmStream::new(Received {
            receive,
            _guard: AbortOnDrop(task.abort_handle()),
        }))
    }
}

struct Received {
    receive: mpsc::UnboundedReceiver<LlmResult<LlmStreamEvent>>,
    _guard: AbortOnDrop,
}

impl futures_core::Stream for Received {
    type Item = LlmResult<LlmStreamEvent>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.receive.poll_recv(cx)
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

    /// The models `machine` offers.
    async fn catalog_on(&self, machine: MachineId) -> Result<Vec<LlmCatalogEntry>, Absent> {
        let conn = self.dial(machine).await?;
        let asked = async {
            match exchange(&*conn, &Request::Catalog)
                .await
                .map_err(|err| err.to_string())?
            {
                Reply::Catalog(carried) => {
                    let bytes = take(&*conn, carried).await.map_err(|err| err.to_string())?;
                    serde_json::from_slice(&bytes)
                        .map_err(|_| "its catalog does not decode".to_owned())
                }
                Reply::Refused(why) => Err(why),
                _ => Err("an unexpected reply".into()),
            }
        }
        .await;
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

    async fn dial(&self, machine: MachineId) -> Result<Box<dyn MeshConnection>, Absent> {
        match tokio::time::timeout(DIAL_TIMEOUT, self.transport.dial(machine, LLM_ALPN)).await {
            Ok(Ok(conn)) => Ok(conn),
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
                    let bytes = take(&*conn, carried).await.map_err(|err| err.to_string())?;
                    Ok(serde_json::from_slice(&bytes)
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

    async fn stream(
        &self,
        request: LlmRequest,
        send: mpsc::UnboundedSender<LlmResult<LlmStreamEvent>>,
    ) {
        let body = match serde_json::to_vec(&request) {
            Ok(body) => body,
            Err(_) => {
                let _ = send.send(Err(FatalLlmError::InvalidRequest.into()));
                return;
            }
        };
        let model = request.model.to_string();
        let mut pause = PAUSE_FIRST;
        loop {
            let mut tried = Vec::new();
            for machine in self.nodes(&mut tried) {
                match self.stream_on(machine, &body, &send).await {
                    Ok(()) => return,
                    Err(why) => tried.push(format!("node {}: {why}", machine.to_hex())),
                }
            }
            if send.is_closed() {
                return;
            }
            self.wait(&model, &tried, &mut pause).await;
        }
    }

    /// Runs the stream on one node, passing its events on. `Err` when the
    /// node did not take it, or broke before any event went out: the next
    /// node runs it from the start.
    async fn stream_on(
        &self,
        machine: MachineId,
        body: &[u8],
        send: &mpsc::UnboundedSender<LlmResult<LlmStreamEvent>>,
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
                    let _ = send.send(Err(error));
                    return Ok(());
                }
                Reply::Refused(why) => return Err(why),
                _ => return Err("an unexpected reply".into()),
            };
            self.taken();
            let mut flowed = false;
            loop {
                if send.is_closed() {
                    let _ = exchange(&*conn, &Request::Cancel { stream: id }).await;
                    return Ok(());
                }
                // Once events flow, a broken node ends the stream: its
                // events cannot be taken back. Before, another node can run it.
                let cut = |flowed: bool| {
                    if !flowed {
                        return Err("broke before its first event".to_owned());
                    }
                    let _ = send.send(Err(RetryableLlmError::StreamCut.into()));
                    Ok(())
                };
                let (events, end) = match exchange(&*conn, &Request::Next { stream: id }).await {
                    Ok(Reply::Events { events, end }) => (events, end),
                    _ => return cut(flowed),
                };
                let batch = match take(&*conn, events)
                    .await
                    .ok()
                    .and_then(|bytes| rmp_serde::from_slice::<Batch>(&bytes).ok())
                {
                    Some(batch) => batch,
                    None => return cut(flowed),
                };
                for event in batch.events {
                    let event = event.and_then(|json| {
                        serde_json::from_str::<LlmStreamEvent>(&json)
                            .map_err(|_| FatalLlmError::InvalidRequest.into())
                    });
                    let failed = event.is_err();
                    if send.send(event).is_err() || failed {
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
}
