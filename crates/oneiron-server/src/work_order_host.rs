//! The issuer's side of the work-order loop (pass 34, section 0; Engine ruling EM-22 = A): what
//! the engine's pass (`oneiron::work_order`) cannot store. A pass asks each machine an open
//! order may run on what it offers now (`Node` on the job protocol), and makes an attempt
//! through the built quote and start on the order's offer, with the machine the PLACE rule
//! picked as the quote's `inputs.machine`. The start's own write checks the order again and
//! writes its attempt entry beside the job.
//!
//! The pass runs on the built job worker (`gpu_host.rs`, OPUS-LE-FLEET's file), on its tick and
//! on each wake: one worker.

use std::sync::{Arc, Mutex, OnceLock};

use oneiron::EntityId;
use oneiron::gpu_job::{GpuJobActor, GpuJobError, GpuJobRequest, GpuJobStart};
use oneiron::work_order::{
    AttemptOutcome, AttemptRefused, AttemptToMake, Blocker, MachineFacts, MachineReach,
    OrderAttemptRef, OrderCharge, OrderHost, PassReport, Room, TemplateFact, WorkOrder,
};

use crate::gpu_execution_node::issuer::{JobNodeClient, NodeCallError, not_the_issuer};
use crate::gpu_execution_node::wire::{
    JobAnswer, JobRefusal, JobRequest, JobStatusAnswer, JobStatusRequest, NodeAnswer, WarmWanted,
};
use crate::gpu_host::{GpuHostError, job_admission, offer_with_backend};
use crate::server::SyncServer;

/// Bytes in a MiB.
const MIB: u64 = 1024 * 1024;

/// The node's refusal, by the node's own code (EM-19): each [`JobRefusal`] maps onto the
/// [`Blocker`] whose code is the one `job_refusal_code` gives it.
impl From<&JobRefusal> for Blocker {
    fn from(refusal: &JobRefusal) -> Self {
        match refusal {
            JobRefusal::NotEnabled => Self::NotEnabled,
            JobRefusal::PeerNotProven => Self::PeerNotProven,
            JobRefusal::NotIssuer => Self::NotIssuer,
            JobRefusal::OwnGrantEnded => Self::OwnGrantEnded,
            JobRefusal::IssuerStandingEnded => Self::IssuerStandingEnded,
            JobRefusal::Paused { why } => Self::Paused { why: why.clone() },
            JobRefusal::Drained { why } => Self::Drained { why: why.clone() },
            JobRefusal::NotReleasable { .. } => Self::NotReleasable,
            JobRefusal::HistoryLost => Self::HistoryLost,
            JobRefusal::KeyConflict => Self::KeyConflict,
            JobRefusal::NotTheKeysIssuer => Self::NotTheKeysIssuer,
            JobRefusal::SubmitSignatureInvalid => Self::SubmitSignatureInvalid,
            JobRefusal::DevicesUnreadable { why } => Self::DevicesUnreadable { why: why.clone() },
            JobRefusal::OutputNotFetchable { why } => Self::OutputNotFetchable { why: why.clone() },
            JobRefusal::NotAcknowledgeable { .. } => Self::NotAcknowledgeable,
            JobRefusal::LogNotReadable { why } => Self::LogNotReadable { why: why.clone() },
        }
    }
}

/// What the machine `machine` reported in `answer` at `now_ms`, as the loop's facts.
#[must_use]
pub fn facts_of_answer(machine: EntityId, answer: Option<&JobAnswer>, now_ms: u64) -> MachineFacts {
    let mut facts = MachineFacts {
        machine,
        reach: MachineReach::Unreachable { since_ms: None },
        enabled: false,
        refusal: None,
        paused: None,
        drained: None,
        templates: None,
        room: Room::default(),
        devices: None,
        window: None,
        keep_headroom_pct: None,
        roles: Vec::new(),
        warm: Vec::new(),
        warm_absent: Vec::new(),
    };
    match answer {
        Some(JobAnswer::Node(node)) => fill_from_node(&mut facts, node, now_ms),
        Some(JobAnswer::Refused(refusal)) => {
            facts.reach = MachineReach::Answered { at_ms: now_ms };
            facts.enabled = !matches!(refusal, JobRefusal::NotEnabled);
            facts.refusal = Some(Blocker::from(refusal));
        }
        // Busy, a receipt, a GPU sample (the answer to another request), or no answer: not
        // reachable for new work now.
        Some(JobAnswer::Busy { .. } | JobAnswer::Receipt(_) | JobAnswer::Availability(_))
        | None => {}
    }
    facts
}

fn fill_from_node(facts: &mut MachineFacts, node: &NodeAnswer, now_ms: u64) {
    facts.reach = MachineReach::Answered { at_ms: now_ms };
    facts.enabled = node.enabled;
    facts.paused.clone_from(&node.paused);
    facts.drained.clone_from(&node.drained);
    facts.templates = Some(
        node.templates
            .iter()
            .map(|template| TemplateFact {
                name: template.name.clone(),
                digest: template.digest.clone(),
            })
            .collect(),
    );
    let free = node
        .disk_free_bytes
        .saturating_sub(node.disk_reserved_bytes)
        .saturating_sub(node.disk_reserve_bytes);
    facts.room.disk_free_mib = Some(free / MIB);
    // Row P2: a key is warm here when its path is present, or, with no path, when an attempt
    // here used it (a hint); a mapped input that is not there blocks an order that lists it.
    facts.warm = node
        .warm
        .iter()
        .filter(|fact| fact.present || (!fact.mapped && fact.uses > 0))
        .map(|fact| fact.key.clone())
        .collect();
    facts.warm_absent = node
        .warm
        .iter()
        .filter(|fact| fact.mapped && !fact.cache && !fact.present)
        .map(|fact| fact.key.clone())
        .collect();
}

/// The loop's host on this server: the node calls through `nodes`, the offers and backends of
/// `[gpu_jobs]`.
pub(crate) struct ServerOrderHost<'a> {
    server: &'a SyncServer,
    nodes: &'a dyn JobNodeClient,
    now_ms: u64,
}

impl<'a> ServerOrderHost<'a> {
    pub(crate) fn new(server: &'a SyncServer, nodes: &'a dyn JobNodeClient, now_ms: u64) -> Self {
        Self {
            server,
            nodes,
            now_ms,
        }
    }

    /// The reference the built cancel checks for the live attempt of `order`.
    fn stop_reference(order: &WorkOrder) -> Option<OrderAttemptRef> {
        let last = order.last_attempt()?;
        Some(OrderAttemptRef {
            order: order.id,
            revision: order.revision,
            n: last.n,
            machine: last.machine,
            ranked: last.ranked.clone(),
            placed: last.placed.clone(),
        })
    }
}

/// The blockers a refused start names: the order's own refusal, the gate's, the budget's.
fn blockers_of_start(error: &GpuJobError) -> Option<Vec<Blocker>> {
    match error {
        GpuJobError::Order(AttemptRefused::OrderChanged) => None,
        GpuJobError::Order(AttemptRefused::Blocked(blocker)) => Some(vec![blocker.clone()]),
        GpuJobError::Denied(_) => Some(vec![Blocker::BudgetSpent]),
        other => Some(vec![Blocker::MachineRefuses {
            reason: other.to_string(),
        }]),
    }
}

impl OrderHost for ServerOrderHost<'_> {
    fn holds(&self, order: &WorkOrder) -> bool {
        match &order.charge {
            OrderCharge::Offer { name } => dispatches_offer(self.server, name).is_ok(),
            OrderCharge::Line { .. } => true,
        }
    }

    fn machine_facts(&self, machines: &[EntityId]) -> Vec<MachineFacts> {
        machines
            .iter()
            .map(|machine| {
                let answer = self.nodes.job(*machine, &JobRequest::Node).ok();
                facts_of_answer(*machine, answer.as_ref(), self.now_ms)
            })
            .collect()
    }

    fn machine_facts_wanting(&self, asks: &[(EntityId, Vec<String>)]) -> Vec<MachineFacts> {
        asks.iter()
            .map(|(machine, keys)| {
                let request = JobRequest::NodeWanting(WarmWanted { keys: keys.clone() });
                let answer = self.nodes.job(*machine, &request).ok();
                facts_of_answer(*machine, answer.as_ref(), self.now_ms)
            })
            .collect()
    }

    fn make_attempt(&self, attempt: &AttemptToMake<'_>) -> AttemptOutcome {
        let OrderCharge::Offer { name } = &attempt.order.charge else {
            // A line unit's attempt is the line's reserve (hunk H3), never a bare start.
            return AttemptOutcome::Refused(vec![Blocker::MachineMissing]);
        };
        let (offer, connector) = match offer_with_backend(self.server, name) {
            Ok(found) => found,
            Err(GpuHostError::NoBackend(_)) => {
                return AttemptOutcome::Refused(vec![Blocker::NotEnabled]);
            }
            Err(error) => {
                return AttemptOutcome::Refused(vec![Blocker::MachineRefuses {
                    reason: error.to_string(),
                }]);
            }
        };
        let mut inputs = serde_json::json!({ "machine": attempt.machine.to_hex() });
        if let [device] = attempt.devices.as_slice() {
            inputs["device_id"] = serde_json::Value::String(device.clone());
        }
        if !attempt.order.wishes.warm.is_empty() {
            inputs["warm"] = serde_json::json!(attempt.order.wishes.warm);
        }
        if let Some(result) = attempt.order.result {
            inputs["result"] = serde_json::json!({
                "artifact": result.artifact.to_hex(),
                "task": result.task.to_hex(),
            });
        }
        let request = GpuJobRequest {
            job_type: attempt.pin.template.clone(),
            image: attempt.order.workload.clone(),
            maximum_secs: Some(attempt.order.request.maximum_secs),
            inputs,
        };
        let quote = match offer.offer.quote(
            &request,
            Some(attempt.job),
            self.server.config.gpu_jobs.default_maximum_secs,
            self.now_ms,
        ) {
            Ok(quote) => quote,
            Err(error) => {
                return AttemptOutcome::Refused(vec![Blocker::MachineRefuses {
                    reason: error.to_string(),
                }]);
            }
        };
        let admission = job_admission(self.server, &offer.offer, &quote);
        let reference = attempt.reference();
        let started = self.server.vault.start_gpu_job(
            GpuJobStart {
                actor: GpuJobActor::Order(&reference),
                offer: &offer.offer,
                quote: &quote,
                resume: None,
                admission: &admission,
            },
            self.server.gpu_jobs.permits(),
            connector.as_ref(),
            self.now_ms,
        );
        match started {
            Ok(_) => AttemptOutcome::Made,
            Err(error) => match blockers_of_start(&error) {
                None => AttemptOutcome::OrderChanged,
                Some(blockers) => {
                    // A refusal after the write (the provider's create) leaves the attempt
                    // made: its job's end tells the loop.
                    if self
                        .server
                        .vault
                        .work_order(&attempt.order.id)
                        .ok()
                        .flatten()
                        .is_some_and(|order| order.attempts.len() >= usize::from(attempt.n))
                    {
                        AttemptOutcome::Made
                    } else {
                        AttemptOutcome::Refused(blockers)
                    }
                }
            },
        }
    }

    fn stop_attempt(&self, order: &WorkOrder, job: &EntityId) -> Result<(), String> {
        let reference = Self::stop_reference(order).ok_or("the order has no attempt")?;
        let job_row = self
            .server
            .vault
            .gpu_job(job)
            .map_err(|error| error.to_string())?
            .ok_or("the attempt's job is not on this issuer")?;
        let (_, connector) = offer_with_backend(self.server, &job_row.offer.name)
            .map_err(|error| error.to_string())?;
        self.server
            .vault
            .cancel_gpu_job(
                GpuJobActor::Order(&reference),
                job,
                self.server.gpu_jobs.permits(),
                connector.as_ref(),
                self.now_ms,
            )
            .map(drop)
            .map_err(|error| error.to_string())
    }
}

/// Whether this server dispatches orders charged to the offer `name`: the offer is posted
/// here, and for a `vault_machine` offer this server is the vault's issuer (one issuer, pass
/// 33, 8.7). `Err` names the refusal a door answers.
///
/// # Errors
///
/// [`Blocker::NotTheIssuer`] on a replica that is not the issuer.
pub fn dispatches_offer(server: &SyncServer, name: &str) -> Result<(), Blocker> {
    let Some(offer) = server.config.gpu_jobs.offer(name) else {
        return Ok(());
    };
    not_the_issuer(server, &offer.backend).map_err(|refused| Blocker::NotTheIssuer {
        issuer: refused.issuer.map(|issuer| issuer.to_hex()),
    })
}

/// One pass of the loop on this server at `now_ms`, with node calls through `nodes`. Orders
/// charged to an offer this server does not dispatch are left to the issuer.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn order_pass(
    server: &Arc<SyncServer>,
    nodes: &dyn JobNodeClient,
    now_ms: u64,
) -> oneiron::Result<PassReport> {
    server
        .vault
        .work_order_pass(&ServerOrderHost::new(server, nodes, now_ms), now_ms)
}

/// The loop's state on this server: the wake its events send, the one-pass-at-a-time lock, and
/// the node client its passes call through. Held by the job worker's host (hunk H2).
#[derive(Default)]
pub(crate) struct OrderLoop {
    wake: tokio::sync::Notify,
    pass: Mutex<()>,
    nodes: OnceLock<Arc<dyn JobNodeClient>>,
}

impl std::fmt::Debug for OrderLoop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrderLoop").finish_non_exhaustive()
    }
}

impl OrderLoop {
    /// Wakes the worker for a pass now: a new order, a cancel, an end.
    pub(crate) fn wake(&self) {
        self.wake.notify_one();
    }

    /// Resolves at the next wake.
    pub(crate) async fn woken(&self) {
        self.wake.notified().await;
    }

    /// The node client passes call through, made at first use.
    fn nodes(&self, server: &Arc<SyncServer>) -> Arc<dyn JobNodeClient> {
        Arc::clone(self.nodes.get_or_init(|| node_client(server)))
    }

    /// Answers node calls through `nodes` from now on, as a test's scripted machines do.
    #[cfg(oneiron_test_support)]
    pub(crate) fn use_nodes(&self, nodes: Arc<dyn JobNodeClient>) -> bool {
        self.nodes.set(nodes).is_ok()
    }
}

/// A node client for a server that cannot call nodes (no mesh, or no runtime): every machine
/// is unreachable.
struct NoNodes;

impl JobNodeClient for NoNodes {
    fn job(&self, _node: EntityId, _request: &JobRequest) -> Result<JobAnswer, NodeCallError> {
        Err(NodeCallError::Unreachable {
            reason: "this server calls no machines".to_owned(),
        })
    }

    fn job_status(
        &self,
        _node: EntityId,
        _request: &JobStatusRequest,
    ) -> Result<JobStatusAnswer, NodeCallError> {
        Err(NodeCallError::Unreachable {
            reason: "this server calls no machines".to_owned(),
        })
    }
}

#[cfg(feature = "mesh")]
fn node_client(server: &Arc<SyncServer>) -> Arc<dyn JobNodeClient> {
    match tokio::runtime::Handle::try_current() {
        Ok(runtime) => Arc::new(crate::gpu_execution_node::issuer::MeshJobNodeClient::new(
            Arc::downgrade(server),
            runtime,
            std::time::Duration::from_secs(server.config.gpu_jobs.vault_machine.call_timeout_secs),
        )),
        Err(_) => Arc::new(NoNodes),
    }
}

#[cfg(not(feature = "mesh"))]
fn node_client(_server: &Arc<SyncServer>) -> Arc<dyn JobNodeClient> {
    Arc::new(NoNodes)
}

/// One pass of the loop at `now_ms` under the loop's lock, so a door's pass and the worker's
/// never run at once.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn locked_order_pass(
    server: &Arc<SyncServer>,
    now_ms: u64,
) -> oneiron::Result<PassReport> {
    let orders = server.gpu_jobs.orders();
    let _pass = orders
        .pass
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let nodes = orders.nodes(server);
    order_pass(server, nodes.as_ref(), now_ms)
}

/// The worker's pass (hunk H2 calls it on each tick and wake): one pass, its failure logged.
pub(crate) fn run_order_pass(server: &Arc<SyncServer>, now_ms: u64) {
    match locked_order_pass(server, now_ms) {
        Ok(report) => {
            for (order, n, machine) in &report.made {
                tracing::info!(
                    order = %order.to_hex(),
                    attempt = n,
                    machine = %machine.to_hex(),
                    "work order attempt made"
                );
            }
        }
        Err(error) => tracing::warn!(error = %error, "work order pass failed"),
    }
}

/// The facts of `machines` as this server's node client reads them now.
pub(crate) fn machine_facts_now(
    server: &Arc<SyncServer>,
    machines: &[EntityId],
    now_ms: u64,
) -> Vec<MachineFacts> {
    let nodes = server.gpu_jobs.orders().nodes(server);
    ServerOrderHost::new(server, nodes.as_ref(), now_ms).machine_facts(machines)
}
