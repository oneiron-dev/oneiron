//! The issuer's side of the work-order loop (pass 34, section 0; Engine ruling EM-22 = A): what
//! the engine's pass (`oneiron::work_order`) cannot store. A pass asks each machine an open
//! order may run on what it offers now (`Node` on the job protocol), and makes an attempt
//! through the built quote and start on the order's offer, with the machine the PLACE rule
//! picked as the quote's `inputs.machine`. The start's own write checks the order again and
//! writes its attempt entry beside the job. A line unit's attempt (row H3) is the line's
//! reserve, which writes the claim and the attempt entry in one write, then the claimed start
//! of the claim's one job on the order's offer.
//!
//! The pass runs on the built job worker (`gpu_host.rs`, OPUS-LE-FLEET's file), on its tick and
//! on each wake: one worker. Its readiness read is the child module `readiness_read`.

mod readiness_read;

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock};

use oneiron::EntityId;
use oneiron::gpu_job::{
    GpuJobActor, GpuJobConnector, GpuJobError, GpuJobRequest, GpuJobStart, GpuOffer, UnitJobStart,
};
use oneiron::llm::decision::{DecisionAnswer, DecisionRung, HumanAskReason};
use oneiron::memory::MEMORY_CODE_MODEL_UNAVAILABLE;
use oneiron::task_verb::sdk::{AiVerdict, AiVerdictRequest};
use oneiron::work_order::decider::{DeciderReceipt, DeciderReply, SlotAsk, SlotAskWindow};
use oneiron::work_order::{
    AttemptOutcome, AttemptRefused, AttemptToMake, Blocker, MachineFacts, MachineReach,
    OrderAttemptRef, OrderCharge, OrderHost, PassReport, Room, TemplateFact, WorkOrder,
};

use crate::gpu_execution_node::issuer::node_status::node_answer;
use crate::gpu_execution_node::issuer::{
    JobNodeClient, NodeCallError, VAULT_MACHINE_BACKEND, not_the_issuer,
};
use crate::gpu_execution_node::wire::{
    JobAnswer, JobRefusal, JobRequest, JobStatusAnswer, JobStatusRequest, LogTailRequest,
    NodeAnswer,
};
use crate::gpu_host::{GpuHostError, job_admission, job_backend, offer_with_backend};
use crate::server::SyncServer;

use readiness_read::mesh_bound;
pub(crate) use readiness_read::run_readiness_read;
#[cfg(oneiron_test_support)]
pub(crate) use readiness_read::worker_pass_asks;

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

/// The facts `node` gives, read through the one view of a node's `Node` answer
/// ([`node_answer`], the one `vault.machines.status` shows): the loop reads no field of the wire
/// answer itself.
fn fill_from_node(facts: &mut MachineFacts, node: &NodeAnswer, now_ms: u64) {
    let node = node_answer(node.clone());
    facts.reach = MachineReach::Answered { at_ms: now_ms };
    facts.enabled = node.enabled;
    facts.paused = node.paused;
    facts.drained = node.drained;
    facts.templates = Some(
        node.templates
            .into_iter()
            .map(|template| TemplateFact {
                name: template.name,
                digest: template.digest,
            })
            .collect(),
    );
    let free = node
        .disk_free_bytes
        .saturating_sub(node.disk_reserved_bytes)
        .saturating_sub(node.disk_reserve_bytes);
    facts.room.disk_free_mib = Some(free / MIB);
}

/// The loop's host on this server: the node calls through `nodes`, the offers and backends of
/// `[gpu_jobs]`.
pub(crate) struct ServerOrderHost<'a> {
    server: &'a SyncServer,
    nodes: &'a dyn JobNodeClient,
    now_ms: u64,
    /// Whether this host is the job worker's own pass, which acts on each `Node` answer's
    /// readiness fact. A placement preview (`vault.machines.place`) and the order door's
    /// immediate pass only read it.
    observe: bool,
    /// The issuer's clock, which dates each `Node` request the worker's pass sends when it is
    /// sent (REVIEW-10544 round 2 P1).
    clock: &'a dyn Fn() -> u64,
}

impl<'a> ServerOrderHost<'a> {
    pub(crate) fn new(server: &'a SyncServer, nodes: &'a dyn JobNodeClient, now_ms: u64) -> Self {
        Self {
            server,
            nodes,
            now_ms,
            observe: false,
            clock: &crate::gpu_host::now_ms,
        }
    }

    /// This host as the job worker's pass: it acts on the readiness facts it reads, on the
    /// vault's issuer of vault machine jobs only (`[gpu_jobs.vault_machine] issuer` names this
    /// install's MACHINE). Another replica that dispatches an offer to the same node reads its
    /// answers and acts on none: neither clears the issuer's drain nor queues the owner's ask
    /// (REVIEW-10518 round 2 P1).
    pub(crate) fn observing(self) -> Self {
        let issuer = not_the_issuer(self.server, VAULT_MACHINE_BACKEND).is_ok();
        Self {
            observe: issuer,
            ..self
        }
    }

    /// Makes a line unit's attempt (row H3): the line's reserve writes the claim and the order's
    /// attempt entry in one write, then the claimed start writes the claim's one job on
    /// `offer_name` under `GpuJobActor::Order`. Once the reserve's write commits the attempt is
    /// made, whatever the start answers: a start the gate refuses releases the claim, and a
    /// claim that never starts is released by custody; the loop reads either as the attempt's
    /// end.
    fn make_line_attempt(&self, attempt: &AttemptToMake<'_>, offer_name: &str) -> AttemptOutcome {
        if let Err(blocker) = dispatches_offer(self.server, offer_name) {
            return AttemptOutcome::Refused(vec![blocker]);
        }
        let (offer, connector) = match offer_with_backend(self.server, offer_name) {
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
        match self
            .server
            .vault
            .reserve_order_attempt(attempt, self.now_ms)
        {
            Ok(Ok(_)) => {}
            Ok(Err(AttemptRefused::OrderChanged)) => return AttemptOutcome::OrderChanged,
            Ok(Err(AttemptRefused::Blocked(blocker))) => {
                return AttemptOutcome::Refused(vec![blocker]);
            }
            // A store failure: the order waits and the next pass asks again.
            Err(error) => {
                return AttemptOutcome::Refused(vec![Blocker::LineNotReady {
                    reason: format!("store_failure: {error}"),
                }]);
            }
        }
        if let Err(why) = self.start_line_attempt(attempt, &offer.offer, connector.as_ref()) {
            tracing::warn!(
                order = %attempt.order.id.to_hex(),
                attempt = attempt.n,
                why = %why,
                "a line unit's attempt reserved its claim and did not start its job"
            );
        }
        AttemptOutcome::Made
    }

    /// The claimed start of the claim `attempt`'s reserve made: quoted on the claim's id with
    /// the claim's job request (its machine is the PLACE pick the reserve pinned), and the one
    /// device the machine's facts give it, when they give one.
    fn start_line_attempt(
        &self,
        attempt: &AttemptToMake<'_>,
        offer: &GpuOffer,
        connector: &dyn GpuJobConnector,
    ) -> Result<(), String> {
        let key = attempt
            .order
            .claim_key(attempt.n)
            .ok_or("a line unit's order has a claim key")?;
        let mut request = self
            .server
            .vault
            .unit_job_request(&key, self.now_ms)
            .map_err(|error| error.to_string())?
            .ok_or("the attempt's claim no longer stands claimed")?;
        if let [device] = attempt.devices.as_slice() {
            request.inputs["device_id"] = serde_json::Value::String(device.clone());
        }
        let quote = offer
            .quote_for(
                attempt.job,
                &request,
                self.server.config.gpu_jobs.default_maximum_secs,
                self.now_ms,
            )
            .map_err(|error| error.to_string())?;
        let reference = attempt.reference();
        self.server
            .vault
            .start_claimed_gpu_job(
                UnitJobStart {
                    actor: GpuJobActor::Order(&reference),
                    offer,
                    quote: &quote,
                },
                &key,
                self.server.gpu_jobs.permits(),
                connector,
                self.now_ms,
            )
            .map(drop)
            .map_err(|error| error.to_string())
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
            OrderCharge::Line { offer, .. } => dispatches_offer(self.server, offer).is_ok(),
        }
    }

    /// Each machine's `Node` answer, as the pass's facts. On the worker's pass, the answer's
    /// readiness fact is acted on first ([`OrderLoop::ask_node_observing`]): a passed check
    /// clears the issuer's drain before the pass places, and a run of failed checks reaches the
    /// owner (CG-2 row 9). Each request is dated when it is sent. Before the mesh listener is
    /// bound no request can start, so none is recorded then.
    fn machine_facts(&self, machines: &[EntityId]) -> Vec<MachineFacts> {
        let orders = self.server.gpu_jobs.orders();
        let observe = self.observe && mesh_bound(self.server);
        machines
            .iter()
            .map(|machine| {
                let answer = if observe {
                    let at_ms = (self.clock)();
                    orders.ask_node_observing(&self.server.vault, self.nodes, *machine, at_ms)
                } else {
                    self.nodes.job(*machine, &JobRequest::Node)
                };
                facts_of_answer(*machine, answer.ok().as_ref(), self.now_ms)
            })
            .collect()
    }

    fn make_attempt(&self, attempt: &AttemptToMake<'_>) -> AttemptOutcome {
        let name = match &attempt.order.charge {
            OrderCharge::Offer { name } => name,
            // A line unit's attempt is the line's reserve (row H3), never a bare start.
            OrderCharge::Line { offer, .. } => return self.make_line_attempt(attempt, offer),
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
        let connector = job_backend(self.server, &job_row).map_err(|error| error.to_string())?;
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

    /// The slot's decider (row P1), asked through this host's decision ladder as one
    /// `ai.verdict` read of the decider's agent: a Choice over the options, inside the slot's
    /// deadline, metered on that agent's own read line. Counted against the slot's hourly
    /// ceiling first. Every model rung blocks on the runtime; the pass runs on a blocking
    /// thread.
    fn decide(&self, ask: &SlotAsk) -> DeciderReply {
        decide_slot_ask(self.server, ask, self.now_ms)
    }
}

/// A slot's decider (row P1; an agent run's PLACE, row P4), asked through `server`'s decision
/// ladder as one `ai.verdict` read of the decider's agent: a Choice over the options, inside the
/// slot's deadline, metered on that agent's own read line. Counted against the slot's hourly
/// ceiling at `now_ms` first. Every model rung blocks on the runtime, so the caller runs on a
/// blocking thread.
pub(crate) fn decide_slot_ask(server: &SyncServer, ask: &SlotAsk, now_ms: u64) -> DeciderReply {
    let admitted = server
        .gpu_jobs
        .orders()
        .asks
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .admit(ask.slot, ask.grant, ask.max_asks_per_hour, now_ms);
    if !admitted {
        return DeciderReply::Ceiling;
    }
    let request = match slot_verdict_request(ask) {
        Ok(request) => request,
        Err(why) => {
            return DeciderReply::Failed {
                why: why.to_owned(),
                receipt: None,
            };
        }
    };
    let memory = server.vault.memory(ask.agent, ask.class);
    let mut evidence_read = Vec::new();
    let answered = crate::decision_verdict::run_verdict_reasoned(
        server,
        ask.agent,
        ask.class,
        &memory,
        None,
        None,
        &request,
        None,
        &mut evidence_read,
        None,
    );
    match answered {
        Err(error) if error.code == MEMORY_CODE_MODEL_UNAVAILABLE => DeciderReply::NoModel,
        Err(error) => DeciderReply::Failed {
            why: error.to_string(),
            receipt: None,
        },
        Ok((verdict, no_answer)) => {
            let receipt = decider_receipt(&verdict);
            match (verdict.answer, no_answer) {
                (DecisionAnswer::Choice(label), _) => DeciderReply::Answered { label, receipt },
                (DecisionAnswer::Abstain, Some(HumanAskReason::ProviderUnavailable))
                    if no_model_read(&verdict.receipt.providers) =>
                {
                    DeciderReply::NoModel
                }
                (DecisionAnswer::Abstain, Some(HumanAskReason::Deadline)) => DeciderReply::Silent {
                    receipt: Some(receipt),
                },
                (DecisionAnswer::Abstain, _) => DeciderReply::Abstained {
                    receipt: Some(receipt),
                },
                (_, _) => DeciderReply::Failed {
                    why: "the decider's read gave no choice".to_owned(),
                    receipt: Some(receipt),
                },
            }
        }
    }
}

/// The `ai.verdict` request of one slot ask: the slot's question, a Choice over its options,
/// the facts it shows as the state, and the slot's deadline as the read's clock.
fn slot_verdict_request(ask: &SlotAsk) -> Result<AiVerdictRequest, &'static str> {
    serde_json::from_value(serde_json::json!({
        "question": ask.question(),
        "contract": { "kind": "choice", "options": ask.options },
        "state": ask.facts,
        "deadline_ms": ask.deadline_ms.max(1),
    }))
    .map_err(|_| "the slot's verdict request does not decode")
}

/// Whether only the rule rung (or none) read the question: no model on this host takes it.
fn no_model_read(providers: &[oneiron::llm::decision::ProviderPin]) -> bool {
    providers
        .iter()
        .all(|pin| matches!(pin.rung, DecisionRung::Rule | DecisionRung::Human))
}

/// What a slot decision keeps of the read's receipt: the question, the providers tried, the
/// rung that answered, the probability and the cost, and no model text.
fn decider_receipt(verdict: &AiVerdict) -> DeciderReceipt {
    let rung_name = |rung: &DecisionRung| {
        serde_json::to_value(rung)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_default()
    };
    DeciderReceipt::of_read(
        verdict.receipt.question.to_hex(),
        verdict
            .receipt
            .providers
            .iter()
            .map(|pin| format!("{}:{}@{}", rung_name(&pin.rung), pin.model, pin.version))
            .collect(),
        verdict.rung.as_ref().map(rung_name),
        verdict.p,
        verdict.receipt.cost_per_thousand,
    )
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
/// charged to an offer this server does not dispatch are left to the issuer. Only the job
/// worker's pass (`observe`) acts on the readiness facts it reads. The order door's immediate
/// pass only reads them.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn order_pass(
    server: &Arc<SyncServer>,
    nodes: &dyn JobNodeClient,
    now_ms: u64,
    observe: bool,
) -> oneiron::Result<PassReport> {
    let host = ServerOrderHost::new(server, nodes, now_ms);
    let host = if observe { host.observing() } else { host };
    server.vault.work_order_pass(&host, now_ms)
}

/// The loop's state on this server: the wake its events send, the one-pass-at-a-time lock, and
/// the node client its passes call through. Held by the job worker's host (hunk H2).
#[derive(Default)]
pub(crate) struct OrderLoop {
    wake: tokio::sync::Notify,
    pass: Mutex<()>,
    nodes: OnceLock<Arc<dyn JobNodeClient>>,
    /// The slot deciders' asks this hour (row P1): the ceiling `policy.slots.max_asks_per_hour`
    /// counts them here, so an issuer that restarts opens a new window.
    asks: Mutex<SlotAskWindow>,
    /// The worker's readings of each machine's readiness fact, by its pass and by its scheduled
    /// read: the last sample and the clear baseline of each machine read in the last
    /// `ReadinessReads::IDLE_MS`, and the last ask of each machine the read may ask (CG-2 row 9).
    readiness: Mutex<crate::gpu_execution_node::issuer::guard::ReadinessReads>,
    /// Whether the worker's scheduled readiness read runs now: one runs at a time.
    reading: Arc<AtomicBool>,
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

    /// The node client passes call through. Only a client that calls machines is kept, made at
    /// the first call with a runtime at hand; a call with none answers through [`NoNodes`] and
    /// leaves the next call to make it, so an early call off the runtime never cuts the loop
    /// off from every machine.
    pub(crate) fn nodes(&self, server: &Arc<SyncServer>) -> Arc<dyn JobNodeClient> {
        if let Some(client) = self.nodes.get() {
            return Arc::clone(client);
        }
        match node_client(server) {
            Some(client) => Arc::clone(self.nodes.get_or_init(|| client)),
            None => Arc::new(NoNodes),
        }
    }

    /// Answers node calls through `nodes` from now on, as a test's scripted machines do.
    #[cfg(oneiron_test_support)]
    pub(crate) fn use_nodes(&self, nodes: Arc<dyn JobNodeClient>) -> bool {
        self.nodes.set(nodes).is_ok()
    }
}

/// Whether the job worker's pass on `server` acts on the readiness facts it reads
/// ([`ServerOrderHost::observing`]), for `tests/issuer_readiness_drain.rs`.
#[cfg(oneiron_test_support)]
pub(crate) fn worker_pass_observes(server: &SyncServer) -> bool {
    ServerOrderHost::new(server, &NoNodes, 0)
        .observing()
        .observe
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

/// A client of `server`'s mesh listener whose calls run on the runtime at hand, or `None` where
/// no runtime is at hand.
#[cfg(feature = "mesh")]
fn node_client(server: &Arc<SyncServer>) -> Option<Arc<dyn JobNodeClient>> {
    let runtime = tokio::runtime::Handle::try_current().ok()?;
    Some(Arc::new(
        crate::gpu_execution_node::issuer::MeshJobNodeClient::new(
            Arc::downgrade(server),
            runtime,
            std::time::Duration::from_secs(server.config.gpu_jobs.vault_machine.call_timeout_secs),
        ),
    ))
}

/// A server built without the mesh calls no machines.
#[cfg(not(feature = "mesh"))]
fn node_client(_server: &Arc<SyncServer>) -> Option<Arc<dyn JobNodeClient>> {
    None
}

/// The order door's immediate pass at `now_ms`, under the loop's lock. It reads each machine's
/// readiness fact and acts on none; the worker's next pass does.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn locked_order_pass(
    server: &Arc<SyncServer>,
    now_ms: u64,
) -> oneiron::Result<PassReport> {
    locked_pass(server, now_ms, false)
}

/// One pass of the loop at `now_ms` under the loop's lock, so that a door's pass and the
/// worker's never run at once. `observe` as in [`order_pass`].
fn locked_pass(
    server: &Arc<SyncServer>,
    now_ms: u64,
    observe: bool,
) -> oneiron::Result<PassReport> {
    let orders = server.gpu_jobs.orders();
    let _pass = orders
        .pass
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let nodes = orders.nodes(server);
    order_pass(server, nodes.as_ref(), now_ms, observe)
}

/// The worker's pass (hunk H2 calls it on each tick and wake): one pass, its failure logged. It
/// is the one pass that acts on the readiness facts it reads.
pub(crate) fn run_order_pass(server: &Arc<SyncServer>, now_ms: u64) {
    match locked_pass(server, now_ms, true) {
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

/// One `Tail` of a key's log on `machine` through the node client the loop calls through
/// (`vault.jobs.logs.tail`, pass 34 7.2). It blocks on the node: call it off the runtime.
pub(crate) fn tail_on_machine(
    server: &Arc<SyncServer>,
    machine: EntityId,
    request: LogTailRequest,
) -> Result<JobStatusAnswer, NodeCallError> {
    let nodes = server.gpu_jobs.orders().nodes(server);
    nodes.job_status(machine, &JobStatusRequest::Tail(request))
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
