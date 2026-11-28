//! The loop (pass 34, section 0; Engine ruling EM-22 = A): one pass over the orders, run on the
//! built job worker's tick and on each event that may change a fit. One worker: a pass ends
//! before the next begins.
//!
//! ```text
//! for each attempt with no end: read its job's end -> AFTER: done | another attempt | give up
//! for each open order:          fit over the allowed machines -> runnable, or the reasons
//! for each runnable order, in the RANK rule's order:
//!     PLACE -> the built quote and start, which write the job and the order's attempt entry
//!     in one write, after checking the requester and the order's revision again
//! ```
//!
//! The issuer's host supplies what the engine cannot store: the machines' reported facts and
//! the built quote and start ([`OrderHost`]). What the start checks in its own write is
//! [`super::start_check`].
use std::collections::{BTreeMap, BTreeSet};

use crate::gpu_job::{GpuEndReason, GpuJobEnd, GpuJobState};
use crate::gpu_line::claim::{CUSTODY_LAPSED, release_claim_in_txn};
use crate::gpu_line::{ClaimState, UnitEnd, claim_in_txn, custody_lapsed_in_txn};
use crate::job_dispatch::DispatchClose;
use crate::job_workload::{JobWorkload, WorkloadPin, WorkloadStartAsk};
use crate::{EntityId, Vault};

use super::after::{AfterPick, after_rule};
use super::blocker::{BlockedOn, Blocker};
use super::caps::RunningCaps;
use super::decider::PassAsks;
use super::fit::{MachineFacts, MachineReach, Needs, fit, scope_allowed};
use super::place::place;
use super::rank::rank;
use super::record::{
    AttemptEnd, CancelWhy, EndKind, GiveUpWhy, OrderAttempt, OrderLimits, OrderState, SlotDecision,
    WorkOrder, attempt_job_id,
};
use super::setting_keys::retry_policy_in_txn;
use super::start_check::OrderAttemptRef;
use crate::warm_key::WarmWanted;

mod blocked;
mod order_rows;
use blocked::{closing_state, earliest_clear};

/// The node refusals inside a launch that clear by trying again (4.7): a busy device, an
/// authority fold that had not caught up, a warm input gone since the facts (row P2: fit then
/// keeps the order off that machine). Any other launch refusal is a changed pin.
pub const RETRYABLE_LAUNCH_REASONS: [&str; 3] =
    ["device_busy", "authority_stale", "warm_key_missing"];

/// What the issuer's host gives a pass.
pub trait OrderHost {
    /// Whether this host dispatches `order` (its offer is posted here, and for the vault's own
    /// machines this host is the issuer). The pass leaves every other order alone.
    fn holds(&self, _order: &WorkOrder) -> bool {
        true
    }

    /// The facts of `machines`, read once per pass. A machine the host cannot reach is
    /// reported as unreachable, never left out.
    fn machine_facts(&self, machines: &[EntityId]) -> Vec<MachineFacts>;

    /// [`Self::machine_facts`], each machine asked with the warm keys of the open orders that
    /// may run there (row P2), which its cache budget keeps. The default asks without them.
    fn machine_facts_wanting(&self, asks: &[(EntityId, WarmWanted)]) -> Vec<MachineFacts> {
        self.machine_facts(&asks.iter().map(|(machine, _)| *machine).collect::<Vec<_>>())
    }

    /// Makes `attempt` through the built quote and start, under the job id the order and the
    /// attempt number fix ([`attempt_job_id`]). The start's own write checks the order again
    /// ([`Vault::record_order_attempt_in_txn`]) and writes its attempt entry beside the job.
    fn make_attempt(&self, attempt: &AttemptToMake<'_>) -> AttemptOutcome;

    /// Asks the built cancel to stop `job`, the live attempt of `order`, which a cancel
    /// reached. Repeated on every pass until the attempt's end is in.
    ///
    /// # Errors
    ///
    /// Why the stop could not be asked now; the next pass asks again.
    fn stop_attempt(&self, order: &WorkOrder, job: &EntityId) -> Result<(), String>;

    /// Asks a slot's named decider (row P1) through the host's decision ladder; a host with no
    /// ladder answers that no model takes the question, and the rule decides.
    fn decide(&self, _ask: &super::decider::SlotAsk) -> super::decider::DeciderReply {
        super::decider::DeciderReply::NoModel
    }
}

/// One attempt the loop asks the host to make.
#[derive(Debug, Clone)]
pub struct AttemptToMake<'a> {
    /// The order as this pass read it: its revision is the one the start's write compares.
    pub order: &'a WorkOrder,
    pub n: u16,
    pub job: EntityId,
    pub machine: EntityId,
    /// The devices the machine's facts would give it, when it reports devices.
    pub devices: Vec<String>,
    pub pin: &'a WorkloadPin,
    pub ranked: SlotDecision,
    pub placed: SlotDecision,
}

impl AttemptToMake<'_> {
    /// The reference the start's write checks and records.
    #[must_use]
    pub fn reference(&self) -> OrderAttemptRef {
        OrderAttemptRef {
            order: self.order.id,
            revision: self.order.revision,
            n: self.n,
            machine: Some(self.machine),
            ranked: self.ranked.clone(),
            placed: self.placed.clone(),
        }
    }
}

/// What came of asking the host for an attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// The start wrote the job and the order's attempt entry in one write.
    Made,
    /// The order changed since this pass read it (a cancel, another write): nothing was made.
    OrderChanged,
    /// The start refused before anything was held, for these reasons.
    Refused(Vec<Blocker>),
}

/// How the job of an attempt stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttemptStanding {
    Live,
    /// No signed end and none can be had from the machine: the owner's write-off or a late
    /// receipt ends it (I3: unknown is never read as ended).
    Unconfirmed,
    Ended(EndKind),
}

/// The release reason of a line unit's claim a cancel of its order reached before its job.
const LINE_CLAIM_ORDER_CANCELLED: &str = "order_cancelled";

/// What one pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PassReport {
    /// Attempts made: order, attempt number, machine.
    pub made: Vec<(EntityId, u16, EntityId)>,
    /// Attempts whose end the pass settled, with the end.
    pub ended: Vec<(EntityId, EndKind)>,
    /// Orders left waiting, with their reasons.
    pub waiting: Vec<(EntityId, Vec<BlockedOn>)>,
    /// Orders the pass gave up or cancelled.
    pub closed: Vec<EntityId>,
}

/// The fit of one open order over its machines.
pub(super) enum OrderFit {
    Runnable {
        pin: WorkloadPin,
        candidates: Vec<EntityId>,
    },
    Blocked(Vec<BlockedOn>),
    /// The authority it runs under ended: it is cancelled.
    AuthorityEnded,
    /// Its `Until` time passed before an attempt was made: it gives up, runnable or not.
    WaitEnded,
    /// The order its `after` names ended without the end it waited for: it gives up (row Q5).
    UpstreamEnded(EntityId),
}

/// The end an attempt's typed terminal names (4.7).
fn end_of_terminal(end: &GpuJobEnd, cancelled: bool, window_passed: bool) -> EndKind {
    match end {
        GpuJobEnd::Exited { code } => EndKind::Exited { code: *code },
        GpuJobEnd::Signalled { signal } => EndKind::Exited {
            code: 128_i32.saturating_add(*signal),
        },
        GpuJobEnd::TimeLimit => EndKind::TimeLimit,
        GpuJobEnd::MemoryLimit => EndKind::MemoryLimit,
        GpuJobEnd::DiskLimit => EndKind::DiskLimit,
        GpuJobEnd::Stopped => EndKind::Stopped,
        GpuJobEnd::Revoked => EndKind::Revoked,
        GpuJobEnd::Withdrawn if window_passed => EndKind::Expired,
        GpuJobEnd::Withdrawn if cancelled => EndKind::Stopped,
        GpuJobEnd::Withdrawn | GpuJobEnd::Refused { .. } => EndKind::NeverStarted,
        GpuJobEnd::LaunchRefused { reason }
            if RETRYABLE_LAUNCH_REASONS
                .iter()
                .any(|retryable| reason.starts_with(retryable)) =>
        {
            EndKind::NeverStarted
        }
        GpuJobEnd::LaunchRefused { .. } => EndKind::LaunchRefusedChanged,
        GpuJobEnd::Lost { .. } => EndKind::Lost,
    }
}

/// The facts of a machine the host does not know: unreachable.
fn unknown_machine(machine: EntityId) -> MachineFacts {
    MachineFacts {
        machine,
        reach: MachineReach::Unreachable { since_ms: None },
        enabled: false,
        refusal: None,
        paused: None,
        drained: None,
        templates: None,
        room: super::fit::Room::default(),
        devices: None,
        window: None,
        keep_headroom_pct: None,
        roles: Vec::new(),
        warm: Vec::new(),
        warm_absent: Vec::new(),
    }
}

impl Vault {
    /// How the job of `attempt` stands, and whether the machine's word says its workload
    /// started: a node's receipt for a node's job; for an offer's job, which has no dispatch
    /// row, its provider's clock (run time reported, or an end by exit or at the maximum). A
    /// resource the provider holds `Pending` has not started. A line unit's attempt whose
    /// claim has no job row yet stands as its claim does ([`Self::line_claim_standing`]).
    fn attempt_standing(
        &self,
        order: &WorkOrder,
        attempt: &OrderAttempt,
        now_ms: u64,
    ) -> crate::Result<(AttemptStanding, bool)> {
        let Some(job) = self.gpu_job(&attempt.job)? else {
            return self.line_claim_standing(order, attempt, now_ms);
        };
        let key = job.chunk().map(|chunk| chunk.idempotency_key.clone());
        let dispatch = match &key {
            Some(key) => self.job_dispatch(key)?,
            None => None,
        };
        let window_passed = dispatch
            .as_ref()
            .is_some_and(|row| matches!(row.closed, Some(DispatchClose::StartWindowPassed)));
        let cancelled = order.cancel.is_some();
        let observation = match &key {
            Some(key) => self.job_observation(key)?,
            None => None,
        };
        let started = match &dispatch {
            Some(_) => observation.as_ref().is_some_and(|row| row.started),
            None => {
                job.chunk()
                    .is_some_and(|chunk| chunk.used_secs > 0 || chunk.base_used_secs > 0)
                    || matches!(
                        job.state,
                        GpuJobState::Stopped
                            | GpuJobState::Ended {
                                reason: GpuEndReason::Exited
                                    | GpuEndReason::AtMaximum
                                    | GpuEndReason::TimeLimit
                            }
                    )
            }
        };
        let terminal = observation.and_then(|row| row.terminal);
        let standing = match job.state {
            GpuJobState::Held { .. } => AttemptStanding::Ended(EndKind::NeverStarted),
            GpuJobState::Ended { reason } => AttemptStanding::Ended(match &terminal {
                Some(terminal) => end_of_terminal(&terminal.end, cancelled, window_passed),
                None => match reason {
                    GpuEndReason::Exited => EndKind::Exited { code: 0 },
                    GpuEndReason::AtMaximum | GpuEndReason::TimeLimit => EndKind::TimeLimit,
                    GpuEndReason::Cancelled => EndKind::Stopped,
                    GpuEndReason::NeverStarted => EndKind::NeverStarted,
                    GpuEndReason::Gone => EndKind::Lost,
                    // The owner wrote the job off (door 10): its end stays unknown.
                    GpuEndReason::Unconfirmed => EndKind::WrittenOff,
                },
            }),
            // Stopped at its maximum with a resume on offer: for the order, it ran to its
            // maximum.
            GpuJobState::Stopped => AttemptStanding::Ended(EndKind::TimeLimit),
            GpuJobState::Reserved | GpuJobState::Running | GpuJobState::Ending { .. } => {
                if dispatch.is_some_and(|row| row.history_lost_at_ms.is_some()) {
                    AttemptStanding::Unconfirmed
                } else {
                    AttemptStanding::Live
                }
            }
        };
        Ok((standing, started))
    }

    /// How a line unit's attempt stands while its claim has no job row (row H3): the attempt's
    /// reserve wrote the claim and the attempt entry, and the claimed start has not written the
    /// job. A claim still `Claimed` is live until its custody lapses or a cancel reaches the
    /// order; then it is released here, by the compare-and-set the reserve and a late start use,
    /// and the attempt never started. A claim released before any job (the start's refusal, its
    /// custody) ends the attempt `NeverStarted`. An offer's attempt with no job row, a missing
    /// claim, or a claim past `Claimed` with no job row is unconfirmed.
    fn line_claim_standing(
        &self,
        order: &WorkOrder,
        attempt: &OrderAttempt,
        now_ms: u64,
    ) -> crate::Result<(AttemptStanding, bool)> {
        let Some(key) = order.claim_key(attempt.n) else {
            return Ok((AttemptStanding::Unconfirmed, false));
        };
        let claim = {
            let txn = self.store.env.read_txn()?;
            claim_in_txn(self, &txn, &key)?
        };
        let Some(claim) = claim.filter(|claim| claim.id == attempt.job) else {
            return Ok((AttemptStanding::Unconfirmed, false));
        };
        let standing = match &claim.state {
            ClaimState::Claimed => {
                let cancelled = order.cancel.is_some();
                let released = self.with_write_txn_grouped(|txn| {
                    if !cancelled && !custody_lapsed_in_txn(self, txn, &claim, now_ms)? {
                        return Ok(false);
                    }
                    let reason = if cancelled {
                        LINE_CLAIM_ORDER_CANCELLED
                    } else {
                        CUSTODY_LAPSED
                    };
                    Ok(release_claim_in_txn(self, txn, &claim, reason, now_ms)?.is_some())
                })?;
                if released {
                    AttemptStanding::Ended(EndKind::NeverStarted)
                } else {
                    AttemptStanding::Live
                }
            }
            ClaimState::Ended(terminal) if matches!(terminal.end, UnitEnd::Released(_)) => {
                AttemptStanding::Ended(EndKind::NeverStarted)
            }
            ClaimState::Ended(_) | ClaimState::Started => AttemptStanding::Unconfirmed,
        };
        Ok((standing, false))
    }

    /// Settles the end `end` of `order`'s last attempt through the AFTER rule; `started` is
    /// the machine's word that the attempt's workload ran, for an attempt that ended before a
    /// pass saw it run.
    fn settle_attempt_end(
        &self,
        asks: &PassAsks<'_>,
        order: &WorkOrder,
        end: EndKind,
        started: bool,
        now_ms: u64,
    ) -> crate::Result<bool> {
        let policy = {
            let txn = self.store.env.read_txn()?;
            retry_policy_in_txn(self, &txn)?
        };
        let (pick, decision) = after_rule(order, end, &policy, now_ms);
        let (pick, decision) = self.decide_after(asks, order, end, pick, decision, now_ms)?;
        self.update_work_order(order, now_ms, |order| {
            if let Some(last) = order.attempts.last_mut() {
                if started {
                    last.started_at_ms.get_or_insert(now_ms);
                }
                last.end = Some(AttemptEnd {
                    kind: end,
                    at_ms: now_ms,
                    after: decision,
                });
            }
            order.state = if let Some(cancel) = order.cancel {
                OrderState::Cancelled {
                    why: CancelWhy::Asked { by: cancel.by },
                }
            } else {
                match pick {
                    AfterPick::Done => OrderState::Done,
                    AfterPick::RetryNow => OrderState::Open {
                        blocked: Vec::new(),
                        looked_at_ms: now_ms,
                        earliest_ms: None,
                    },
                    AfterPick::RetryAt(at_ms) => {
                        order.retry_not_before_ms = Some(at_ms);
                        OrderState::Open {
                            blocked: vec![BlockedOn {
                                machine: None,
                                blocker: Blocker::RetryNotBefore { ms: at_ms },
                            }],
                            looked_at_ms: now_ms,
                            earliest_ms: Some(at_ms),
                        }
                    }
                    AfterPick::GiveUp if end == EndKind::WrittenOff => OrderState::GivenUp {
                        why: GiveUpWhy::WrittenOff,
                    },
                    AfterPick::GiveUp => OrderState::GivenUp {
                        why: GiveUpWhy::Ended { end },
                    },
                }
            };
        })
    }

    /// The fit of the open order `order` over `machines` at `now_ms`.
    pub(super) fn order_fit(
        &self,
        order: &WorkOrder,
        machines: &[MachineFacts],
        running: &RunningCaps,
        now_ms: u64,
    ) -> crate::Result<OrderFit> {
        // An attempt with no end keeps the order as it is, whatever else ended: its receipt or
        // the owner's write-off still lands on the order (I3).
        if let Some(last) = order.last_attempt()
            && last.end.is_none()
        {
            return Ok(OrderFit::Blocked(vec![BlockedOn {
                machine: last.machine.map(|machine| machine.to_hex()),
                blocker: Blocker::AttemptUnconfirmed {
                    key: last.job.to_hex(),
                },
            }]));
        }
        let txn = self.store.env.read_txn()?;
        if self.order_authority_in_txn(&txn, order)?.is_none() {
            return Ok(OrderFit::AuthorityEnded);
        }
        if order.wait_ran_out(now_ms) {
            return Ok(OrderFit::WaitEnded);
        }
        if let Some(hold) = order.timed_hold(now_ms) {
            return Ok(OrderFit::Blocked(vec![hold]));
        }
        if let Some(held) = self.order_conditions_in_txn(&txn, order, running)? {
            return Ok(held);
        }
        let Some(row) = self.job_workload_in_txn(&txn, &order.workload)? else {
            return Ok(OrderFit::Blocked(vec![BlockedOn {
                machine: None,
                blocker: Blocker::WorkloadUnknown,
            }]));
        };
        let Some(starter) = order.ordered_by.starter() else {
            return Ok(OrderFit::AuthorityEnded);
        };
        // The order's hard limit on scope kinds: no machine can run a pin outside it.
        if !scope_allowed(&order.limits, &row.pin.scope) {
            return Ok(OrderFit::Blocked(vec![BlockedOn {
                machine: None,
                blocker: Blocker::scope_not_allowed(&row.pin.scope),
            }]));
        }
        let allowed = allowed_machines(&order.limits, &row);
        if allowed.is_empty() {
            let blocker = if row.approval.is_none() {
                Blocker::WorkloadNotApproved
            } else {
                Blocker::NoMachine
            };
            return Ok(OrderFit::Blocked(vec![BlockedOn {
                machine: None,
                blocker,
            }]));
        }
        let mut blocked = Vec::new();
        let mut candidates = Vec::new();
        let mut runnable_pin = None;
        for machine in allowed {
            let facts = machines
                .iter()
                .find(|facts| facts.machine == machine)
                .cloned()
                .unwrap_or_else(|| unknown_machine(machine));
            let ask = WorkloadStartAsk {
                workload: &order.workload,
                machine,
                maximum_secs: order.request.maximum_secs,
                starter,
            };
            let mut reasons = Vec::new();
            match self.workload_approval_in_txn(&txn, &ask, now_ms)? {
                Ok(pin) => {
                    reasons.extend(fit(order, (&pin.template, &pin.template_digest), &facts));
                    if reasons.is_empty() {
                        candidates.push(machine);
                        runnable_pin = Some(pin);
                        continue;
                    }
                }
                Err(refused) => reasons.push(Blocker::from(&refused)),
            }
            blocked.extend(reasons.into_iter().map(|blocker| BlockedOn {
                machine: Some(machine.to_hex()),
                blocker,
            }));
        }
        Ok(match runnable_pin {
            Some(pin) => OrderFit::Runnable { pin, candidates },
            None => OrderFit::Blocked(blocked),
        })
    }

    /// Writes why `order` waits, or ends it: cancelled when its authority ended, given up when
    /// no wait can clear what blocks it on every machine, when it may not wait, or when its
    /// wait has run out.
    pub(super) fn block_order(
        &self,
        order: &WorkOrder,
        blocked: Vec<BlockedOn>,
        authority_ended: bool,
        now_ms: u64,
        report: &mut PassReport,
    ) -> crate::Result<()> {
        let next = closing_state(order, &blocked, authority_ended, now_ms);
        let closes = next.as_ref().is_some_and(OrderState::is_terminal);
        let earliest_ms = earliest_clear(&blocked);
        let wrote = self.update_work_order(order, now_ms, |order| {
            order.state = next.unwrap_or(OrderState::Open {
                blocked: blocked.clone(),
                looked_at_ms: now_ms,
                earliest_ms,
            });
        })?;
        if wrote {
            if closes {
                report.closed.push(order.id);
            } else {
                report.waiting.push((order.id, blocked));
            }
        }
        Ok(())
    }

    /// One pass of the loop at `now_ms` (section 0).
    ///
    /// # Errors
    ///
    /// Storage errors. A refused attempt is not an error: the order waits with its reasons.
    pub fn work_order_pass(&self, host: &dyn OrderHost, now_ms: u64) -> crate::Result<PassReport> {
        let mut report = PassReport::default();
        let asks = PassAsks::new(host);
        // The ends of live attempts first, so an order whose attempt ended may run again in
        // this pass.
        for order in self.work_orders()? {
            if order.state.is_terminal() || !host.holds(&order) {
                continue;
            }
            let Some(attempt) = order.last_attempt().filter(|last| last.end.is_none()) else {
                continue;
            };
            let (standing, started) = self.attempt_standing(&order, attempt, now_ms)?;
            match standing {
                AttemptStanding::Live => {
                    // The first pass that sees the machine's word records the start, which
                    // settles a started wait in the same write. A lost write is read again at
                    // the next pass.
                    if started
                        && attempt.started_at_ms.is_none()
                        && !self.update_work_order(&order, now_ms, |order| {
                            if let Some(last) = order.attempts.last_mut() {
                                last.started_at_ms.get_or_insert(now_ms);
                            }
                        })?
                    {
                        continue;
                    }
                    if order.cancel.is_some()
                        && let Err(error) = host.stop_attempt(&order, &attempt.job)
                    {
                        tracing::warn!(
                            order = %order.id.to_hex(),
                            error = %error,
                            "work order: the cancel's stop could not be asked"
                        );
                    }
                }
                AttemptStanding::Unconfirmed => {
                    if matches!(order.state, OrderState::Running { .. }) {
                        let blocked = vec![BlockedOn {
                            machine: attempt.machine.map(|machine| machine.to_hex()),
                            blocker: Blocker::AttemptUnconfirmed {
                                key: attempt.job.to_hex(),
                            },
                        }];
                        self.update_work_order(&order, now_ms, |order| {
                            order.state = OrderState::Open {
                                blocked,
                                looked_at_ms: now_ms,
                                earliest_ms: None,
                            };
                        })?;
                    }
                }
                AttemptStanding::Ended(end) => {
                    if self.settle_attempt_end(&asks, &order, end, started, now_ms)? {
                        report.ended.push((order.id, end));
                    }
                }
            }
        }
        let all_orders = self.work_orders()?;
        // Caps count every live attempt in the vault, as the attempt's own write counts them.
        let mut caps = RunningCaps::of(&all_orders);
        let orders: Vec<WorkOrder> = all_orders
            .into_iter()
            .filter(|order| host.holds(order))
            .collect();
        // Each machine an open order may run on, with the warm keys those orders list.
        let mut wanted: BTreeMap<EntityId, BTreeSet<String>> = BTreeMap::new();
        {
            let txn = self.store.env.read_txn()?;
            for order in orders
                .iter()
                .filter(|order| matches!(order.state, OrderState::Open { .. }))
            {
                if let Some(row) = self.job_workload_in_txn(&txn, &order.workload)? {
                    for machine in allowed_machines(&order.limits, &row) {
                        wanted
                            .entry(machine)
                            .or_default()
                            .extend(order.wishes.warm.iter().cloned());
                    }
                }
            }
        }
        let wanting: Vec<(EntityId, WarmWanted)> = wanted
            .into_iter()
            .map(|(machine, keys)| (machine, WarmWanted::of(&keys)))
            .collect();
        let mut machines = if wanting.is_empty() {
            Vec::new()
        } else {
            host.machine_facts_wanting(&wanting)
        };
        let mut running: BTreeMap<String, u32> = BTreeMap::new();
        for order in &orders {
            if matches!(order.state, OrderState::Running { .. }) {
                *running.entry(order.family_key()).or_default() += 1;
            }
        }
        let mut runnable = Vec::new();
        for order in orders
            .iter()
            .filter(|order| matches!(order.state, OrderState::Open { .. }))
        {
            match self.order_fit(order, &machines, &caps, now_ms)? {
                OrderFit::Runnable { .. } => runnable.push(order),
                OrderFit::Blocked(blocked) => {
                    self.block_order(order, blocked, false, now_ms, &mut report)?;
                }
                OrderFit::AuthorityEnded => {
                    self.block_order(order, Vec::new(), true, now_ms, &mut report)?;
                }
                OrderFit::WaitEnded => {
                    self.block_order(order, Vec::new(), false, now_ms, &mut report)?;
                }
                OrderFit::UpstreamEnded(upstream) => {
                    self.give_up_on_upstream(order, upstream, now_ms, &mut report)?;
                }
            }
        }
        let by_rule = rank(&runnable, &running);
        let dispatch = self.ranked_by_decider(&asks, &by_rule, &running, now_ms)?;
        for (order, ranked) in dispatch {
            // Fit again against the room this pass's earlier attempts took.
            let (pin, candidates) = match self.order_fit(order, &machines, &caps, now_ms)? {
                OrderFit::Runnable { pin, candidates } => (pin, candidates),
                OrderFit::Blocked(blocked) => {
                    self.block_order(order, blocked, false, now_ms, &mut report)?;
                    continue;
                }
                OrderFit::AuthorityEnded => {
                    self.block_order(order, Vec::new(), true, now_ms, &mut report)?;
                    continue;
                }
                OrderFit::WaitEnded => {
                    self.block_order(order, Vec::new(), false, now_ms, &mut report)?;
                    continue;
                }
                OrderFit::UpstreamEnded(upstream) => {
                    self.give_up_on_upstream(order, upstream, now_ms, &mut report)?;
                    continue;
                }
            };
            let candidate_facts: Vec<&MachineFacts> = machines
                .iter()
                .filter(|facts| candidates.contains(&facts.machine))
                .collect();
            // A candidate with no reported facts fits on what the approval says alone.
            let unknown: Vec<MachineFacts> = candidates
                .iter()
                .filter(|machine| !machines.iter().any(|facts| facts.machine == **machine))
                .map(|machine| unknown_machine(*machine))
                .collect();
            let all: Vec<&MachineFacts> =
                candidate_facts.into_iter().chain(unknown.iter()).collect();
            let Some((chosen, placed)) = place(order, &all) else {
                continue;
            };
            let Some((chosen, placed)) =
                self.decide_place(&asks, order, &all, (chosen, placed), now_ms, &mut report)?
            else {
                continue;
            };
            let machine = chosen.machine;
            let needs = Needs::of(&order.request);
            let devices = chosen
                .devices_for(&needs, &order.limits.device_ids)
                .unwrap_or_default();
            let n = order.next_attempt_number();
            let attempt = AttemptToMake {
                order,
                n,
                job: attempt_job_id(&order.id, n)?,
                machine,
                devices: devices.clone(),
                pin: &pin,
                ranked,
                placed,
            };
            match host.make_attempt(&attempt) {
                AttemptOutcome::Made => {
                    report.made.push((order.id, n, machine));
                    caps.hold(order);
                    if let Some(facts) = machines.iter_mut().find(|facts| facts.machine == machine)
                    {
                        let until =
                            now_ms.saturating_add(order.request.maximum_secs.saturating_mul(1_000));
                        facts.hold(&needs, &devices, until);
                    }
                }
                AttemptOutcome::OrderChanged => {}
                AttemptOutcome::Refused(blockers) => {
                    let Some(current) = self.work_order(&order.id)? else {
                        continue;
                    };
                    let authority_ended = blockers.contains(&Blocker::GrantNotLive);
                    let blocked = blockers
                        .into_iter()
                        .map(|blocker| BlockedOn {
                            machine: Some(machine.to_hex()),
                            blocker,
                        })
                        .collect();
                    self.block_order(&current, blocked, authority_ended, now_ms, &mut report)?;
                }
            }
        }
        Ok(report)
    }
}

/// The machines an order with `limits` may run on: its own limit, else the ones its
/// workload's approval names.
#[must_use]
pub fn allowed_machines(limits: &OrderLimits, workload: &JobWorkload) -> Vec<EntityId> {
    if limits.machines.is_empty() {
        workload
            .approval
            .as_ref()
            .map(|approval| approval.machines.clone())
            .unwrap_or_default()
    } else {
        limits.machines.clone()
    }
}
