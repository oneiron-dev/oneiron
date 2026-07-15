//! Dreamer wake-pass driver (ONE-1288, DREAM-001 residual).
//!
//! One wake pass = one bounded work cycle on one node (a Dreamer wake-pass,
//! never a process wake). The driver composes the LANDED primitives only —
//! atomic admission (`admit_next_consolidation`), reserve-then-spend budget
//! settlement, park rows, milestones-as-claims, and the ephemeral progress
//! lane — and adds the LOOP: admit → execute → settle/complete or park,
//! until a stop condition. The engine owns no timer or cron: hosts call
//! [`request_wake`] to ENQUEUE and [`DreamerWakeDriver::run_wake_pass`] to
//! RUN the pass — two separate host calls. Idle = nothing runs.

use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use rmpv::Value;

use crate::Vault;
use crate::dreamer_runner::{
    AbortDreamerBudgetReservation, AdmitDreamerConsolidationJob, AdmitDreamerJob,
    CompleteDreamerJob, DREAMER_MILESTONE_PREDICATE, DREAMER_MILESTONE_VALUE_SCHEMA_VERSION,
    DreamerAdmissionOutcome, DreamerAdmittedJob, DreamerClaimAuthoringAdmission,
    DreamerClaimAuthoringBatchTier, DreamerConsolidationAdmissionOutcome,
    DreamerConsolidationScope, DreamerJobPayload, DreamerMilestoneClaim, DreamerMilestoneKind,
    DreamerRunnerStore, EnqueueDreamerConsolidationJob, EnqueueDreamerJobOutcome, ParkDreamerJob,
    SettleDreamerBudget,
};
#[cfg(feature = "sync")]
use crate::dreamer_runner::{
    DreamerJobProgressProducer, DreamerJobProgressState, DreamerJobProgressUpdate,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::job_queue::JobId;
use crate::llm::{
    BUDGET_LAND_PROMPT_TEMPLATE, BUDGET_LAND_PROMPT_TEMPLATE_ID, BUDGET_PLAN_PROMPT_TEMPLATE,
    BUDGET_PLAN_PROMPT_TEMPLATE_ID, BudgetGuard, BudgetRead, BudgetSignalDeliveryChannel,
    BudgetSteeringSignal, BudgetThreshold,
};
#[cfg(feature = "sync")]
use crate::sync::EphemeralStore;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteEnvelope};

/// Wake-pass wall-clock ceiling: the REAL ceiling (1184-D4-C), monotonic.
pub const DREAMER_WAKE_PASS_WALL_CLOCK_CEILING_MS: u64 = 180_000;
/// Bounded graceful-wrap window before the hard cut (1184-D4-E):
/// finalize window = `[165_000, 180_000)` under the default ceiling.
pub const DREAMER_GRACEFUL_WRAP_WINDOW_MS: u64 = 15_000;
/// Wrap-up-soon notice threshold (1184-D4-D): counter OR clock percent.
pub const DREAMER_WRAP_UP_NOTICE_PERCENT: u64 = 80;
/// Park reason stamped on jobs cut at the wake-pass ceiling.
pub const DREAMER_HARD_CUT_PARK_REASON: &str = "wake-pass hard cut";
/// Park-owner token for deadline hard-cut parks: the step layer parks the
/// cut job under this token (no trap is opened at the ceiling), and only a
/// resumer presenting it may clear the row.
pub const DREAMER_HARD_CUT_PARK_OWNER: &str = "dreamer.step:hard-cut";
/// Park reason stamped on jobs preempted by a cooperative cancellation
/// request (ONE-1683 H-S5/R2): the admitted job is parked and its budget
/// reservation refunded before the pass stops — cancellation never leaks.
pub const DREAMER_CANCELLED_PARK_REASON: &str = "wake-pass cancelled";
/// Park reason PREFIX stamped on jobs whose executor returned a
/// non-deadline error (ONE-1683 H-S5/R2): the error path parks the admitted
/// job and refunds its reservation before the error propagates.
pub const DREAMER_EXECUTOR_ERROR_PARK_REASON: &str = "executor error";

/// What woke the Dreamer (C9 wake model, design D2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WakeTrigger {
    Compaction,
    SessionEnd,
    Event,
    Timer,
}

impl WakeTrigger {
    /// Default consolidation scope for this trigger. `Event` defaults to
    /// Micro; the event payload may override at [`request_wake`] time.
    #[must_use]
    pub const fn default_scope(self) -> DreamerConsolidationScope {
        match self {
            Self::Compaction | Self::Event => DreamerConsolidationScope::Micro,
            Self::SessionEnd => DreamerConsolidationScope::Meso,
            Self::Timer => DreamerConsolidationScope::Macro,
        }
    }
}

type NowMsFn = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Monotonic wake-pass deadline (immune to wall-time jumps).
///
/// ONE-1288 ships the type + reads; the pinned 180s ceiling constant and
/// finalize-window behavior are ONE-1305.
pub struct WakePassDeadline {
    ceiling_ms: u64,
    elapsed_ms: NowMsFn,
}

impl WakePassDeadline {
    /// Starts a deadline NOW over a monotonic [`Instant`] clock.
    #[must_use]
    pub fn new(ceiling_ms: u64) -> Self {
        let origin = Instant::now();
        Self {
            ceiling_ms,
            elapsed_ms: Arc::new(move || {
                u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX)
            }),
        }
    }

    /// Test constructor with an injected elapsed-ms clock (no wall clock in
    /// logic — chain test pin).
    #[must_use]
    pub fn with_clock(ceiling_ms: u64, elapsed_ms: NowMsFn) -> Self {
        Self {
            ceiling_ms,
            elapsed_ms,
        }
    }

    fn elapsed(&self) -> u64 {
        (self.elapsed_ms)()
    }

    /// Milliseconds left before the hard ceiling.
    #[must_use]
    pub fn remaining_ms(&self) -> u64 {
        self.ceiling_ms.saturating_sub(self.elapsed())
    }

    /// Elapsed share of the ceiling in percent, saturating at 100.
    #[must_use]
    pub fn elapsed_percent(&self) -> u64 {
        if self.ceiling_ms == 0 {
            return 100;
        }
        let numerator = u128::from(self.elapsed()).saturating_mul(100);
        (numerator / u128::from(self.ceiling_ms)).min(100) as u64
    }

    /// True once the hard ceiling has passed.
    #[must_use]
    pub fn expired(&self) -> bool {
        self.elapsed() >= self.ceiling_ms
    }

    /// True inside the bounded graceful-wrap window before the hard cut:
    /// `elapsed >= ceiling - DREAMER_GRACEFUL_WRAP_WINDOW_MS` (ONE-1305).
    #[must_use]
    pub fn in_finalize_window(&self) -> bool {
        self.elapsed()
            >= self
                .ceiling_ms
                .saturating_sub(DREAMER_GRACEFUL_WRAP_WINDOW_MS)
    }
}

impl fmt::Debug for WakePassDeadline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WakePassDeadline")
            .field("ceiling_ms", &self.ceiling_ms)
            .field("elapsed_ms", &self.elapsed())
            .finish()
    }
}

/// Cooperative wake-pass cancellation token (ONE-1683, H-S5/R2).
///
/// A supervisor raises the flag with [`cancel`](Self::cancel); the running
/// pass observes it ONLY at its job-boundary checkpoints (loop top and the
/// pre-dispatch point after admission) — the same places the deadline stops
/// admission. Cancellation is never honored mid-await inside the executor or
/// between a gated write's start and its settle: aborting a pass mid-write
/// would reopen the S3 off-record fence leak. A cancel that lands after a
/// job was admitted parks that job and refunds its budget reservation
/// through the ordinary Park bookkeeping before the pass reports
/// [`WakePassStop::Cancelled`].
///
/// Clones share the flag; the token holds no waker — it is a level, not an
/// edge, and the pass polls it synchronously as it reaches each checkpoint.
#[derive(Debug, Clone, Default)]
pub struct WakeCancellation {
    cancelled: Arc<std::sync::atomic::AtomicBool>,
}

impl WakeCancellation {
    /// A fresh, un-cancelled token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cooperative preemption. Idempotent; never blocks.
    pub fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// True once cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// Budget legibility attached to EVERY host-call response inside a wake
/// pass (1184-D4-D): remaining budget, remaining wall-clock, the wrap-up
/// notice, and the finalize deadline once the graceful-wrap window opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BudgetLegibilityEnvelope {
    pub remaining_units: u64,
    pub limit_units: u64,
    pub remaining_ms: u64,
    pub wrap_up: bool,
    pub finalize_by_ms: Option<u64>,
}

/// Composes the legibility envelope from the ONE wake-budget counter read
/// ([`BudgetRead`]) and the pass deadline. The runner-store reservation
/// ledger is NOT consulted (design §D5).
#[must_use]
pub fn legibility_envelope(
    read: &BudgetRead,
    deadline: &WakePassDeadline,
    wrap_fired: bool,
    finalize: bool,
) -> BudgetLegibilityEnvelope {
    BudgetLegibilityEnvelope {
        remaining_units: read.remaining_units,
        limit_units: read.limit_units,
        remaining_ms: deadline.remaining_ms(),
        wrap_up: wrap_fired,
        finalize_by_ms: finalize.then(|| deadline.remaining_ms()),
    }
}

/// [`legibility_envelope`] with wrap/finalize derived from the same read:
/// wrap-up once `max(counter_percent, clock_percent) >= 80`, finalize once
/// the deadline enters its graceful-wrap window.
#[must_use]
pub fn current_legibility(
    read: &BudgetRead,
    deadline: &WakePassDeadline,
) -> BudgetLegibilityEnvelope {
    let wrap_fired =
        read.depleted_percent().max(deadline.elapsed_percent()) >= DREAMER_WRAP_UP_NOTICE_PERCENT;
    legibility_envelope(read, deadline, wrap_fired, deadline.in_finalize_window())
}

/// Input for one wake pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunWakePass {
    pub trigger: WakeTrigger,
    pub scope: DreamerConsolidationScope,
    pub local_node_id: u64,
    pub lease_owner: String,
    pub budget_total_units: u64,
    pub reserve_units: u64,
    pub now: u64,
}

/// Why the pass stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WakePassStop {
    QueueEmpty,
    BudgetExhausted,
    DeadlineHardCut,
    Trapped,
    NotHomeNode,
    NoHomeNode,
    /// A [`WakeCancellation`] request was honored at a job-boundary
    /// checkpoint. Any job admitted when the request landed was parked and
    /// its budget reservation refunded — nothing leaks (H-S5/R2).
    Cancelled,
}

/// Wake-pass tally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WakePassReport {
    pub admitted: u32,
    pub completed: u32,
    pub failed: u32,
    pub parked: u32,
    pub stop: WakePassStop,
}

/// Terminal execution outcome one executor reports for one admitted job.
///
/// There is NO `Trap` variant by design (D18): traps surface at the STEP
/// layer; a trapped job comes back as `Park` carrying the trap note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DreamerJobExecution {
    Completed { completed_units: u64 },
    Park { reason: String },
}

/// Per-job execution context handed to the executor.
pub struct WakeJobContext<'a> {
    pub vault: &'a Vault,
    pub deadline: &'a WakePassDeadline,
    pub budget_id: &'a str,
    pub now_ms: u64,
}

/// Executes one admitted Dreamer job.
///
/// AT-LEAST-ONCE contract: the driver may re-execute a job after a crash or
/// resume — executors MUST be step-based (ONE-1343 `call_as_step`) so
/// re-execution fast-forwards through memoized steps instead of re-spending.
/// Milestones mark durable progress; this ticket does not implement step
/// memoization itself.
///
/// PARK-OWNER contract (design D2): the STEP LAYER is the one park-owner for
/// trap suspensions — it writes the trap record and parks the job in its own
/// wtxn. The executor still returns `Park` carrying the trap note; the
/// driver detects the existing parked row and only publishes progress,
/// never parking a second time.
#[allow(async_fn_in_trait)]
pub trait DreamerJobExecutor {
    async fn execute(
        &mut self,
        job: &DreamerAdmittedJob,
        ctx: &mut WakeJobContext<'_>,
    ) -> Result<DreamerJobExecution>;
}

/// Durable milestone authorship for driver-written Started/Done milestones.
///
/// The driver mints one milestone claim per event from this template; hosts
/// that do not care about durable milestones simply do not configure one.
#[derive(Debug, Clone)]
pub struct WakeMilestoneAuthor {
    pub subject: EntityId,
    pub envelope: WriteEnvelope,
}

/// Live-progress lane for the sync build: producer + ephemeral store.
#[cfg(feature = "sync")]
pub struct WakeProgressLane<'a> {
    pub producer: DreamerJobProgressProducer,
    pub ephemeral: &'a EphemeralStore,
}

/// The wake-pass driver: one bounded work cycle over the consolidation
/// queue on one node.
pub struct DreamerWakeDriver<'a> {
    vault: &'a Vault,
    store: DreamerRunnerStore<'a>,
    budget_id: String,
    deadline: WakePassDeadline,
    milestones: Option<WakeMilestoneAuthor>,
    /// The ONE wake-budget counter (LLM-4 guard) for legibility + the 80%
    /// wrap notice; None keeps the counter side of the trigger silent.
    guard: Option<BudgetGuard>,
    wrap_notice_fired: bool,
    finalize_entered: bool,
    steering: Vec<BudgetSteeringSignal>,
    #[cfg(feature = "sync")]
    progress: Option<WakeProgressLane<'a>>,
}

impl<'a> DreamerWakeDriver<'a> {
    /// Opens a driver over an already-open vault. One wake budget per pass.
    #[must_use]
    pub fn new(vault: &'a Vault, budget_id: impl Into<String>, deadline: WakePassDeadline) -> Self {
        Self {
            vault,
            store: DreamerRunnerStore::new(vault),
            budget_id: budget_id.into(),
            deadline,
            milestones: None,
            guard: None,
            wrap_notice_fired: false,
            finalize_entered: false,
            steering: Vec::new(),
            #[cfg(feature = "sync")]
            progress: None,
        }
    }

    /// Configures the wake-budget counter for legibility and the 80% wrap
    /// notice (reuses the LLM-4 guard — never a second counter).
    #[must_use]
    pub fn with_budget_guard(mut self, guard: BudgetGuard) -> Self {
        self.guard = Some(guard);
        self
    }

    /// Steering signals queued during this pass (`SteeringQueueNextTurn`
    /// delivery: the host drains and delivers them on the next turn).
    #[must_use]
    pub fn steering_signals(&self) -> &[BudgetSteeringSignal] {
        &self.steering
    }

    /// Configures durable Started/Done milestone authorship.
    #[must_use]
    pub fn with_milestone_author(mut self, author: WakeMilestoneAuthor) -> Self {
        self.milestones = Some(author);
        self
    }

    /// Configures the live ephemeral progress lane.
    #[cfg(feature = "sync")]
    #[must_use]
    pub fn with_progress(mut self, lane: WakeProgressLane<'a>) -> Self {
        self.progress = Some(lane);
        self
    }

    /// This pass's deadline.
    #[must_use]
    pub const fn deadline(&self) -> &WakePassDeadline {
        &self.deadline
    }

    /// Runs one wake pass: admit → execute → settle/complete or park, until
    /// a stop condition. Every budget/lease mutation goes through the landed
    /// atomic admission/settle methods; the driver never touches private
    /// rows directly.
    ///
    /// `cancel` is a cooperative preemption request (ONE-1683, H-S5/R2):
    /// it is polled ONLY at the job-boundary checkpoints — the loop top and
    /// the pre-dispatch point right after admission — never mid-await inside
    /// `exec.execute` and never between a gated write and its settle. A
    /// cancel that lands after admission parks the admitted job and refunds
    /// its budget reservation before the pass stops
    /// [`WakePassStop::Cancelled`]. Hosts that never cancel pass a fresh
    /// [`WakeCancellation`].
    pub async fn run_wake_pass<E: DreamerJobExecutor + ?Sized>(
        &mut self,
        input: RunWakePass,
        exec: &mut E,
        cancel: &WakeCancellation,
    ) -> Result<WakePassReport> {
        // Per-pass driver state (ONE-1305): a reused driver must fire its
        // wrap/finalize notices anew each pass, and steering signals belong
        // to the pass that raised them — the host drains them after run.
        self.wrap_notice_fired = false;
        self.finalize_entered = false;
        self.steering.clear();

        let mut report = WakePassReport {
            admitted: 0,
            completed: 0,
            failed: 0,
            parked: 0,
            stop: WakePassStop::QueueEmpty,
        };

        loop {
            if cancel.is_cancelled() {
                // Cooperative-preemption boundary (H-S5/R2): between jobs
                // the driver holds no admitted job and no in-flight gated
                // write, so stopping here can never truncate a gated write
                // or an off-record close.
                report.stop = WakePassStop::Cancelled;
                break;
            }
            self.maybe_fire_wrap_notice();
            if self.deadline.expired() {
                // Hard cut, unconditionally: the sequential driver holds no
                // in-flight leases here (the step layer's deadline race
                // aborts and parks mid-step losers before returning).
                report.stop = WakePassStop::DeadlineHardCut;
                break;
            }
            if self.enter_finalize_if_due() {
                // Graceful wrap: admit NO new jobs and NO new step leases;
                // the pass ends under deadline/budget pressure.
                report.stop = if self.counter_exhausted() {
                    WakePassStop::BudgetExhausted
                } else {
                    WakePassStop::DeadlineHardCut
                };
                break;
            }

            let admitted =
                match self
                    .store
                    .admit_next_consolidation(AdmitDreamerConsolidationJob {
                        scope: input.scope,
                        local_node_id: input.local_node_id,
                        claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
                        claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
                        admission: AdmitDreamerJob {
                            lease_owner: input.lease_owner.clone(),
                            now: input.now,
                            budget_id: self.budget_id.clone(),
                            budget_total_units: input.budget_total_units,
                            reserve_units: input.reserve_units,
                            started_milestone: self
                                .milestone_claim(DreamerMilestoneKind::Started, input.now),
                        },
                    })? {
                    DreamerConsolidationAdmissionOutcome::NoHomeNode => {
                        report.stop = WakePassStop::NoHomeNode;
                        break;
                    }
                    DreamerConsolidationAdmissionOutcome::NotHomeNode(_) => {
                        report.stop = WakePassStop::NotHomeNode;
                        break;
                    }
                    DreamerConsolidationAdmissionOutcome::ClaimAuthoringBudgetTrap(_) => {
                        // The store already paused the job (admission-level trap).
                        report.stop = WakePassStop::Trapped;
                        break;
                    }
                    DreamerConsolidationAdmissionOutcome::Admission(
                        DreamerAdmissionOutcome::Empty,
                    ) => {
                        report.stop = WakePassStop::QueueEmpty;
                        break;
                    }
                    DreamerConsolidationAdmissionOutcome::Admission(
                        DreamerAdmissionOutcome::BudgetExhausted(_),
                    ) => {
                        report.stop = WakePassStop::BudgetExhausted;
                        break;
                    }
                    DreamerConsolidationAdmissionOutcome::Admission(
                        DreamerAdmissionOutcome::Admitted(job),
                    ) => *job,
                };

            report.admitted += 1;
            let job_id = admitted.status.job.id;

            // Cooperative-preemption checkpoint (H-S5/R2): the ONE point
            // between admission and settle where a cancel is honored is
            // HERE, before the executor dispatch — never mid-await. The
            // admitted job flows through the ordinary Park arm below, which
            // refunds its budget reservation and parks it before the pass
            // stops.
            let cancel_requested = cancel.is_cancelled();
            let executed = if cancel_requested {
                Ok(DreamerJobExecution::Park {
                    reason: DREAMER_CANCELLED_PARK_REASON.to_owned(),
                })
            } else {
                self.publish(job_id, ProgressKind::Running, None, input.now)?;
                let mut ctx = WakeJobContext {
                    vault: self.vault,
                    deadline: &self.deadline,
                    budget_id: &self.budget_id,
                    now_ms: input.now.saturating_mul(1_000),
                };
                exec.execute(&admitted, &mut ctx).await
            };
            let execution = match executed {
                Ok(execution) => execution,
                Err(error) => {
                    // A mid-step deadline loss may surface as an executor
                    // ERROR (a host propagating the step layer's
                    // DeadlineHardCut instead of mapping it to Park). The
                    // budget refund, the park bookkeeping, and the
                    // checkpoint milestone must still run — treat it as the
                    // hard-cut park it is instead of bailing out.
                    let step_layer_parked = self
                        .store
                        .parked_job(job_id)?
                        .is_some_and(|row| row.reason == DREAMER_HARD_CUT_PARK_REASON);
                    if !step_layer_parked && !self.deadline.expired() {
                        // H-S5/R2 (ONE-1683): a non-deadline executor error
                        // must release what admission acquired BEFORE the
                        // error propagates — refund the budget reservation
                        // and park the admitted job, mirroring the Park arm
                        // below. Returning the error first used to leak the
                        // admitted job (stuck leased) AND its reservation.
                        self.store
                            .abort_budget_reservation(AbortDreamerBudgetReservation {
                                budget_id: self.budget_id.clone(),
                                child_job: job_id,
                                now: input.now,
                            })?;
                        let reason = format!("{DREAMER_EXECUTOR_ERROR_PARK_REASON}: {error}");
                        if self.store.parked_job(job_id)?.is_some() {
                            // One park-owner: the step layer already parked
                            // this job (under a non-hard-cut reason) inside
                            // its own wtxn — publish only, never re-park.
                            self.publish(job_id, ProgressKind::Parked, Some(reason), input.now)?;
                        } else {
                            self.park_job(job_id, reason, input.lease_owner.clone(), input.now)?;
                        }
                        return Err(error);
                    }
                    DreamerJobExecution::Park {
                        reason: DREAMER_HARD_CUT_PARK_REASON.to_owned(),
                    }
                }
            };

            match execution {
                DreamerJobExecution::Completed { completed_units } => {
                    self.store.settle_budget(SettleDreamerBudget {
                        budget_id: self.budget_id.clone(),
                        child_job: job_id,
                        actual_units: completed_units,
                        now: input.now,
                    })?;
                    self.complete_job(&admitted, input.now)?;
                    self.write_milestone(job_id, DreamerMilestoneKind::Done, input.now)?;
                    report.completed += 1;
                }
                DreamerJobExecution::Park { reason } => {
                    // The lease is not settled as spent — refund the
                    // reservation.
                    self.store
                        .abort_budget_reservation(AbortDreamerBudgetReservation {
                            budget_id: self.budget_id.clone(),
                            child_job: job_id,
                            now: input.now,
                        })?;
                    let hard_cut =
                        reason == DREAMER_HARD_CUT_PARK_REASON || self.deadline.expired();
                    if self.store.parked_job(job_id)?.is_some() {
                        // One park-owner: the step layer already parked this
                        // job inside its trap wtxn — publish only.
                        self.publish(job_id, ProgressKind::Parked, Some(reason), input.now)?;
                    } else {
                        self.park_job(job_id, reason, input.lease_owner.clone(), input.now)?;
                    }
                    if hard_cut {
                        // A deadline-cut park leaves a durable resume point.
                        self.write_milestone(
                            job_id,
                            DreamerMilestoneKind::CheckpointReached,
                            input.now,
                        )?;
                    }
                    report.parked += 1;
                }
            }

            if cancel_requested {
                // The admitted job was parked and its reservation refunded
                // through the Park arm above — the pass may now stop at this
                // job boundary (H-S5/R2).
                report.stop = WakePassStop::Cancelled;
                break;
            }
        }

        Ok(report)
    }

    /// Fires the ONE 80% wrap-up notice: `max(counter_percent,
    /// clock_percent) >= 80`, whichever crosses first, exactly once per
    /// pass. Reuses the LLM-4 `Plan80` threshold + PLAN template — the
    /// driver is the one emitter, so the guard's own ladder events (which
    /// surface inside step admissions) never double-signal the pass.
    fn maybe_fire_wrap_notice(&mut self) {
        if self.wrap_notice_fired {
            return;
        }
        let counter_percent = self
            .guard
            .as_ref()
            .map_or(0, |guard| guard.read().depleted_percent());
        if counter_percent.max(self.deadline.elapsed_percent()) < DREAMER_WRAP_UP_NOTICE_PERCENT {
            return;
        }
        self.wrap_notice_fired = true;
        self.steering.push(BudgetSteeringSignal {
            threshold: BudgetThreshold::Plan80,
            channel: BudgetSignalDeliveryChannel::SteeringQueueNextTurn,
            template_id: BUDGET_PLAN_PROMPT_TEMPLATE_ID.to_owned(),
            message: BUDGET_PLAN_PROMPT_TEMPLATE.to_owned(),
        });
    }

    fn counter_exhausted(&self) -> bool {
        self.guard
            .as_ref()
            .is_some_and(|guard| guard.read().remaining_units == 0)
    }

    /// Enters the graceful-wrap finalize phase once (`in_finalize_window()`
    /// OR counter exhaustion), emitting the LAND steering signal exactly
    /// once. Returns true while finalize is active.
    fn enter_finalize_if_due(&mut self) -> bool {
        if !self.finalize_entered {
            if !self.deadline.in_finalize_window() && !self.counter_exhausted() {
                return false;
            }
            self.finalize_entered = true;
            self.steering.push(BudgetSteeringSignal {
                threshold: BudgetThreshold::Land95,
                channel: BudgetSignalDeliveryChannel::SteeringQueueNextTurn,
                template_id: BUDGET_LAND_PROMPT_TEMPLATE_ID.to_owned(),
                message: BUDGET_LAND_PROMPT_TEMPLATE.to_owned(),
            });
        }
        true
    }

    fn milestone_claim(
        &self,
        kind: DreamerMilestoneKind,
        now: u64,
    ) -> Option<DreamerMilestoneClaim> {
        self.milestones
            .as_ref()
            .map(|author| DreamerMilestoneClaim {
                claim_id: EntityId::now(),
                subject: author.subject,
                kind,
                envelope: author.envelope.clone(),
                occurred: TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
            })
    }

    /// Writes a durable milestone claim for `job_id` through the gate,
    /// matching the landed `dreamer.job_milestone` value codec exactly
    /// (pinned keys `schema_version`/`job_id`/`milestone`/`at`).
    fn write_milestone(&self, job_id: JobId, kind: DreamerMilestoneKind, now: u64) -> Result<()> {
        let Some(author) = &self.milestones else {
            return Ok(());
        };
        let claim_id = EntityId::now();
        let value = Value::Map(vec![
            (
                Value::from("schema_version"),
                Value::from(DREAMER_MILESTONE_VALUE_SCHEMA_VERSION),
            ),
            (
                Value::from("job_id"),
                Value::Binary(job_id.as_bytes().to_vec()),
            ),
            (Value::from("milestone"), Value::from(kind.as_str())),
            (Value::from("at"), Value::from(now)),
        ]);
        let candidate = ClaimCandidate::new(
            DREAMER_MILESTONE_PREDICATE,
            crate::claim::ClaimSubject::Entity(author.subject),
            value,
            1.0,
        );
        let occurred = TimeRange {
            start: now,
            end: now,
        };
        self.vault.with_write_txn(|wtxn| {
            self.vault
                .batch_in()
                .claim_candidate(&claim_id, candidate, &author.envelope, occurred, now)
                .apply(wtxn)
        })
    }

    fn complete_job(&mut self, admitted: &DreamerAdmittedJob, now: u64) -> Result<()> {
        let input = CompleteDreamerJob {
            id: admitted.status.job.id,
            lease_owner: admitted.status.job.lease_owner.clone().unwrap_or_default(),
            attempt_count: admitted.status.job.attempt_count,
            now,
        };
        #[cfg(feature = "sync")]
        if let Some(lane) = &mut self.progress {
            self.store
                .complete_with_progress(input, &mut lane.producer, lane.ephemeral)?;
            return Ok(());
        }
        self.store.complete(input)?;
        Ok(())
    }

    fn park_job(
        &mut self,
        job_id: JobId,
        reason: String,
        park_owner: String,
        now: u64,
    ) -> Result<()> {
        let input = ParkDreamerJob {
            job_id,
            reason,
            park_owner,
            now,
        };
        #[cfg(feature = "sync")]
        if let Some(lane) = &mut self.progress {
            self.store
                .park_job_with_progress(input, &mut lane.producer, lane.ephemeral)?;
            return Ok(());
        }
        self.store.park_job(input)?;
        Ok(())
    }

    // The Result is only fallible on the sync progress lane.
    #[cfg_attr(not(feature = "sync"), allow(clippy::unnecessary_wraps))]
    fn publish(
        &mut self,
        job_id: JobId,
        kind: ProgressKind,
        message: Option<String>,
        now: u64,
    ) -> Result<()> {
        #[cfg(feature = "sync")]
        if let Some(lane) = &mut self.progress {
            let state = match kind {
                ProgressKind::Running => DreamerJobProgressState::Running,
                ProgressKind::Parked => DreamerJobProgressState::Parked,
            };
            self.store.publish_progress(
                &mut lane.producer,
                lane.ephemeral,
                DreamerJobProgressUpdate {
                    job_id,
                    state,
                    message,
                    completed_units: 0,
                    total_units: None,
                    updated_at_ms: now.saturating_mul(1_000),
                },
            )?;
        }
        #[cfg(not(feature = "sync"))]
        let _ = (job_id, kind, message, now);
        Ok(())
    }
}

/// Driver-internal progress vocabulary (maps onto the sync-gated
/// `DreamerJobProgressState` when the progress lane is configured).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProgressKind {
    Running,
    Parked,
}

/// Wake scheduling entry: enqueues one consolidation job on the advisory
/// job-table floor. The engine owns NO timer/cron — hosts call this.
///
/// `trigger` carries host intent; the scope is the caller's (typically
/// `trigger.default_scope()`, which an Event payload may override).
pub fn request_wake(
    store: &DreamerRunnerStore<'_>,
    trigger: WakeTrigger,
    scope: DreamerConsolidationScope,
    payload: DreamerJobPayload,
    dedupe_key: Option<String>,
    run_id: Option<String>,
    now: u64,
) -> Result<EnqueueDreamerJobOutcome> {
    // The trigger's runtime effect is scope derivation, owned by the caller
    // via `WakeTrigger::default_scope`; it is accepted here so hosts express
    // intent at the single wake entry point.
    let _ = trigger;
    store.enqueue_consolidation(EnqueueDreamerConsolidationJob {
        scope,
        input: payload.input,
        parent_job: payload.parent_job,
        dedupe_key,
        run_id,
        now,
    })
}

#[cfg(test)]
mod tests;
