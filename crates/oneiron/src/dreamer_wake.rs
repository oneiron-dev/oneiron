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
#[cfg(feature = "sync")]
use crate::sync::EphemeralStore;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteEnvelope};

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
}

impl fmt::Debug for WakePassDeadline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WakePassDeadline")
            .field("ceiling_ms", &self.ceiling_ms)
            .field("elapsed_ms", &self.elapsed())
            .finish()
    }
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
            #[cfg(feature = "sync")]
            progress: None,
        }
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
    pub async fn run_wake_pass<E: DreamerJobExecutor + ?Sized>(
        &mut self,
        input: RunWakePass,
        exec: &mut E,
    ) -> Result<WakePassReport> {
        let mut report = WakePassReport {
            admitted: 0,
            completed: 0,
            failed: 0,
            parked: 0,
            stop: WakePassStop::QueueEmpty,
        };

        loop {
            if self.deadline.expired() {
                report.stop = WakePassStop::DeadlineHardCut;
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
            self.publish(job_id, ProgressKind::Running, None, input.now)?;

            let execution = {
                let mut ctx = WakeJobContext {
                    vault: self.vault,
                    deadline: &self.deadline,
                    budget_id: &self.budget_id,
                    now_ms: input.now.saturating_mul(1_000),
                };
                exec.execute(&admitted, &mut ctx).await?
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
                    if self.store.parked_job(job_id)?.is_some() {
                        // One park-owner: the step layer already parked this
                        // job inside its trap wtxn — publish only.
                        self.publish(job_id, ProgressKind::Parked, Some(reason), input.now)?;
                    } else {
                        self.park_job(job_id, reason, input.now)?;
                    }
                    report.parked += 1;
                }
            }
        }

        Ok(report)
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

    fn park_job(&mut self, job_id: JobId, reason: String, now: u64) -> Result<()> {
        let input = ParkDreamerJob {
            job_id,
            reason,
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
