//! The wake loop: admit, warn, dispatch under panic containment, stop conditions.

mod admission;
mod attribution;
mod claim_authoring;
mod concurrent;
mod executor_error;
mod hooks;
mod observe;
mod park_cause;
mod rewrite;
mod settle;
mod stop;

pub use self::claim_authoring::{BoundClaimAuthoringSelector, ClaimAuthoringSelection};
use self::observe::WakePassClock;
pub(crate) use self::park_cause::{llm_waits_on_owner_act, waits_on_owner_act};
pub(crate) use self::rewrite::check_host_wake_rewrite;
use self::settle::Settlement;
use self::stop::{attempt_stop, boundary_stop};

use std::future::poll_fn;
use std::panic::AssertUnwindSafe;
use std::pin::pin;
use std::task::Poll;

use crate::Vault;
use crate::attempt_queue::{AttemptQueue, LandingWarningOutcome, WarnAttemptBudgetPressure};
use crate::dreamer_runner::{
    AdmitDreamerAttempt, AdmitDreamerConsolidationAttempt, DreamerAdmissionOutcome,
    DreamerClaimAuthoringBatchTier, DreamerConsolidationAdmissionOutcome,
    DreamerConsolidationScope, DreamerMilestoneKind, DreamerParkCause, DreamerRunnerStore,
    ParkDreamerAttempt, SettleDreamerBudget,
};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Result;
use crate::llm::{
    BUDGET_LAND_PROMPT_TEMPLATE, BUDGET_LAND_PROMPT_TEMPLATE_ID, BUDGET_PLAN_PROMPT_TEMPLATE,
    BUDGET_PLAN_PROMPT_TEMPLATE_ID, BudgetGuard, BudgetSignalDeliveryChannel, BudgetSteeringSignal,
    BudgetThreshold,
};

use super::deadline::{DREAMER_WRAP_UP_NOTICE_PERCENT, WakeCancellation, WakePassDeadline};
use super::settlement::admitted_lease;
#[cfg(feature = "sync")]
use super::types::WakeProgressLane;
use super::types::{
    DreamerAttemptExecution, DreamerAttemptExecutor, LandingRequest, ProgressKind, RunWakePass,
    WakeAttemptContext, WakeAttemptMeter, WakeMilestoneAuthor, WakePassReport, WakePassStop,
    WakeTrigger,
};

/// Park reason stamped on attempts cut at the wake-pass ceiling.
pub const DREAMER_HARD_CUT_PARK_REASON: &str = "wake-pass hard cut";

/// Park-owner token for a step-layer hard-cut park. Retained for recovery of
/// existing park rows; admitted LLM calls now finish and settle before the
/// enclosing executor stops run continuation.
pub const DREAMER_HARD_CUT_PARK_OWNER: &str = "dreamer.step:hard-cut";

/// Park reason stamped on attempts preempted by a cooperative cancellation
/// request (ONE-1683 H-S5/R2): the admitted attempt is parked and its budget
/// reservation refunded before the pass stops — cancellation never leaks.
pub const DREAMER_CANCELLED_PARK_REASON: &str = "wake-pass cancelled";

/// Park reason stamped on attempts the host's pause preempted before dispatch
/// (FIX 6909): parked and refunded as a cancelled one, but resumable.
pub const DREAMER_PAUSED_PARK_REASON: &str = "wake-pass paused";

/// Park reason PREFIX stamped on attempts whose executor returned a
/// non-deadline error (ONE-1683 H-S5/R2): the error path parks the admitted
/// attempt and refunds its reservation before the error propagates.
pub const DREAMER_EXECUTOR_ERROR_PARK_REASON: &str = "executor error";

/// One `Pending` poll with an immediate self-wake — the runtime-agnostic
/// equivalent of `tokio::task::yield_now` (the engine takes no runtime
/// dependency). [`DreamerWakeDriver::run_wake_pass`] awaits this at every
/// attempt boundary so an enclosing `select!` (the ONE-1683 supervisor's
/// shutdown branch) gets a poll between attempts even when executors complete
/// synchronously.
fn yield_once() -> impl std::future::Future<Output = ()> {
    let mut yielded = false;
    poll_fn(move |task_cx| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            task_cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
}

/// The wake-pass driver: one bounded work cycle over the consolidation
/// queue on one node.
pub struct DreamerWakeDriver<'a> {
    pub(super) vault: &'a Vault,
    pub(super) store: DreamerRunnerStore<'a>,
    pub(super) budget_id: String,
    pub(super) deadline: WakePassDeadline,
    pub(super) milestones: Option<WakeMilestoneAuthor>,
    /// The ONE wake-budget counter (LLM-4 guard) for legibility + the 80%
    /// wrap notice; None keeps the counter side of the trigger silent.
    pub(super) guard: Option<BudgetGuard>,
    pub(super) wrap_notice_fired: bool,
    pub(super) finalize_entered: bool,
    pub(super) steering: Vec<BudgetSteeringSignal>,
    consolidation_only: bool,
    skill_optimizer: Option<crate::dreamer_runner::maintenance::CoachSkillOptimizer<'a>>,
    contribution_host:
        Option<&'a (dyn crate::dreamer_runner::maintenance::ContributionReplayHost + Send + Sync)>,
    claim_authoring: ClaimAuthoringSelection,
    /// The material this pass's `host.wake` pre-hooks added (FIX 8722).
    hook_material: Vec<String>,
    #[cfg(feature = "sync")]
    pub(super) progress: Option<WakeProgressLane<'a>>,
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
            consolidation_only: false,
            skill_optimizer: None,
            contribution_host: None,
            claim_authoring: ClaimAuthoringSelection::None,
            hook_material: Vec::new(),
            #[cfg(feature = "sync")]
            progress: None,
        }
    }

    /// The material this pass's `host.wake` pre-hooks added, in order, each
    /// text re-validated and re-gated (FIX 8722); empty when none did.
    #[must_use]
    pub fn hook_material(&self) -> &[String] {
        &self.hook_material
    }

    /// Attach the Coach's author and independent typed-decision replay judge.
    pub fn with_skill_optimizer(
        mut self,
        optimizer: crate::dreamer_runner::maintenance::CoachSkillOptimizer<'a>,
    ) -> Self {
        self.skill_optimizer = Some(optimizer);
        self
    }

    /// Attach the host's replay capsule for the Coach's contribution checks.
    pub fn with_contribution_host(
        mut self,
        host: &'a (dyn crate::dreamer_runner::maintenance::ContributionReplayHost + Send + Sync),
    ) -> Self {
        self.contribution_host = Some(host);
        self
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
    /// it is polled ONLY at the attempt-boundary checkpoints — the loop top and
    /// the pre-dispatch point right after admission — never mid-await inside
    /// `exec.execute` and never between a gated write and its settle. A
    /// cancel that lands after admission parks the admitted attempt and refunds
    /// its budget reservation before the pass stops
    /// [`WakePassStop::Cancelled`]. Hosts that never cancel pass a fresh
    /// [`WakeCancellation`].
    ///
    /// The loop yields to the runtime once per attempt boundary, so a
    /// supervisor selecting over this future and a shutdown signal gets a
    /// poll between attempts — and can raise `cancel` in time — even when every
    /// executor completes synchronously. A panic inside `exec.execute` is
    /// contained at the same boundary: the admitted attempt is parked, its
    /// reservation refunded, and the pass returns an error instead of
    /// unwinding past the bookkeeping.
    pub async fn run_wake_pass<E: DreamerAttemptExecutor + ?Sized>(
        &mut self,
        input: RunWakePass,
        exec: &mut E,
        cancel: &WakeCancellation,
    ) -> Result<WakePassReport> {
        let clock = WakePassClock::start(&input);
        let hooks = match self.pre_wake_hooks(&input)? {
            Ok(hooks) => hooks,
            Err(skipped) => return Ok(skipped),
        };
        self.start_wake_observation(&input);
        let report = self.run_begun_wake_pass(input, exec, cancel).await;
        self.finish_wake_observation(report.as_ref());
        let report = report?;
        self.post_wake_hooks(hooks, &report);
        clock.log(&report);
        Ok(report)
    }

    fn begin_wake(&mut self, input: &RunWakePass) -> Result<()> {
        let now = input.now;
        // Per-pass driver state (ONE-1305): a reused driver must fire its
        // wrap/finalize notices anew each pass, and steering signals belong
        // to the pass that raised them — the host drains them after run.
        self.wrap_notice_fired = false;
        self.finalize_entered = false;
        self.steering.clear();

        // ONE-1708: a human-assigned TASK realizes no job, so its follow-up has
        // no queue row to be admitted from. It rides the wake pass itself —
        // ordinary Dreamer maintenance over the synced TASK fact, before any
        // attempt is admitted and outside the budget/lease loop entirely.
        crate::llm::resume_peer_result_steps(self.vault, now.saturating_mul(1_000))?;
        // A consent answer, budget grant or person's response already sent
        // (here, or by a peer through sync) resumes its parked attempt as
        // the same try, admissible in this very pass.
        crate::llm::resume_signalled_steps(self.vault, now.saturating_mul(1_000))?;
        // An ended pass's Checkpoint parks, and its Retry parks whose delay
        // passed, resume as the same tries (DOOR-144).
        self.resume_checkpoints(input);
        // An owner Stop's owed abandon is retried once due, on every wake
        // host, with a program runtime bound or none (FIX 7352).
        self.store.recover_owed_stop_abandons(now);
        // A crash between a paid wake call and its settle leaves the spend
        // owed; charge it from the step's terminal usage before any attempt
        // is admitted (FIX 11450). A reconcile that fails is logged and never
        // stops the pass.
        match super::owed::reconcile_owed_calls(self.vault, now) {
            Ok((charged, dropped)) => {
                tracing::debug!(charged, dropped, "reconciled owed wake calls");
            }
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "owed wake calls were not reconciled this pass"
                );
            }
        }
        crate::human_task::run_human_followups_on_wake(self.vault, now)?;
        self.vault.retry_pending_ask_soft_confirms(usize::MAX)?;
        // PEOPLE `about`: a person whose facts moved queues its lines anew.
        crate::dreamer_consolidation::enqueue_person_about_on_wake(self.vault, now)?;
        // Each free-time cycle whose owner-set boundary has come opens on
        // the elected home (FIX 4453), before any attempt is admitted. A
        // cycle that cannot open is logged and never stops the pass.
        if !self.consolidation_only
            && input.trigger == WakeTrigger::Timer
            && input.scope == DreamerConsolidationScope::Macro
            && let Err(error) = self
                .vault
                .enqueue_due_free_time_cycles(now, input.local_node_id)
        {
            tracing::warn!(
                kind = ?error.kind(),
                "free-time cycles did not open this pass"
            );
        }
        // Due Arcs (FIX 7509 P8) are swept on the same home Timer pass.
        if !self.consolidation_only
            && input.trigger == WakeTrigger::Timer
            && input.scope == DreamerConsolidationScope::Macro
        {
            super::arc_backstop::sweep_on_timer(self.vault, now, input.local_node_id);
        }

        Ok(())
    }

    async fn run_prepared_wake_pass<E: DreamerAttemptExecutor + ?Sized>(
        &mut self,
        input: RunWakePass,
        exec: &mut E,
        cancel: &WakeCancellation,
        prepared_wake: &crate::dreamer_consolidation::PreparedWake,
    ) -> Result<WakePassReport> {
        let admission_policy = self.vault.dreamer_wake_policy()?;
        let mut report = WakePassReport {
            admitted: 0,
            completed: 0,
            failed: 0,
            deferred: 0,
            parked: 0,
            landed: 0,
            sources_truncated: 0,
            stop: WakePassStop::QueueEmpty,
            claim_authoring_fallback: None,
        };
        // Set once a TASK's admission is refused: the rest of the pass admits
        // the vault's own work and no more TASKs.
        let mut task_admission_refused = false;
        // The same for turn programs (DOOR-141 PR2).
        let mut program_admission_refused = false;
        // The first executor error parked as a Retry (FIX 7272): the pass
        // goes on past it and returns it at its end.
        let mut held_error: Option<crate::Error> = None;

        loop {
            // Attempt-boundary yield (ONE-1683): one Pending poll with a
            // self-wake per iteration, so a supervisor selecting over this
            // pass and its shutdown signal is re-polled between attempts even
            // when the executor completes synchronously — otherwise a
            // shutdown requested mid-pass could not raise the cancellation
            // flag until the whole queue drained.
            yield_once().await;
            if let Some(stop) = boundary_stop(self, cancel) {
                report.stop = stop;
                break;
            }

            let priority = self.admit_priority(
                &input,
                exec,
                &admission_policy,
                &mut task_admission_refused,
                &mut program_admission_refused,
            )?;
            let mut admitted =
                match priority {
                    DreamerAdmissionOutcome::Admitted(attempt) => *attempt,
                    DreamerAdmissionOutcome::BudgetExhausted(_) => {
                        report.stop = WakePassStop::BudgetExhausted;
                        break;
                    }
                    DreamerAdmissionOutcome::Empty => match self.store.admit_next_consolidation(
                        AdmitDreamerConsolidationAttempt {
                            scope: input.scope,
                            local_node_id: input.local_node_id,
                            claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
                            claim_authoring: self.selected_claim_authoring(&mut report)?,
                            admission: AdmitDreamerAttempt {
                                lease_owner: input.lease_owner.clone(),
                                now: input.now,
                                budget_id: self.budget_id.clone(),
                                budget_total_units: input.budget_total_units,
                                reserve_units: input.reserve_units,
                                started_milestone: self
                                    .milestone_claim(DreamerMilestoneKind::Started, input.now)?,
                            },
                        },
                    )? {
                        DreamerConsolidationAdmissionOutcome::NoHomeNode => {
                            report.stop = WakePassStop::NoHomeNode;
                            break;
                        }
                        DreamerConsolidationAdmissionOutcome::NotHomeNode(_) => {
                            report.stop = WakePassStop::NotHomeNode;
                            break;
                        }
                        DreamerConsolidationAdmissionOutcome::ClaimAuthoringBudgetTrap(_) => {
                            // The store already paused the attempt (admission-level trap).
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
                            DreamerAdmissionOutcome::Admitted(attempt),
                        ) => *attempt,
                    },
                };

            report.admitted += 1;
            let attempt_id = admitted.status.attempt.id;
            self.observe_admitted(&admitted);
            // The runner line this attempt reserved on: the pass's, or the
            // line the host routed it to.
            let line = admitted.reservation.budget_id.clone();
            // The line an owed wake call of this attempt charges (FIX 11450).
            if let Some(wake) = self.deadline.wake_ref() {
                self.vault
                    .active_wakes
                    .record_attempt_line(wake, attempt_id, &line);
            }

            // ONE-1896 §3, quota/budget rung, at the ONE boundary where this
            // pass both holds a leased attempt and can still act: the wake
            // counter is already inside its wrap window, so the RUNTIME warns
            // the worker to land while there is budget left to land with.
            // Purely a request — nothing is terminated, the executor still
            // runs, and a worker that ignores it keeps its lease. Once per
            // admitted generation: the queue door is idempotent per
            // outstanding ask, so a re-admitted attempt records one row. A
            // warning that fails flows through the executor-error arm below,
            // as a Running-progress publish failure does (FIX 7273).
            let mut pressure = Ok(());
            if self.budget_pressure_now() {
                match AttemptQueue::new(self.vault).warn_budget_pressure(
                    WarnAttemptBudgetPressure {
                        id: attempt_id,
                        now: input.now,
                    },
                ) {
                    Ok(LandingWarningOutcome::LandingRequested(record)) => {
                        // The executor reads its attempt from the admitted
                        // snapshot, so the warning has to be IN it — otherwise
                        // a cooperative worker would have to guess that the
                        // runtime asked.
                        admitted.status.attempt = record;
                    }
                    Ok(
                        LandingWarningOutcome::AlreadyRequested(_)
                        | LandingWarningOutcome::NotRunning(_),
                    ) => {}
                    Err(error) => pressure = Err(error),
                }
            }

            // Cooperative-preemption checkpoint (H-S5/R2): the ONE point
            // between admission and settle where a cancel is honored is
            // HERE, before the executor dispatch — never mid-await. The
            // admitted attempt flows through the ordinary Park arm below, which
            // refunds its budget reservation and parks it before the pass
            // stops.
            let cancel_requested = cancel.is_cancelled();
            let mut backlog_left = false;
            // What the attempt's own run line charged, read outside the
            // executor's future (SCAN C012): an attempt that never
            // dispatched registers nothing and settles zero.
            let spend_meter = WakeAttemptMeter::default();
            // Where a non-executor outcome came from, for its outcome line
            // (FIX 7271); `None` is the executor's own.
            let mut stage = None;
            let mut hard_cut_error = None;
            let executed = if let Err(pressure_error) = pressure {
                stage = Some("budget_pressure");
                Err(pressure_error)
            } else if cancel_requested && cancel.is_paused() {
                // The host's pause (FIX 6909): a later pass resumes it.
                stage = Some("paused");
                Ok(DreamerAttemptExecution::Park {
                    reason: DREAMER_PAUSED_PARK_REASON.to_owned(),
                    cause: DreamerParkCause::Paused,
                })
            } else if cancel_requested {
                stage = Some("cancelled");
                Ok(DreamerAttemptExecution::Park {
                    reason: DREAMER_CANCELLED_PARK_REASON.to_owned(),
                    cause: DreamerParkCause::Cancelled,
                })
            } else if let Err(publish_error) =
                self.publish(attempt_id, ProgressKind::Running, None, input.now)
            {
                // A Running-progress publish failure after admission flows
                // through the same release arm as an executor error —
                // propagating it directly would leave the admitted attempt
                // leased and its reservation held.
                stage = Some("progress_publish");
                Err(publish_error)
            } else if admitted.status.attempt.kind == input.scope.attempt_kind()
                && !prepared_wake.contains_attempt(attempt_id)
            {
                // Enqueued after the frozen wake revision, or past the head of
                // a backlog larger than one wake prepares: never admit it to
                // this snapshot or fall back to a newer per-attempt read. Past
                // the head, the pass ends here and the next prepares the rest.
                stage = Some("backlog_deferred");
                backlog_left = prepared_wake.left_for_later(attempt_id);
                Ok(DreamerAttemptExecution::Deferred {
                    completed_units: 0,
                    retry_at: input.now.saturating_add(1),
                    step_hashes: Vec::new(),
                })
            } else if let Some(crate::dreamer_consolidation::AttemptPreparation::Refused {
                reason,
                ..
            }) = prepared_wake.preparation(attempt_id)
            {
                // A refused preparation is prepared again after its retry
                // delay (FIX 7272); none waits on an owner act.
                stage = Some("prepared_refused");
                Ok(DreamerAttemptExecution::Park {
                    reason: (*reason).to_owned(),
                    cause: DreamerParkCause::Retry,
                })
            } else if matches!(
                prepared_wake.preparation(attempt_id),
                Some(crate::dreamer_consolidation::AttemptPreparation::ResidencyDeferred)
            ) {
                // A source away from this replica (OF-534) is a wait, never
                // a park: the attempt stays queued and runs on promotion.
                stage = Some("residency_deferred");
                Ok(DreamerAttemptExecution::Deferred {
                    completed_units: 0,
                    retry_at: input
                        .now
                        .saturating_add(crate::dreamer_consolidation::RESIDENCY_RETRY_SECS),
                    step_hashes: Vec::new(),
                })
            } else {
                let mut ctx = WakeAttemptContext {
                    vault: self.vault,
                    deadline: &self.deadline,
                    cancel: Some(cancel),
                    budget_id: &line,
                    now_ms: input.now.saturating_mul(1_000),
                    prepared_wake: Some(prepared_wake),
                    prepared_attempt: match prepared_wake.preparation(attempt_id) {
                        Some(crate::dreamer_consolidation::AttemptPreparation::Ready(plan)) => {
                            Some(plan)
                        }
                        _ => None,
                    },
                    spend_meter: Some(&spend_meter),
                };
                if ctx.prepared_attempt.is_some_and(
                    crate::dreamer_consolidation::PreparedConsolidationAttempt::sources_truncated,
                ) {
                    report.sources_truncated = report.sources_truncated.saturating_add(1);
                }
                // Panic containment at the per-attempt boundary (ONE-1683): a
                // panicking executor unwinding past the driver would skip
                // the park/refund bookkeeping below, leaving the attempt leased
                // and the reservation held until external lease cleanup.
                // Catch it and route it through the executor-error arm. It
                // parks as its cause says, but this executor is not used
                // again in this pass: the pass ends on the panic and the
                // next one gets a fresh executor (FIX 7322).
                let mut execute = pin!(async {
                    if admitted.status.attempt.kind
                        == crate::dreamer_runner::DREAMER_VAULT_CLEANUP_ATTEMPT_KIND
                    {
                        crate::vault_cleanup::run_vault_cleanup(self.vault, &attempt_id)?;
                        Ok(DreamerAttemptExecution::Completed {
                            completed_units: 0,
                            step_hashes: Vec::new(),
                        })
                    } else if admitted.status.attempt.kind
                        == crate::dreamer_runner::DREAMER_SKILL_OPTIMIZE_ATTEMPT_KIND
                    {
                        crate::dreamer_runner::maintenance::optimize::execute(
                            &admitted,
                            &ctx,
                            self.skill_optimizer.as_ref(),
                        )
                    } else if admitted.status.attempt.kind
                        == crate::dreamer_runner::maintenance::MAINTENANCE_QUEUE_KIND
                        && admitted.status.payload.attempt_type
                            != crate::dreamer_runner::maintenance::COMPACTION_CHECK_FACET
                        && admitted.status.payload.attempt_type
                            != crate::dreamer_runner::maintenance::digest::DIGEST_ASSESS_FACET
                    {
                        crate::dreamer_runner::maintenance::execute(
                            &admitted,
                            &ctx,
                            self.contribution_host,
                        )
                    } else if admitted.status.attempt.kind
                        == crate::dreamer_runner::DREAMER_RECIPE_WAKE_ATTEMPT_KIND
                    {
                        super::recipe_wake::execute(&admitted, &ctx)
                    } else {
                        // The host's executor runs the rest, a self-written
                        // compaction's check (FIX 4465 B) and an urgent
                        // digest's harm question (OF-194) among them: each
                        // is judged on the model or ladder the host lends.
                        exec.execute(&admitted, &mut ctx).await
                    }
                });
                let caught = poll_fn(|task_cx| {
                    match std::panic::catch_unwind(AssertUnwindSafe(|| {
                        execute.as_mut().poll(task_cx)
                    })) {
                        Ok(poll) => poll.map(Ok),
                        Err(panic) => Poll::Ready(Err(panic)),
                    }
                })
                .await;
                match caught {
                    Ok(result) => result,
                    // The payload is dropped unread: a panic message can quote
                    // the row the executor was working on, and logs never
                    // carry world text. The attempt id says where to look.
                    Err(_payload) => {
                        tracing::error!(
                            attempt_id = %bytes_to_hex_lower(attempt_id.as_bytes()),
                            kind = "executor_panic",
                            "dreamer attempt executor panicked; parking the admitted attempt"
                        );
                        stage = Some("executor_panic");
                        Err(crate::Error::InvariantViolation(
                            "dreamer attempt executor panicked",
                        ))
                    }
                }
            };
            let execution = match executed {
                Ok(execution) => execution,
                Err(error) => {
                    // An executor may already have parked a hard-cut attempt
                    // before surfacing an error. The budget refund, park
                    // bookkeeping, and checkpoint milestone must still run.
                    let step_layer_parked = self
                        .store
                        .parked_attempt(attempt_id)?
                        .is_some_and(|row| row.reason == DREAMER_HARD_CUT_PARK_REASON);
                    if !step_layer_parked && !self.deadline.expired() {
                        // H-S5/R2 (ONE-1683): a non-deadline executor error
                        // releases what admission acquired before the error
                        // leaves the pass.
                        let stage = stage.unwrap_or("executor_err");
                        let ends_pass = self.park_executor_error(
                            &admitted,
                            &line,
                            &spend_meter,
                            &error,
                            stage,
                            &input,
                        )?;
                        // A contained panic ends the pass once it parked
                        // (FIX 7322, Engine 10-21); other errors go on.
                        if ends_pass || stage == "executor_panic" {
                            return Err(error);
                        }
                        // FIX 7272: parked as a Retry a later pass resumes
                        // after its delay, so this pass goes on and fails at
                        // its end.
                        report.parked += 1;
                        held_error.get_or_insert(error);
                        if cancel_requested {
                            report.stop = WakePassStop::Cancelled;
                            break;
                        }
                        continue;
                    }
                    hard_cut_error = Some(error.kind());
                    DreamerAttemptExecution::Park {
                        reason: DREAMER_HARD_CUT_PARK_REASON.to_owned(),
                        cause: DreamerParkCause::Checkpoint,
                    }
                }
            };

            self.settle_execution(
                &*exec,
                Settlement {
                    input: &input,
                    admitted: &admitted,
                    line: &line,
                    spend_meter: &spend_meter,
                    attempt_id,
                    execution,
                    stage,
                    hard_cut_error,
                },
                &mut report,
            )
            .await?;

            if let Some(stop) = attempt_stop(cancel_requested, backlog_left) {
                report.stop = stop;
                break;
            }
        }

        // A pass that went on past a Retry-parked executor error still
        // fails, on the first one (FIX 7272).
        held_error.map_or(Ok(report), Err)
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

    /// Whether the pass counter has entered its wrap window, which is the
    /// quota/budget condition ONE-1896 warns a running worker about.
    ///
    /// Reuses the SAME [`BudgetGuard`] read the wrap notice and the finalize
    /// window already use — no second meter and no second threshold.
    fn budget_pressure_now(&self) -> bool {
        self.guard.as_ref().is_some_and(|guard| {
            let read = guard.read();
            read.depleted_percent() >= DREAMER_WRAP_UP_NOTICE_PERCENT || read.remaining_units == 0
        })
    }

    // The Result is only fallible on the sync progress lane.
}
