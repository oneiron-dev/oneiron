//! The wake loop: admit, warn, dispatch under panic containment, stop conditions.

use std::future::poll_fn;
use std::panic::AssertUnwindSafe;
use std::pin::pin;
use std::task::Poll;

use crate::Vault;
use crate::attempt_queue::{AttemptQueue, LandingWarningOutcome, WarnAttemptBudgetPressure};
use crate::dreamer_runner::{
    AbortDreamerBudgetReservation, AdmitDreamerAttempt, AdmitDreamerConsolidationAttempt,
    DreamerAdmissionOutcome, DreamerClaimAuthoringAdmission, DreamerClaimAuthoringBatchTier,
    DreamerConsolidationAdmissionOutcome, DreamerConsolidationScope, DreamerMilestoneKind,
    DreamerRunnerStore, SettleDreamerBudget,
};
use crate::error::Result;
use crate::llm::{
    BUDGET_LAND_PROMPT_TEMPLATE, BUDGET_LAND_PROMPT_TEMPLATE_ID, BUDGET_PLAN_PROMPT_TEMPLATE,
    BUDGET_PLAN_PROMPT_TEMPLATE_ID, BudgetGuard, BudgetSignalDeliveryChannel, BudgetSteeringSignal,
    BudgetThreshold,
};

use super::deadline::{DREAMER_WRAP_UP_NOTICE_PERCENT, WakeCancellation, WakePassDeadline};
#[cfg(feature = "sync")]
use super::types::WakeProgressLane;
use super::types::{
    DreamerAttemptExecution, DreamerAttemptExecutor, LandingRequest, ProgressKind, RunWakePass,
    WakeAttemptContext, WakeMilestoneAuthor, WakePassReport, WakePassStop, WakeTrigger,
};

/// Park reason stamped on attempts cut at the wake-pass ceiling.
pub const DREAMER_HARD_CUT_PARK_REASON: &str = "wake-pass hard cut";

/// Park-owner token for deadline hard-cut parks: the step layer parks the
/// cut attempt under this token (no trap is opened at the ceiling), and only a
/// resumer presenting it may clear the row.
pub const DREAMER_HARD_CUT_PARK_OWNER: &str = "dreamer.step:hard-cut";

/// Park reason stamped on attempts preempted by a cooperative cancellation
/// request (ONE-1683 H-S5/R2): the admitted attempt is parked and its budget
/// reservation refunded before the pass stops — cancellation never leaks.
pub const DREAMER_CANCELLED_PARK_REASON: &str = "wake-pass cancelled";

/// Park reason PREFIX stamped on attempts whose executor returned a
/// non-deadline error (ONE-1683 H-S5/R2): the error path parks the admitted
/// attempt and refunds its reservation before the error propagates.
pub const DREAMER_EXECUTOR_ERROR_PARK_REASON: &str = "executor error";

/// Byte ceiling the runner store enforces on park reasons and progress
/// messages (`MAX_DREAMER_PARK_REASON_LEN` / `MAX_DREAMER_PROGRESS_MESSAGE_LEN`
/// in `dreamer_runner`, both 512 — private to that module, so mirrored here;
/// `executor_error_with_oversized_display_still_parks` pins the mirror
/// against the store's real validation).
pub(super) const MAX_WAKE_PARK_REASON_BYTES: usize = 512;

/// Clamps a park/progress reason to the runner store's validation ceiling,
/// cutting at a UTF-8 character boundary. An unbounded reason (typically an
/// executor error `Display`) must never fail park validation — a failed park
/// after admission would leave the attempt leased and is exactly the leak the
/// executor-error arm exists to close (ONE-1683). Only the durable reason
/// string is shortened; the full error still propagates to the caller.
pub(super) fn clamp_park_reason(mut reason: String) -> String {
    if reason.len() <= MAX_WAKE_PARK_REASON_BYTES {
        return reason;
    }
    let mut cut = MAX_WAKE_PARK_REASON_BYTES;
    while !reason.is_char_boundary(cut) {
        cut -= 1;
    }
    reason.truncate(cut);
    reason
}

/// Best-effort text of a caught panic payload, for tracing.
fn panic_message(panic: &(dyn std::any::Any + Send)) -> &str {
    if let Some(message) = panic.downcast_ref::<&'static str>() {
        message
    } else if let Some(message) = panic.downcast_ref::<String>() {
        message
    } else {
        "non-string panic payload"
    }
}

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
        crate::human_task::run_human_followups_on_wake(self.vault, input.now)?;

        let mut report = WakePassReport {
            admitted: 0,
            completed: 0,
            failed: 0,
            parked: 0,
            landed: 0,
            stop: WakePassStop::QueueEmpty,
        };

        loop {
            // Attempt-boundary yield (ONE-1683): one Pending poll with a
            // self-wake per iteration, so a supervisor selecting over this
            // pass and its shutdown signal is re-polled between attempts even
            // when the executor completes synchronously — otherwise a
            // shutdown requested mid-pass could not raise the cancellation
            // flag until the whole queue drained.
            yield_once().await;
            if cancel.is_cancelled() {
                // Cooperative-preemption boundary (H-S5/R2): between attempts
                // the driver holds no admitted attempt and no in-flight gated
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
                // Graceful wrap: admit NO new attempts and NO new step leases;
                // the pass ends under deadline/budget pressure.
                report.stop = if self.counter_exhausted() {
                    WakePassStop::BudgetExhausted
                } else {
                    WakePassStop::DeadlineHardCut
                };
                break;
            }

            let cleanup = if input.trigger == WakeTrigger::Timer
                && input.scope == DreamerConsolidationScope::Macro
            {
                self.store.admit_next_vault_cleanup(AdmitDreamerAttempt {
                    lease_owner: input.lease_owner.clone(),
                    now: input.now,
                    budget_id: self.budget_id.clone(),
                    budget_total_units: input.budget_total_units,
                    reserve_units: input.reserve_units,
                    started_milestone: self
                        .milestone_claim(DreamerMilestoneKind::Started, input.now),
                })?
            } else {
                DreamerAdmissionOutcome::Empty
            };
            let mut admitted =
                match cleanup {
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
                            claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
                            admission: AdmitDreamerAttempt {
                                lease_owner: input.lease_owner.clone(),
                                now: input.now,
                                budget_id: self.budget_id.clone(),
                                budget_total_units: input.budget_total_units,
                                reserve_units: input.reserve_units,
                                started_milestone: self
                                    .milestone_claim(DreamerMilestoneKind::Started, input.now),
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

            // ONE-1896 §3, quota/budget rung, at the ONE boundary where this
            // pass both holds a leased attempt and can still act: the wake
            // counter is already inside its wrap window, so the RUNTIME warns
            // the worker to land while there is budget left to land with.
            // Purely a request — nothing is terminated, the executor still
            // runs, and a worker that ignores it keeps its lease. Once per
            // admitted generation: the queue door is idempotent per
            // outstanding ask, so a re-admitted attempt records one row.
            if self.budget_pressure_now() {
                match AttemptQueue::new(self.vault).warn_budget_pressure(
                    WarnAttemptBudgetPressure {
                        id: attempt_id,
                        now: input.now,
                    },
                )? {
                    LandingWarningOutcome::LandingRequested(record) => {
                        // The executor reads its attempt from the admitted
                        // snapshot, so the warning has to be IN it — otherwise
                        // a cooperative worker would have to guess that the
                        // runtime asked.
                        admitted.status.attempt = record;
                    }
                    LandingWarningOutcome::AlreadyRequested(_)
                    | LandingWarningOutcome::NotRunning(_) => {}
                }
            }

            // Cooperative-preemption checkpoint (H-S5/R2): the ONE point
            // between admission and settle where a cancel is honored is
            // HERE, before the executor dispatch — never mid-await. The
            // admitted attempt flows through the ordinary Park arm below, which
            // refunds its budget reservation and parks it before the pass
            // stops.
            let cancel_requested = cancel.is_cancelled();
            let executed = if cancel_requested {
                Ok(DreamerAttemptExecution::Park {
                    reason: DREAMER_CANCELLED_PARK_REASON.to_owned(),
                })
            } else if let Err(publish_error) =
                self.publish(attempt_id, ProgressKind::Running, None, input.now)
            {
                // A Running-progress publish failure after admission flows
                // through the same release arm as an executor error —
                // propagating it directly would leave the admitted attempt
                // leased and its reservation held.
                Err(publish_error)
            } else {
                let mut ctx = WakeAttemptContext {
                    vault: self.vault,
                    deadline: &self.deadline,
                    budget_id: &self.budget_id,
                    now_ms: input.now.saturating_mul(1_000),
                };
                // Panic containment at the per-attempt boundary (ONE-1683): a
                // panicking executor unwinding past the driver would skip
                // the park/refund bookkeeping below, leaving the attempt leased
                // and the reservation held until external lease cleanup.
                // Catch it and route it through the executor-error arm; the
                // executor is abandoned when the error propagates (a
                // supervisor builds a fresh one per pass), so the
                // AssertUnwindSafe is never observable.
                let mut execute = pin!(async {
                    if admitted.status.attempt.kind
                        == crate::dreamer_runner::DREAMER_VAULT_CLEANUP_ATTEMPT_KIND
                    {
                        crate::vault_cleanup::run_vault_cleanup(self.vault, &attempt_id)?;
                        Ok(DreamerAttemptExecution::Completed { completed_units: 0 })
                    } else {
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
                    Err(panic) => {
                        tracing::error!(
                            panic = panic_message(panic.as_ref()),
                            "dreamer attempt executor panicked; parking the admitted attempt"
                        );
                        Err(crate::Error::InvariantViolation(
                            "dreamer attempt executor panicked",
                        ))
                    }
                }
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
                        .parked_attempt(attempt_id)?
                        .is_some_and(|row| row.reason == DREAMER_HARD_CUT_PARK_REASON);
                    if !step_layer_parked && !self.deadline.expired() {
                        // H-S5/R2 (ONE-1683): a non-deadline executor error
                        // must release what admission acquired BEFORE the
                        // error propagates — refund the budget reservation
                        // and park the admitted attempt, mirroring the Park arm
                        // below. Returning the error first used to leak the
                        // admitted attempt (stuck leased) AND its reservation.
                        self.store
                            .abort_budget_reservation(AbortDreamerBudgetReservation {
                                budget_id: self.budget_id.clone(),
                                child_attempt: attempt_id,
                                now: input.now,
                            })?;
                        // The durable reason is clamped to the store's
                        // validation ceiling: an oversized error Display
                        // failing park validation here would reintroduce
                        // the leaked-lease bug this arm fixes. The full
                        // error propagates below untouched.
                        let reason = clamp_park_reason(format!(
                            "{DREAMER_EXECUTOR_ERROR_PARK_REASON}: {error}"
                        ));
                        if self.store.parked_attempt(attempt_id)?.is_some() {
                            // One park-owner: the step layer already parked
                            // this attempt (under a non-hard-cut reason) inside
                            // its own wtxn — publish only, never re-park. A
                            // publish failure must not mask the executor
                            // error: the attempt is parked either way.
                            if let Err(publish_error) = self.publish(
                                attempt_id,
                                ProgressKind::Parked,
                                Some(reason),
                                input.now,
                            ) {
                                tracing::warn!(
                                    ?publish_error,
                                    "parked-progress publish failed after executor error"
                                );
                            }
                        } else {
                            self.park_attempt(
                                attempt_id,
                                reason,
                                input.lease_owner.clone(),
                                input.now,
                            )?;
                        }
                        return Err(error);
                    }
                    DreamerAttemptExecution::Park {
                        reason: DREAMER_HARD_CUT_PARK_REASON.to_owned(),
                    }
                }
            };

            match execution {
                DreamerAttemptExecution::Completed { completed_units } => {
                    self.store.settle_budget(SettleDreamerBudget {
                        budget_id: self.budget_id.clone(),
                        child_attempt: attempt_id,
                        actual_units: completed_units,
                        now: input.now,
                    })?;
                    self.complete_attempt(&admitted, input.now)?;
                    self.write_milestone(attempt_id, DreamerMilestoneKind::Done, input.now)?;
                    report.completed += 1;
                }
                DreamerAttemptExecution::Landed {
                    completed_units,
                    reserve_units,
                    status,
                    resume_point,
                    hand_off,
                } => {
                    let spent_reserve_units = self.land_attempt(
                        &admitted,
                        LandingRequest {
                            reserve_units,
                            status,
                            resume_point,
                            hand_off,
                        },
                        input.now,
                    )?;
                    // Ordinary work AND the bounded landing spend come out of
                    // the same reservation: both are units this attempt really
                    // consumed, so the wake ledger settles the sum rather than
                    // refunding work that happened.
                    self.store.settle_budget(SettleDreamerBudget {
                        budget_id: self.budget_id.clone(),
                        child_attempt: attempt_id,
                        actual_units: completed_units.saturating_add(spent_reserve_units),
                        now: input.now,
                    })?;
                    // A designed landing leaves a durable resume point, exactly
                    // like a deadline-cut park — never a `Done` milestone,
                    // which would claim the job delivered.
                    self.write_milestone(
                        attempt_id,
                        DreamerMilestoneKind::CheckpointReached,
                        input.now,
                    )?;
                    report.landed += 1;
                }
                DreamerAttemptExecution::Park { reason } => {
                    // Executor-authored reasons get the same clamp as the
                    // error arm's: park validation failing on length here
                    // would propagate AFTER the refund but BEFORE the park,
                    // leaving the attempt leased.
                    let reason = clamp_park_reason(reason);
                    // The lease is not settled as spent — refund the
                    // reservation.
                    self.store
                        .abort_budget_reservation(AbortDreamerBudgetReservation {
                            budget_id: self.budget_id.clone(),
                            child_attempt: attempt_id,
                            now: input.now,
                        })?;
                    let hard_cut =
                        reason == DREAMER_HARD_CUT_PARK_REASON || self.deadline.expired();
                    if self.store.parked_attempt(attempt_id)?.is_some() {
                        // One park-owner: the step layer already parked this
                        // attempt inside its trap wtxn — publish only.
                        self.publish(attempt_id, ProgressKind::Parked, Some(reason), input.now)?;
                    } else {
                        self.park_attempt(
                            attempt_id,
                            reason,
                            input.lease_owner.clone(),
                            input.now,
                        )?;
                    }
                    if hard_cut {
                        // A deadline-cut park leaves a durable resume point.
                        self.write_milestone(
                            attempt_id,
                            DreamerMilestoneKind::CheckpointReached,
                            input.now,
                        )?;
                    }
                    report.parked += 1;
                }
            }

            if cancel_requested {
                // The admitted attempt was parked and its reservation refunded
                // through the Park arm above — the pass may now stop at this
                // attempt boundary (H-S5/R2).
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
