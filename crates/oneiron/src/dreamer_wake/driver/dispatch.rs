//! One admitted attempt's dispatch (§3.4 split, FIX 10611): the outcome a
//! checkpoint between admission and settle decides, or the executor's own,
//! run under panic containment. The run line's meter is the pass loop's:
//! the attempt's context and its pinned future borrow it here and drop
//! before the dispatch returns, so the loop settles from it after.

use std::panic::AssertUnwindSafe;
use std::pin::pin;

use super::*;
use crate::dreamer_consolidation::PreparedWake;
use crate::dreamer_runner::DreamerAdmittedAttempt;

/// What one admitted attempt dispatches with: its pass, the attempt, the
/// pass's cancellation and whether it was raised at the checkpoint, the
/// wake's frozen preparation, the attempt's run line and its meter, and the
/// budget-pressure warning's outcome.
pub(super) struct Dispatch<'d> {
    pub(super) input: &'d RunWakePass,
    pub(super) admitted: &'d DreamerAdmittedAttempt,
    pub(super) cancel: &'d WakeCancellation,
    pub(super) cancel_requested: bool,
    pub(super) prepared_wake: &'d PreparedWake,
    pub(super) line: &'d str,
    pub(super) spend_meter: &'d WakeAttemptMeter,
    pub(super) pressure: Result<()>,
}

/// What a dispatch decided, for the attempt's settlement.
pub(super) struct Dispatched {
    pub(super) executed: Result<DreamerAttemptExecution>,
    /// Where a non-executor outcome came from, for its outcome line (FIX
    /// 7271); `None` is the executor's own.
    pub(super) stage: Option<&'static str>,
    /// Whether this attempt sits past the head of a backlog larger than one
    /// wake prepares: the pass ends after it.
    pub(super) backlog_left: bool,
}

impl DreamerWakeDriver<'_> {
    /// Dispatches `dispatch`'s attempt on `exec`, counting a truncated
    /// source set on `report`.
    pub(super) async fn dispatch_admitted<E: DreamerAttemptExecutor + ?Sized>(
        &mut self,
        dispatch: Dispatch<'_>,
        exec: &mut E,
        report: &mut WakePassReport,
    ) -> Dispatched {
        let Dispatch {
            input,
            admitted,
            cancel,
            cancel_requested,
            prepared_wake,
            line,
            spend_meter,
            pressure,
        } = dispatch;
        let attempt_id = admitted.status.attempt.id;
        let mut backlog_left = false;
        // Where a non-executor outcome came from, for its outcome line
        // (FIX 7271); `None` is the executor's own.
        let mut stage = None;
        // Cooperative-preemption checkpoint (H-S5/R2): the ONE point
        // between admission and settle where a cancel is honored is
        // HERE, before the executor dispatch — never mid-await. The
        // admitted attempt flows through the ordinary Park arm below, which
        // refunds its budget reservation and parks it before the pass
        // stops.
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
                budget_id: line,
                now_ms: input.now.saturating_mul(1_000),
                prepared_wake: Some(prepared_wake),
                prepared_attempt: match prepared_wake.preparation(attempt_id) {
                    Some(crate::dreamer_consolidation::AttemptPreparation::Ready(plan)) => {
                        Some(plan)
                    }
                    _ => None,
                },
                spend_meter: Some(spend_meter),
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
                        admitted,
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
                        admitted,
                        &ctx,
                        self.contribution_host,
                    )
                } else if admitted.status.attempt.kind
                    == crate::dreamer_runner::DREAMER_RECIPE_WAKE_ATTEMPT_KIND
                {
                    super::super::recipe_wake::execute(admitted, &ctx)
                } else {
                    // The host's executor runs the rest, a self-written
                    // compaction's check (FIX 4465 B) and an urgent
                    // digest's harm question (OF-194) among them: each
                    // is judged on the model or ladder the host lends.
                    exec.execute(admitted, &mut ctx).await
                }
            });
            let caught = poll_fn(|task_cx| {
                match std::panic::catch_unwind(AssertUnwindSafe(|| execute.as_mut().poll(task_cx)))
                {
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
        Dispatched {
            executed,
            stage,
            backlog_left,
        }
    }
}
