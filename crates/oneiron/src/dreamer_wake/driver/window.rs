//! One wake pass's partition window (FIX 12487): plain Micro
//! partitions admitted back to back, up to the selection policy's
//! width, extracted side by side by the executor and settled here one
//! by one in admission order through the same settle path as a serial
//! dispatch. Admission, budget lines and lease bookkeeping stay the
//! serial loop's; only the extraction wait overlaps.

use std::panic::AssertUnwindSafe;
use std::pin::pin;

use super::dispatch::Dispatched;
use super::settle::Settlement;
use super::stop::attempt_stop;
use super::*;
use crate::dreamer_consolidation::PreparedWake;
use crate::dreamer_runner::DreamerAdmittedAttempt;

/// One admitted partition held for the window: everything its serial
/// dispatch would have carried, owned until its settle.
pub(super) struct WindowSlot {
    pub(super) admitted: DreamerAdmittedAttempt,
    pub(super) line: String,
    pub(super) spend_meter: WakeAttemptMeter,
}

/// Whether the pass goes on after one attempt settles.
pub(super) enum SettleFlow {
    Continue,
    Break(WakePassStop),
    FailPass(crate::Error),
}

impl SettleFlow {
    /// Folds one more settled attempt's stop into the window's: a pass
    /// failure dominates a stop, the first of each kind wins.
    fn absorb(&mut self, next: SettleFlow) {
        match next {
            SettleFlow::Continue => {}
            SettleFlow::Break(_) => {
                if matches!(self, SettleFlow::Continue) {
                    *self = next;
                }
            }
            SettleFlow::FailPass(_) => {
                if !matches!(self, SettleFlow::FailPass(_)) {
                    *self = next;
                }
            }
        }
    }
}

/// A window member is exactly what the executor's window contract
/// holds: a plain Micro partition (the consolidation kind, the scope's
/// own attempt type) whose preparation is Ready at this wake revision.
/// A budget-pressure warning failure and a raised cancellation keep
/// their serial pre-dispatch arms instead of joining.
pub(super) fn window_eligible(
    admitted: &DreamerAdmittedAttempt,
    prepared_wake: &PreparedWake,
    pressure_ok: bool,
    cancel_requested: bool,
    parallelism: usize,
) -> bool {
    parallelism > 1
        && pressure_ok
        && !cancel_requested
        && admitted.status.attempt.kind
            == crate::dreamer_runner::DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND
        && admitted.status.payload.attempt_type
            == crate::dreamer_runner::DreamerConsolidationScope::Micro.as_str()
        && matches!(
            prepared_wake.preparation(admitted.status.attempt.id),
            Some(crate::dreamer_consolidation::AttemptPreparation::Ready(_))
        )
}

impl DreamerWakeDriver<'_> {
    /// Settles one dispatched attempt: the executor-error arm, the
    /// settlement itself, and the stop the settled attempt calls. The
    /// serial loop and a window flush share this, so a windowed slot
    /// settles byte-identically to a serial dispatch.
    #[expect(
        clippy::too_many_arguments,
        reason = "one settled attempt joins its pass, line, meter, dispatch outcome, executor and report"
    )]
    pub(super) async fn settle_attempt_outcome<E: DreamerAttemptExecutor + ?Sized>(
        &mut self,
        input: &RunWakePass,
        admitted: &DreamerAdmittedAttempt,
        line: &String,
        spend_meter: &WakeAttemptMeter,
        cancel_requested: bool,
        dispatched: Dispatched,
        exec: &E,
        held_error: &mut Option<crate::Error>,
        report: &mut WakePassReport,
    ) -> Result<SettleFlow> {
        let Dispatched {
            executed,
            stage,
            backlog_left,
        } = dispatched;
        let attempt_id = admitted.status.attempt.id;
        let mut hard_cut_error = None;
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
                        admitted,
                        line,
                        spend_meter,
                        &error,
                        stage,
                        input,
                    )?;
                    // A contained panic ends the pass once it parked
                    // (FIX 7322, Engine 10-21); other errors go on.
                    if ends_pass || stage == "executor_panic" {
                        return Ok(SettleFlow::FailPass(error));
                    }
                    // FIX 7272: parked as a Retry a later pass resumes
                    // after its delay, so this pass goes on and fails at
                    // its end.
                    report.parked += 1;
                    held_error.get_or_insert(error);
                    if cancel_requested {
                        return Ok(SettleFlow::Break(WakePassStop::Cancelled));
                    }
                    return Ok(SettleFlow::Continue);
                }
                hard_cut_error = Some(error.kind());
                DreamerAttemptExecution::Park {
                    reason: DREAMER_HARD_CUT_PARK_REASON.to_owned(),
                    cause: crate::dreamer_runner::DreamerParkCause::Checkpoint,
                }
            }
        };

        self.settle_execution(
            exec,
            Settlement {
                input,
                admitted,
                line,
                spend_meter,
                attempt_id,
                execution,
                stage,
                hard_cut_error,
            },
            report,
        )
        .await?;

        Ok(match attempt_stop(cancel_requested, backlog_left) {
            Some(stop) => SettleFlow::Break(stop),
            None => SettleFlow::Continue,
        })
    }

    /// Releases an admitted attempt that never reached dispatch: the
    /// window flush ahead of it ended the pass (a panic or another
    /// pass-ending failure), so it parks as a later pass resumes and
    /// its reservation refunds, before the flush failure leaves the
    /// pass (FIX 12487 round 1). Left undispatched it would stay leased
    /// with the reservation held until the maintenance sweep. The
    /// executor is never touched (a panicking one is not reused in the
    /// pass, FIX 7322).
    pub(super) fn release_unflushed_admission(
        &mut self,
        input: &RunWakePass,
        admitted: &DreamerAdmittedAttempt,
        line: &str,
        cancel: &WakeCancellation,
        cancel_requested: bool,
        report: &mut WakePassReport,
    ) -> Result<()> {
        let (reason, cause) = if cancel_requested && cancel.is_paused() {
            (
                DREAMER_PAUSED_PARK_REASON.to_owned(),
                crate::dreamer_runner::DreamerParkCause::Paused,
            )
        } else if cancel_requested {
            (
                DREAMER_CANCELLED_PARK_REASON.to_owned(),
                crate::dreamer_runner::DreamerParkCause::Cancelled,
            )
        } else {
            (
                "partition window flush ended the pass before dispatch".to_owned(),
                crate::dreamer_runner::DreamerParkCause::Retry,
            )
        };
        let parked = self.park_attempt(admitted, reason, cause, &input.lease_owner, input.now);
        let park = if parked.is_ok() {
            "committed"
        } else {
            "park_failed"
        };
        // Never dispatched: no run line, no owed calls, so the refund
        // settles at zero.
        let refunded = self.store.abort_budget_reservation(
            crate::dreamer_runner::AbortDreamerBudgetReservation {
                budget_id: line.to_owned(),
                child_attempt: admitted.status.attempt.id,
                now: input.now,
            },
        );
        let settlement = if refunded.is_ok() {
            "refunded"
        } else {
            "settle_failed"
        };
        self.log_attempt_outcome(
            admitted,
            "window_flush_release",
            None,
            Some(cause),
            settlement,
            park,
        );
        parked?;
        refunded?;
        report.parked += 1;
        Ok(())
    }

    /// Releases every held window admission ahead of a collection-time
    /// error's return (FIX 12487 round 2): the look-ahead admission
    /// chain failing says nothing about the slots already leased, and
    /// returning past them would hold their reservations until the
    /// maintenance sweep. Each release is self-fenced; a failure is
    /// warn-logged and the drain goes on - the caller returns the
    /// original collection error either way.
    pub(super) fn release_window_for_collection_error(
        &mut self,
        window: &mut Vec<WindowSlot>,
        input: &RunWakePass,
        cancel: &WakeCancellation,
        report: &mut WakePassReport,
    ) {
        let cancel_requested = cancel.is_cancelled();
        for slot in std::mem::take(window) {
            if let Err(release_error) = self.release_unflushed_admission(
                input,
                &slot.admitted,
                &slot.line,
                cancel,
                cancel_requested,
                report,
            ) {
                tracing::warn!(
                    kind = ?release_error.kind(),
                    "release of a held window admission failed; its lease falls to the maintenance reclaim"
                );
            }
        }
    }

    /// Runs the held window's partitions through the executor and
    /// settles every slot in admission order, including a slot whose
    /// Running publish failed and — after a panicking executor — slots
    /// that never ran. An empty window settles nothing.
    #[expect(
        clippy::too_many_arguments,
        reason = "a flush joins the window to its pass, executor, cancellation, wake and report"
    )]
    pub(super) async fn flush_window<E: DreamerAttemptExecutor + ?Sized>(
        &mut self,
        window: &mut Vec<WindowSlot>,
        input: &RunWakePass,
        exec: &mut E,
        cancel: &WakeCancellation,
        prepared_wake: &PreparedWake,
        held_error: &mut Option<crate::Error>,
        report: &mut WakePassReport,
    ) -> Result<SettleFlow> {
        if window.is_empty() {
            return Ok(SettleFlow::Continue);
        }
        let slots = std::mem::take(window);
        let mut outcomes: Vec<Option<(Result<DreamerAttemptExecution>, Option<&'static str>)>> =
            (0..slots.len()).map(|_| None).collect();
        // The Running publish a serial dispatch makes before the
        // executor runs, per slot; a failed publish flows through the
        // same release arm as an executor error (FIX 7273), and its
        // slot does not run.
        let mut run_indices = Vec::new();
        for (index, slot) in slots.iter().enumerate() {
            match self.publish(
                slot.admitted.status.attempt.id,
                ProgressKind::Running,
                None,
                input.now,
            ) {
                Ok(()) => run_indices.push(index),
                Err(error) => outcomes[index] = Some((Err(error), Some("progress_publish"))),
            }
        }
        if !run_indices.is_empty() {
            let mut window_args: Vec<(&DreamerAdmittedAttempt, WakeAttemptContext<'_>)> =
                Vec::with_capacity(run_indices.len());
            for &index in &run_indices {
                let slot = &slots[index];
                let attempt_id = slot.admitted.status.attempt.id;
                let prepared_attempt = match prepared_wake.preparation(attempt_id) {
                    Some(crate::dreamer_consolidation::AttemptPreparation::Ready(plan)) => {
                        Some(plan)
                    }
                    _ => None,
                };
                if prepared_attempt.is_some_and(
                    crate::dreamer_consolidation::PreparedConsolidationAttempt::sources_truncated,
                ) {
                    report.sources_truncated = report.sources_truncated.saturating_add(1);
                }
                // Pre-dispatch sync (FIX 11963), as a serial dispatch:
                // a wake ask raised while the window filled trips the
                // device work these attempts are about to admit under.
                sync_wake_cancel(cancel, &self.device_cancel);
                window_args.push((
                    &slot.admitted,
                    WakeAttemptContext {
                        vault: self.vault,
                        deadline: &self.deadline,
                        cancel: Some(cancel),
                        device_cancel: Some(self.device_cancel.clone()),
                        budget_id: &slot.line,
                        now_ms: input.now.saturating_mul(1_000),
                        prepared_wake: Some(prepared_wake),
                        prepared_attempt,
                        spend_meter: Some(&slot.spend_meter),
                    },
                ));
            }
            // The window's one panic containment, as a serial dispatch
            // holds per attempt: a panic parks every slot it may have
            // touched and ends the pass through their settles below.
            let mut execute = pin!(exec.execute_partition_window(&mut window_args));
            let caught = poll_fn(|task_cx| {
                match std::panic::catch_unwind(AssertUnwindSafe(|| execute.as_mut().poll(task_cx)))
                {
                    Ok(poll) => poll.map(Ok),
                    Err(panic) => Poll::Ready(Err(panic)),
                }
            })
            .await;
            match caught {
                Ok(results) => {
                    let mut results = results.into_iter();
                    for &index in &run_indices {
                        let executed = results.next().unwrap_or_else(|| {
                            Err(crate::Error::InvariantViolation(
                                "a partition window answered fewer slots than it held",
                            ))
                        });
                        // A slot the executor's own per-slot containment
                        // caught panicking carries the shared panic
                        // error: it takes the executor-panic stage (and
                        // ends the pass, FIX 7322) exactly as if the
                        // window-wide catch above had taken it (FIX
                        // 12487 round 2).
                        let stage = match &executed {
                            Err(error) if crate::dreamer_wake::is_executor_panic_error(error) => {
                                Some("executor_panic")
                            }
                            _ => None,
                        };
                        outcomes[index] = Some((executed, stage));
                    }
                }
                Err(_payload) => {
                    for &index in &run_indices {
                        let attempt_id = slots[index].admitted.status.attempt.id;
                        tracing::error!(
                            attempt_id = %bytes_to_hex_lower(attempt_id.as_bytes()),
                            kind = "executor_panic",
                            "dreamer attempt executor panicked; parking the admitted attempt"
                        );
                        outcomes[index] = Some((
                            Err(crate::dreamer_wake::executor_panic_error()),
                            Some("executor_panic"),
                        ));
                    }
                }
            }
        }

        // Every executed slot settles even when an earlier slot's
        // settle fails: the first error is kept and returned after the
        // drain, so one store error never abandons the window's later
        // admitted attempts leased with reservations held (FIX 12487
        // round 1). Every settle write is per-attempt and self-fenced,
        // so draining in admission order is safe.
        let mut flow = SettleFlow::Continue;
        let mut first_error: Option<crate::Error> = None;
        for (slot, outcome) in slots.into_iter().zip(outcomes) {
            let (executed, stage) = outcome.expect("every window slot decided before its settle");
            match self
                .settle_attempt_outcome(
                    input,
                    &slot.admitted,
                    &slot.line,
                    &slot.spend_meter,
                    false,
                    Dispatched {
                        executed,
                        stage,
                        backlog_left: false,
                    },
                    &*exec,
                    held_error,
                    report,
                )
                .await
            {
                Ok(next) => flow.absorb(next),
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(flow)
    }
}
