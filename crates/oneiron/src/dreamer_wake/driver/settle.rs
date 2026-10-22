//! Where one executed attempt settles: its budget, its completion, its
//! deferral, landing or park, with the milestone and the report count each
//! writes. The loop then checks whether the pass stops.

use super::*;
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::error::ErrorKind;

/// What one executed attempt settles from: the pass, the admitted attempt,
/// its run line and meter, and its execution with how it got there.
pub(super) struct Settlement<'s> {
    pub(super) input: &'s RunWakePass,
    pub(super) admitted: &'s DreamerAdmittedAttempt,
    pub(super) line: &'s String,
    pub(super) spend_meter: &'s WakeAttemptMeter,
    pub(super) attempt_id: AttemptId,
    pub(super) execution: DreamerAttemptExecution,
    pub(super) stage: Option<&'static str>,
    pub(super) hard_cut_error: Option<ErrorKind>,
}

impl DreamerWakeDriver<'_> {
    /// Settles `state`'s execution and counts it on `report`.
    pub(super) async fn settle_execution<E: DreamerAttemptExecutor + ?Sized>(
        &mut self,
        exec: &E,
        state: Settlement<'_>,
        report: &mut WakePassReport,
    ) -> Result<()> {
        let Settlement {
            input,
            admitted,
            line,
            spend_meter,
            attempt_id,
            execution,
            stage,
            hard_cut_error,
        } = state;
        match execution {
            DreamerAttemptExecution::Completed { completed_units } => {
                self.store.settle_budget(SettleDreamerBudget {
                    budget_id: line.clone(),
                    child_attempt: attempt_id,
                    actual_units: completed_units,
                    now: input.now,
                })?;
                self.complete_attempt(exec, admitted, input.now).await?;
                self.write_attempt_milestone(admitted, DreamerMilestoneKind::Done, input.now)?;
                report.completed += 1;
            }
            DreamerAttemptExecution::Deferred {
                completed_units,
                retry_at,
            } => {
                self.store.defer_selection(
                    admitted,
                    SettleDreamerBudget {
                        budget_id: line.clone(),
                        child_attempt: attempt_id,
                        actual_units: completed_units,
                        now: input.now,
                    },
                    retry_at,
                )?;
                let stage = stage.unwrap_or("deferred");
                self.log_attempt_outcome(admitted, stage, None, None, "settled", "none");
                self.write_attempt_milestone(
                    admitted,
                    DreamerMilestoneKind::CheckpointReached,
                    input.now,
                )?;
                report.deferred += 1;
            }
            DreamerAttemptExecution::Landed {
                completed_units,
                reserve_units,
                status,
                resume_point,
                hand_off,
            } => {
                let spent_reserve_units = self.land_attempt(
                    admitted,
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
                    budget_id: line.clone(),
                    child_attempt: attempt_id,
                    actual_units: completed_units.saturating_add(spent_reserve_units),
                    now: input.now,
                })?;
                self.log_attempt_outcome(admitted, "landed", None, None, "settled", "none");
                // A designed landing leaves a durable resume point, exactly
                // like a deadline-cut park — never a `Done` milestone,
                // which would claim the job delivered.
                self.write_attempt_milestone(
                    admitted,
                    DreamerMilestoneKind::CheckpointReached,
                    input.now,
                )?;
                report.landed += 1;
            }
            DreamerAttemptExecution::ParkWithSpend {
                reason,
                cause,
                completed_units,
                step_hashes,
            } => {
                // The in-flight call finished and was charged. Stop the run
                // at this boundary without refunding its real spend or
                // publishing post-deadline output.
                self.store.settle_checkpoint_budget(
                    SettleDreamerBudget {
                        budget_id: line.clone(),
                        child_attempt: attempt_id,
                        actual_units: completed_units,
                        now: input.now,
                    },
                    &step_hashes,
                    ParkDreamerAttempt {
                        attempt_id,
                        reason: reason.clone(),
                        cause,
                        park_owner: input.lease_owner.clone(),
                        now: input.now,
                    },
                    admitted_lease(admitted, &input.lease_owner),
                )?;
                let stage = stage.unwrap_or("park_with_spend");
                let settled = "checkpoint_settled";
                self.log_attempt_outcome(admitted, stage, None, Some(cause), settled, "committed");
                self.publish(attempt_id, ProgressKind::Parked, Some(reason), input.now)?;
                self.write_attempt_milestone(
                    admitted,
                    DreamerMilestoneKind::CheckpointReached,
                    input.now,
                )?;
                report.parked += 1;
            }
            DreamerAttemptExecution::Park { reason, cause } => {
                // The lease is not settled as spent: what its run line
                // charged stays spent (SCAN C012), the rest of the
                // reservation is refunded, all of it for an attempt that
                // never dispatched.
                let settled =
                    self.settle_charged_or_abort(line, attempt_id, spend_meter, input.now)?;
                let hard_cut = reason == DREAMER_HARD_CUT_PARK_REASON || self.deadline.expired();
                let (cause, park) = if let Some(row) = self.store.parked_attempt(attempt_id)? {
                    // One park-owner: the step layer already parked this
                    // attempt inside its trap wtxn — publish only.
                    self.publish(attempt_id, ProgressKind::Parked, Some(reason), input.now)?;
                    (row.cause, "step_layer_parked")
                } else {
                    self.park_attempt(admitted, reason, cause, &input.lease_owner, input.now)?;
                    (cause, "committed")
                };
                let stage = match stage {
                    Some(stage) => stage,
                    None if hard_cut => "hard_cut",
                    None => "park",
                };
                self.log_attempt_outcome(
                    admitted,
                    stage,
                    hard_cut_error,
                    Some(cause),
                    settled,
                    park,
                );
                if hard_cut {
                    // A deadline-cut park leaves a durable resume point.
                    self.write_attempt_milestone(
                        admitted,
                        DreamerMilestoneKind::CheckpointReached,
                        input.now,
                    )?;
                }
                report.parked += 1;
            }
        }
        Ok(())
    }
}
