//! Terminal end of a queued TASK realization its requester withdrew (FIX
//! 11687): the Dreamer lane's mirror of `AgentDispatcher::end_withdrawn`,
//! without the agent spend-lease settlement. The admission scan hands it a
//! hint, never a claim: the row is judged again here, and a try another
//! worker took first, or whose requester stands now, is left as it is.
use super::*;
use crate::attempt_queue::{AttemptState, FailAttempt};

impl DreamerRunnerStore<'_> {
    /// Ends the queued TASK realization `id` admission found its requester
    /// withdrawn for, as `lease_owner`: the TASK runner's queued turn taken
    /// first (Rule 5), then in a writer of its own the try is judged again,
    /// claimed and taken, its TASK fails not to be retried, the try fails
    /// for good with the typed reason, its retained budget is settled and
    /// its step receipts go. Other
    /// kinds never reach here; a row that is no withdrawn queued
    /// realization is left as it is.
    pub(super) fn end_withdrawn_task_realize(
        &self,
        id: AttemptId,
        lease_owner: &str,
        now: u64,
    ) -> Result<()> {
        let held = crate::task_verb::highway_runner::queued_runner_report_turn(self.vault, id)?;
        // The grouped write door, as the agent ladder's own fail: a TASK
        // this failure settles wakes its peer-result waiters once it
        // commits.
        let ended = self.vault.with_write_txn_grouped(|txn| {
            let Some(row) = self.attempts.get_in_write_txn(&*txn, id)? else {
                return Ok(None);
            };
            if row.kind != DREAMER_TASK_REALIZE_ATTEMPT_KIND {
                return Ok(None);
            }
            if !matches!(row.state, AttemptState::Queued | AttemptState::Scheduled) {
                return Ok(None);
            }
            if !row.accepts_worker(lease_owner) {
                return Ok(None);
            }
            let Some(withdrawn) = decode_dreamer_attempt_status(row)
                .ok()
                .and_then(|status| {
                    crate::task_verb::decode_task_realization_input(&status.payload.input).ok()
                })
                .and_then(|(_, requester)| requester)
                .and_then(|requester| requester.withdrawn_in_txn(self.vault, &*txn))
            else {
                return Ok(None);
            };
            let ClaimOutcome::Claimed(attempt) = crate::ports::JobQueue::port_job_claim_id(
                self.vault,
                txn,
                id,
                ClaimAttempt {
                    lease_owner: lease_owner.to_owned(),
                    now,
                },
            )?
            else {
                return Ok(None);
            };
            crate::task_verb::highway_runner::accept_leased_task_in_txn(self.vault, txn, &attempt)?;
            let reason = withdrawn.code();
            crate::task_verb::highway_runner::report_leased_task_in_txn(
                self.vault,
                txn,
                attempt.id,
                crate::task_verb::highway_runner::RunnerSettle::Failed {
                    error: reason,
                    retryable: false,
                },
                held.as_ref(),
            )?;
            let _failed = crate::ports::JobQueue::port_job_fail(
                self.vault,
                txn,
                FailAttempt {
                    id: attempt.id,
                    lease_owner: lease_owner.to_owned(),
                    attempt_count: attempt.attempt_count,
                    reason: reason.to_owned(),
                    now,
                },
            )?;
            let budget_lines = BUDGET_RESERVATION
                .scan(&self.vault.store, &*txn)?
                .into_iter()
                .filter(|(key, _)| key.attempt_id == attempt.id)
                .map(|(key, reservation)| {
                    if key.budget_id != reservation.budget_id
                        || reservation.attempt_id != attempt.id
                    {
                        return Err(invalid_dreamer_runner(
                            "dreamer budget reservation key/body mismatch",
                        ));
                    }
                    Ok(key.budget_id)
                })
                .collect::<Result<Vec<_>>>()?;
            crate::dreamer_wake::owed::reconcile_ended_attempt_in_txn(
                self.vault,
                txn,
                attempt.id,
                &budget_lines,
                now,
            )?;
            self.cleanup_step_receipts_in_txn(txn, attempt.id)?;
            Ok(Some(attempt))
        })?;
        if let Some(attempt) = ended {
            self.vault.store.notify_attempt_observers();
            self.vault.store.notify_task_updates(
                attempt
                    .task_ref
                    .as_deref()
                    .and_then(|task| EntityId::from_hex(task).ok()),
            );
        }
        Ok(())
    }
}
