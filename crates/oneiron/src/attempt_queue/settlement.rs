//! Transaction-composable completion and failure with terminal pack receipts.

use crate::error::Result;
use crate::store::Rows;
use crate::store::model_step_submission::StepBudgetRefusal;

use super::AttemptQueue;
use super::encoding::decode_record;
use super::lifecycle::{PackReceiptActor, RunEvent, RunLifecycle, RunRow, RunStep, TerminalCommit};
use super::telemetry::invalid_transition;
use super::types::{AttemptState, CompleteAttempt, CompleteOutcome, FailAttempt, FailOutcome};
use super::validate::{validate_failure_reason, validate_lease_owner, validate_transition_lease};

impl AttemptQueue<'_> {
    /// Marks a leased attempt complete. Completing an already-completed attempt is an
    /// idempotent success; all other states are rejected.
    pub fn complete(&self, input: CompleteAttempt) -> Result<CompleteOutcome> {
        {
            let rtxn = self.store.env.read_txn()?;
            let Some(raw_record) = self.store.attempt_records.get(&rtxn, input.id.as_bytes())?
            else {
                return Err(invalid_transition("complete", "missing"));
            };
            let record = decode_record(&raw_record, input.id)?;
            if record.state == AttemptState::Completed {
                return Ok(CompleteOutcome::AlreadyCompleted(record));
            }
        }

        let outcome =
            self.store
                .group_write(None, |wtxn| match self.complete_in_txn(wtxn, input) {
                    Ok(outcome @ CompleteOutcome::Completed(_)) => Rows::Commit(outcome),
                    answer => Rows::Discard(answer),
                })?;
        if let CompleteOutcome::Completed(record) = &outcome {
            self.store.notify_attempt_observers();
            // The TASK this attempt realizes folds its board status from it.
            self.store.notify_task_updates(realized_task(record));
            // FIX 11482: the settled row's job notice commits here, outside
            // any owner scope, so this door sends the signal itself.
            self.store.notify_notification_updates();
        }
        Ok(outcome)
    }

    /// Marks a leased attempt terminally failed. Failing an already-failed attempt is
    /// an idempotent success; all other states are rejected.
    pub fn fail(&self, input: FailAttempt) -> Result<FailOutcome> {
        let outcome =
            self.store
                .group_write(None, |wtxn| match self.fail_untyped_in_txn(wtxn, input) {
                    Ok(outcome @ FailOutcome::Failed(_)) => Rows::Commit(outcome),
                    answer => Rows::Discard(answer),
                })?;
        if let FailOutcome::Failed(record) = &outcome {
            self.store.notify_attempt_observers();
            self.store.notify_task_updates(realized_task(record));
            // FIX 11482: the settled row's job notice commits here, outside
            // any owner scope, so this door sends the signal itself.
            self.store.notify_notification_updates();
        }
        Ok(outcome)
    }

    /// The generic public door's refusal and terminal write, in the caller's
    /// transaction.
    fn fail_untyped_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: FailAttempt,
    ) -> Result<FailOutcome> {
        // The generic public door has no detector verdict, policy, or healer
        // case. Agent-dispatch attempts must enter the typed failure ladder;
        // only that crate-private transaction may terminalize their leases.
        let record = self
            .get_in_write_txn(wtxn, input.id)?
            .ok_or_else(|| invalid_transition("fail", "missing"))?;
        if record.kind == crate::store::dreamer_attempt_kind::DREAMER_RUNNER_ATTEMPT_KIND
            && crate::dreamer_runner::decode_dreamer_attempt_payload(&record.payload).is_ok_and(
                |payload| {
                    payload.attempt_type
                        == crate::attempt_queue::dispatch_payload::AGENT_DISPATCH_ATTEMPT_TYPE
                },
            )
        {
            return Err(invalid_transition(
                "fail",
                "agent dispatch requires typed evidence",
            ));
        }
        if record.state == AttemptState::Failed {
            return Ok(FailOutcome::AlreadyFailed(record));
        }
        self.fail_in_txn(wtxn, input)
    }

    /// Transaction-composable [`Self::fail`], including its terminal pack receipt.
    pub(crate) fn fail_storage_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: FailAttempt,
    ) -> Result<FailOutcome> {
        self.fail_storage_with_refusal_in_txn(wtxn, input, None)
    }

    /// [`Self::fail_storage_in_txn`] keeping `budget_refusal` on the failed
    /// row beside its reason, so the row's receipt, run tree and owner views
    /// read it typed (BUDGET-TRAP-UNTYPED-NO-SENDER).
    pub(crate) fn fail_storage_with_refusal_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: FailAttempt,
        budget_refusal: Option<StepBudgetRefusal>,
    ) -> Result<FailOutcome> {
        let Some(raw_record) = self.store.attempt_records.get(wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("fail", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        match RunLifecycle::step(RunRow::of(&record), RunEvent::Fail) {
            RunStep::Replay => Ok(FailOutcome::AlreadyFailed(record)),
            RunStep::Move { .. } => {
                validate_lease_owner(&input.lease_owner)?;
                validate_transition_lease(
                    &record,
                    &input.lease_owner,
                    input.attempt_count,
                    "fail",
                )?;
                validate_failure_reason(&input.reason)?;
                let _ = RunLifecycle::fail(&mut record, input.now);
                record.budget_refusal = budget_refusal;
                self.commit_terminal_in_txn(
                    wtxn,
                    &mut record,
                    TerminalCommit {
                        last_error: Some(input.reason),
                        now: input.now,
                        receipt_actor: PackReceiptActor::Caller(&input.lease_owner),
                    },
                )?;
                self.notify_settled_in_txn(wtxn, &record)?;
                Ok(FailOutcome::Failed(record))
            }
            RunStep::Note { .. } | RunStep::Keep | RunStep::Refuse => {
                Err(invalid_transition("fail", record.state.as_str()))
            }
        }
    }
}

impl AttemptQueue<'_> {
    pub(crate) fn fail_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        input: FailAttempt,
    ) -> Result<FailOutcome> {
        crate::ports::JobQueue::port_job_fail(self, txn, input)
    }

    /// [`Self::fail_in_txn`] keeping `budget_refusal` on the failed row.
    pub(crate) fn fail_with_refusal_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        input: FailAttempt,
        budget_refusal: Option<StepBudgetRefusal>,
    ) -> Result<FailOutcome> {
        crate::ports::JobQueue::port_job_fail_with_refusal(self, txn, input, budget_refusal)
    }
}

/// The TASK an attempt realizes, when it names one.
fn realized_task(record: &super::AttemptRecord) -> Option<crate::EntityId> {
    record
        .task_ref
        .as_deref()
        .and_then(|task| crate::EntityId::from_hex(task).ok())
}
