//! Transaction-composable completion and failure with terminal pack receipts.

use crate::error::Result;
use crate::store::Rows;

use super::AttemptQueue;
use super::encoding::{decode_record, encode_record};
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
        if matches!(outcome, CompleteOutcome::Completed(_)) {
            self.store.notify_attempt_observers();
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
        if matches!(outcome, FailOutcome::Failed(_)) {
            self.store.notify_attempt_observers();
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
        if record.kind == crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND
            && crate::dreamer_runner::decode_dreamer_attempt_payload(&record.payload).is_ok_and(
                |payload| {
                    payload.attempt_type == crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE
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
        let Some(raw_record) = self.store.attempt_records.get(wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("fail", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        match record.state {
            AttemptState::Failed => Ok(FailOutcome::AlreadyFailed(record)),
            AttemptState::Leased => {
                validate_lease_owner(&input.lease_owner)?;
                validate_transition_lease(
                    &record,
                    &input.lease_owner,
                    input.attempt_count,
                    "fail",
                )?;
                validate_failure_reason(&input.reason)?;
                record.state = AttemptState::Failed;
                record.lease_owner = None;
                record.backoff_until = None;
                record.last_error = Some(input.reason);
                record.updated_at = input.now;
                self.delete_dedupe_entry_for_record(wtxn, &record)?;
                let encoded = encode_record(&record)?;
                self.store
                    .attempt_records
                    .put(wtxn, record.id.as_bytes(), &encoded)?;
                crate::receipt::stamp_attempt_pack_receipt_in_txn(
                    self.store,
                    wtxn,
                    &record,
                    &input.lease_owner,
                )?;
                Ok(FailOutcome::Failed(record))
            }
            state => Err(invalid_transition("fail", state.as_str())),
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
}
