//! Attempt completion inside a caller-owned transaction.

use crate::error::Result;

use super::encoding::decode_record;
use super::engine::AttemptQueue;
use super::lifecycle::{PackReceiptActor, RunEvent, RunLifecycle, RunRow, RunStep, TerminalCommit};
use super::telemetry::invalid_transition;
use super::types::{AttemptRecord, CompleteAttempt, CompleteOutcome};
use super::validate::{validate_lease_owner, validate_transition_lease};

impl AttemptQueue<'_> {
    /// Completes an attempt, retires its dedupe entry, and stamps its pack
    /// receipt in the caller's transaction. The caller must abort on error.
    /// Already-completed attempts are idempotent, as in [`Self::complete`].
    /// Every completion door ends here, so the Dreamer projector round an
    /// attempt carries is applied in the transaction that completes it.
    pub(crate) fn complete_storage_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: CompleteAttempt,
    ) -> Result<CompleteOutcome> {
        let Some(raw_record) = self.store.attempt_records.get(wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("complete", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        match RunLifecycle::step(RunRow::of(&record), RunEvent::Complete) {
            RunStep::Replay => Ok(CompleteOutcome::AlreadyCompleted(record)),
            RunStep::Move { .. } => {
                validate_lease_owner(&input.lease_owner)?;
                validate_transition_lease(
                    &record,
                    &input.lease_owner,
                    input.attempt_count,
                    "complete",
                )?;
                let _ = RunLifecycle::complete(&mut record, input.now);
                self.commit_terminal_in_txn(
                    wtxn,
                    &mut record,
                    TerminalCommit {
                        last_error: None,
                        now: input.now,
                        receipt_actor: PackReceiptActor::Caller(&input.lease_owner),
                    },
                )?;
                crate::dreamer_wake::apply_projection_in_txn(self.store, wtxn, &record)?;
                self.notify_settled_in_txn(wtxn, &record)?;
                Ok(CompleteOutcome::Completed(record))
            }
            RunStep::Note { .. } | RunStep::Keep | RunStep::Refuse => {
                Err(invalid_transition("complete", record.state.as_str()))
            }
        }
    }
}

impl AttemptQueue<'_> {
    /// Records the inbox notification for a row this handle just settled, in
    /// the transaction that settles it (OF-221). Only a vault-opened handle
    /// has the vault's entity door to write through. An agent run's try
    /// sets its run TASK's outcome here too, in the same write, while this
    /// machine holds the run (FIX 4747): every terminal door ends here, and
    /// a retry or a landing handoff, which carry the run on, do not. So does
    /// each wait its spawner holds over it (`tasks.wait({agents})`, slice
    /// 6.5b): reduced here, and delivered when this row ends it.
    pub(crate) fn notify_settled_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        record: &AttemptRecord,
    ) -> Result<()> {
        if let Some(vault) = self.vault {
            vault.record_job_notification_in_txn(wtxn, record)?;
            vault.enqueue_health_review_in_txn(wtxn, record)?;
            crate::agent_dispatch::settle_agent_run_task_in_txn(vault, wtxn, record)?;
            // Slice 6.5b: a parent's wait over this child is answered in the
            // write that ends it.
            crate::agent_dispatch::settle_agent_child_waits_in_txn(vault, wtxn, record)?;
        }
        Ok(())
    }

    pub(crate) fn complete_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        input: CompleteAttempt,
    ) -> Result<CompleteOutcome> {
        crate::ports::JobQueue::port_job_complete(self, txn, input)
    }
}
