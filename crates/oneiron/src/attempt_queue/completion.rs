//! Attempt completion inside a caller-owned transaction.

use crate::error::Result;

use super::encoding::decode_record;
use super::engine::AttemptQueue;
use super::telemetry::invalid_transition;
use super::types::{AttemptRecord, AttemptState, CompleteAttempt, CompleteOutcome};
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
        match record.state {
            AttemptState::Completed => Ok(CompleteOutcome::AlreadyCompleted(record)),
            AttemptState::Leased => {
                validate_lease_owner(&input.lease_owner)?;
                validate_transition_lease(
                    &record,
                    &input.lease_owner,
                    input.attempt_count,
                    "complete",
                )?;
                record.state = AttemptState::Completed;
                record.lease_owner = None;
                record.backoff_until = None;
                record.last_error = None;
                record.updated_at = input.now;
                self.delete_dedupe_entry_for_record(wtxn, &record)?;
                let encoded = self.encode_in_txn(wtxn, &mut record)?;
                self.store
                    .attempt_records
                    .put(wtxn, record.id.as_bytes(), &encoded)?;
                crate::receipt::stamp_attempt_pack_receipt_in_txn(
                    self.store,
                    wtxn,
                    &record,
                    &input.lease_owner,
                )?;
                crate::dreamer_wake::apply_projection_in_txn(self.store, wtxn, &record)?;
                self.notify_settled_in_txn(wtxn, &record)?;
                Ok(CompleteOutcome::Completed(record))
            }
            state => Err(invalid_transition("complete", state.as_str())),
        }
    }
}

impl AttemptQueue<'_> {
    /// Records the inbox notification for a row this handle just settled, in
    /// the transaction that settles it (OF-221). Only a vault-opened handle
    /// has the vault's entity door to write through.
    pub(crate) fn notify_settled_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        record: &AttemptRecord,
    ) -> Result<()> {
        if let Some(vault) = self.vault {
            vault.record_job_notification_in_txn(wtxn, record)?;
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
