//! Attempt completion inside a caller-owned transaction.

use crate::error::Result;

use super::encoding::{decode_record, encode_record};
use super::engine::AttemptQueue;
use super::telemetry::invalid_transition;
use super::types::{AttemptState, CompleteAttempt, CompleteOutcome};
use super::validate::{validate_lease_owner, validate_transition_lease};

impl AttemptQueue<'_> {
    /// Completes an attempt, retires its dedupe entry, and stamps its pack
    /// receipt in the caller's transaction. The caller must abort on error.
    /// Already-completed attempts are idempotent, as in [`Self::complete`].
    pub(crate) fn complete_in_txn(
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
                Ok(CompleteOutcome::Completed(record))
            }
            state => Err(invalid_transition("complete", state.as_str())),
        }
    }
}
