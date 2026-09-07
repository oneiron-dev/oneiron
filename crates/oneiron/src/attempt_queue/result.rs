//! Transaction-composable result attachment and abandonment.

use crate::error::Result;

use super::AttemptQueue;
use super::encoding::{decode_record, encode_record};
use super::telemetry::invalid_transition;
use super::types::{AbandonAttempt, AbandonOutcome, AttemptRecord, AttemptState, SetAttemptResult};
use super::validate::{
    validate_failure_reason, validate_lease_owner, validate_result_rebind, validate_result_ref,
    validate_transition_lease,
};

impl AttemptQueue<'_> {
    /// Checks a live lease even when a same-reference generic retry would be a no-op.
    pub(crate) fn check_result_lease(
        record: &AttemptRecord,
        lease_owner: &str,
        attempt_count: u32,
        action: &'static str,
    ) -> Result<()> {
        if !record.state.is_running() {
            return Err(invalid_transition(action, record.state.as_str()));
        }
        validate_lease_owner(lease_owner)?;
        validate_transition_lease(record, lease_owner, attempt_count, action)
    }

    /// Names the artifact version a LIVE attempt's durable output lives in.
    ///
    /// Fenced exactly like [`Self::complete`] and [`Self::fail`]: only the
    /// worker holding this lease generation may speak for the row. The verb is
    /// separate from settling because the exhaust becomes durable BEFORE the
    /// row settles — that ordering is what lets an executor that then stops
    /// without completing still point at what it produced.
    ///
    /// [`AttemptState::Landing`] is accepted alongside `Leased`: a landing row
    /// still owns its lease and is doing bounded finishing work, which is
    /// precisely the work that produces a final artifact.
    ///
    /// Idempotent for the SAME reference in ANY state, including terminal, so
    /// a capture retried after a crash converges instead of refusing. A
    /// DIFFERENT reference on a row that already carries one is refused
    /// outright (write-once).
    pub fn set_result(&self, input: SetAttemptResult) -> Result<AttemptRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let record = self.set_result_in_txn(&mut wtxn, input)?;
        wtxn.commit()?;
        Ok(record)
    }

    /// Composes custody writes and result attachment in the caller's transaction.
    pub(crate) fn set_result_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: SetAttemptResult,
    ) -> Result<AttemptRecord> {
        validate_result_ref(input.result_ref.as_str())?;
        let Some(raw_record) = self.store.attempt_records.get(wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("set_result", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        validate_result_rebind(&record, &input.result_ref)?;
        if record.result_ref.as_ref() == Some(&input.result_ref) {
            return Ok(record);
        }
        match record.state {
            AttemptState::Leased | AttemptState::Landing => {
                validate_lease_owner(&input.lease_owner)?;
                validate_transition_lease(
                    &record,
                    &input.lease_owner,
                    input.attempt_count,
                    "set_result",
                )?;
                record.result_ref = Some(input.result_ref);
                // A landing has one bounded lease window, and attaching an
                // artifact must not silently extend it (the same rule the
                // operator-note path holds). Only live claim work moves the
                // lease-expiry clock.
                if record.state != AttemptState::Landing {
                    record.updated_at = input.now;
                }
                let encoded = encode_record(&record)?;
                self.store
                    .attempt_records
                    .put(wtxn, record.id.as_bytes(), &encoded)?;
                Ok(record)
            }
            state => Err(invalid_transition("set_result", state.as_str())),
        }
    }

    /// Marks a live attempt abandoned: it stopped without delivering, and
    /// nobody stopped it.
    ///
    /// Abandoning an already-abandoned attempt is an idempotent success; every
    /// other state is rejected. A pre-lease row (queued, scheduled, paused) is
    /// deliberately NOT abandonable — nothing was ever carrying it, so the
    /// honest verb there is cancel. A row that already settled some other way
    /// is not reopened.
    ///
    /// The result reference is required by the input type AND re-validated
    /// here, and the reason is stamped as the row's `last_error`, so the state
    /// can never be reached without evidence of what it left behind.
    pub fn abandon(&self, input: AbandonAttempt) -> Result<AbandonOutcome> {
        {
            let rtxn = self.store.env.read_txn()?;
            let Some(raw_record) = self.store.attempt_records.get(&rtxn, input.id.as_bytes())?
            else {
                return Err(invalid_transition("abandon", "missing"));
            };
            let record = decode_record(&raw_record, input.id)?;
            if record.state == AttemptState::Abandoned {
                return Ok(AbandonOutcome::AlreadyAbandoned(record));
            }
        }

        let mut wtxn = self.store.env.write_txn()?;
        let outcome = self.abandon_in_txn(&mut wtxn, input)?;
        wtxn.commit()?;
        Ok(outcome)
    }

    /// Composes the terminal row, pack receipt, and custody writes atomically.
    pub(crate) fn abandon_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: AbandonAttempt,
    ) -> Result<AbandonOutcome> {
        let Some(raw_record) = self.store.attempt_records.get(wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("abandon", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        match record.state {
            AttemptState::Abandoned => Ok(AbandonOutcome::AlreadyAbandoned(record)),
            AttemptState::Leased | AttemptState::Landing => {
                validate_lease_owner(&input.lease_owner)?;
                validate_transition_lease(
                    &record,
                    &input.lease_owner,
                    input.attempt_count,
                    "abandon",
                )?;
                validate_failure_reason(&input.reason)?;
                validate_result_ref(input.result_ref.as_str())?;
                validate_result_rebind(&record, &input.result_ref)?;
                record.state = AttemptState::Abandoned;
                // The landing was answered-but-unfinished advisory state; an
                // abandoned row settles by reason + result_ref, and the
                // placement rule forbids a landing record outside
                // landing/cancelled.
                record.cancel_state.landing = None;
                record.lease_owner = None;
                record.scheduled_at = None;
                record.backoff_until = None;
                record.last_error = Some(input.reason);
                record.result_ref = Some(input.result_ref);
                record.updated_at = input.now;
                // A settled row owns no advisory dedupe claim: the next
                // dispatch under the same key must mint a fresh try rather
                // than be handed this stopped one.
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
                Ok(AbandonOutcome::Abandoned(record))
            }
            state => Err(invalid_transition("abandon", state.as_str())),
        }
    }
}
