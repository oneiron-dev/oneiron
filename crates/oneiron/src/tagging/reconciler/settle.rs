//! Settlement: a marker completed, skipped, failed or retried with its
//! trace, each in one transaction.

use super::coordinator::TaggingReconciler;
use crate::EntityId;
use crate::attempt_queue::{AttemptQueue, AttemptRecord, CompleteAttempt, FailAttempt, RetryAttempt};
use crate::error::Result;
use crate::memory::extraction::EncoderOutput;
use crate::tagging::history;
use crate::tagging::input::{TurnInput, turn_text_in_txn};
use crate::tagging::marker::{TaggingMode, retry_marker_in_txn};
use crate::tagging::tags::tagged_messages_absent_in_txn;
use crate::tagging::trace::{SkipReason, TaggingFailure, TaggingOutcome, TaggingTrace, attempt_hex};

/// Failure reason of a marker whose payload this build cannot read.
const UNREADABLE_MARKER: &str = "unreadable_tagging_marker";
/// Retry reason of a marker whose turn's tagged MESSAGE is away from this
/// replica (OF-534).
const MESSAGES_ABSENT: &str = "messages_absent";

impl TaggingReconciler {
    /// Waits out a turn whose tagged MESSAGE is away from this replica
    /// (OF-534): the marker is retried on the failure backoff, the turn's
    /// saved set and every row of it untouched, until a promotion brings the
    /// row back and a try reads the whole text. Never a skip: an empty
    /// turn's skip would delete the set.
    pub(super) fn defer(
        &self,
        record: &AttemptRecord,
        prior_retries: u32,
        trace: TaggingTrace,
    ) -> Result<TaggingTrace> {
        let delay = self.backoff.delay_secs(prior_retries);
        self.retry_traced(record, delay, MESSAGES_ABSENT, trace, |retry_at| {
            TaggingOutcome::Deferred { retry_at }
        })
    }

    /// Nothing is owed: the marker completes with no tagger call. In save
    /// mode a turn left with no text loses the tags it held, in the settling
    /// write: none of them was read from text it still has.
    ///
    /// The skip stands only for the turn it read: a witness that added text
    /// since then was absorbed by this leased marker, so the settling
    /// transaction reads the turn again and, if it now has text, the marker
    /// is retried at once on it. So is one whose tagged MESSAGE left this
    /// replica since (OF-534): its next try waits for the row, and the set
    /// stays.
    pub(super) fn skip(
        &self,
        record: &AttemptRecord,
        turn: &EntityId,
        reason: SkipReason,
        mut trace: TaggingTrace,
    ) -> Result<TaggingTrace> {
        trace.outcome = TaggingOutcome::Skipped { reason };
        let settled = self
            .vault
            .try_with_write_txn_grouped(|txn| -> Result<bool> {
                if tagged_messages_absent_in_txn(&self.vault.store, txn, turn)? {
                    return Ok(false);
                }
                let read = turn_text_in_txn(&self.vault, txn, turn)?;
                if matches!(read, TurnInput::Ready { .. }) {
                    return Ok(false);
                }
                if self.config.mode == TaggingMode::Save && matches!(read, TurnInput::Empty) {
                    crate::tagging::tags::replace_in_txn(&self.vault, txn, turn, None)?;
                }
                self.settle_in_txn(txn, record, &trace)?;
                Ok(true)
            })?;
        if settled {
            return Ok(trace);
        }
        self.retry_traced(record, 0, "superseded", trace, |retry_at| {
            TaggingOutcome::Superseded { retry_at }
        })
    }

    pub(super) fn shadowed(&self, output: &EncoderOutput) -> TaggingOutcome {
        TaggingOutcome::Shadowed {
            spans: output.spans.len(),
            links: output.links.len(),
            mood: output.vad.is_some(),
            mapped_spans: output
                .spans
                .iter()
                .filter(|span| self.config.labels.contains_key(&span.label))
                .count(),
            context_links: output.context_links.len(),
            speaker_links: output.speaker_links.len(),
        }
    }

    /// Completes a marker, records its trace, and prunes it from the job
    /// ledger with every try it retried, in one transaction.
    pub(super) fn settle_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        record: &AttemptRecord,
        trace: &TaggingTrace,
    ) -> Result<()> {
        self.complete_in_txn(txn, record)?;
        self.record_in_txn(txn, trace)?;
        AttemptQueue::from_store(&self.vault.store).prune_settled_in_txn(txn, record.id)?;
        Ok(())
    }

    /// Records `trace` in the history, stamped as the transaction's job rows
    /// are.
    pub(super) fn record_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        trace: &TaggingTrace,
    ) -> Result<()> {
        let recorded_at = self.stamp_in_txn(txn)?;
        history::record_in_txn(&self.vault, txn, trace, recorded_at)
    }

    fn complete_in_txn(&self, txn: &mut heed::RwTxn<'_>, record: &AttemptRecord) -> Result<()> {
        #[cfg(test)]
        if self.vault.test_hooks().take_fail_next_tagging_settlement() {
            return Err(crate::error::Error::MapFull);
        }
        AttemptQueue::from_store(&self.vault.store).complete_storage_in_txn(
            txn,
            CompleteAttempt {
                id: record.id,
                lease_owner: self.lease_owner.clone(),
                attempt_count: record.attempt_count,
                now: self.stamp_in_txn(txn)?,
            },
        )?;
        Ok(())
    }

    /// Fails a marker whose payload this build cannot read, since no pass
    /// ever can, records its trace, and prunes it from the job ledger with
    /// every try it retried: the settlement every door that finds such a
    /// payload makes.
    pub(super) fn fail_unreadable_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        record: &AttemptRecord,
        trace: &TaggingTrace,
    ) -> Result<()> {
        let queue = AttemptQueue::from_store(&self.vault.store);
        queue.fail_storage_in_txn(
            txn,
            FailAttempt {
                id: record.id,
                lease_owner: self.lease_owner.clone(),
                attempt_count: record.attempt_count,
                reason: UNREADABLE_MARKER.to_owned(),
                now: self.stamp_in_txn(txn)?,
            },
        )?;
        self.record_in_txn(txn, trace)?;
        queue.prune_settled_in_txn(txn, record.id)?;
        Ok(())
    }

    pub(super) fn retry(
        &self,
        record: &AttemptRecord,
        prior_retries: u32,
        failure: TaggingFailure,
        trace: TaggingTrace,
    ) -> Result<TaggingTrace> {
        let reason = match failure {
            TaggingFailure::Call { .. } => "call_failed",
            TaggingFailure::Refused { .. } => "answer_refused",
            TaggingFailure::Panicked => "tagger_panicked",
        };
        let delay = self.backoff.delay_secs(prior_retries);
        self.retry_traced(record, delay, reason, trace, |retry_at| {
            TaggingOutcome::Failed { failure, retry_at }
        })
    }

    /// Retries the marker `delay_secs` from now and records its trace, whose
    /// outcome `outcome` names from the retry's time, in one transaction.
    pub(super) fn retry_traced(
        &self,
        record: &AttemptRecord,
        delay_secs: u64,
        reason: &str,
        mut trace: TaggingTrace,
        outcome: impl FnOnce(u64) -> TaggingOutcome,
    ) -> Result<TaggingTrace> {
        self.vault.try_with_write_txn_grouped(|txn| {
            let stamp = self.stamp_in_txn(txn)?;
            let retry_at = stamp.saturating_add(delay_secs);
            // A retry owed at once is ready at once, whatever the clock reads
            // at the next claim; a backoff counts from this stamp.
            let ready_at = if delay_secs == 0 { 0 } else { retry_at };
            self.retry_in_txn(txn, record, ready_at, reason)?;
            trace.outcome = outcome(retry_at);
            history::record_in_txn(&self.vault, txn, &trace, stamp)?;
            Ok(trace)
        })
    }

    /// Retries a marker this owner holds, in the caller's transaction, with
    /// its successor ready at `retry_at`. The successor's id is derived from
    /// the try it retries, so no retry draws from the vault's id source and
    /// shadow leaves every later write's entity ids as a run with no tagger
    /// leaves them. Every caller has read the payload first.
    pub(super) fn retry_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        record: &AttemptRecord,
        retry_at: u64,
        reason: &str,
    ) -> Result<()> {
        #[cfg(test)]
        if self.vault.test_hooks().take_fail_next_tagging_settlement() {
            return Err(crate::error::Error::MapFull);
        }
        retry_marker_in_txn(
            &self.vault,
            txn,
            RetryAttempt {
                id: record.id,
                lease_owner: self.lease_owner.clone(),
                attempt_count: record.attempt_count,
                backoff_until: retry_at,
                last_error: Some(reason.to_owned()),
                now: self.stamp_in_txn(txn)?,
            },
        )
    }
}

/// The trace of an attempt on `record` before its payload is read: what a
/// payload this build cannot read leaves.
pub(super) fn unreadable_trace(record: &AttemptRecord, prior_retries: u32) -> TaggingTrace {
    TaggingTrace {
        attempt: attempt_hex(&record.id),
        turn: None,
        checkpoint: String::new(),
        stack: None,
        model: None,
        input_hash: None,
        try_number: prior_retries.saturating_add(1),
        call_micros: None,
        execution: None,
        outcome: TaggingOutcome::Unreadable,
    }
}
