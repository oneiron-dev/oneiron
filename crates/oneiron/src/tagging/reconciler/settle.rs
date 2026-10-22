//! Settlement (FIX 6755): a marker completed, skipped, failed or retried
//! with its trace, each in one transaction. A prepared marker settles here
//! whichever path its call took, so there is one settlement path.

use super::call::Called;
use super::claim::PreparedCall;
use super::coordinator::{PreparedTagging, TaggingReconciler};
use crate::EntityId;
use crate::attempt_queue::{
    AttemptQueue, AttemptRecord, CompleteAttempt, FailAttempt, RetryAttempt,
};
use crate::error::Result;
use crate::memory::extraction::EncoderOutput;
use crate::tagging::history;
use crate::tagging::input::{TurnInput, turn_text_in_txn};
use crate::tagging::marker::{TaggingMode, retry_marker_in_txn};
use crate::tagging::save::{self, Answer};
use crate::tagging::tags::tagged_messages_absent_in_txn;
use crate::tagging::trace::{
    SkipReason, TaggingFailure, TaggingOutcome, TaggingTrace, attempt_hex,
};

/// Failure reason of a marker whose payload this build cannot read.
const UNREADABLE_MARKER: &str = "unreadable_tagging_marker";
/// Retry reason of a marker whose turn's tagged MESSAGE is away from this
/// replica (OF-534).
const MESSAGES_ABSENT: &str = "messages_absent";
/// Retry reason of a marker whose turn changed while it was read.
const SUPERSEDED: &str = "superseded";

impl TaggingReconciler {
    /// Settles `prepared` on what its call came back with: a failed call or
    /// a refused answer is a retry on the failure backoff, and an answer that
    /// passed every check ([`Self::checked`]) settles against the turn's
    /// current text. Once its write commits the marker leaves this
    /// reconciler's hold; an error leaves it held for the next hand-back.
    pub(super) fn settle_called(
        &self,
        prepared: PreparedTagging,
        called: Called,
    ) -> Result<TaggingTrace> {
        let PreparedTagging { trace, call, hold } = prepared;
        let trace = match self.checked(&call, called) {
            Ok(output) => self.settle_answer(&call, &output, trace)?,
            Err(failure) => self.retry(&call, failure, trace)?,
        };
        hold.settled();
        Ok(trace)
    }

    /// Settles an answer that passed every check. It stands only for the
    /// text it tagged: the settling transaction reads the turn's own text
    /// again; the window was context, which it never reads. In save mode the
    /// tags land in that same write, so a turn's marker settles exactly when
    /// its tags are saved. A turn whose text changed while the tagger read it
    /// is superseded, retried at once on the new text, and one whose tagged
    /// MESSAGE left this replica meanwhile (OF-534) is deferred: each in that
    /// same transaction, with its trace. Each retry carries the row's payload
    /// as that transaction reads it, so a live write's promotion of the marker
    /// since its claim carries over.
    fn settle_answer(
        &self,
        call: &PreparedCall,
        output: &EncoderOutput,
        mut trace: TaggingTrace,
    ) -> Result<TaggingTrace> {
        let turn = call.payload.turn;
        let made_by = self.encoder.model_id().as_str().to_owned();
        self.vault
            .try_with_write_txn_grouped(|txn| -> Result<TaggingTrace> {
                // Inference ran outside this writer: a MESSAGE the saved set
                // was read from may have left this replica since.
                if tagged_messages_absent_in_txn(&self.vault.store, txn, &turn)? {
                    return self.defer_in_txn(txn, &call.record, call.prior_retries, trace);
                }
                let current = matches!(
                    turn_text_in_txn(&self.vault, txn, &turn)?,
                    TurnInput::Ready { text_hash: ref now, .. } if *now == call.text_hash
                );
                if !current {
                    return self.supersede_in_txn(txn, &call.record, trace);
                }
                trace.outcome = match self.config.mode {
                    TaggingMode::Shadow => self.shadowed(output),
                    TaggingMode::Save => {
                        let mut envelope = save::envelope(
                            &call.hash,
                            &made_by,
                            &self.config,
                            output.stack_sha16.as_deref(),
                        );
                        // A conversation register's digest moves with the
                        // conversation; the turn's own text says whether the
                        // set still indexes its words (FIX 10167).
                        if !call.input.register.is_live() {
                            envelope.text_hash = Some(call.text_hash.clone());
                        }
                        let answer = Answer {
                            turn,
                            input: &call.input,
                            output,
                            envelope,
                        };
                        let now = self.stamp_in_txn(txn)?;
                        let saved = save::save_in_txn(&self.vault, txn, answer, &self.config, now)?;
                        TaggingOutcome::Saved {
                            spans: output.spans.len(),
                            links: output.links.len(),
                            mood: output.vad.is_some(),
                            linked: saved.linked,
                            minted: saved.minted,
                            context_links: output.context_links.len(),
                            speaker_links: output.speaker_links.len(),
                            unresolved_context_links: saved.unresolved_context_links,
                            unresolved_speaker_links: saved.unresolved_speaker_links,
                            surprise: saved.surprise,
                        }
                    }
                };
                self.settle_in_txn(txn, &call.record, &trace)?;
                Ok(trace)
            })
    }

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
        self.vault
            .try_with_write_txn_grouped(|txn| self.defer_in_txn(txn, record, prior_retries, trace))
    }

    /// [`Self::defer`], in the caller's transaction.
    fn defer_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        record: &AttemptRecord,
        prior_retries: u32,
        trace: TaggingTrace,
    ) -> Result<TaggingTrace> {
        let delay = self.backoff.delay_secs(prior_retries);
        self.retry_traced_in_txn(txn, record, delay, MESSAGES_ABSENT, trace, |retry_at| {
            TaggingOutcome::Deferred { retry_at }
        })
    }

    /// Retries the marker at once on its turn's new text, recording its
    /// trace, in the caller's transaction.
    fn supersede_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        record: &AttemptRecord,
        trace: TaggingTrace,
    ) -> Result<TaggingTrace> {
        self.retry_traced_in_txn(txn, record, 0, SUPERSEDED, trace, |retry_at| {
            TaggingOutcome::Superseded { retry_at }
        })
    }

    /// Nothing is owed: the marker completes with no tagger call. In save
    /// mode a turn left with no text loses the tags it held, in the settling
    /// write: none of them was read from text it still has.
    ///
    /// The skip stands only for the turn it read: a witness that added text
    /// since then was absorbed by this leased marker, so the settling
    /// transaction reads the turn again and, if it now has text, the marker
    /// is retried at once on it, in that same transaction. So is one whose
    /// tagged MESSAGE left this replica since (OF-534): its next try waits
    /// for the row, and the set stays.
    pub(super) fn skip(
        &self,
        record: &AttemptRecord,
        turn: &EntityId,
        reason: SkipReason,
        mut trace: TaggingTrace,
    ) -> Result<TaggingTrace> {
        trace.outcome = TaggingOutcome::Skipped { reason };
        self.vault
            .try_with_write_txn_grouped(|txn| -> Result<TaggingTrace> {
                if tagged_messages_absent_in_txn(&self.vault.store, txn, turn)? {
                    return self.supersede_in_txn(txn, record, trace);
                }
                let read = turn_text_in_txn(&self.vault, txn, turn)?;
                if matches!(read, TurnInput::Ready { .. }) {
                    return self.supersede_in_txn(txn, record, trace);
                }
                if self.config.mode == TaggingMode::Save && matches!(read, TurnInput::Empty) {
                    crate::tagging::tags::replace_in_txn(&self.vault, txn, turn, None)?;
                }
                self.settle_in_txn(txn, record, &trace)?;
                Ok(trace)
            })
    }

    fn shadowed(&self, output: &EncoderOutput) -> TaggingOutcome {
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

    fn retry(
        &self,
        call: &PreparedCall,
        failure: TaggingFailure,
        trace: TaggingTrace,
    ) -> Result<TaggingTrace> {
        let reason = match failure {
            TaggingFailure::Call { .. } => "call_failed",
            TaggingFailure::Refused { .. } => "answer_refused",
            TaggingFailure::Panicked => "tagger_panicked",
        };
        let delay = self.backoff.delay_secs(call.prior_retries);
        self.retry_traced(&call.record, delay, reason, trace, |retry_at| {
            TaggingOutcome::Failed { failure, retry_at }
        })
    }

    /// Retries the marker `delay_secs` from now and records its trace, whose
    /// outcome `outcome` names from the retry's time, in one transaction.
    fn retry_traced(
        &self,
        record: &AttemptRecord,
        delay_secs: u64,
        reason: &str,
        trace: TaggingTrace,
        outcome: impl FnOnce(u64) -> TaggingOutcome,
    ) -> Result<TaggingTrace> {
        self.vault.try_with_write_txn_grouped(|txn| {
            self.retry_traced_in_txn(txn, record, delay_secs, reason, trace, outcome)
        })
    }

    /// [`Self::retry_traced`], in the caller's transaction.
    fn retry_traced_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        record: &AttemptRecord,
        delay_secs: u64,
        reason: &str,
        mut trace: TaggingTrace,
        outcome: impl FnOnce(u64) -> TaggingOutcome,
    ) -> Result<TaggingTrace> {
        let stamp = self.stamp_in_txn(txn)?;
        let retry_at = stamp.saturating_add(delay_secs);
        // A retry owed at once is ready at once, whatever the clock reads at
        // the next claim; a backoff counts from this stamp.
        let ready_at = if delay_secs == 0 { 0 } else { retry_at };
        self.retry_in_txn(txn, record, ready_at, reason)?;
        trace.outcome = outcome(retry_at);
        history::record_in_txn(&self.vault, txn, &trace, stamp)?;
        Ok(trace)
    }

    /// Retries a marker this owner holds, in the caller's transaction, with
    /// its successor ready at `retry_at`. The successor's id is derived from
    /// the try it retries, so no retry draws from the vault's id source and
    /// shadow leaves every later write's entity ids as a run with no tagger
    /// leaves them. Every caller has read the payload first. The successor
    /// carries the payload the row holds in `txn`, so a live write's
    /// promotion of the try since its claim carries over (FIX 6755).
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
