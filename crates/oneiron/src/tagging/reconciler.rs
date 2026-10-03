//! The drain pass a host worker drives: claim ready markers, read each turn,
//! call the tagger outside any write transaction, check the answer, settle.

use std::collections::BTreeMap;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Instant;

use super::input::{TurnInput, turn_input_in_txn};
use super::marker::{MarkerPayload, TAGGING_MARKER_KIND, enqueue_marker_in_txn};
use super::output::{AnswerMood, check_output};
use super::trace::{SkipReason, TaggingFailure, TaggingOutcome, TaggingTrace, attempt_hex};
use crate::Vault;
use crate::attempt_queue::{
    AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome, CompleteAttempt,
    FailAttempt, RetryAttempt,
};
use crate::embed::EmbedderLocality;
use crate::error::{Error, Result};
use crate::memory::extraction::{EncoderOutput, ExtractionEncoder};

const DEFAULT_LEASE_OWNER: &str = "oneironer-tagging";
const DEFAULT_BATCH_SIZE: usize = 16;
/// Startup scan bound when this worker's own stale leases are looked up.
const MAX_STARTUP_SCAN: usize = 1 << 24;

/// Retry backoff for a failed attempt, in store-clock seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaggingBackoff {
    /// Delay before a marker's first retry; every later retry doubles it.
    pub first_secs: u64,
    /// Ceiling on the doubled delay.
    pub max_secs: u64,
}

impl Default for TaggingBackoff {
    fn default() -> Self {
        Self {
            first_secs: 5,
            max_secs: 300,
        }
    }
}

impl TaggingBackoff {
    fn delay_secs(self, prior_retries: u32) -> u64 {
        let factor = 1_u64.checked_shl(prior_retries).unwrap_or(u64::MAX);
        self.first_secs.saturating_mul(factor).min(self.max_secs)
    }
}

/// What one pass did.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TaggingPass {
    /// One trace per claimed marker, in claim order.
    pub traces: Vec<TaggingTrace>,
    /// Tagger calls made.
    pub calls: usize,
    /// Calls that returned an error or panicked; a refused answer is not one.
    pub failed_calls: usize,
}

/// Drains tagging markers through one host-served tagger.
///
/// Every claimed marker settles inside the pass: completed, retried with
/// backoff, or (for a payload this build cannot read) failed. No marker ever
/// fails the write that committed it.
pub struct TaggingReconciler {
    vault: Arc<Vault>,
    encoder: Arc<dyn ExtractionEncoder>,
    checkpoint: String,
    lease_owner: String,
    batch_size: usize,
    backoff: TaggingBackoff,
    label_kinds: BTreeMap<String, u8>,
}

impl TaggingReconciler {
    /// A reconciler for an armed vault and an on-device tagger.
    ///
    /// A tagger off the device would carry vault text away, and extraction
    /// leaves the device only behind the host egress predicate, which no
    /// tagger door has yet; so it is refused here.
    pub fn new(vault: Arc<Vault>, encoder: Arc<dyn ExtractionEncoder>) -> Result<Self> {
        let checkpoint = vault
            .config
            .tagging
            .as_ref()
            .map(|tagging| tagging.checkpoint.clone())
            .ok_or_else(|| {
                Error::InvalidConfig("tagging markers are not armed on this vault".to_owned())
            })?;
        if encoder.locality() != EmbedderLocality::OnDevice {
            return Err(Error::InvalidConfig(
                "a tagger off the device needs the host egress predicate".to_owned(),
            ));
        }
        Ok(Self {
            vault,
            encoder,
            checkpoint,
            lease_owner: DEFAULT_LEASE_OWNER.to_owned(),
            batch_size: DEFAULT_BATCH_SIZE,
            backoff: TaggingBackoff::default(),
            label_kinds: BTreeMap::new(),
        })
    }

    /// Markers claimed per pass, at least one.
    #[must_use]
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size.max(1);
        self
    }

    #[must_use]
    pub fn with_backoff(mut self, backoff: TaggingBackoff) -> Self {
        self.backoff = backoff;
        self
    }

    /// The lease owner this worker claims under. One worker per vault.
    #[must_use]
    pub fn with_lease_owner(mut self, lease_owner: impl Into<String>) -> Self {
        self.lease_owner = lease_owner.into();
        self
    }

    /// The configured label table: model label to entity type byte. In shadow
    /// it only counts the spans it maps.
    #[must_use]
    pub fn with_label_kinds(mut self, label_kinds: BTreeMap<String, u8>) -> Self {
        self.label_kinds = label_kinds;
        self
    }

    /// Returns every marker this lease owner still holds to the ready index.
    ///
    /// Run once at worker start: one worker serves a vault, so a lease under
    /// its own name outlived the process that took it. Each returns as an
    /// immediate retry, so the turn is tagged once more and settled once.
    pub fn release_stale_leases(&self) -> Result<usize> {
        let queue = AttemptQueue::new(&self.vault);
        let stale: Vec<AttemptRecord> = queue
            .list_kind_bounded(TAGGING_MARKER_KIND, MAX_STARTUP_SCAN)?
            .into_iter()
            .filter(|record| {
                record.state == AttemptState::Leased
                    && record.lease_owner.as_deref() == Some(self.lease_owner.as_str())
            })
            .collect();
        for record in &stale {
            queue.retry(RetryAttempt {
                id: record.id,
                lease_owner: self.lease_owner.clone(),
                attempt_count: record.attempt_count,
                backoff_until: 0,
                last_error: Some("worker_restarted".to_owned()),
                now: 0,
            })?;
        }
        Ok(stale.len())
    }

    /// The store-clock second the earliest waiting marker becomes claimable.
    pub fn next_ready_at(&self) -> Result<Option<u64>> {
        AttemptQueue::new(&self.vault).next_ready_at_of_kind(TAGGING_MARKER_KIND)
    }

    /// Claims and settles up to the batch size of ready markers.
    ///
    /// A failed attempt ends the pass early: a tagger that is down costs one
    /// attempt per pass, not one per waiting marker, and a refused marker is
    /// never claimed twice in one pass.
    pub fn drain_once(&self) -> Result<TaggingPass> {
        self.drain_once_with(|_| {})
    }

    /// [`Self::drain_once`], handing each trace to `on_trace` the moment its
    /// marker settles.
    pub fn drain_once_with(&self, mut on_trace: impl FnMut(&TaggingTrace)) -> Result<TaggingPass> {
        let queue = AttemptQueue::new(&self.vault);
        let mut pass = TaggingPass::default();
        for _ in 0..self.batch_size {
            let claimed = queue.claim_kind(
                TAGGING_MARKER_KIND,
                ClaimAttempt {
                    lease_owner: self.lease_owner.clone(),
                    now: self.vault.now_recorded_at(),
                },
            )?;
            let ClaimOutcome::Claimed(record) = claimed else {
                break;
            };
            let trace = self.attempt(&queue, &record, &mut pass)?;
            let failed = matches!(trace.outcome, TaggingOutcome::Failed { .. });
            on_trace(&trace);
            pass.traces.push(trace);
            if failed {
                break;
            }
        }
        Ok(pass)
    }

    fn attempt(
        &self,
        queue: &AttemptQueue<'_>,
        record: &AttemptRecord,
        pass: &mut TaggingPass,
    ) -> Result<TaggingTrace> {
        let prior_retries = queue.retry_chain_depth(record.id)?;
        let mut trace = TaggingTrace {
            attempt: attempt_hex(&record.id),
            turn: None,
            checkpoint: String::new(),
            model: None,
            input_hash: None,
            try_number: prior_retries.saturating_add(1),
            call_micros: None,
            outcome: TaggingOutcome::Unreadable,
        };
        let Some(payload) = MarkerPayload::decode(&record.payload) else {
            queue.fail(FailAttempt {
                id: record.id,
                lease_owner: self.lease_owner.clone(),
                attempt_count: record.attempt_count,
                reason: "unreadable_tagging_marker".to_owned(),
                now: 0,
            })?;
            return Ok(trace);
        };
        trace.turn = Some(payload.turn);
        trace.checkpoint.clone_from(&payload.checkpoint);
        if payload.checkpoint != self.checkpoint {
            // Owed by another checkpoint: the active tagger owes the turn now.
            self.vault.try_with_write_txn(|txn| -> Result<()> {
                enqueue_marker_in_txn(&self.vault, txn, payload.turn, &self.checkpoint)?;
                self.complete_in_txn(txn, record)
            })?;
            trace.outcome = TaggingOutcome::Rekeyed;
            return Ok(trace);
        }
        let read = {
            let txn = self.vault.store.env.read_txn()?;
            turn_input_in_txn(&self.vault, &txn, &payload.turn)?
        };
        let (input, hash) = match read {
            TurnInput::Gone => return self.skip(record, SkipReason::TurnGone, trace),
            TurnInput::Empty => return self.skip(record, SkipReason::NoText, trace),
            TurnInput::Ready { input, hash } => (input, hash),
        };
        trace.input_hash = Some(hash.clone());
        trace.model = Some(self.encoder.model_id().as_str().to_owned());
        pass.calls += 1;
        let started = Instant::now();
        let called = std::panic::catch_unwind(AssertUnwindSafe(|| self.encoder.infer(&input)));
        trace.call_micros = Some(u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX));
        let output = match called {
            Ok(Ok(output)) => output,
            Ok(Err(error)) => {
                pass.failed_calls += 1;
                let failure = TaggingFailure::Call {
                    code: failure_code(&error),
                };
                return self.retry(queue, record, prior_retries, failure, trace);
            }
            Err(_) => {
                pass.failed_calls += 1;
                return self.retry(
                    queue,
                    record,
                    prior_retries,
                    TaggingFailure::Panicked,
                    trace,
                );
            }
        };
        if let Err(refusal) = check_output(&input, &output) {
            let failure = TaggingFailure::Refused { refusal };
            return self.retry(queue, record, prior_retries, failure, trace);
        }
        // The answer stands only for the text it read: settle against the turn
        // as the settling transaction sees it.
        let settled = self.vault.try_with_write_txn(|txn| -> Result<bool> {
            let current = matches!(
                turn_input_in_txn(&self.vault, txn, &payload.turn)?,
                TurnInput::Ready { hash: ref now, .. } if *now == hash
            );
            if current {
                self.complete_in_txn(txn, record)?;
            }
            Ok(current)
        })?;
        if settled {
            trace.outcome = self.shadowed(&output);
            return Ok(trace);
        }
        let retry_at = self.retry_at(queue, record, 0, "superseded")?;
        trace.outcome = TaggingOutcome::Superseded { retry_at };
        Ok(trace)
    }

    /// Nothing is owed: the marker completes with no tagger call.
    fn skip(
        &self,
        record: &AttemptRecord,
        reason: SkipReason,
        mut trace: TaggingTrace,
    ) -> Result<TaggingTrace> {
        self.vault
            .try_with_write_txn(|txn| self.complete_in_txn(txn, record))?;
        trace.outcome = TaggingOutcome::Skipped { reason };
        Ok(trace)
    }

    fn shadowed(&self, output: &EncoderOutput) -> TaggingOutcome {
        TaggingOutcome::Shadowed {
            spans: output.spans.len(),
            links: output.links.len(),
            mood: output.vad.present(),
            mapped_spans: output
                .spans
                .iter()
                .filter(|span| self.label_kinds.contains_key(&span.label))
                .count(),
        }
    }

    fn complete_in_txn(&self, txn: &mut heed::RwTxn<'_>, record: &AttemptRecord) -> Result<()> {
        AttemptQueue::from_store(&self.vault.store).complete_in_txn(
            txn,
            CompleteAttempt {
                id: record.id,
                lease_owner: self.lease_owner.clone(),
                attempt_count: record.attempt_count,
                now: 0,
            },
        )?;
        Ok(())
    }

    fn retry(
        &self,
        queue: &AttemptQueue<'_>,
        record: &AttemptRecord,
        prior_retries: u32,
        failure: TaggingFailure,
        mut trace: TaggingTrace,
    ) -> Result<TaggingTrace> {
        let reason = match failure {
            TaggingFailure::Call { .. } => "call_failed",
            TaggingFailure::Refused { .. } => "answer_refused",
            TaggingFailure::Panicked => "tagger_panicked",
        };
        let delay = self.backoff.delay_secs(prior_retries);
        let retry_at = self.retry_at(queue, record, delay, reason)?;
        trace.outcome = TaggingOutcome::Failed { failure, retry_at };
        Ok(trace)
    }

    fn retry_at(
        &self,
        queue: &AttemptQueue<'_>,
        record: &AttemptRecord,
        delay_secs: u64,
        reason: &str,
    ) -> Result<u64> {
        let retry_at = self.vault.now_recorded_at().saturating_add(delay_secs);
        queue.retry(RetryAttempt {
            id: record.id,
            lease_owner: self.lease_owner.clone(),
            attempt_count: record.attempt_count,
            backoff_until: retry_at,
            last_error: Some(reason.to_owned()),
            now: 0,
        })?;
        Ok(retry_at)
    }
}

/// A host failure code is caller-safe by contract (the host builds it with no
/// vault text); every other error reports only its stable kind.
fn failure_code(error: &Error) -> String {
    match error {
        Error::UpstreamToolFailure { code, .. } => code.clone(),
        other => format!("{:?}", other.kind()),
    }
}
