//! The drain pass a host worker drives: claim ready markers, read each turn,
//! call the tagger outside any write transaction, check the answer, settle.

use std::collections::BTreeMap;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use super::input::{TurnInput, turn_input_in_txn};
use super::marker::{
    MarkerPayload, TAGGING_MARKER_KIND, enqueue_marker_in_txn, retry_marker_in_txn,
};
use super::output::{AnswerMood, check_output};
use super::trace::{SkipReason, TaggingFailure, TaggingOutcome, TaggingTrace, attempt_hex};
use crate::EntityId;
use crate::Vault;
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome,
    CompleteAttempt, FailAttempt, RetryAttempt, decode_record,
};
use crate::embed::EmbedderLocality;
use crate::error::{Error, Result};
use crate::memory::extraction::{EncoderOutput, ExtractionEncoder};

const DEFAULT_LEASE_OWNER: &str = "oneironer-tagging";
const DEFAULT_BATCH_SIZE: usize = 16;
/// Failure reason of a marker whose payload this build cannot read.
const UNREADABLE_MARKER: &str = "unreadable_tagging_marker";
/// Retry reasons of the markers a reconciler hands back.
const WORKER_RESTARTED: &str = "worker_restarted";
const SETTLEMENT_FAILED: &str = "settlement_failed";

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

impl TaggingPass {
    /// The earliest store-clock second a marker this pass failed is retried
    /// at: when the worker next has a retry to claim, read from the pass
    /// itself rather than from the queue.
    #[must_use]
    pub fn earliest_retry_at(&self) -> Option<u64> {
        self.traces
            .iter()
            .filter_map(|trace| match trace.outcome {
                TaggingOutcome::Failed { retry_at, .. } => Some(retry_at),
                _ => None,
            })
            .min()
    }
}

/// Drains tagging markers through one host-served tagger.
///
/// Every claimed marker settles inside the pass: completed, retried with
/// backoff, or (for a payload this build cannot read) failed. A marker whose
/// settling write fails stays this reconciler's, as does one a stopped worker
/// left leased, and its next pass hands it back before claiming anything. No
/// marker ever fails the write that committed it.
pub struct TaggingReconciler {
    vault: Arc<Vault>,
    encoder: Arc<dyn ExtractionEncoder>,
    checkpoint: String,
    lease_owner: String,
    batch_size: usize,
    backoff: TaggingBackoff,
    label_kinds: BTreeMap<String, u8>,
    /// Markers leased under this owner that no pass is settling, each with
    /// the reason it is handed back: a claim whose settling write failed, or
    /// a lease a stopped worker left. No claim, witness or publication
    /// reaches a leased marker, so only this reconciler can return it.
    unsettled: Mutex<Vec<(AttemptRecord, &'static str)>>,
    /// Whether the scan for stale leases has run; until it has, every pass
    /// starts by running it.
    stale_scanned: AtomicBool,
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
            unsettled: Mutex::new(Vec::new()),
            stale_scanned: AtomicBool::new(false),
        })
    }

    /// The store clock as this worker reads it, for scheduling its waits:
    /// reading it moves no clock floor of the vault, in memory or on disk, so
    /// a shadow worker leaves every later write's clock as a vault with no
    /// tagger leaves it. A job row is stamped inside its write transaction,
    /// from this or the vault's committed clock floor, whichever is later.
    #[must_use]
    pub fn now(&self) -> u64 {
        self.vault.store.clock.peek_recorded_at()
    }

    /// The stamp a job row this reconciler writes takes, inside its write
    /// transaction: [`Self::now`], or the clock floor the vault has committed
    /// if later. Neither floor moves.
    fn stamp_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<u64> {
        crate::ports::job_recorded_at_in_txn(&self.vault.store, txn)
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

    /// Returns every marker this lease owner still holds to the ready index,
    /// and reports how many it found.
    ///
    /// Run at worker start: one worker serves a vault, so a lease under its
    /// own name outlived the process that took it. Each returns as an
    /// immediate retry, so the turn is tagged once more and settled once. A
    /// release that fails is not dropped: what the scan found stays this
    /// reconciler's to hand back, and a scan that failed runs again, both at
    /// the start of its next pass.
    ///
    /// One pass over the job records keeps only this owner's leased markers;
    /// a row of any kind this build cannot decode is passed over, so no other
    /// job's row can stop the worker from starting.
    pub fn release_stale_leases(&self) -> Result<usize> {
        let stale = {
            let txn = self.vault.store.env.read_txn()?;
            let mut stale = Vec::new();
            for row in self.vault.store.attempt_records.iter(&txn)? {
                let (key, raw) = row?;
                let Ok(id) = AttemptId::from_bytes(&key) else {
                    continue;
                };
                let Ok(record) = decode_record(&raw, id) else {
                    continue;
                };
                if record.kind == TAGGING_MARKER_KIND
                    && record.state == AttemptState::Leased
                    && record.lease_owner.as_deref() == Some(self.lease_owner.as_str())
                {
                    stale.push(record);
                }
            }
            stale
        };
        let found = stale.len();
        {
            let mut unsettled = self
                .unsettled
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            for record in stale {
                if !unsettled.iter().any(|(held, _)| held.id == record.id) {
                    unsettled.push((record, WORKER_RESTARTED));
                }
            }
        }
        self.stale_scanned.store(true, Ordering::Release);
        self.return_unsettled()?;
        Ok(found)
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
    ///
    /// An error after a claim leaves that marker leased: the pass keeps it
    /// and returns the error, and the next pass hands it back first.
    pub fn drain_once_with(&self, mut on_trace: impl FnMut(&TaggingTrace)) -> Result<TaggingPass> {
        if self.stale_scanned.load(Ordering::Acquire) {
            self.return_unsettled()?;
        } else {
            self.release_stale_leases()?;
        }
        let queue = AttemptQueue::new(&self.vault);
        let mut pass = TaggingPass::default();
        for _ in 0..self.batch_size {
            let Some(record) = self.claim()? else {
                break;
            };
            let trace = match self.attempt(&queue, &record, &mut pass) {
                Ok(trace) => trace,
                Err(error) => {
                    self.unsettled
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push((record, SETTLEMENT_FAILED));
                    return Err(error);
                }
            };
            let failed = matches!(trace.outcome, TaggingOutcome::Failed { .. });
            on_trace(&trace);
            pass.traces.push(trace);
            if failed {
                break;
            }
        }
        Ok(pass)
    }

    /// Leases the next ready marker.
    ///
    /// Every job row this reconciler writes is stamped from the store clock
    /// without persisting its floor, and a claim that finds nothing commits
    /// nothing: a shadow worker writes nothing outside the job tables, even
    /// while the clock runs and the queue is empty. The lease is stamped once
    /// the write lock is held, so waiting for another writer does not age it.
    fn claim(&self) -> Result<Option<AttemptRecord>> {
        let mut txn = self.vault.store.env.write_txn()?;
        #[cfg(test)]
        self.vault.test_hooks().run_after_tagging_claim_writer();
        let now = self.stamp_in_txn(&txn)?;
        let claimed = AttemptQueue::from_store(&self.vault.store).claim_kind_storage_in_txn(
            &mut txn,
            Some(TAGGING_MARKER_KIND),
            ClaimAttempt {
                lease_owner: self.lease_owner.clone(),
                now,
            },
            now,
        )?;
        let ClaimOutcome::Claimed(record) = claimed else {
            return Ok(None);
        };
        txn.commit()?;
        self.vault.store.notify_attempt_observers();
        Ok(Some(record))
    }

    /// Hands back each marker this reconciler holds, as an immediate retry.
    /// One that is no longer leased under this owner at the held lease
    /// generation was settled after all, and is let go. A failed hand-back
    /// keeps the rest and fails the pass, so the next one tries again.
    fn return_unsettled(&self) -> Result<()> {
        let mut unsettled = self
            .unsettled
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        while let Some((record, reason)) = unsettled.last() {
            self.vault.try_with_write_txn(|txn| -> Result<()> {
                let current = self
                    .vault
                    .store
                    .attempt_records
                    .get(txn, record.id.as_bytes())?
                    .and_then(|raw| decode_record(&raw, record.id).ok());
                let still_held = current.is_some_and(|current| {
                    current.state == AttemptState::Leased
                        && current.lease_owner == record.lease_owner
                        && current.attempt_count == record.attempt_count
                });
                if still_held {
                    self.retry_in_txn(txn, record, 0, reason)?;
                }
                Ok(())
            })?;
            unsettled.pop();
        }
        Ok(())
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
            self.vault
                .try_with_write_txn(|txn| self.fail_unreadable_in_txn(txn, record))?;
            return Ok(trace);
        };
        trace.turn = Some(payload.turn);
        trace.checkpoint.clone_from(&payload.checkpoint);
        if payload.checkpoint != self.checkpoint {
            // Owed by another checkpoint: the active tagger owes the turn now.
            self.vault.try_with_write_txn(|txn| -> Result<()> {
                let now = self.stamp_in_txn(txn)?;
                enqueue_marker_in_txn(&self.vault, txn, payload.turn, &self.checkpoint, now)?;
                self.complete_in_txn(txn, record)
            })?;
            trace.outcome = TaggingOutcome::Rekeyed;
            return Ok(trace);
        }
        let read = {
            let txn = self.vault.store.env.read_txn()?;
            turn_input_in_txn(&self.vault, &txn, &payload.turn)?
        };
        #[cfg(test)]
        run_after_turn_read_hook();
        let (input, hash) = match read {
            TurnInput::Gone => {
                return self.skip(record, &payload.turn, SkipReason::TurnGone, trace);
            }
            TurnInput::Empty => {
                return self.skip(record, &payload.turn, SkipReason::NoText, trace);
            }
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
                return self.retry(record, prior_retries, failure, trace);
            }
            Err(_) => {
                pass.failed_calls += 1;
                return self.retry(record, prior_retries, TaggingFailure::Panicked, trace);
            }
        };
        if let Err(refusal) = check_output(&input, &output) {
            let failure = TaggingFailure::Refused { refusal };
            return self.retry(record, prior_retries, failure, trace);
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
        let retry_at = self.retry_at(record, 0, "superseded")?;
        trace.outcome = TaggingOutcome::Superseded { retry_at };
        Ok(trace)
    }

    /// Nothing is owed: the marker completes with no tagger call.
    ///
    /// The skip stands only for the turn it read: a witness that added text
    /// since then was absorbed by this leased marker, so the settling
    /// transaction reads the turn again and, if it now has text, the marker
    /// is retried at once on it.
    fn skip(
        &self,
        record: &AttemptRecord,
        turn: &EntityId,
        reason: SkipReason,
        mut trace: TaggingTrace,
    ) -> Result<TaggingTrace> {
        let settled = self.vault.try_with_write_txn(|txn| -> Result<bool> {
            let owes_nothing = !matches!(
                turn_input_in_txn(&self.vault, txn, turn)?,
                TurnInput::Ready { .. }
            );
            if owes_nothing {
                self.complete_in_txn(txn, record)?;
            }
            Ok(owes_nothing)
        })?;
        if settled {
            trace.outcome = TaggingOutcome::Skipped { reason };
            return Ok(trace);
        }
        let retry_at = self.retry_at(record, 0, "superseded")?;
        trace.outcome = TaggingOutcome::Superseded { retry_at };
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
        #[cfg(test)]
        if self.vault.test_hooks().take_fail_next_tagging_settlement() {
            return Err(Error::MapFull);
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

    /// Fails a marker whose payload this build cannot read: no pass ever can.
    fn fail_unreadable_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        record: &AttemptRecord,
    ) -> Result<()> {
        AttemptQueue::from_store(&self.vault.store).fail_storage_in_txn(
            txn,
            FailAttempt {
                id: record.id,
                lease_owner: self.lease_owner.clone(),
                attempt_count: record.attempt_count,
                reason: UNREADABLE_MARKER.to_owned(),
                now: self.stamp_in_txn(txn)?,
            },
        )?;
        Ok(())
    }

    fn retry(
        &self,
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
        let retry_at = self.retry_at(record, delay, reason)?;
        trace.outcome = TaggingOutcome::Failed { failure, retry_at };
        Ok(trace)
    }

    fn retry_at(&self, record: &AttemptRecord, delay_secs: u64, reason: &str) -> Result<u64> {
        self.vault.try_with_write_txn(|txn| {
            let retry_at = self.stamp_in_txn(txn)?.saturating_add(delay_secs);
            // A retry owed at once is ready at once, whatever the clock reads
            // at the next claim; a backoff counts from this stamp.
            let ready_at = if delay_secs == 0 { 0 } else { retry_at };
            self.retry_in_txn(txn, record, ready_at, reason)?;
            Ok(retry_at)
        })
    }

    /// Retries a marker this owner holds, in the caller's transaction, with
    /// its successor ready at `retry_at`. The successor's id is derived like
    /// a new marker's, so no retry draws from the vault's id source and shadow
    /// leaves every later write's entity ids as a run with no tagger leaves
    /// them. A payload this build cannot read is failed, as a pass fails it.
    fn retry_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        record: &AttemptRecord,
        retry_at: u64,
        reason: &str,
    ) -> Result<()> {
        #[cfg(test)]
        if self.vault.test_hooks().take_fail_next_tagging_settlement() {
            return Err(Error::MapFull);
        }
        let Some(payload) = MarkerPayload::decode(&record.payload) else {
            return self.fail_unreadable_in_txn(txn, record);
        };
        retry_marker_in_txn(
            &self.vault,
            txn,
            &payload,
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

#[cfg(test)]
std::thread_local! {
    static AFTER_TURN_READ: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Runs `hook` once on this thread, between an attempt's read of its turn and
/// the transaction that settles it.
#[cfg(test)]
pub(super) fn set_after_turn_read_hook(hook: impl FnOnce() + 'static) {
    AFTER_TURN_READ.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_after_turn_read_hook() {
    let hook = AFTER_TURN_READ.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
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
