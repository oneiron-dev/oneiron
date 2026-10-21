//! The claim (FIX 6755): a ready live marker before any bulk one, read
//! outside the writer and leased under it, then the claimed marker's payload
//! and turn read into what its one call needs. A claimed marker is entered in
//! the reconciler's held set before its lease commits.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use super::coordinator::{PreparedTagging, TaggingPreparation, TaggingReconciler};
use super::settle::unreadable_trace;
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use crate::error::Result;
use crate::memory::extraction::{EncoderInput, ExtractionWork};
use crate::tagging::input::{TurnInput, turn_input_in_txn};
use crate::tagging::marker::{MarkerPayload, TAGGING_MARKER_KIND, enqueue_marker_in_txn};
use crate::tagging::tags::tagged_messages_absent_in_txn;
use crate::tagging::trace::{HandBackReason, SkipReason, TaggingOutcome, TaggingTrace};

/// A marker leased under the reconciler's owner and not settled yet.
pub(super) struct Held {
    pub(super) record: AttemptRecord,
    /// Why a hand-back returns it.
    pub(super) reason: HandBackReason,
    /// Whether its preparation, its call, its settlement or a hand-back owns
    /// it now: no hand-back starts on it until that owner lets it go.
    pub(super) owned: bool,
}

/// The markers a reconciler holds, shared with each claim's hold.
pub(super) type HeldSet = Arc<Mutex<Vec<Held>>>;

/// The held markers, read past a poisoned lock. No caller holds it across a
/// write: a claim takes it under the writer.
pub(super) fn lock_held(held: &Mutex<Vec<Held>>) -> MutexGuard<'_, Vec<Held>> {
    held.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The reconciler's hold on one marker it claimed, entered in its held set,
/// owned, before the claim commits, so neither the start scan nor a hand-back
/// meets the lease unowned. Dropped while the marker is unsettled, by an
/// error, a panic or a host that let its preparation go, it leaves the marker
/// to the next hand-back.
pub(super) struct ClaimHold {
    held: HeldSet,
    id: AttemptId,
}

impl ClaimHold {
    /// Enters `record`, owned, in `held`. An entry of the same row left by a
    /// claim whose commit failed goes: the row is leased only by this one.
    fn new(held: &HeldSet, record: &AttemptRecord) -> Self {
        let mut entries = lock_held(held);
        entries.retain(|entry| entry.record.id != record.id);
        entries.push(Held {
            record: record.clone(),
            reason: HandBackReason::SettlementFailed,
            owned: true,
        });
        Self {
            held: Arc::clone(held),
            id: record.id,
        }
    }

    /// The marker settled: it leaves the held set.
    pub(super) fn settled(self) {
        lock_held(&self.held).retain(|entry| entry.record.id != self.id);
    }
}

impl Drop for ClaimHold {
    fn drop(&mut self) {
        disown(&mut lock_held(&self.held), self.id);
    }
}

/// Leaves the held marker of row `id` to the next hand-back.
pub(super) fn disown(held: &mut [Held], id: AttemptId) {
    if let Some(entry) = held.iter_mut().find(|entry| entry.record.id == id) {
        entry.owned = false;
    }
}

/// A prepared marker's owned state: no transaction and no borrowed bytes.
pub(super) struct PreparedCall {
    /// The leased row: its id, lease owner and lease generation.
    pub(super) record: AttemptRecord,
    pub(super) payload: MarkerPayload,
    /// The marker's effective class when it was claimed.
    pub(super) work: ExtractionWork,
    pub(super) input: EncoderInput,
    /// The digest of the whole input, window included.
    pub(super) hash: String,
    /// The digest of the turn's own text, which the settling write reads
    /// again.
    pub(super) text_hash: String,
    /// Tries of the marker before this one.
    pub(super) prior_retries: u32,
}

/// What a claim found.
enum Claim {
    /// Nothing of the asked class is ready.
    Empty,
    /// Bulk was asked while a live marker is ready.
    Replan,
    /// The leased row, held from before its lease committed.
    Leased(Box<AttemptRecord>, ClaimHold),
}

impl TaggingReconciler {
    /// Leases the next ready marker of class `asked`, or of either class,
    /// live first, when `None`, reading only the owner-retained entries of
    /// the readiness index. The entries to act on are found outside the
    /// writer, and under it only those are read again, so another kind's
    /// waiting jobs cost the writer nothing, and a claim with nothing to
    /// claim or repair takes no writer at all.
    ///
    /// Every job row this reconciler writes is stamped from the store clock
    /// without persisting its floor, and a claim that finds nothing commits
    /// nothing: a shadow worker writes nothing outside the job state, even
    /// while the clock runs and the queue is empty. The lease is stamped once
    /// the write lock is held, so waiting for another writer does not age it.
    ///
    /// A ready live marker is claimed before any bulk one (FIX 6755): bulk is
    /// planned only from a read that found no live marker ready, and leased
    /// only if nothing has committed since that read or the writer finds no
    /// live marker ready either; otherwise a claim of either class is planned
    /// again, so a live marker committed meanwhile goes first, and a bulk
    /// claim is [`Claim::Replan`]. A payload this build cannot read is
    /// claimed as live, to be failed.
    fn claim(&self, asked: Option<ExtractionWork>) -> Result<Claim> {
        let queue = AttemptQueue::from_store(&self.vault.store);
        let attempt = |now| ClaimAttempt {
            lease_owner: self.lease_owner.clone(),
            now,
        };
        loop {
            // The plan, its class, and for bulk the read that found no live
            // marker ready.
            let (plan, live, fence) = {
                let txn = self.vault.store.env.read_txn()?;
                let now = self.stamp_in_txn(&txn)?;
                let mut ready = false;
                let plan = queue.owner_retained_matching_claim_plan_in_txn(
                    &txn,
                    TAGGING_MARKER_KIND,
                    &attempt(now),
                    now,
                    |record| {
                        let claims = self.claims_live(record);
                        ready |= claims;
                        Ok(claims)
                    },
                )?;
                match (ready, asked) {
                    (true, Some(ExtractionWork::Bulk)) => return Ok(Claim::Replan),
                    (true, _) | (false, Some(ExtractionWork::Live)) => (plan, true, None),
                    (false, _) => {
                        let plan = queue.owner_retained_matching_claim_plan_in_txn(
                            &txn,
                            TAGGING_MARKER_KIND,
                            &attempt(now),
                            now,
                            |record| Ok(!self.claims_live(record)),
                        )?;
                        (plan, false, Some(txn.id()))
                    }
                }
            };
            if plan.is_empty() {
                return Ok(Claim::Empty);
            }
            let mut txn = self.vault.store.env.write_txn()?;
            #[cfg(test)]
            self.vault.test_hooks().run_after_tagging_claim_writer();
            let now = self.stamp_in_txn(&txn)?;
            // The writer right after the read commits as its next id. Past any
            // other commit, the writer looks for a ready live marker itself, so
            // a busy store cannot keep bulk planning forever.
            if fence.is_some_and(|read| read.checked_add(1) != Some(txn.id())) {
                let mut ready = false;
                queue.owner_retained_matching_claim_plan_in_txn(
                    &txn,
                    TAGGING_MARKER_KIND,
                    &attempt(now),
                    now,
                    |record| {
                        let claims = self.claims_live(record);
                        ready |= claims;
                        Ok(claims)
                    },
                )?;
                if ready {
                    txn.abort();
                    if asked == Some(ExtractionWork::Bulk) {
                        return Ok(Claim::Replan);
                    }
                    continue;
                }
            }
            let (claimed, repaired) = queue.claim_owner_retained_matching_in_txn(
                &mut txn,
                TAGGING_MARKER_KIND,
                attempt(now),
                now,
                &plan,
                |record| Ok(self.claims_live(record) == live),
            )?;
            let ClaimOutcome::Claimed(record) = claimed else {
                // An empty claim commits only the index entries it repaired,
                // so the next pass does not meet them again.
                if repaired {
                    txn.commit()?;
                    self.vault.store.notify_attempt_observers();
                }
                return Ok(Claim::Empty);
            };
            // Held before the lease commits: a commit that fails leaves an
            // entry the next hand-back finds not leased, and lets go.
            let hold = ClaimHold::new(&self.unsettled, &record);
            txn.commit()?;
            self.vault.store.notify_attempt_observers();
            return Ok(Claim::Leased(Box::new(record), hold));
        }
    }

    /// Whether `record` is claimed in the live class: its marker's effective
    /// class is live, or its payload is one this build cannot read, which a
    /// live claim fails rather than leaving it behind every bulk marker.
    fn claims_live(&self, record: &AttemptRecord) -> bool {
        MarkerPayload::decode(&record.payload)
            .is_none_or(|payload| payload.effective_work(&self.vault) == ExtractionWork::Live)
    }

    /// [`Self::ready_class`]: one read, with the claim's own plans and
    /// predicates, live first. Only a row a claim would lease counts.
    pub(super) fn peek_class(&self) -> Result<Option<ExtractionWork>> {
        let queue = AttemptQueue::from_store(&self.vault.store);
        let txn = self.vault.store.env.read_txn()?;
        let now = self.stamp_in_txn(&txn)?;
        let attempt = ClaimAttempt {
            lease_owner: self.lease_owner.clone(),
            now,
        };
        for work in [ExtractionWork::Live, ExtractionWork::Bulk] {
            let mut ready = false;
            queue.owner_retained_matching_claim_plan_in_txn(
                &txn,
                TAGGING_MARKER_KIND,
                &attempt,
                now,
                |record| {
                    let claims = self.claims_live(record) == (work == ExtractionWork::Live);
                    ready |= claims;
                    Ok(claims)
                },
            )?;
            if ready {
                return Ok(Some(work));
            }
        }
        Ok(None)
    }

    /// The class the marker of row `id`, read as `payload`, is owed at as
    /// the row stands in `txn`: a live write may have promoted it since it
    /// was read. A row gone or unreadable since keeps the class `payload`
    /// carries.
    fn persisted_work_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: AttemptId,
        payload: &MarkerPayload,
    ) -> Result<ExtractionWork> {
        let persisted = AttemptQueue::from_store(&self.vault.store)
            .get_in_write_txn(txn, id)?
            .and_then(|row| MarkerPayload::decode(&row.payload));
        let payload = persisted.as_ref().unwrap_or(payload);
        Ok(payload.effective_work(&self.vault))
    }

    /// Claims a marker ([`Self::claim`]) and reads what its call needs. A
    /// marker owed no call settles here, in one transaction with its trace:
    /// a payload this build cannot read is failed, one owed to another
    /// tagger is rekeyed at the class its row carries under that writer, a
    /// turn gone or left with no text is skipped, and one whose tagged
    /// MESSAGE is away from this replica (OF-534) is deferred.
    pub(super) fn prepare(&self, asked: Option<ExtractionWork>) -> Result<TaggingPreparation> {
        let (record, hold) = match self.claim(asked)? {
            Claim::Empty => return Ok(TaggingPreparation::Empty),
            Claim::Replan => return Ok(TaggingPreparation::Replan),
            Claim::Leased(record, hold) => (*record, hold),
        };
        let queue = AttemptQueue::new(&self.vault);
        let prior_retries = queue.retry_chain_depth(record.id)?;
        let mut trace = unreadable_trace(&record, prior_retries);
        let Some(payload) = MarkerPayload::decode(&record.payload) else {
            self.vault.try_with_write_txn_grouped(|txn| {
                self.fail_unreadable_in_txn(txn, &record, &trace)
            })?;
            return Ok(settled(hold, trace));
        };
        let turn = payload.turn;
        trace.turn = Some(turn);
        trace.checkpoint.clone_from(&payload.checkpoint);
        trace.stack.clone_from(&payload.stack);
        if !payload.owed_to(&self.config) {
            // Owed to another checkpoint or stack: the active tagger owes the
            // turn now.
            trace.outcome = TaggingOutcome::Rekeyed;
            self.vault.try_with_write_txn_grouped(|txn| -> Result<()> {
                let now = self.stamp_in_txn(txn)?;
                let work = self.persisted_work_in_txn(txn, record.id, &payload)?;
                enqueue_marker_in_txn(&self.vault, txn, turn, &self.config, now, work)?;
                self.settle_in_txn(txn, &record, &trace)
            })?;
            return Ok(settled(hold, trace));
        }
        // A MESSAGE the turn's saved tags were read from is away from this
        // replica (OF-534): the turn reads only partly here, so neither a
        // fragment's answer nor an empty turn's skip may replace its set.
        let read = {
            let txn = self.vault.store.env.read_txn()?;
            if tagged_messages_absent_in_txn(&self.vault.store, &txn, &turn)? {
                None
            } else {
                Some(turn_input_in_txn(&self.vault, &txn, &turn)?)
            }
        };
        #[cfg(test)]
        super::run_after_turn_read_hook();
        let (input, hash, text_hash) = match read {
            None => {
                let trace = self.defer(&record, prior_retries, trace)?;
                return Ok(settled(hold, trace));
            }
            Some(TurnInput::Gone) => {
                let trace = self.skip(&record, &turn, SkipReason::TurnGone, trace)?;
                return Ok(settled(hold, trace));
            }
            Some(TurnInput::Empty) => {
                let trace = self.skip(&record, &turn, SkipReason::NoText, trace)?;
                return Ok(settled(hold, trace));
            }
            Some(TurnInput::Ready {
                input,
                hash,
                text_hash,
            }) => (input, hash, text_hash),
        };
        trace.input_hash = Some(hash.clone());
        trace.model = Some(self.encoder.model_id().as_str().to_owned());
        let work = payload.effective_work(&self.vault);
        Ok(TaggingPreparation::Ready(PreparedTagging {
            trace,
            call: Box::new(PreparedCall {
                record,
                payload,
                work,
                input,
                hash,
                text_hash,
                prior_retries,
            }),
            hold,
        }))
    }
}

/// A marker that settled while it was prepared: its hold lets it go.
fn settled(hold: ClaimHold, trace: TaggingTrace) -> TaggingPreparation {
    hold.settled();
    TaggingPreparation::Settled(trace)
}
