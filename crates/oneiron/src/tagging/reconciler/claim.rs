//! The claim: a ready live marker before any bulk one, read outside the
//! writer and leased under it.

use super::coordinator::TaggingReconciler;
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use crate::error::Result;
use crate::memory::extraction::ExtractionWork;
use crate::tagging::marker::{MarkerPayload, TAGGING_MARKER_KIND};

impl TaggingReconciler {
    /// Leases the next ready marker, reading only the owner-retained entries
    /// of the readiness index. The entries to act on are found outside the
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
    /// live marker ready either; otherwise the claim is planned again, so a
    /// live marker committed meanwhile goes first. A payload this build
    /// cannot read is claimed as live, to be failed.
    pub(super) fn claim(&self) -> Result<Option<AttemptRecord>> {
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
                if ready {
                    (plan, true, None)
                } else {
                    let plan = queue.owner_retained_matching_claim_plan_in_txn(
                        &txn,
                        TAGGING_MARKER_KIND,
                        &attempt(now),
                        now,
                        |record| Ok(!self.claims_live(record)),
                    )?;
                    (plan, false, Some(txn.id()))
                }
            };
            if plan.is_empty() {
                return Ok(None);
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
                return Ok(None);
            };
            txn.commit()?;
            self.vault.store.notify_attempt_observers();
            return Ok(Some(record));
        }
    }

    /// Whether `record` is claimed in the live class: its marker's effective
    /// class is live, or its payload is one this build cannot read, which a
    /// live claim fails rather than leaving it behind every bulk marker.
    fn claims_live(&self, record: &AttemptRecord) -> bool {
        MarkerPayload::decode(&record.payload)
            .is_none_or(|payload| payload.effective_work(&self.vault) == ExtractionWork::Live)
    }

    /// The class the marker of row `id`, read as `payload`, is owed at as
    /// the row stands in `txn`: a live write may have promoted it since it
    /// was read. A row gone or unreadable since keeps the class `payload`
    /// carries.
    pub(super) fn persisted_work_in_txn(
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
}
