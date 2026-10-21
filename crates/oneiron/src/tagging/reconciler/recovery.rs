//! Recovery: the start scan for leases a stopped worker left, the rehome of
//! markers an earlier build left below the owner-retained range, and the
//! hand-back of every marker this reconciler holds unsettled.

use std::sync::PoisonError;
use std::sync::atomic::Ordering;

use super::coordinator::TaggingReconciler;
use super::settle::unreadable_trace;
use crate::attempt_queue::{
    AttemptId, AttemptInterventionKind, AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt,
    ClaimOutcome, EnqueueOutcome, InterveneAttempt, decode_record,
};
use crate::error::{ArtifactError, Error, Result};
use crate::tagging::history;
use crate::tagging::marker::{MarkerPayload, TAGGING_MARKER_KIND, enqueue_marker_in_txn};
use crate::tagging::trace::{HandBackReason, TaggingOutcome, TaggingTrace};

impl TaggingReconciler {
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
    /// job's row can stop the worker from starting. The same pass finds the
    /// markers an earlier build left waiting or paused below the
    /// owner-retained id range, where claims never look, and moves each onto
    /// a new marker in the range, as a marker of another checkpoint is moved;
    /// and the ready markers in the range whose ready entry a fault left
    /// stale, and puts the entry back, so a claim reaches each when its row
    /// says it is ready.
    pub fn release_stale_leases(&self) -> Result<usize> {
        self.release_stale_leases_until_paused(&|| false)
    }

    /// [`Self::release_stale_leases`], reading `paused` before the scan and
    /// before each write after it (FIX 6902). While it holds, the release
    /// starts nothing more and returns what it found: a lease it has not
    /// handed back stays this reconciler's, and the scan counts as not run,
    /// so the next pass runs it again.
    pub fn release_stale_leases_until_paused(&self, paused: &dyn Fn() -> bool) -> Result<usize> {
        if paused() {
            return Ok(0);
        }
        let queue = AttemptQueue::from_store(&self.vault.store);
        let (stale, stranded, unindexed) = {
            let txn = self.vault.store.env.read_txn()?;
            let mut stale = Vec::new();
            let mut stranded = Vec::new();
            let mut unindexed = Vec::new();
            for row in crate::ports::JobQueueRead::port_job_rows(&self.vault.store, &txn, None)? {
                let (id, raw) = match row {
                    Ok(row) => row,
                    Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(_))) => continue,
                    Err(error) => return Err(error),
                };
                let Ok(record) = decode_record(&raw, id) else {
                    continue;
                };
                if record.kind != TAGGING_MARKER_KIND {
                    continue;
                }
                if record.state == AttemptState::Leased
                    && record.lease_owner.as_deref() == Some(self.lease_owner.as_str())
                {
                    stale.push(record);
                } else if !crate::attempt_queue::owner_retained_id(&id) {
                    if matches!(
                        record.state,
                        AttemptState::Queued | AttemptState::Scheduled | AttemptState::Paused
                    ) {
                        stranded.push(id);
                    }
                } else if queue.owner_retained_ready_entry_missing(&txn, &record)? {
                    unindexed.push(id);
                }
            }
            (stale, stranded, unindexed)
        };
        let found = stale.len();
        {
            let mut unsettled = self
                .unsettled
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            for record in stale {
                if !unsettled.iter().any(|(held, _)| held.id == record.id) {
                    unsettled.push((record, HandBackReason::WorkerRestarted));
                }
            }
        }
        if self.return_unsettled(paused)? {
            return Ok(found);
        }
        for id in stranded {
            if paused() {
                return Ok(found);
            }
            self.vault
                .try_with_write_txn_grouped(|txn| self.rehome_in_txn(txn, id))?;
        }
        for chunk in unindexed.chunks(history::PRUNE_BUDGET) {
            if paused() {
                return Ok(found);
            }
            self.vault.try_with_write_txn_grouped(|txn| {
                for id in chunk {
                    queue.restore_owner_retained_ready_entry_in_txn(txn, *id)?;
                }
                Ok::<(), Error>(())
            })?;
        }
        self.stale_scanned.store(true, Ordering::Release);
        Ok(found)
    }

    /// Moves a marker an earlier build left waiting below the owner-retained
    /// range onto a new marker in it: leased, settled as rekeyed with its
    /// trace and pruned, then owed again under a derived id. One that has
    /// left the queue since the scan is let go.
    fn rehome_in_txn(&self, txn: &mut heed::RwTxn<'_>, id: AttemptId) -> Result<()> {
        let queue = AttemptQueue::from_store(&self.vault.store);
        let Some(found) = queue.get_in_write_txn(txn, id)? else {
            return Ok(());
        };
        match found.state {
            AttemptState::Queued | AttemptState::Scheduled => {}
            AttemptState::Paused => return self.rehome_paused_in_txn(txn, &found),
            _ => return Ok(()),
        }
        let now = self.stamp_in_txn(txn)?;
        let ClaimOutcome::Claimed(record) = queue.claim_id_storage_in_txn(
            txn,
            id,
            ClaimAttempt {
                lease_owner: self.lease_owner.clone(),
                now,
            },
            u64::MAX,
        )?
        else {
            return Ok(());
        };
        let prior_retries = queue.retry_chain_depth_in_txn(txn, record.id)?;
        let unread = unreadable_trace(&record, prior_retries);
        let Some(payload) = MarkerPayload::decode(&record.payload) else {
            return self.fail_unreadable_in_txn(txn, &record, &unread);
        };
        // The class the row carries under this writer (FIX 6755).
        let work = payload.effective_work(&self.vault);
        let trace = TaggingTrace {
            turn: Some(payload.turn),
            checkpoint: payload.checkpoint,
            stack: payload.stack,
            outcome: TaggingOutcome::Rekeyed,
            ..unread
        };
        // Settled first, so its dedupe entry is free for the new marker.
        self.settle_in_txn(txn, &record, &trace)?;
        enqueue_marker_in_txn(&self.vault, txn, payload.turn, &self.config, now, work)?;
        Ok(())
    }

    /// [`Self::rehome_in_txn`] for a paused marker, which stays paused: it is
    /// cancelled, traced as rekeyed and pruned, and the new marker is paused
    /// in the same transaction under the actor and note of the pause it
    /// carried, so nothing becomes runnable that an operator held.
    fn rehome_paused_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        paused: &AttemptRecord,
    ) -> Result<()> {
        let queue = AttemptQueue::from_store(&self.vault.store);
        let now = self.stamp_in_txn(txn)?;
        let (actor, note) = paused
            .events
            .iter()
            .rev()
            .find(|event| event.kind == AttemptInterventionKind::Pause)
            .map_or_else(
                || (self.lease_owner.clone(), None),
                |event| (event.actor.clone(), event.note.clone()),
            );
        queue.intervene_in_txn(
            txn,
            InterveneAttempt {
                id: paused.id,
                kind: AttemptInterventionKind::Cancel,
                actor: self.lease_owner.clone(),
                note: None,
                now,
            },
        )?;
        let prior_retries = queue.retry_chain_depth_in_txn(txn, paused.id)?;
        let unread = unreadable_trace(paused, prior_retries);
        let payload = MarkerPayload::decode(&paused.payload);
        let trace = match &payload {
            Some(payload) => TaggingTrace {
                turn: Some(payload.turn),
                checkpoint: payload.checkpoint.clone(),
                stack: payload.stack.clone(),
                outcome: TaggingOutcome::Rekeyed,
                ..unread
            },
            None => unread,
        };
        self.record_in_txn(txn, &trace)?;
        queue.prune_settled_in_txn(txn, paused.id)?;
        let Some(payload) = payload else {
            return Ok(());
        };
        // The class the row carried under this writer (FIX 6755).
        let work = payload.effective_work(&self.vault);
        if let EnqueueOutcome::Enqueued(owed) =
            enqueue_marker_in_txn(&self.vault, txn, payload.turn, &self.config, now, work)?
        {
            queue.intervene_in_txn(
                txn,
                InterveneAttempt {
                    id: owed.id,
                    kind: AttemptInterventionKind::Pause,
                    actor,
                    note,
                    now,
                },
            )?;
        }
        Ok(())
    }

    /// Hands back each marker this reconciler holds, as an immediate retry,
    /// recording the trace of the try it finalizes. One that is no longer
    /// leased under this owner at the held lease generation was settled after
    /// all, and is let go. A failed hand-back keeps the rest and fails the
    /// pass, so the next one tries again. `Ok(true)` when `paused` cut it
    /// short: what it has not handed back stays held for the next pass.
    pub(super) fn return_unsettled(&self, paused: &dyn Fn() -> bool) -> Result<bool> {
        let mut unsettled = self
            .unsettled
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        while let Some((record, reason)) = unsettled.last() {
            if paused() {
                return Ok(true);
            }
            self.vault.try_with_write_txn_grouped(|txn| -> Result<()> {
                let current =
                    crate::ports::JobQueueRead::port_job_row(&self.vault.store, txn, &record.id)?
                        .and_then(|raw| decode_record(&raw, record.id).ok());
                let still_held = current.is_some_and(|current| {
                    current.state == AttemptState::Leased
                        && current.lease_owner == record.lease_owner
                        && current.attempt_count == record.attempt_count
                });
                if still_held {
                    self.hand_back_in_txn(txn, record, *reason)?;
                }
                Ok(())
            })?;
            unsettled.pop();
        }
        Ok(false)
    }

    /// Hands a held marker back as an immediate retry and records the trace
    /// of the try it finalizes. A payload no pass can read is settled as a
    /// pass settles it.
    fn hand_back_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        record: &AttemptRecord,
        reason: HandBackReason,
    ) -> Result<()> {
        let prior_retries =
            AttemptQueue::from_store(&self.vault.store).retry_chain_depth_in_txn(txn, record.id)?;
        let unread = unreadable_trace(record, prior_retries);
        let Some(payload) = MarkerPayload::decode(&record.payload) else {
            return self.fail_unreadable_in_txn(txn, record, &unread);
        };
        let stamp = self.stamp_in_txn(txn)?;
        self.retry_in_txn(txn, record, 0, reason.as_str())?;
        let trace = TaggingTrace {
            turn: Some(payload.turn),
            checkpoint: payload.checkpoint,
            stack: payload.stack,
            outcome: TaggingOutcome::HandedBack {
                reason,
                retry_at: stamp,
            },
            ..unread
        };
        history::record_in_txn(&self.vault, txn, &trace, stamp)
    }
}
