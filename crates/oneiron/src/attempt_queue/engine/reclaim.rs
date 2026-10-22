//! Lease cleanup: an expired lease goes back to the ready index under the
//! same try, and an expired landing settles as the hard rung's force
//! cancellation. Split from the mutation doors by move.

use crate::attempt_queue::cancel::{
    ATTEMPT_RUNTIME_ACTOR, ForceCancelAuthority, force_cancel_record, validate_force_authority,
};
use crate::attempt_queue::encoding::{
    decode_record, lease_expired, ready_at, ready_key, waiting_on_backoff,
};
use crate::attempt_queue::telemetry::emit_attempt_queue_cleanup_span;
use crate::attempt_queue::types::{
    AttemptId, AttemptQueueCleanupReport, AttemptQueueRetryReason, AttemptRecord, AttemptState,
    CleanupAttemptLeases,
};
use crate::attempt_queue::validate::validate_cleanup_leases_input;
use crate::error::Result;

use super::AttemptQueue;

const RETRY_REASON_LEASE_TIMEOUT: &str = "lease_timeout";

/// The cleanup reason for a pending row waiting on a readiness instant: a
/// first try (no `retry_of`) scheduled for later is due later (FIX 6106); a
/// real retry, or a row already due, keeps the retry-backoff class.
fn waiting_reason(record: &AttemptRecord, now: u64) -> AttemptQueueRetryReason {
    if record.retry_of.is_none() && ready_at(record) > now {
        AttemptQueueRetryReason::DueLater
    } else {
        AttemptQueueRetryReason::RetryBackoff
    }
}

impl AttemptQueue<'_> {
    /// Returns expired leases to the ready index under LMDB's single-writer
    /// invariant. Cleanup never assigns a replacement owner; reclaim still
    /// happens through [`Self::claim`]'s atomic admission step.
    pub fn cleanup_leases(&self, input: CleanupAttemptLeases) -> Result<AttemptQueueCleanupReport> {
        self.cleanup_leases_except(input, &std::collections::HashSet::new())
    }

    /// [`Self::cleanup_leases`], leaving the leases in `held` as they are: a
    /// host's restart keeps an attempt parked on a signal (a budget or consent
    /// trap) leased until that signal resumes it.
    pub fn cleanup_leases_except(
        &self,
        input: CleanupAttemptLeases,
        held: &std::collections::HashSet<AttemptId>,
    ) -> Result<AttemptQueueCleanupReport> {
        validate_cleanup_leases_input(&input)?;

        let rtxn = self.store.env.read_txn()?;
        let mut report = AttemptQueueCleanupReport::default();
        let mut expired_candidates = Vec::new();

        for row in self.store.attempt_records.iter(&rtxn)? {
            let (key, raw_record) = row?;
            let id = AttemptId::from_bytes(&key)?;
            let record = decode_record(&raw_record, id)?;
            match record.state {
                AttemptState::Queued | AttemptState::Paused | AttemptState::Scheduled => {
                    report.pending += 1;
                    if waiting_on_backoff(&record) {
                        report.increment_retry_reason(waiting_reason(&record, input.now));
                    }
                }
                AttemptState::Leased | AttemptState::Landing
                    if !held.contains(&id)
                        && lease_expired(&record, input.now, input.lease_timeout_secs) =>
                {
                    report.running += 1;
                    expired_candidates.push(id);
                }
                AttemptState::Leased | AttemptState::Landing => {
                    report.running += 1;
                }
                AttemptState::Completed => {
                    report.done += 1;
                }
                AttemptState::Failed => {
                    report.failed += 1;
                }
                AttemptState::Cancelled => {
                    report.done += 1;
                }
                // Settled work, never a reclaim candidate: an abandoned row
                // holds no lease to expire and cannot re-enter the ready
                // index. It counts as done — nothing faulted — with its own
                // sub-count so a stopped executor stays visible.
                AttemptState::Abandoned => {
                    report.done += 1;
                    report.abandoned += 1;
                }
            }
        }
        drop(rtxn);

        if !expired_candidates.is_empty() {
            let mut wtxn = self.store.env.write_txn()?;
            let mut lost_leases = Vec::new();
            for id in expired_candidates {
                let Some(raw_record) = self.store.attempt_records.get(&wtxn, id.as_bytes())? else {
                    mark_rechecked_candidate_not_running(&mut report);
                    continue;
                };
                let mut record = decode_record(&raw_record, id)?;
                match record.state {
                    AttemptState::Leased
                        if lease_expired(&record, input.now, input.lease_timeout_secs) =>
                    {
                        // A reclaimed lease resumes the SAME try — the row was
                        // never finalized, so this is a lease-generation reset,
                        // not a logical retry, and mints no new row. FIX 9932:
                        // every executor family's next lease resumes state
                        // keyed by this id (parks, reservations, paid steps,
                        // checkpoints, packs, fences) that no helper carries
                        // to a new id in this writer, so an abandoned try and
                        // a fresh recovery row would lose it. The expired
                        // generation's exhaust, its attached result and its
                        // recorded checkpoint, stays on the row it resumes.
                        record.state = AttemptState::Queued;
                        record.lease_owner = None;
                        record.scheduled_at = None;
                        record.backoff_until = None;
                        record.last_error = Some(RETRY_REASON_LEASE_TIMEOUT.to_owned());
                        record.updated_at = input.now;
                        let encoded = self.encode_in_txn(&mut wtxn, &mut record)?;
                        self.store.attempt_records.put(
                            &mut wtxn,
                            record.id.as_bytes(),
                            &encoded,
                        )?;
                        let ready_key = ready_key(ready_at(&record), record.id);
                        self.store.attempt_ready.put(
                            &mut wtxn,
                            &ready_key,
                            record.id.as_bytes(),
                        )?;
                        mark_rechecked_candidate_not_running(&mut report);
                        report.pending += 1;
                        report.stale_requeued += 1;
                        report.increment_retry_reason(AttemptQueueRetryReason::LeaseTimeout);
                        lost_leases.push((record.id, record.attempt_count));
                    }
                    // A landing whose lease actually expired cannot be requeued
                    // as ordinary work — it is mid-flight, not pre-flight — and
                    // it must not hold a dead lease forever. Expiry is the hard
                    // rung's runtime ground, so the runtime authors a terminal
                    // force cancellation and the landing's own accounting rides
                    // the receipt.
                    AttemptState::Landing
                        if lease_expired(&record, input.now, input.lease_timeout_secs) =>
                    {
                        // The runtime's own ground, minted through the same
                        // authority token the owner path uses — cleanup never
                        // hand-writes an actor onto a terminal receipt.
                        let authority = ForceCancelAuthority::lease_expiry();
                        validate_force_authority(&authority)?;
                        force_cancel_record(
                            &self.store.limit_watch,
                            &mut record,
                            authority.grounds(),
                            authority.actor().to_owned(),
                            Some(RETRY_REASON_LEASE_TIMEOUT.to_owned()),
                            input.now,
                        )?;
                        let encoded = self.encode_in_txn(&mut wtxn, &mut record)?;
                        self.store.attempt_records.put(
                            &mut wtxn,
                            record.id.as_bytes(),
                            &encoded,
                        )?;
                        crate::receipt::stamp_attempt_pack_receipt_in_txn(
                            self.store,
                            &mut wtxn,
                            &record,
                            ATTEMPT_RUNTIME_ACTOR,
                        )?;
                        self.delete_dedupe_entry_for_record(&mut wtxn, &record)?;
                        self.notify_settled_in_txn(&mut wtxn, &record)?;
                        mark_rechecked_candidate_not_running(&mut report);
                        report.done += 1;
                        report.landing_force_cancelled += 1;
                        lost_leases.push((record.id, record.attempt_count));
                    }
                    AttemptState::Leased | AttemptState::Landing => {}
                    AttemptState::Queued | AttemptState::Paused | AttemptState::Scheduled => {
                        mark_rechecked_candidate_not_running(&mut report);
                        report.pending += 1;
                        if waiting_on_backoff(&record) {
                            report.increment_retry_reason(waiting_reason(&record, input.now));
                        }
                    }
                    AttemptState::Completed => {
                        mark_rechecked_candidate_not_running(&mut report);
                        report.done += 1;
                    }
                    AttemptState::Failed => {
                        mark_rechecked_candidate_not_running(&mut report);
                        report.failed += 1;
                    }
                    AttemptState::Cancelled => {
                        mark_rechecked_candidate_not_running(&mut report);
                        report.done += 1;
                    }
                    AttemptState::Abandoned => {
                        mark_rechecked_candidate_not_running(&mut report);
                        report.done += 1;
                        report.abandoned += 1;
                    }
                }
            }
            wtxn.commit()?;
            self.store.notify_attempt_observers();
            // Committed: the step each reclaimed lease or expired landing was
            // running stops (FIX 600).
            for (id, generation) in lost_leases {
                crate::engine_executor::stop_attempt_step(self.vault, id, generation);
            }
        }

        self.store.diagnostics.attempt_queue.record(&report);
        emit_attempt_queue_cleanup_span(&input, &report);
        Ok(report)
    }

    /// [`Self::cleanup_leases`] for one kind's rows alone: an expired lease
    /// of `kind` goes back to the ready index through the same transition,
    /// while every unsettled row of any other kind is held as it is, however
    /// old its lease, so a worker reclaiming its own expired claims never
    /// takes another worker's. `None` when no lease of `kind` had expired:
    /// nothing was written.
    pub fn cleanup_kind_leases(
        &self,
        kind: &str,
        input: CleanupAttemptLeases,
    ) -> Result<Option<AttemptQueueCleanupReport>> {
        validate_cleanup_leases_input(&input)?;
        let mut others = std::collections::HashSet::new();
        let mut expired = false;
        {
            let rtxn = self.store.env.read_txn()?;
            for row in self.store.attempt_records.iter(&rtxn)? {
                let (key, raw_record) = row?;
                let id = AttemptId::from_bytes(&key)?;
                let record = decode_record(&raw_record, id)?;
                if record.state.is_terminal() {
                    continue;
                }
                if record.kind != kind {
                    // Every unsettled row of another kind, not only a leased
                    // one: a row claimed after this read is held all the same.
                    others.insert(id);
                } else if record.state.is_running()
                    && lease_expired(&record, input.now, input.lease_timeout_secs)
                {
                    expired = true;
                }
            }
        }
        if !expired {
            return Ok(None);
        }
        self.cleanup_leases_except(input, &others).map(Some)
    }
}
fn mark_rechecked_candidate_not_running(report: &mut AttemptQueueCleanupReport) {
    report.running = report.running.saturating_sub(1);
}
