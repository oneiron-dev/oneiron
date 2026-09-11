//! Retry/intervene/manifest append plus lease-cleanup mutation doors.

use crate::attempt_queue::cancel::{
    ATTEMPT_RUNTIME_ACTOR, AttemptCancelState, AttemptLandingReserve, ForceCancelAuthority,
    force_cancel_record, validate_force_authority,
};
use crate::attempt_queue::encoding::{
    DedupeIndexKeys, decode_record, encode_record, lease_expired, ready_at, ready_key,
    waiting_on_backoff,
};
use crate::attempt_queue::telemetry::{
    emit_attempt_queue_cleanup_span, invalid_transition, record_attempt_queue_cleanup_metrics,
};
use crate::attempt_queue::types::{
    AttemptId, AttemptInterventionEffect, AttemptInterventionKind, AttemptQueueCleanupReport,
    AttemptQueueRetryReason, AttemptRecord, AttemptState, CleanupAttemptLeases, InterveneAttempt,
    InterveneOutcome, MAX_ATTEMPT_MANIFEST_ENTRIES, ManifestEntry, RetryAttempt, RetryOutcome,
};
use crate::attempt_queue::validate::{
    ERR_MANIFEST_FULL, append_attempt_event, validate_cleanup_leases_input,
    validate_intervention_actor, validate_lease_owner, validate_manifest_entry,
    validate_optional_failure_reason, validate_optional_intervention_note,
    validate_transition_lease,
};
use crate::error::{Error, Result};

use super::AttemptQueue;
use crate::error::ArtifactError;
const RETRY_REASON_LEASE_TIMEOUT: &str = "lease_timeout";
/// Stable reason stamped on a retried source row when the caller supplied none.
pub(in crate::attempt_queue) const RETRY_REASON_UNSPECIFIED: &str = "retry";
impl AttemptQueue<'_> {
    /// Retries a leased attempt by finalizing it and minting a fresh try.
    ///
    /// The leased source row becomes terminally [`AttemptState::Failed`] and is
    /// never claimable again; it stays point-readable for per-try receipts and
    /// forensics. A new row copies the immutable payload/provenance, links back
    /// through `retry_of`, and waits in [`AttemptState::Scheduled`] until
    /// `scheduled_at`. Both rows plus every index move commit as one LMDB
    /// transaction, so a fault before commit leaves neither a half-finalized
    /// source nor an orphan retry.
    pub fn retry(&self, input: RetryAttempt) -> Result<RetryOutcome> {
        let mut wtxn = self.store.env.write_txn()?;
        let outcome = self.retry_in_txn(&mut wtxn, input)?;
        wtxn.commit()?;
        Ok(outcome)
    }

    /// Retries inside a caller-owned transaction, including both rows and all
    /// index moves. The caller must abort the transaction on error.
    pub(crate) fn retry_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: RetryAttempt,
    ) -> Result<RetryOutcome> {
        let Some(raw_record) = self.store.attempt_records.get(wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("retry", "missing"));
        };
        let mut source = decode_record(&raw_record, input.id)?;
        if source.state != AttemptState::Leased {
            return Err(invalid_transition("retry", source.state.as_str()));
        }
        validate_lease_owner(&input.lease_owner)?;
        validate_transition_lease(&source, &input.lease_owner, input.attempt_count, "retry")?;
        validate_optional_failure_reason(input.last_error.as_deref())?;

        let next = AttemptRecord {
            id: AttemptId::now(),
            kind: source.kind.clone(),
            payload: source.payload.clone(),
            state: AttemptState::Scheduled,
            lease_owner: None,
            attempt_count: 0,
            claimed_at: None,
            scheduled_at: Some(input.backoff_until),
            retry_of: Some(source.id),
            backoff_until: None,
            last_error: None,
            task_ref: source.task_ref.clone(),
            run_id: source.run_id.clone(),
            dedupe_key: source.dedupe_key.clone(),
            // The scope travels WITH the key it scopes, so the index move below
            // derives the child's entry from the row itself — never from a
            // caller's state or a decoded TASK payload.
            dedupe_actor_ref: source.dedupe_actor_ref.clone(),
            created_at: input.now,
            updated_at: input.now,
            events: Vec::new(),
            // A retry is a NEW attempt: its attribution manifest starts empty,
            // the finalized source keeps the prior try's.
            manifest: Vec::new(),
            // Likewise its cancel lifecycle: the new try inherits neither the
            // source's refusal history nor its spent landing reserve. It DOES
            // inherit the dial's VALUES, so a retried try lands on the same
            // terms — but not its one-shot mark, because the new row's own
            // admission dials it against the new row's own lease generation.
            cancel_state: AttemptCancelState {
                reserve: AttemptLandingReserve {
                    spent_units: 0,
                    dial_generation: None,
                    ..source.cancel_state.reserve
                },
                ..AttemptCancelState::default()
            },
            // A retry is a NEW attempt: it has produced nothing yet, and the
            // finalized source keeps sole ownership of the artifact its own
            // try left behind.
            result_ref: None,
        };

        // A `Failed` row must carry a reason, so an omitted retry cause
        // normalizes to a stable non-empty token rather than failing the call.
        source.state = AttemptState::Failed;
        source.lease_owner = None;
        source.scheduled_at = None;
        source.backoff_until = None;
        source.last_error = Some(
            input
                .last_error
                .unwrap_or_else(|| RETRY_REASON_UNSPECIFIED.to_owned()),
        );
        source.updated_at = input.now;

        let encoded_source = encode_record(&source)?;
        self.store
            .attempt_records
            .put(wtxn, source.id.as_bytes(), &encoded_source)?;
        let encoded_next = encode_record(&next)?;
        self.store
            .attempt_records
            .put(wtxn, next.id.as_bytes(), &encoded_next)?;

        // The source was leased, so it holds no ready entry to retire; only the
        // new row enters the ready index, at its own scheduled instant.
        let ready_key = ready_key(ready_at(&next), next.id);
        self.store
            .attempt_ready
            .put(wtxn, &ready_key, next.id.as_bytes())?;
        self.store.put_attempt_run_index_in_txn(
            wtxn,
            next.run_id.as_deref(),
            next.id.as_bytes(),
        )?;

        // Only the newest pending member of a dedupe chain owns the advisory
        // index, so the entry moves off the now-terminal source. The chain
        // stays in ONE key family: an actor-scoped chain keeps its v2 entry, a
        // pre-1876 actorless chain keeps its v1 entry until it drains.
        self.delete_dedupe_entry_for_record(wtxn, &source)?;
        if let Some(dedupe_key) = next.dedupe_key.as_deref() {
            let keys =
                DedupeIndexKeys::new(&next.kind, next.dedupe_actor_ref.as_deref(), dedupe_key);
            self.store
                .attempt_dedupe
                .put(wtxn, &keys.primary[..], next.id.as_bytes())?;
        }

        Ok(RetryOutcome::Retried(next))
    }

    /// Applies a durable operator intervention to an attempt row. Pause removes a
    /// queued row from the ready index, resume restores it, cancel makes a
    /// queued or paused row terminal, and interrupt records an event without
    /// changing claimability.
    pub fn intervene(&self, input: InterveneAttempt) -> Result<InterveneOutcome> {
        let mut wtxn = self.store.env.write_txn()?;
        let outcome = self.intervene_in_txn(&mut wtxn, input)?;
        wtxn.commit()?;
        Ok(outcome)
    }

    pub(crate) fn intervene_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: InterveneAttempt,
    ) -> Result<InterveneOutcome> {
        validate_intervention_actor(&input.actor)?;
        validate_optional_intervention_note(input.note.as_deref())?;

        let Some(raw_record) = self.store.attempt_records.get(wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition(input.kind.as_str(), "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;

        let effect = match input.kind {
            AttemptInterventionKind::Interrupt => match record.state {
                AttemptState::Queued
                | AttemptState::Leased
                | AttemptState::Paused
                | AttemptState::Scheduled
                // A landing row is still live work, so it can still be handed
                // an operator note; interrupt changes no claimability.
                | AttemptState::Landing => {
                    append_attempt_event(
                        &mut record,
                        input.kind,
                        input.actor,
                        input.note,
                        input.now,
                    )?;
                    // A landing has one bounded lease window. An operator
                    // note must not become a hidden heartbeat that extends
                    // that window; only accepting the landing starts it.
                    if record.state != AttemptState::Landing {
                        record.updated_at = input.now;
                    }
                    AttemptInterventionEffect::Interrupted
                }
                state => return Err(invalid_transition(input.kind.as_str(), state.as_str())),
            },
            AttemptInterventionKind::Pause => match record.state {
                AttemptState::Paused => AttemptInterventionEffect::AlreadyPaused,
                // A paused row keeps its readiness instant so resume can restore
                // the exact schedule instead of pulling the try forward.
                AttemptState::Queued | AttemptState::Scheduled => {
                    self.delete_ready_entry_for_record(wtxn, &record)?;
                    append_attempt_event(
                        &mut record,
                        input.kind,
                        input.actor,
                        input.note,
                        input.now,
                    )?;
                    record.state = AttemptState::Paused;
                    record.lease_owner = None;
                    record.updated_at = input.now;
                    AttemptInterventionEffect::Paused
                }
                state => return Err(invalid_transition(input.kind.as_str(), state.as_str())),
            },
            AttemptInterventionKind::Resume => match record.state {
                AttemptState::Paused => {
                    self.delete_ready_entry_for_record(wtxn, &record)?;
                    append_attempt_event(
                        &mut record,
                        input.kind,
                        input.actor,
                        input.note,
                        input.now,
                    )?;
                    // Restoring a still-deferred row as Queued would render it
                    // as runnable-now on every read surface; keep it honest.
                    record.state = if record.scheduled_at.is_some() {
                        AttemptState::Scheduled
                    } else {
                        AttemptState::Queued
                    };
                    record.lease_owner = None;
                    record.updated_at = input.now;
                    let ready_key = ready_key(ready_at(&record), record.id);
                    self.store
                        .attempt_ready
                        .put(wtxn, &ready_key, record.id.as_bytes())?;
                    AttemptInterventionEffect::Resumed
                }
                AttemptState::Queued | AttemptState::Leased | AttemptState::Scheduled => {
                    AttemptInterventionEffect::AlreadyResumed
                }
                state => return Err(invalid_transition(input.kind.as_str(), state.as_str())),
            },
            AttemptInterventionKind::Cancel => match record.state {
                AttemptState::Cancelled => AttemptInterventionEffect::AlreadyCancelled,
                AttemptState::Queued | AttemptState::Paused | AttemptState::Scheduled => {
                    self.delete_ready_entry_for_record(wtxn, &record)?;
                    append_attempt_event(
                        &mut record,
                        input.kind,
                        input.actor,
                        input.note,
                        input.now,
                    )?;
                    record.state = AttemptState::Cancelled;
                    record.lease_owner = None;
                    record.scheduled_at = None;
                    record.backoff_until = None;
                    record.last_error = None;
                    record.updated_at = input.now;
                    self.delete_dedupe_entry_for_record(wtxn, &record)?;
                    AttemptInterventionEffect::Cancelled
                }
                state => return Err(invalid_transition(input.kind.as_str(), state.as_str())),
            },
        };

        let encoded = encode_record(&record)?;
        self.store
            .attempt_records
            .put(wtxn, record.id.as_bytes(), &encoded)?;

        Ok(InterveneOutcome { effect, record })
    }

    /// Appends one row to a live attempt's PACK MANIFEST (ARCH-0053 §3).
    ///
    /// The pack is alive for the whole attempt, so this door accepts every
    /// pending state (queued, leased, paused) and refuses the terminal ones:
    /// a completed/failed/cancelled attempt's manifest is the evidence the
    /// terminal receipt already projected, and appending to it after the fact
    /// would rewrite history.
    ///
    /// Never drains at the cap (see [`MAX_ATTEMPT_MANIFEST_ENTRIES`]): a full
    /// manifest is a typed refusal, so append-only cannot be violated
    /// silently.
    ///
    /// `updated_at` is deliberately NOT bumped: it is the lease-expiry clock
    /// ([`Self::cleanup_leases`]), and turning a pack load into a lease
    /// heartbeat would silently change reclaim timing for every attempt that
    /// pulls a skill. Manifest rows carry their own `at`.
    pub fn append_manifest_entry(
        &self,
        id: AttemptId,
        entry: ManifestEntry,
    ) -> Result<AttemptRecord> {
        validate_manifest_entry(&entry)?;

        let mut wtxn = self.store.env.write_txn()?;
        let Some(raw_record) = self.store.attempt_records.get(&wtxn, id.as_bytes())? else {
            return Err(invalid_transition("append_manifest_entry", "missing"));
        };
        let mut record = decode_record(&raw_record, id)?;
        if !record.state.is_pending() {
            return Err(invalid_transition(
                "append_manifest_entry",
                record.state.as_str(),
            ));
        }
        if record.manifest.len() >= MAX_ATTEMPT_MANIFEST_ENTRIES {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_MANIFEST_FULL,
            )));
        }
        record.manifest.push(entry);
        let encoded = encode_record(&record)?;
        self.store
            .attempt_records
            .put(&mut wtxn, record.id.as_bytes(), &encoded)?;
        wtxn.commit()?;

        Ok(record)
    }

    /// Returns expired leases to the ready index under LMDB's single-writer
    /// invariant. Cleanup never assigns a replacement owner; reclaim still
    /// happens through [`Self::claim`]'s atomic admission step.
    pub fn cleanup_leases(&self, input: CleanupAttemptLeases) -> Result<AttemptQueueCleanupReport> {
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
                        report.increment_retry_reason(AttemptQueueRetryReason::RetryBackoff);
                    }
                }
                AttemptState::Leased | AttemptState::Landing
                    if lease_expired(&record, input.now, input.lease_timeout_secs) =>
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
                        // not a logical retry, and mints no new row.
                        record.state = AttemptState::Queued;
                        record.lease_owner = None;
                        record.scheduled_at = None;
                        record.backoff_until = None;
                        record.last_error = Some(RETRY_REASON_LEASE_TIMEOUT.to_owned());
                        record.updated_at = input.now;
                        let encoded = encode_record(&record)?;
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
                            &mut record,
                            authority.grounds(),
                            authority.actor().to_owned(),
                            Some(RETRY_REASON_LEASE_TIMEOUT.to_owned()),
                            input.now,
                        )?;
                        let encoded = encode_record(&record)?;
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
                        mark_rechecked_candidate_not_running(&mut report);
                        report.done += 1;
                        report.landing_force_cancelled += 1;
                    }
                    AttemptState::Leased | AttemptState::Landing => {}
                    AttemptState::Queued | AttemptState::Paused | AttemptState::Scheduled => {
                        mark_rechecked_candidate_not_running(&mut report);
                        report.pending += 1;
                        if waiting_on_backoff(&record) {
                            report.increment_retry_reason(AttemptQueueRetryReason::RetryBackoff);
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
        }

        record_attempt_queue_cleanup_metrics(&report);
        emit_attempt_queue_cleanup_span(&input, &report);
        Ok(report)
    }
}
fn mark_rechecked_candidate_not_running(report: &mut AttemptQueueCleanupReport) {
    report.running = report.running.saturating_sub(1);
}
