//! The [`AttemptQueue`] handle and its lease state machine.
//!
//! Deliberately kept whole: enqueue, claim, complete, fail, retry, intervene,
//! manifest append, cleanup, and the read paths are one transactional
//! discipline over the same LMDB row set. Supporting concerns live beside it —
//! types in [`super::types`], validators in [`super::validate`], key/row
//! encoding in [`super::encoding`], counters in [`super::telemetry`], and the
//! ONE-1896 graceful-cancel/landing doors in [`super::cancel`].

use std::collections::HashSet;

use crate::Vault;
use crate::dreamer_runner::{
    DREAMER_RUNNER_ATTEMPT_KIND, DreamerAttemptPayload, decode_dreamer_attempt_payload,
};
use crate::error::{Error, Result};
use crate::store::Store;

use super::cancel::{
    ATTEMPT_RUNTIME_ACTOR, AttemptCancelState, AttemptLandingReserve, ForceCancelAuthority,
    force_cancel_record, validate_force_authority,
};
use super::encoding::{
    DedupeIndexKeys, READY_KEY_LEN, decode_ready_key, decode_record, dedupe_index_key,
    encode_record, lease_expired, legacy_dedupe_index_key, ready_at, ready_key,
    validate_dedupe_record, waiting_on_backoff,
};
use super::telemetry::{
    emit_attempt_queue_cleanup_span, invalid_transition, record_attempt_queue_cleanup_metrics,
};
use super::types::{
    AttemptId, AttemptInterventionEffect, AttemptInterventionKind, AttemptQueueCleanupReport,
    AttemptQueueRetryReason, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome,
    CleanupAttemptLeases, CompleteAttempt, CompleteOutcome, EnqueueAttempt, EnqueueOutcome,
    FailAttempt, FailOutcome, InterveneAttempt, InterveneOutcome, MAX_ATTEMPT_MANIFEST_ENTRIES,
    ManifestEntry, RetryAttempt, RetryOutcome, attempt_record_order,
};
use super::validate::{
    ERR_MANIFEST_FULL, append_attempt_event, lease_claimed_record, validate_cleanup_leases_input,
    validate_failure_reason, validate_intervention_actor, validate_kind, validate_lease_owner,
    validate_manifest_entry, validate_optional_dedupe, validate_optional_failure_reason,
    validate_optional_intervention_note, validate_optional_run_id, validate_transition_lease,
};

const RETRY_REASON_LEASE_TIMEOUT: &str = "lease_timeout";
/// Stable reason stamped on a retried source row when the caller supplied none.
pub(super) const RETRY_REASON_UNSPECIFIED: &str = "retry";
const CLAIM_KIND_WRITE_RETRY_LIMIT: usize = 3;
const DREAMER_RUN_ROOT_CLIMB_LIMIT: usize = 64;

#[derive(Debug, Default)]
struct ClaimKindReadScan {
    stale_ready_keys: Vec<Vec<u8>>,
    ready_replacements: Vec<([u8; READY_KEY_LEN], AttemptId)>,
    stale_missing_record_ids: HashSet<AttemptId>,
    candidate: Option<ClaimKindCandidate>,
}

#[derive(Debug)]
struct ClaimKindCandidate {
    ready_key: Vec<u8>,
    id: AttemptId,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum ClaimKindWriteAttempt {
    Claimed(AttemptRecord),
    Empty,
    Retry,
}

/// Queue handle over a vault store.
pub struct AttemptQueue<'a> {
    /// Visible to the whole `attempt_queue` module tree: the ONE-1896 cancel
    /// doors in [`super::cancel`] are inherent methods on this same handle and
    /// run against this same store under the same transactional discipline.
    pub(super) store: &'a Store,
}

impl<'a> AttemptQueue<'a> {
    /// Opens a queue handle over an already-open vault.
    #[must_use]
    pub fn new(vault: &'a Vault) -> Self {
        Self {
            store: &vault.store,
        }
    }

    /// Enqueues an attempt, returning an existing row when the caller-supplied
    /// dedupe key already maps to an attempt.
    pub fn enqueue(&self, input: EnqueueAttempt) -> Result<EnqueueOutcome> {
        self.enqueue_with_task_ref(input, None)
    }

    /// Enqueues an attempt with an optional backlink to its owning task.
    pub fn enqueue_with_task_ref(
        &self,
        input: EnqueueAttempt,
        task_ref: Option<String>,
    ) -> Result<EnqueueOutcome> {
        validate_kind(&input.kind)?;
        validate_optional_dedupe(input.dedupe_key.as_deref())?;
        validate_optional_run_id(input.run_id.as_deref())?;

        let dedupe_blake3_key = input
            .dedupe_key
            .as_deref()
            .map(|dedupe_key| DedupeIndexKeys::new(&input.kind, dedupe_key));
        if let (Some(dedupe_key), Some(index_key)) =
            (input.dedupe_key.as_deref(), dedupe_blake3_key.as_ref())
        {
            let rtxn = self.store.env.read_txn()?;
            if let Some(record) = self.read_existing_dedupe_in_read_txn(
                &rtxn,
                &index_key.blake3[..],
                &input.kind,
                dedupe_key,
            )? {
                return Ok(EnqueueOutcome::Existing(record));
            }
        }

        let mut wtxn = self.store.env.write_txn()?;
        let outcome = self.enqueue_with_task_ref_in_txn(&mut wtxn, input, task_ref)?;
        wtxn.commit()?;

        Ok(outcome)
    }

    /// Enqueues an attempt into a caller-owned write transaction.
    ///
    /// The caller owns commit/abort. This is used by higher-level private
    /// runner stores that need to co-commit their own local indexes with the
    /// generic attempt row.
    pub(crate) fn enqueue_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: EnqueueAttempt,
    ) -> Result<EnqueueOutcome> {
        self.enqueue_with_task_ref_in_txn(wtxn, input, None)
    }

    /// Transaction-composable enqueue with an owning TASK backlink.
    pub(crate) fn enqueue_with_task_ref_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: EnqueueAttempt,
        task_ref: Option<String>,
    ) -> Result<EnqueueOutcome> {
        validate_kind(&input.kind)?;
        validate_optional_dedupe(input.dedupe_key.as_deref())?;
        validate_optional_run_id(input.run_id.as_deref())?;

        let dedupe_blake3_key = input
            .dedupe_key
            .as_deref()
            .map(|dedupe_key| DedupeIndexKeys::new(&input.kind, dedupe_key));
        if let (Some(dedupe_key), Some(index_key)) =
            (input.dedupe_key.as_deref(), dedupe_blake3_key.as_ref())
            && let Some(record) = self.read_existing_dedupe_in_write_txn(
                wtxn,
                &index_key.blake3[..],
                &input.kind,
                dedupe_key,
            )?
        {
            return Ok(EnqueueOutcome::Existing(record));
        }

        let record = AttemptRecord {
            id: AttemptId::now(),
            kind: input.kind,
            payload: input.payload,
            state: AttemptState::Queued,
            lease_owner: None,
            attempt_count: 0,
            claimed_at: None,
            scheduled_at: None,
            retry_of: None,
            backoff_until: None,
            last_error: None,
            task_ref,
            run_id: input.run_id,
            dedupe_key: input.dedupe_key,
            created_at: input.now,
            updated_at: input.now,
            events: Vec::new(),
            manifest: Vec::new(),
            cancel_state: AttemptCancelState::default(),
        };

        let encoded = encode_record(&record)?;
        self.store
            .attempt_records
            .put(wtxn, record.id.as_bytes(), &encoded)?;
        self.store.put_attempt_run_index_in_txn(
            wtxn,
            record.run_id.as_deref(),
            record.id.as_bytes(),
        )?;
        let ready_key = ready_key(ready_at(&record), record.id);
        self.store
            .attempt_ready
            .put(wtxn, &ready_key, record.id.as_bytes())?;
        if let Some(index_key) = dedupe_blake3_key.as_ref() {
            self.store
                .attempt_dedupe
                .put(wtxn, &index_key.blake3[..], record.id.as_bytes())?;
        }

        Ok(EnqueueOutcome::Enqueued(record))
    }

    /// Atomically claims the oldest queued attempt under LMDB's single-writer
    /// invariant.
    pub fn claim(&self, input: ClaimAttempt) -> Result<ClaimOutcome> {
        self.claim_matching(input, None)
    }

    /// Atomically claims the oldest queued attempt with the requested kind.
    ///
    /// Non-matching queued attempts remain ready for their own workers; malformed
    /// ready rows and stale indexes are still repaired while scanning.
    pub fn claim_kind(&self, kind: &str, input: ClaimAttempt) -> Result<ClaimOutcome> {
        validate_kind(kind)?;
        validate_lease_owner(&input.lease_owner)?;
        self.claim_kind_with_read_scan(kind, input)
    }

    /// Claims the oldest queued attempt with the requested kind in a caller-owned
    /// write transaction.
    ///
    /// The caller owns commit/abort. This path intentionally uses the
    /// write-transaction scan so higher-level stores can co-commit the lease
    /// with their own local state.
    pub(crate) fn claim_kind_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        kind: &str,
        input: ClaimAttempt,
    ) -> Result<ClaimOutcome> {
        validate_kind(kind)?;
        self.claim_matching_in_txn(wtxn, input, Some(kind))
    }

    /// Repairs ready/dedupe rows while returning the oldest claimable attempt id of
    /// this kind, without leasing it.
    pub(crate) fn ready_kind_candidate_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        kind: &str,
        now: u64,
    ) -> Result<Option<AttemptId>> {
        validate_kind(kind)?;

        let mut scan = ClaimKindReadScan::default();
        for row in self.store.attempt_ready.iter(&*wtxn)? {
            let (key, value) = row?;
            let Ok((key_ready_at, key_id)) = decode_ready_key(&key) else {
                scan.stale_ready_keys.push(key.to_vec());
                continue;
            };
            let Ok(id) = AttemptId::from_bytes(&value) else {
                scan.stale_ready_keys.push(key.to_vec());
                continue;
            };
            if id != key_id {
                scan.stale_ready_keys.push(key.to_vec());
                continue;
            }
            let Some(raw_record) = self.store.attempt_records.get(&*wtxn, id.as_bytes())? else {
                scan.stale_missing_record_ids.insert(id);
                scan.stale_ready_keys.push(key.to_vec());
                continue;
            };
            let record = decode_record(&raw_record, id)?;
            if !record.state.is_ready_indexed() {
                scan.stale_ready_keys.push(key.to_vec());
                continue;
            }
            let record_ready_at = ready_at(&record);
            if record_ready_at != key_ready_at {
                scan.stale_ready_keys.push(key.to_vec());
                if record_ready_at > now {
                    scan.ready_replacements
                        .push((ready_key(record_ready_at, id), id));
                    continue;
                }
                if record.kind != kind {
                    scan.ready_replacements
                        .push((ready_key(record_ready_at, id), id));
                    continue;
                }
            } else if record_ready_at > now || record.kind != kind {
                continue;
            }
            scan.candidate = Some(ClaimKindCandidate {
                ready_key: key.to_vec(),
                id,
            });
            break;
        }

        let candidate = scan.candidate.as_ref().map(|candidate| candidate.id);
        self.apply_claim_kind_read_repairs(wtxn, scan)?;
        Ok(candidate)
    }

    fn claim_kind_with_read_scan(&self, kind: &str, input: ClaimAttempt) -> Result<ClaimOutcome> {
        for _ in 0..CLAIM_KIND_WRITE_RETRY_LIMIT {
            let scan = self.scan_claim_kind_ready_rows(kind, input.now)?;
            match self.try_claim_scanned_kind_candidate(kind, &input, scan)? {
                ClaimKindWriteAttempt::Claimed(record) => return Ok(ClaimOutcome::Claimed(record)),
                ClaimKindWriteAttempt::Empty => return Ok(ClaimOutcome::Empty),
                ClaimKindWriteAttempt::Retry => {}
            }
        }

        self.claim_matching(input, Some(kind))
    }

    fn scan_claim_kind_ready_rows(&self, kind: &str, now: u64) -> Result<ClaimKindReadScan> {
        let rtxn = self.store.env.read_txn()?;
        let mut scan = ClaimKindReadScan::default();
        for row in self.store.attempt_ready.iter(&rtxn)? {
            let (key, value) = row?;
            let Ok((key_ready_at, key_id)) = decode_ready_key(&key) else {
                scan.stale_ready_keys.push(key.to_vec());
                continue;
            };
            let Ok(id) = AttemptId::from_bytes(&value) else {
                scan.stale_ready_keys.push(key.to_vec());
                continue;
            };
            if id != key_id {
                scan.stale_ready_keys.push(key.to_vec());
                continue;
            }
            let Some(raw_record) = self.store.attempt_records.get(&rtxn, id.as_bytes())? else {
                scan.stale_missing_record_ids.insert(id);
                scan.stale_ready_keys.push(key.to_vec());
                continue;
            };
            let record = decode_record(&raw_record, id)?;
            if !record.state.is_ready_indexed() {
                scan.stale_ready_keys.push(key.to_vec());
                continue;
            }
            let record_ready_at = ready_at(&record);
            if record_ready_at != key_ready_at {
                scan.stale_ready_keys.push(key.to_vec());
                if record_ready_at > now {
                    scan.ready_replacements
                        .push((ready_key(record_ready_at, id), id));
                    continue;
                }
                if record.kind != kind {
                    scan.ready_replacements
                        .push((ready_key(record_ready_at, id), id));
                    continue;
                }
            } else if record_ready_at > now || record.kind != kind {
                continue;
            }
            scan.candidate = Some(ClaimKindCandidate {
                ready_key: key.to_vec(),
                id,
            });
            break;
        }

        Ok(scan)
    }

    fn try_claim_scanned_kind_candidate(
        &self,
        kind: &str,
        input: &ClaimAttempt,
        scan: ClaimKindReadScan,
    ) -> Result<ClaimKindWriteAttempt> {
        let mut wtxn = self.store.env.write_txn()?;
        let mut claimed = None;
        if let Some(candidate) = scan.candidate.as_ref() {
            let Some(value) = self.store.attempt_ready.get(&wtxn, &candidate.ready_key)? else {
                self.apply_claim_kind_read_repairs(&mut wtxn, scan)?;
                wtxn.commit()?;
                return Ok(ClaimKindWriteAttempt::Retry);
            };
            let Ok(id) = AttemptId::from_bytes(&value) else {
                self.apply_claim_kind_read_repairs(&mut wtxn, scan)?;
                wtxn.commit()?;
                return Ok(ClaimKindWriteAttempt::Retry);
            };
            if id != candidate.id {
                self.apply_claim_kind_read_repairs(&mut wtxn, scan)?;
                wtxn.commit()?;
                return Ok(ClaimKindWriteAttempt::Retry);
            }
            let Some(raw_record) = self.store.attempt_records.get(&wtxn, id.as_bytes())? else {
                self.apply_claim_kind_read_repairs(&mut wtxn, scan)?;
                wtxn.commit()?;
                return Ok(ClaimKindWriteAttempt::Retry);
            };
            let mut record = decode_record(&raw_record, id)?;
            if !record.state.is_ready_indexed()
                || ready_at(&record) > input.now
                || record.kind != kind
            {
                self.apply_claim_kind_read_repairs(&mut wtxn, scan)?;
                wtxn.commit()?;
                return Ok(ClaimKindWriteAttempt::Retry);
            }
            lease_claimed_record(&mut record, &input.lease_owner, input.now)?;
            claimed = Some((candidate.ready_key.clone(), id, record));
        }

        self.apply_claim_kind_read_repairs(&mut wtxn, scan)?;

        let Some((ready_key, id, record)) = claimed else {
            wtxn.commit()?;
            return Ok(ClaimKindWriteAttempt::Empty);
        };

        self.store.attempt_ready.delete(&mut wtxn, &ready_key)?;
        let encoded = encode_record(&record)?;
        self.store
            .attempt_records
            .put(&mut wtxn, id.as_bytes(), &encoded)?;
        wtxn.commit()?;

        Ok(ClaimKindWriteAttempt::Claimed(record))
    }

    fn apply_claim_kind_read_repairs(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        scan: ClaimKindReadScan,
    ) -> Result<()> {
        self.delete_dedupe_entries_for_ids(wtxn, &scan.stale_missing_record_ids)?;
        for key in scan.stale_ready_keys {
            self.store.attempt_ready.delete(wtxn, &key)?;
        }
        for (key, id) in scan.ready_replacements {
            self.store.attempt_ready.put(wtxn, &key, id.as_bytes())?;
        }
        Ok(())
    }

    fn claim_matching(
        &self,
        input: ClaimAttempt,
        kind_filter: Option<&str>,
    ) -> Result<ClaimOutcome> {
        validate_lease_owner(&input.lease_owner)?;

        let mut wtxn = self.store.env.write_txn()?;
        let outcome = self.claim_matching_in_txn(&mut wtxn, input, kind_filter)?;
        wtxn.commit()?;

        Ok(outcome)
    }

    fn claim_matching_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: ClaimAttempt,
        kind_filter: Option<&str>,
    ) -> Result<ClaimOutcome> {
        validate_lease_owner(&input.lease_owner)?;

        let mut stale_ready_keys = Vec::new();
        let mut ready_replacements = Vec::new();
        let mut stale_missing_record_ids = HashSet::new();
        let mut claimed = None;
        for row in self.store.attempt_ready.iter(&*wtxn)? {
            let (key, value) = row?;
            let Ok((key_ready_at, key_id)) = decode_ready_key(&key) else {
                stale_ready_keys.push(key.to_vec());
                continue;
            };
            let Ok(id) = AttemptId::from_bytes(&value) else {
                stale_ready_keys.push(key.to_vec());
                continue;
            };
            if id != key_id {
                stale_ready_keys.push(key.to_vec());
                continue;
            }
            let Some(raw_record) = self.store.attempt_records.get(&*wtxn, id.as_bytes())? else {
                stale_missing_record_ids.insert(id);
                stale_ready_keys.push(key.to_vec());
                continue;
            };
            let mut record = decode_record(&raw_record, id)?;
            if !record.state.is_ready_indexed() {
                stale_ready_keys.push(key.to_vec());
                continue;
            }
            let record_ready_at = ready_at(&record);
            if record_ready_at != key_ready_at {
                stale_ready_keys.push(key.to_vec());
                if record_ready_at > input.now {
                    ready_replacements.push((ready_key(record_ready_at, id), id));
                    continue;
                }
            } else if record_ready_at > input.now {
                continue;
            }
            if kind_filter.is_some_and(|kind| record.kind != kind) {
                if record_ready_at != key_ready_at {
                    ready_replacements.push((ready_key(record_ready_at, id), id));
                }
                continue;
            }
            lease_claimed_record(&mut record, &input.lease_owner, input.now)?;
            claimed = Some((key.to_vec(), id, record));
            break;
        }

        self.delete_dedupe_entries_for_ids(wtxn, &stale_missing_record_ids)?;
        for key in stale_ready_keys {
            self.store.attempt_ready.delete(wtxn, &key)?;
        }
        for (key, id) in ready_replacements {
            self.store.attempt_ready.put(wtxn, &key, id.as_bytes())?;
        }

        let Some((ready_key, id, record)) = claimed else {
            return Ok(ClaimOutcome::Empty);
        };

        self.store.attempt_ready.delete(wtxn, &ready_key)?;
        let encoded = encode_record(&record)?;
        self.store
            .attempt_records
            .put(wtxn, id.as_bytes(), &encoded)?;

        Ok(ClaimOutcome::Claimed(record))
    }

    /// Marks a leased attempt complete. Completing an already-completed attempt is an
    /// idempotent success; all other states are rejected.
    pub fn complete(&self, input: CompleteAttempt) -> Result<CompleteOutcome> {
        {
            let rtxn = self.store.env.read_txn()?;
            let Some(raw_record) = self.store.attempt_records.get(&rtxn, input.id.as_bytes())?
            else {
                return Err(invalid_transition("complete", "missing"));
            };
            let record = decode_record(&raw_record, input.id)?;
            if record.state == AttemptState::Completed {
                return Ok(CompleteOutcome::AlreadyCompleted(record));
            }
        }

        let mut wtxn = self.store.env.write_txn()?;
        let Some(raw_record) = self.store.attempt_records.get(&wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("complete", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        match record.state {
            AttemptState::Completed => Ok(CompleteOutcome::AlreadyCompleted(record)),
            AttemptState::Leased => {
                validate_lease_owner(&input.lease_owner)?;
                validate_transition_lease(
                    &record,
                    &input.lease_owner,
                    input.attempt_count,
                    "complete",
                )?;
                record.state = AttemptState::Completed;
                record.lease_owner = None;
                record.backoff_until = None;
                record.last_error = None;
                record.updated_at = input.now;
                self.delete_dedupe_entry_for_record(&mut wtxn, &record)?;
                let encoded = encode_record(&record)?;
                self.store
                    .attempt_records
                    .put(&mut wtxn, record.id.as_bytes(), &encoded)?;
                crate::receipt::stamp_attempt_pack_receipt_in_txn(
                    self.store,
                    &mut wtxn,
                    &record,
                    &input.lease_owner,
                )?;
                wtxn.commit()?;
                Ok(CompleteOutcome::Completed(record))
            }
            state => Err(invalid_transition("complete", state.as_str())),
        }
    }

    /// Marks a leased attempt terminally failed. Failing an already-failed attempt is
    /// an idempotent success; all other states are rejected.
    pub fn fail(&self, input: FailAttempt) -> Result<FailOutcome> {
        {
            let rtxn = self.store.env.read_txn()?;
            let Some(raw_record) = self.store.attempt_records.get(&rtxn, input.id.as_bytes())?
            else {
                return Err(invalid_transition("fail", "missing"));
            };
            let record = decode_record(&raw_record, input.id)?;
            if record.state == AttemptState::Failed {
                return Ok(FailOutcome::AlreadyFailed(record));
            }
        }

        let mut wtxn = self.store.env.write_txn()?;
        let Some(raw_record) = self.store.attempt_records.get(&wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("fail", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        match record.state {
            AttemptState::Failed => Ok(FailOutcome::AlreadyFailed(record)),
            AttemptState::Leased => {
                validate_lease_owner(&input.lease_owner)?;
                validate_transition_lease(
                    &record,
                    &input.lease_owner,
                    input.attempt_count,
                    "fail",
                )?;
                validate_failure_reason(&input.reason)?;
                record.state = AttemptState::Failed;
                record.lease_owner = None;
                record.backoff_until = None;
                record.last_error = Some(input.reason);
                record.updated_at = input.now;
                self.delete_dedupe_entry_for_record(&mut wtxn, &record)?;
                let encoded = encode_record(&record)?;
                self.store
                    .attempt_records
                    .put(&mut wtxn, record.id.as_bytes(), &encoded)?;
                crate::receipt::stamp_attempt_pack_receipt_in_txn(
                    self.store,
                    &mut wtxn,
                    &record,
                    &input.lease_owner,
                )?;
                wtxn.commit()?;
                Ok(FailOutcome::Failed(record))
            }
            state => Err(invalid_transition("fail", state.as_str())),
        }
    }

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
        let Some(raw_record) = self.store.attempt_records.get(&wtxn, input.id.as_bytes())? else {
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
            .put(&mut wtxn, source.id.as_bytes(), &encoded_source)?;
        let encoded_next = encode_record(&next)?;
        self.store
            .attempt_records
            .put(&mut wtxn, next.id.as_bytes(), &encoded_next)?;

        // The source was leased, so it holds no ready entry to retire; only the
        // new row enters the ready index, at its own scheduled instant.
        let ready_key = ready_key(ready_at(&next), next.id);
        self.store
            .attempt_ready
            .put(&mut wtxn, &ready_key, next.id.as_bytes())?;
        self.store.put_attempt_run_index_in_txn(
            &mut wtxn,
            next.run_id.as_deref(),
            next.id.as_bytes(),
        )?;

        // Only the newest pending member of a dedupe chain owns the advisory
        // index, so the entry moves off the now-terminal source.
        self.delete_dedupe_entry_for_record(&mut wtxn, &source)?;
        if let Some(dedupe_key) = next.dedupe_key.as_deref() {
            let index_key = dedupe_index_key(&next.kind, dedupe_key);
            self.store
                .attempt_dedupe
                .put(&mut wtxn, &index_key[..], next.id.as_bytes())?;
        }

        wtxn.commit()?;
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
            return Err(Error::InvalidAttemptQueueRecord(ERR_MANIFEST_FULL));
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
                }
            }
            wtxn.commit()?;
        }

        record_attempt_queue_cleanup_metrics(&report);
        emit_attempt_queue_cleanup_span(&input, &report);
        Ok(report)
    }

    /// Reads an attempt by id.
    pub fn get(&self, id: AttemptId) -> Result<Option<AttemptRecord>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.attempt_records.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        decode_record(&raw, id).map(Some)
    }

    /// Reads an attempt by id inside a caller-owned write transaction.
    pub(crate) fn get_in_write_txn(
        &self,
        wtxn: &heed::RwTxn<'_>,
        id: AttemptId,
    ) -> Result<Option<AttemptRecord>> {
        let Some(raw) = self.store.attempt_records.get(wtxn, id.as_bytes())? else {
            return Ok(None);
        };
        decode_record(&raw, id).map(Some)
    }

    /// Reads every row realizing one TASK inside a caller-owned write
    /// transaction, in deterministic creation order.
    ///
    /// Membership is re-DERIVED, never re-read by id: [`Self::retry`] mints a
    /// NEW row under the same `task_ref` and finalizes its source, so a caller
    /// holding a pre-transaction id snapshot cannot reach the successor by
    /// re-reading the ids it already knows.
    pub(crate) fn list_task_in_write_txn(
        &self,
        wtxn: &heed::RwTxn<'_>,
        task_ref: &str,
    ) -> Result<Vec<AttemptRecord>> {
        let mut records = Vec::new();
        for row in self.store.attempt_records.iter(wtxn)? {
            let (key, raw_record) = row?;
            let id = AttemptId::from_bytes(&key)?;
            let record = decode_record(&raw_record, id)?;
            if record.task_ref.as_deref() == Some(task_ref) {
                records.push(record);
            }
        }
        records.sort_by(attempt_record_order);
        Ok(records)
    }

    /// Reads all persisted attempt rows in deterministic creation order.
    pub fn list(&self) -> Result<Vec<AttemptRecord>> {
        let rtxn = self.store.env.read_txn()?;
        let mut records = Vec::new();
        for row in self.store.attempt_records.iter(&rtxn)? {
            let (key, raw_record) = row?;
            let id = AttemptId::from_bytes(&key)?;
            records.push(decode_record(&raw_record, id)?);
        }
        records.sort_by(attempt_record_order);
        Ok(records)
    }

    /// Reads persisted attempt rows for one run id in deterministic creation order.
    pub fn list_run(&self, run_id: &str) -> Result<Vec<AttemptRecord>> {
        validate_optional_run_id(Some(run_id))?;
        let rtxn = self.store.env.read_txn()?;
        let mut records = Vec::new();
        for id_bytes in self.store.attempt_ids_for_run_in_txn(&rtxn, run_id)? {
            let id = AttemptId::from_bytes(&id_bytes)?;
            let Some(raw_record) = self.store.attempt_records.get(&rtxn, id.as_bytes())? else {
                return Err(Error::CorruptedIndex("attempt run index"));
            };
            let record = decode_record(&raw_record, id)?;
            if record.run_id.as_deref() != Some(run_id) {
                return Err(Error::CorruptedIndex("attempt run index"));
            }
            records.push(record);
        }
        records.sort_by(attempt_record_order);
        Ok(records)
    }

    pub(crate) fn dreamer_run_root_id(&self, run_id: &str) -> Result<Option<AttemptId>> {
        validate_optional_run_id(Some(run_id))?;
        let rtxn = self.store.env.read_txn()?;
        dreamer_run_root_id_in_txn(self.store, &rtxn, run_id)
    }

    fn read_existing_dedupe_in_read_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        index_key: &[u8],
        kind: &str,
        dedupe_key: &str,
    ) -> Result<Option<AttemptRecord>> {
        let Some(existing_id) = self.store.attempt_dedupe.get(txn, index_key)? else {
            return Ok(None);
        };
        let id = AttemptId::from_bytes(&existing_id)?;
        let Some(raw) = self.store.attempt_records.get(txn, id.as_bytes())? else {
            return Ok(None);
        };
        let record = decode_record(&raw, id)?;
        validate_dedupe_record(&record, kind, dedupe_key)?;
        if !record.state.is_pending() {
            return Ok(None);
        }
        Ok(Some(record))
    }

    fn read_existing_dedupe_in_write_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        blake3_key: &[u8],
        kind: &str,
        dedupe_key: &str,
    ) -> Result<Option<AttemptRecord>> {
        if let Some(record) =
            self.read_existing_dedupe_entry_in_write_txn(txn, blake3_key, kind, dedupe_key)?
        {
            return Ok(Some(record));
        }

        let legacy_key = legacy_dedupe_index_key(kind, dedupe_key);
        let Some(record) =
            self.read_existing_dedupe_entry_in_write_txn(txn, &legacy_key, kind, dedupe_key)?
        else {
            return Ok(None);
        };
        self.store
            .attempt_dedupe
            .put(txn, blake3_key, record.id.as_bytes())?;
        self.store.attempt_dedupe.delete(txn, &legacy_key)?;
        Ok(Some(record))
    }

    fn read_existing_dedupe_entry_in_write_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        index_key: &[u8],
        kind: &str,
        dedupe_key: &str,
    ) -> Result<Option<AttemptRecord>> {
        let Some(existing_id) = self.store.attempt_dedupe.get(txn, index_key)? else {
            return Ok(None);
        };
        let id = AttemptId::from_bytes(&existing_id)?;
        let Some(raw) = self.store.attempt_records.get(txn, id.as_bytes())? else {
            self.store.attempt_dedupe.delete(txn, index_key)?;
            return Ok(None);
        };
        let record = decode_record(&raw, id)?;
        validate_dedupe_record(&record, kind, dedupe_key)?;
        if !record.state.is_pending() {
            self.store.attempt_dedupe.delete(txn, index_key)?;
            return Ok(None);
        }
        Ok(Some(record))
    }

    pub(super) fn delete_dedupe_entry_for_record(
        &self,
        txn: &mut heed::RwTxn<'_>,
        record: &AttemptRecord,
    ) -> Result<()> {
        if let Some(dedupe_key) = record.dedupe_key.as_deref() {
            let blake3_key = dedupe_index_key(&record.kind, dedupe_key);
            let legacy_key = legacy_dedupe_index_key(&record.kind, dedupe_key);
            self.store.attempt_dedupe.delete(txn, &blake3_key[..])?;
            self.store.attempt_dedupe.delete(txn, &legacy_key)?;
        }
        Ok(())
    }

    fn delete_dedupe_entries_for_ids(
        &self,
        txn: &mut heed::RwTxn<'_>,
        ids: &HashSet<AttemptId>,
    ) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let mut keys = Vec::new();
        for row in self.store.attempt_dedupe.iter(txn)? {
            let (key, value) = row?;
            let id = AttemptId::from_bytes(&value)?;
            if ids.contains(&id) {
                keys.push(key.to_vec());
            }
        }
        for key in keys {
            self.store.attempt_dedupe.delete(txn, &key)?;
        }
        Ok(())
    }

    pub(super) fn delete_ready_entry_for_record(
        &self,
        txn: &mut heed::RwTxn<'_>,
        record: &AttemptRecord,
    ) -> Result<()> {
        self.store
            .attempt_ready
            .delete(txn, &ready_key(ready_at(record), record.id))?;
        Ok(())
    }
}

fn mark_rechecked_candidate_not_running(report: &mut AttemptQueueCleanupReport) {
    report.running = report.running.saturating_sub(1);
}

/// Resolves the OF-193 Dreamer root for one stamped run id using the durable
/// run index.  A branch-only run climbs parent links with the same bounded,
/// fail-safe behavior used by the inbox projection.
pub(crate) fn dreamer_run_root_id_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    run_id: &str,
) -> Result<Option<AttemptId>> {
    let mut records = Vec::new();
    // The sidecar is ordered by attempt id; preserve the prior `list_run`
    // behavior by selecting a root/branch in deterministic creation order.
    let mut first_branch: Option<(AttemptId, DreamerAttemptPayload)> = None;
    for id_bytes in store.attempt_ids_for_run_in_txn(txn, run_id)? {
        let id = AttemptId::from_bytes(&id_bytes)?;
        let Some(raw) = store.attempt_records.get(txn, id.as_bytes())? else {
            return Err(Error::CorruptedIndex("attempt run index"));
        };
        let record = decode_record(&raw, id)?;
        if record.run_id.as_deref() != Some(run_id) {
            return Err(Error::CorruptedIndex("attempt run index"));
        }
        records.push(record);
    }
    records.sort_by(attempt_record_order);
    for record in records {
        if record.kind != DREAMER_RUNNER_ATTEMPT_KIND {
            continue;
        }
        let Ok(payload) = decode_dreamer_attempt_payload(&record.payload) else {
            continue;
        };
        if payload.parent_attempt.is_none() {
            return Ok(Some(record.id));
        }
        if first_branch.is_none() {
            first_branch = Some((record.id, payload));
        }
    }

    let Some((mut attempt_id, mut payload)) = first_branch else {
        return Ok(None);
    };
    let mut visited = HashSet::from([attempt_id]);
    while let Some(parent_id) = payload.parent_attempt {
        if visited.len() >= DREAMER_RUN_ROOT_CLIMB_LIMIT || !visited.insert(parent_id) {
            break;
        }
        let Some(raw) = store.attempt_records.get(txn, parent_id.as_bytes())? else {
            break;
        };
        let parent = decode_record(&raw, parent_id)?;
        if parent.kind != DREAMER_RUNNER_ATTEMPT_KIND {
            break;
        }
        let Ok(parent_payload) = decode_dreamer_attempt_payload(&parent.payload) else {
            break;
        };
        attempt_id = parent_id;
        payload = parent_payload;
    }
    Ok(Some(attempt_id))
}
