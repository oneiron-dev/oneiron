//! The [`AttemptQueue`] handle and its lease state machine.
//!
//! Deliberately kept whole: enqueue, claim, complete, fail, retry, intervene,
//! manifest append, cleanup, and the read paths are one transactional
//! discipline over the same LMDB row set. Supporting concerns live beside it —
//! types in [`super::types`], validators in [`super::validate`], key/row
//! encoding in [`super::encoding`], counters in [`super::telemetry`].

use std::collections::HashSet;

use crate::Vault;
use crate::dreamer_runner::{
    DREAMER_RUNNER_ATTEMPT_KIND, DreamerAttemptPayload, decode_dreamer_attempt_payload,
};
use crate::error::{Error, Result};
use crate::store::Store;

use super::encoding::{
    DedupeIndexKeys, READY_KEY_LEN, decode_ready_key, decode_record, dedupe_index_key,
    encode_record, lease_expired, legacy_dedupe_index_key, ready_at, ready_key,
    validate_dedupe_record, waiting_on_backoff,
};
use super::telemetry::{
    emit_attempt_queue_cleanup_span, invalid_transition, record_attempt_queue_cleanup_metrics,
};
use super::types::{
    ATTEMPT_RUNTIME_ACTOR, AcceptAttemptLanding, AttemptCancelReceipt, AttemptCancelReceiptKind,
    AttemptCancelState, AttemptCancellation, AttemptId, AttemptInterventionEffect,
    AttemptInterventionKind, AttemptLanding, AttemptLandingReserve, AttemptLeaseWarningReport,
    AttemptQueueCleanupReport, AttemptQueueRetryReason, AttemptRecord, AttemptState, CancelMode,
    CancelRejectionOutcome, CancelRequestOutcome, CancelStanding, ClaimAttempt, ClaimOutcome,
    CleanupAttemptLeases, CompleteAttempt, CompleteOutcome, DialLandingReserve, EnqueueAttempt,
    EnqueueOutcome, FailAttempt, FailOutcome, FinishAttemptLanding, FinishLandingOutcome,
    ForceAttemptCancel, ForceCancelAuthority, ForceCancelGrounds, ForceCancelOutcome,
    InterveneAttempt, InterveneOutcome, LANDING_RESERVE_PERCENT, LEASE_LANDING_WARNING_PERCENT,
    LandingOutcome, LandingReserveSpendOutcome, LandingTrigger, LandingWarningOutcome,
    LeaseWarningOutcome, MAX_ATTEMPT_MANIFEST_ENTRIES, ManifestEntry, RecordAttemptResumePoint,
    RejectAttemptCancel, RequestAttemptCancel, RetryAttempt, RetryOutcome,
    SpendAttemptLandingReserve, WarnAttemptBudgetPressure, WarnAttemptLeaseExpiry,
    WarnExpiringAttemptLeases, attempt_record_order,
};
use super::validate::{
    CancelReceiptDraft, ERR_HANDOFF_WITHOUT_RESUME_POINT, ERR_MANIFEST_FULL,
    ERR_RESERVE_SPEND_ZERO, append_attempt_event, append_cancel_receipt, count_cancel_rejection,
    count_cancel_request, lease_claimed_record, validate_cancel_actor, validate_cancel_standing,
    validate_cleanup_leases_input, validate_failure_reason, validate_intervention_actor,
    validate_kind, validate_lease_owner, validate_manifest_entry, validate_optional_cancel_status,
    validate_optional_dedupe, validate_optional_failure_reason,
    validate_optional_intervention_note, validate_optional_resume_point, validate_optional_run_id,
    validate_reserve_percent, validate_resume_point, validate_transition_lease,
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

/// Who authored one soft-request row, and why.
#[derive(Debug)]
struct SoftRequestAuthorship {
    actor: String,
    /// `None` for a runtime-authored warning: standing is a claim an ACTOR
    /// makes, and the runtime is not one of them.
    standing: Option<CancelStanding>,
    trigger: LandingTrigger,
    reason: Option<String>,
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
    store: &'a Store,
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
            // inherit the dial, so a retried try lands on the same terms.
            cancel_state: AttemptCancelState {
                reserve: AttemptLandingReserve {
                    spent_units: 0,
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

    /// RUNG 1 (soft): asks a running attempt to stop.
    ///
    /// This NEVER mutates a running attempt to terminal cancelled. It records a
    /// durable, typed request and leaves the worker to answer by landing
    /// ([`Self::accept_landing`]) or refusing ([`Self::reject_cancel`]). A
    /// caller that could not establish standing passes
    /// [`CancelStanding::None`](super::types::CancelStanding::None) and gets
    /// [`CancelRequestOutcome::NoStanding`] with the row untouched.
    ///
    /// Asking again is legitimate and additive: every ask is its own append-only
    /// receipt, so a worker that refuses repeatedly accumulates the evidence
    /// that says so.
    pub fn request_cancel(&self, input: RequestAttemptCancel) -> Result<CancelRequestOutcome> {
        let mut wtxn = self.store.env.write_txn()?;
        let outcome = self.request_cancel_in_txn(&mut wtxn, input)?;
        wtxn.commit()?;
        Ok(outcome)
    }

    /// Transaction-composable [`Self::request_cancel`], so an adapter can
    /// co-commit the request with its own gate/proposal state.
    pub(crate) fn request_cancel_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: RequestAttemptCancel,
    ) -> Result<CancelRequestOutcome> {
        validate_cancel_actor(&input.actor)?;
        validate_optional_failure_reason(input.reason.as_deref())?;

        let Some(raw_record) = self.store.attempt_records.get(wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("cancel_request", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        if !input.standing.may_request() {
            return Ok(CancelRequestOutcome::NoStanding(record));
        }
        validate_cancel_standing(input.standing)?;
        match record.state {
            AttemptState::Landing => return Ok(CancelRequestOutcome::AlreadyLanding(record)),
            AttemptState::Completed | AttemptState::Failed | AttemptState::Cancelled => {
                return Ok(CancelRequestOutcome::AlreadySettled(record));
            }
            // Only a CLAIMED, leased realization has a worker who can answer.
            // Recording a pending ask against a queued/paused/scheduled row
            // would create an obligation nobody holds: `accept_landing` and
            // `reject_cancel` both require the lease, so the ask could never be
            // discharged, and its permanent `pending` would read as a worker
            // that will not answer. Pre-lease work is stopped, not asked.
            AttemptState::Leased => {}
            AttemptState::Queued | AttemptState::Paused | AttemptState::Scheduled => {
                return Ok(CancelRequestOutcome::NotRunning(record));
            }
        }

        self.record_soft_request(
            wtxn,
            &mut record,
            SoftRequestAuthorship {
                actor: input.actor,
                standing: Some(input.standing),
                trigger: input.trigger,
                reason: input.reason,
            },
            input.now,
        )?;
        let pressure = record.cancel_state.pressure;
        Ok(CancelRequestOutcome::Requested { record, pressure })
    }

    /// Appends one soft-request receipt and persists the row. `updated_at` is
    /// deliberately NOT bumped: it is the lease-expiry clock, and letting a
    /// requester restart it would let repeated asking keep a stalled worker's
    /// lease alive forever.
    fn record_soft_request(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        record: &mut AttemptRecord,
        authorship: SoftRequestAuthorship,
        now: u64,
    ) -> Result<()> {
        append_cancel_receipt(
            record,
            AttemptCancelReceiptKind::SoftRequested,
            authorship.actor,
            CancelReceiptDraft {
                standing: authorship.standing,
                trigger: Some(authorship.trigger),
                reason: authorship.reason,
                ..CancelReceiptDraft::default()
            },
            now,
        )?;
        count_cancel_request(&mut record.cancel_state.pressure);
        let encoded = encode_record(record)?;
        self.store
            .attempt_records
            .put(wtxn, record.id.as_bytes(), &encoded)?;
        Ok(())
    }

    /// The worker ACCEPTS a stop and enters [`AttemptState::Landing`].
    ///
    /// The lease fence is the same one `complete`/`fail` use, so a stale
    /// generation or a wrong owner cannot land someone else's attempt. The row
    /// keeps its lease: landing is bounded work, not a release.
    ///
    /// This is the one cancel door that DOES restart the lease clock, and only
    /// once: accepting buys the worker a fresh, bounded window to finish in.
    /// Landing work itself — resume points, reserve spends — deliberately does
    /// not touch `updated_at`, so a worker cannot land forever by continuing to
    /// look busy; when that window runs out, cleanup force-cancels.
    pub fn accept_landing(&self, input: AcceptAttemptLanding) -> Result<LandingOutcome> {
        validate_lease_owner(&input.lease_owner)?;
        validate_optional_cancel_status(input.status.as_deref())?;
        validate_optional_resume_point(input.resume_point.as_ref())?;

        let mut wtxn = self.store.env.write_txn()?;
        let Some(raw_record) = self.store.attempt_records.get(&wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("accept_landing", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        match record.state {
            AttemptState::Landing => {
                validate_transition_lease(
                    &record,
                    &input.lease_owner,
                    input.attempt_count,
                    "accept_landing",
                )?;
                return Ok(LandingOutcome::AlreadyLanding(record));
            }
            AttemptState::Leased => {}
            state => return Err(invalid_transition("accept_landing", state.as_str())),
        }
        validate_transition_lease(
            &record,
            &input.lease_owner,
            input.attempt_count,
            "accept_landing",
        )?;

        // The ANSWERED request is the source of truth for trigger provenance;
        // the worker cannot relabel a lease warning as an unrelated cancel
        // request while answering it. A self-triggered landing has no pending
        // request and uses the typed trigger supplied by the worker.
        //
        // Which request is answered is chosen by identity, never by recency:
        // with a peer ask and a runtime warning both outstanding, the landing
        // must name the one it actually answers.
        let answered = select_pending_request(&record, input.request_sequence, "accept_landing")?;
        let answered_sequence = answered.map(|request| request.sequence);
        let trigger = answered
            .and_then(|request| request.trigger)
            .unwrap_or(input.trigger);
        let requested_by = answered
            .map(|request| request.actor.clone())
            .unwrap_or(input.lease_owner.clone());
        record.cancel_state.landing = Some(AttemptLanding {
            trigger,
            requested_by,
            entered_at: input.now,
            status: input.status.clone(),
        });
        if let Some(resume_point) = input.resume_point.clone() {
            record.cancel_state.resume_point = Some(resume_point);
        }
        // Landing satisfies every outstanding ask — they all wanted the worker
        // to stop, and it is stopping — so no request stays owed an answer.
        // The receipt still names the ONE request this landing answers, so the
        // trigger and the requester on it are the real ones.
        record.cancel_state.pressure.pending = 0;
        record.state = AttemptState::Landing;
        record.updated_at = input.now;
        let recorded_resume_point = record.cancel_state.resume_point.clone();
        append_cancel_receipt(
            &mut record,
            AttemptCancelReceiptKind::LandingAccepted,
            input.lease_owner,
            CancelReceiptDraft {
                trigger: Some(trigger),
                status: input.status,
                resume_point: recorded_resume_point,
                request_sequence: answered_sequence,
                ..CancelReceiptDraft::default()
            },
            input.now,
        )?;
        let encoded = encode_record(&record)?;
        self.store
            .attempt_records
            .put(&mut wtxn, record.id.as_bytes(), &encoded)?;
        wtxn.commit()?;
        Ok(LandingOutcome::Landing(record))
    }

    /// The worker REFUSES a soft request and stays at work.
    ///
    /// The refusal is append-only evidence and the refusal count is the
    /// pathology signal. Nothing here terminates anything: only the hard rung
    /// can stop a worker that will not land.
    pub fn reject_cancel(&self, input: RejectAttemptCancel) -> Result<CancelRejectionOutcome> {
        validate_lease_owner(&input.lease_owner)?;
        validate_failure_reason(&input.reason)?;
        validate_optional_cancel_status(input.status.as_deref())?;

        let mut wtxn = self.store.env.write_txn()?;
        let Some(raw_record) = self.store.attempt_records.get(&wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("cancel_reject", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        if record.state != AttemptState::Leased {
            return Err(invalid_transition("cancel_reject", record.state.as_str()));
        }
        validate_transition_lease(
            &record,
            &input.lease_owner,
            input.attempt_count,
            "cancel_reject",
        )?;
        // Preserve the trigger on the request being answered. The worker's
        // refusal reason is new evidence, but it must not erase whether the
        // ask came from a peer, a quota warning, or lease expiry — and with
        // several asks outstanding it must name the one it refused, or the
        // remaining requesters inherit an answer nobody gave them.
        let Some(answered) =
            select_pending_request(&record, input.request_sequence, "cancel_reject")?
        else {
            return Err(invalid_transition("cancel_reject", "no_request"));
        };
        let trigger = answered.trigger;
        let answered_request_sequence = answered.sequence;

        count_cancel_rejection(&mut record.cancel_state.pressure);
        append_cancel_receipt(
            &mut record,
            AttemptCancelReceiptKind::SoftRejected,
            input.lease_owner,
            CancelReceiptDraft {
                trigger,
                reason: Some(input.reason),
                status: input.status,
                request_sequence: Some(answered_request_sequence),
                ..CancelReceiptDraft::default()
            },
            input.now,
        )?;
        let encoded = encode_record(&record)?;
        self.store
            .attempt_records
            .put(&mut wtxn, record.id.as_bytes(), &encoded)?;
        wtxn.commit()?;

        let pressure = record.cancel_state.pressure;
        Ok(CancelRejectionOutcome {
            record,
            pressure,
            pathology: pressure.is_pathological(),
            answered_request_sequence,
        })
    }

    /// Records the exact resume point a successor picks up from.
    ///
    /// Landing-only: a resume point recorded by a still-running attempt would
    /// name a position the worker is about to move past.
    pub fn record_resume_point(&self, input: RecordAttemptResumePoint) -> Result<AttemptRecord> {
        validate_lease_owner(&input.lease_owner)?;
        validate_resume_point(&input.resume_point)?;

        let mut wtxn = self.store.env.write_txn()?;
        let Some(raw_record) = self.store.attempt_records.get(&wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("record_resume_point", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        if record.state != AttemptState::Landing {
            return Err(invalid_transition(
                "record_resume_point",
                record.state.as_str(),
            ));
        }
        validate_transition_lease(
            &record,
            &input.lease_owner,
            input.attempt_count,
            "record_resume_point",
        )?;

        record.cancel_state.resume_point = Some(input.resume_point.clone());
        let trigger = record.cancel_state.landing.as_ref().map(|l| l.trigger);
        append_cancel_receipt(
            &mut record,
            AttemptCancelReceiptKind::ResumePointRecorded,
            input.lease_owner,
            CancelReceiptDraft {
                trigger,
                resume_point: Some(input.resume_point),
                ..CancelReceiptDraft::default()
            },
            input.now,
        )?;
        let encoded = encode_record(&record)?;
        self.store
            .attempt_records
            .put(&mut wtxn, record.id.as_bytes(), &encoded)?;
        wtxn.commit()?;
        Ok(record)
    }

    /// Dials the attempt's budget and carves its landing reserve out of it.
    ///
    /// Refused once the attempt is landing or terminal: re-dialing mid-landing
    /// would let a worker mint the very reserve it is spending. The ordinary
    /// execution meter for this attempt must be built with
    /// [`AttemptRecord::ordinary_budget_limit_units`], which is what makes the
    /// reserve unreachable by normal work.
    pub fn dial_landing_reserve(&self, input: DialLandingReserve) -> Result<AttemptRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let record = self.dial_landing_reserve_in_txn(&mut wtxn, input)?;
        wtxn.commit()?;
        Ok(record)
    }

    /// Transaction-composable [`Self::dial_landing_reserve`], so an admission
    /// path can co-commit the dial with the lease it just took: the units a
    /// runner reserved for an attempt and the attempt's own landing slice are
    /// one fact, and a crash between them would leave a leased attempt with a
    /// budget but no way to land inside it.
    pub(crate) fn dial_landing_reserve_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: DialLandingReserve,
    ) -> Result<AttemptRecord> {
        let reserve_percent = input.reserve_percent.unwrap_or(LANDING_RESERVE_PERCENT);
        validate_reserve_percent(reserve_percent)?;

        let Some(raw_record) = self.store.attempt_records.get(wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("dial_landing_reserve", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        match record.state {
            AttemptState::Queued
            | AttemptState::Leased
            | AttemptState::Paused
            | AttemptState::Scheduled => {}
            state => {
                return Err(invalid_transition("dial_landing_reserve", state.as_str()));
            }
        }
        record.cancel_state.reserve =
            AttemptLandingReserve::dialed(input.limit_units, reserve_percent);
        let encoded = encode_record(&record)?;
        self.store
            .attempt_records
            .put(wtxn, record.id.as_bytes(), &encoded)?;
        Ok(record)
    }

    /// Spends landing reserve units.
    ///
    /// Fails closed on both axes: out of landing mode is a typed transition
    /// refusal, and a request larger than what remains spends NOTHING and
    /// reports [`LandingReserveSpendOutcome::Exhausted`]. There is no partial
    /// spend, so the terminal receipt's accounting is exact.
    pub fn spend_landing_reserve(
        &self,
        input: SpendAttemptLandingReserve,
    ) -> Result<LandingReserveSpendOutcome> {
        validate_lease_owner(&input.lease_owner)?;
        if input.units == 0 {
            return Err(Error::InvalidAttemptQueueRecord(ERR_RESERVE_SPEND_ZERO));
        }

        let mut wtxn = self.store.env.write_txn()?;
        let Some(raw_record) = self.store.attempt_records.get(&wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("spend_landing_reserve", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        if record.state != AttemptState::Landing {
            return Err(invalid_transition(
                "spend_landing_reserve",
                record.state.as_str(),
            ));
        }
        validate_transition_lease(
            &record,
            &input.lease_owner,
            input.attempt_count,
            "spend_landing_reserve",
        )?;

        let remaining_units = record.cancel_state.reserve.remaining_units();
        if input.units > remaining_units {
            return Ok(LandingReserveSpendOutcome::Exhausted {
                record,
                requested_units: input.units,
                remaining_units,
            });
        }
        record.cancel_state.reserve.spent_units = record
            .cancel_state
            .reserve
            .spent_units
            .checked_add(input.units)
            .ok_or(Error::ArithmeticOverflow("landing reserve spend"))?;
        let trigger = record.cancel_state.landing.as_ref().map(|l| l.trigger);
        append_cancel_receipt(
            &mut record,
            AttemptCancelReceiptKind::ReserveSpent,
            input.lease_owner,
            CancelReceiptDraft {
                trigger,
                reserve_units: input.units,
                ..CancelReceiptDraft::default()
            },
            input.now,
        )?;
        let encoded = encode_record(&record)?;
        self.store
            .attempt_records
            .put(&mut wtxn, record.id.as_bytes(), &encoded)?;
        wtxn.commit()?;

        let remaining_units = record.cancel_state.reserve.remaining_units();
        Ok(LandingReserveSpendOutcome::Spent {
            record,
            remaining_units,
        })
    }

    /// Finishes a landing: the row becomes terminally cancelled in
    /// [`CancelMode::Landed`], optionally handing off to a successor that
    /// carries the exact resume point.
    ///
    /// Never `Completed`: a landing is an honest stop. The landed row is
    /// finalized and its advisory dedupe entry moves to the successor, exactly
    /// as a retry moves it, so the pair can never both be completed.
    pub fn finish_landing(&self, input: FinishAttemptLanding) -> Result<FinishLandingOutcome> {
        validate_lease_owner(&input.lease_owner)?;

        let mut wtxn = self.store.env.write_txn()?;
        let Some(raw_record) = self.store.attempt_records.get(&wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("finish_landing", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        if record.state != AttemptState::Landing {
            return Err(invalid_transition("finish_landing", record.state.as_str()));
        }
        let lease_owner = input.lease_owner.clone();
        validate_transition_lease(&record, &lease_owner, input.attempt_count, "finish_landing")?;
        if input.hand_off && record.cancel_state.resume_point.is_none() {
            return Err(Error::InvalidAttemptQueueRecord(
                ERR_HANDOFF_WITHOUT_RESUME_POINT,
            ));
        }

        let successor = if input.hand_off {
            Some(landing_successor(&record, input.scheduled_at, input.now))
        } else {
            None
        };

        let trigger = record.cancel_state.landing.as_ref().map(|l| l.trigger);
        record.state = AttemptState::Cancelled;
        record.lease_owner = None;
        record.scheduled_at = None;
        record.backoff_until = None;
        record.last_error = None;
        record.updated_at = input.now;
        record.cancel_state.cancellation = Some(AttemptCancellation {
            mode: CancelMode::Landed,
            grounds: None,
            actor: lease_owner.clone(),
            at: input.now,
            reason: None,
            trigger,
            reserve_units: record.cancel_state.reserve.reserve_units,
            reserve_spent_units: record.cancel_state.reserve.spent_units,
        });
        let landed_resume_point = record.cancel_state.resume_point.clone();
        let landed_reserve_spent = record.cancel_state.reserve.spent_units;
        append_cancel_receipt(
            &mut record,
            AttemptCancelReceiptKind::Landed,
            lease_owner,
            CancelReceiptDraft {
                trigger,
                resume_point: landed_resume_point,
                reserve_units: landed_reserve_spent,
                ..CancelReceiptDraft::default()
            },
            input.now,
        )?;

        let encoded = encode_record(&record)?;
        self.store
            .attempt_records
            .put(&mut wtxn, record.id.as_bytes(), &encoded)?;
        // Landing is a terminal attempt door too: preserve the existing PACK
        // receipt invariant when the live attempt accumulated a manifest.
        crate::receipt::stamp_attempt_pack_receipt_in_txn(
            self.store,
            &mut wtxn,
            &record,
            record
                .cancel_state
                .cancellation
                .as_ref()
                .map_or(ATTEMPT_RUNTIME_ACTOR, |cancellation| {
                    cancellation.actor.as_str()
                }),
        )?;
        self.delete_dedupe_entry_for_record(&mut wtxn, &record)?;

        let Some(successor) = successor else {
            wtxn.commit()?;
            return Ok(FinishLandingOutcome::Landed(record));
        };

        let encoded_successor = encode_record(&successor)?;
        self.store
            .attempt_records
            .put(&mut wtxn, successor.id.as_bytes(), &encoded_successor)?;
        let ready_key = ready_key(ready_at(&successor), successor.id);
        self.store
            .attempt_ready
            .put(&mut wtxn, &ready_key, successor.id.as_bytes())?;
        self.store.put_attempt_run_index_in_txn(
            &mut wtxn,
            successor.run_id.as_deref(),
            successor.id.as_bytes(),
        )?;
        if let Some(dedupe_key) = successor.dedupe_key.as_deref() {
            let index_key = dedupe_index_key(&successor.kind, dedupe_key);
            self.store
                .attempt_dedupe
                .put(&mut wtxn, &index_key[..], successor.id.as_bytes())?;
        }
        wtxn.commit()?;
        Ok(FinishLandingOutcome::HandedOff {
            landed: record,
            successor,
        })
    }

    /// RUNG 2 (hard): terminates an attempt, unrefusably.
    ///
    /// Authorization IS the [`super::types::ForceCancelAuthority`] token, which
    /// only the owner path or a runtime ground can mint; there is no actor
    /// string here for a worker to supply, so the terminal receipt cannot be
    /// forged. Terminal already means terminal: a settled attempt is reported,
    /// never re-killed.
    pub fn force_cancel(&self, input: ForceAttemptCancel) -> Result<ForceCancelOutcome> {
        validate_optional_failure_reason(input.reason.as_deref())?;

        let mut wtxn = self.store.env.write_txn()?;
        let outcome = self.force_cancel_in_txn(&mut wtxn, input)?;
        wtxn.commit()?;
        Ok(outcome)
    }

    /// Transaction-composable [`Self::force_cancel`].
    pub(crate) fn force_cancel_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: ForceAttemptCancel,
    ) -> Result<ForceCancelOutcome> {
        validate_optional_failure_reason(input.reason.as_deref())?;
        // The authority's actor becomes the terminal receipt's actor, so it is
        // validated BEFORE any durable state changes: an owner-verified but
        // malformed identity (empty, oversized, or claiming the runtime's own
        // name) must fail at the door rather than terminalize the attempt and
        // leave behind a cancellation row that `decode_record` then refuses.
        validate_force_authority(&input.authority)?;

        let Some(raw_record) = self.store.attempt_records.get(wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("cancel_force", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        match record.state {
            AttemptState::Cancelled => return Ok(ForceCancelOutcome::AlreadyCancelled(record)),
            AttemptState::Completed | AttemptState::Failed => {
                return Ok(ForceCancelOutcome::AlreadySettled(record));
            }
            _ => {}
        }

        if record.state.is_ready_indexed() {
            self.delete_ready_entry_for_record(wtxn, &record)?;
        }
        force_cancel_record(
            &mut record,
            input.authority.grounds(),
            input.authority.actor().to_owned(),
            input.reason,
            input.now,
        )?;
        let encoded = encode_record(&record)?;
        self.store
            .attempt_records
            .put(wtxn, record.id.as_bytes(), &encoded)?;
        // A hard cancellation is a terminal queue door, so a PACK loaded by
        // the attempt still receives the same atomic receipt as complete/fail.
        crate::receipt::stamp_attempt_pack_receipt_in_txn(
            self.store,
            wtxn,
            &record,
            input.authority.actor(),
        )?;
        self.delete_dedupe_entry_for_record(wtxn, &record)?;
        Ok(ForceCancelOutcome::Cancelled(record))
    }

    /// Runtime QUOTA/BUDGET warning — the `budget.land.95` rung's queue door.
    ///
    /// The runtime, not an actor, authors it: a worker whose wake counter is
    /// nearly spent is asked to LAND while there is still budget to land WITH,
    /// which is the whole point of holding a reserve back. Idempotent per
    /// outstanding ask, so a loop that observes pressure on every iteration
    /// records one row and does not inflate the refusal pressure counters.
    pub fn warn_budget_pressure(
        &self,
        input: WarnAttemptBudgetPressure,
    ) -> Result<LandingWarningOutcome> {
        let mut wtxn = self.store.env.write_txn()?;
        let outcome = self.warn_budget_pressure_in_txn(&mut wtxn, input)?;
        wtxn.commit()?;
        Ok(outcome)
    }

    /// Transaction-composable [`Self::warn_budget_pressure`].
    pub(crate) fn warn_budget_pressure_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: WarnAttemptBudgetPressure,
    ) -> Result<LandingWarningOutcome> {
        let Some(raw_record) = self.store.attempt_records.get(wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("budget_warning", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        match record.state {
            AttemptState::Leased => {}
            AttemptState::Landing => return Ok(LandingWarningOutcome::AlreadyRequested(record)),
            _ => return Ok(LandingWarningOutcome::NotRunning(record)),
        }
        if record.cancel_state.pressure.pending > 0 {
            return Ok(LandingWarningOutcome::AlreadyRequested(record));
        }

        self.record_soft_request(
            wtxn,
            &mut record,
            SoftRequestAuthorship {
                actor: ATTEMPT_RUNTIME_ACTOR.to_owned(),
                // No standing token: the runtime is not an actor making a
                // claim, and only these runtime doors may author the row.
                standing: None,
                trigger: LandingTrigger::BudgetWarning,
                reason: None,
            },
            input.now,
        )?;
        Ok(LandingWarningOutcome::LandingRequested(record))
    }

    /// Sweeps live leases and WARNS the ones inside the expiry window.
    ///
    /// The lane that reclaims expired leases ([`Self::cleanup_leases`]) is the
    /// one lane that already knows the lease timeout, so the warning rung lives
    /// beside it and stays strictly distinct from it: this door never
    /// terminalizes, never requeues, and never touches a row whose lease has
    /// ALREADY expired — that row belongs to cleanup's hard rung.
    pub fn warn_expiring_leases(
        &self,
        input: WarnExpiringAttemptLeases,
    ) -> Result<AttemptLeaseWarningReport> {
        if input.lease_timeout_secs == 0 {
            return Err(Error::InvalidAttemptQueueRecord(
                super::validate::ERR_LEASE_TIMEOUT_ZERO,
            ));
        }

        let mut candidates = Vec::new();
        {
            let rtxn = self.store.env.read_txn()?;
            for row in self.store.attempt_records.iter(&rtxn)? {
                let (key, raw_record) = row?;
                let id = AttemptId::from_bytes(&key)?;
                let record = decode_record(&raw_record, id)?;
                if record.state == AttemptState::Leased {
                    candidates.push(id);
                }
            }
        }

        let mut report = AttemptLeaseWarningReport::default();
        if candidates.is_empty() {
            return Ok(report);
        }

        let mut wtxn = self.store.env.write_txn()?;
        for id in candidates {
            let Some(raw_record) = self.store.attempt_records.get(&wtxn, id.as_bytes())? else {
                continue;
            };
            let mut record = decode_record(&raw_record, id)?;
            if record.state != AttemptState::Leased {
                continue;
            }
            report.scanned += 1;
            if lease_expired(&record, input.now, input.lease_timeout_secs) {
                report.expired += 1;
                continue;
            }
            let age = input.now.saturating_sub(record.updated_at);
            if age < lease_warning_after_secs(input.lease_timeout_secs) {
                report.not_due += 1;
                continue;
            }
            if record.cancel_state.pressure.pending > 0 {
                report.already_requested += 1;
                continue;
            }
            self.record_soft_request(
                &mut wtxn,
                &mut record,
                SoftRequestAuthorship {
                    actor: ATTEMPT_RUNTIME_ACTOR.to_owned(),
                    standing: None,
                    trigger: LandingTrigger::LeaseWarning,
                    reason: None,
                },
                input.now,
            )?;
            report.warned += 1;
        }
        wtxn.commit()?;
        Ok(report)
    }

    /// Runtime lease-expiry WARNING — the soft rung, not the reclaim.
    ///
    /// Inside the warning window the runtime asks the worker to land, which is
    /// the whole point of the distinction: expiry can only reclaim or force,
    /// and by then the worker's unlanded work is already lost. The request is
    /// idempotent per outstanding ask, so repeated polling records one row.
    pub fn warn_lease_expiry(&self, input: WarnAttemptLeaseExpiry) -> Result<LeaseWarningOutcome> {
        if input.lease_timeout_secs == 0 {
            return Err(Error::InvalidAttemptQueueRecord(
                super::validate::ERR_LEASE_TIMEOUT_ZERO,
            ));
        }

        let mut wtxn = self.store.env.write_txn()?;
        let Some(raw_record) = self.store.attempt_records.get(&wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("lease_warning", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        match record.state {
            AttemptState::Landing => return Ok(LeaseWarningOutcome::AlreadyRequested(record)),
            AttemptState::Leased => {}
            state => return Err(invalid_transition("lease_warning", state.as_str())),
        }
        if lease_expired(&record, input.now, input.lease_timeout_secs) {
            return Ok(LeaseWarningOutcome::Expired(record));
        }
        let warn_after_secs = lease_warning_after_secs(input.lease_timeout_secs);
        let age = input.now.saturating_sub(record.updated_at);
        if age < warn_after_secs {
            return Ok(LeaseWarningOutcome::NotDue(record));
        }
        if record.cancel_state.pressure.pending > 0 {
            return Ok(LeaseWarningOutcome::AlreadyRequested(record));
        }

        self.record_soft_request(
            &mut wtxn,
            &mut record,
            SoftRequestAuthorship {
                actor: ATTEMPT_RUNTIME_ACTOR.to_owned(),
                // No standing token: this row is the RUNTIME's own warning, not
                // a request an actor made, and only these runtime doors may
                // author it.
                standing: None,
                trigger: LandingTrigger::LeaseWarning,
                reason: None,
            },
            input.now,
        )?;
        wtxn.commit()?;
        Ok(LeaseWarningOutcome::LandingRequested(record))
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

    fn delete_dedupe_entry_for_record(
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

    fn delete_ready_entry_for_record(
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

/// Every soft request still owed an answer, OLDEST FIRST.
///
/// A request's identity is its own receipt `sequence`, and an answer names the
/// request it consumed, so "still pending" is the set difference — not a guess
/// from recency. Gated on the pending counter so an already-answered round
/// (or a terminal row, whose asks are moot) yields nothing.
fn pending_soft_requests(record: &AttemptRecord) -> Vec<&AttemptCancelReceipt> {
    if record.cancel_state.pressure.pending == 0 {
        return Vec::new();
    }
    let answered: HashSet<u64> = record
        .cancel_state
        .receipts
        .iter()
        .filter(|receipt| receipt.kind.answers_request())
        .filter_map(|receipt| receipt.request_sequence)
        .collect();
    record
        .cancel_state
        .receipts
        .iter()
        .filter(|receipt| {
            receipt.kind == AttemptCancelReceiptKind::SoftRequested
                && !answered.contains(&receipt.sequence)
        })
        .collect()
}

/// Resolves WHICH outstanding request a worker's answer consumes.
///
/// `None` selects the oldest outstanding ask — the only recency rule that is
/// stable under repeated asking. An explicit sequence must name a request that
/// is actually outstanding: answering an unknown or already-answered one is a
/// typed refusal, never a silent re-answer of some other requester's ask.
fn select_pending_request<'r>(
    record: &'r AttemptRecord,
    request_sequence: Option<u64>,
    action: &'static str,
) -> Result<Option<&'r AttemptCancelReceipt>> {
    let pending = pending_soft_requests(record);
    match request_sequence {
        None => Ok(pending.first().copied()),
        Some(sequence) => pending
            .into_iter()
            .find(|receipt| receipt.sequence == sequence)
            .map(Some)
            .ok_or_else(|| invalid_transition(action, "unknown_request")),
    }
}

/// Instant, as an age against the lease clock, at which the runtime may warn.
fn lease_warning_after_secs(lease_timeout_secs: u64) -> u64 {
    let warn_after =
        ((u128::from(lease_timeout_secs) * u128::from(LEASE_LANDING_WARNING_PERCENT)) / 100) as u64;
    // A one-second timeout must still leave a window where warning is possible
    // and expiry has not happened; without the clamp the warning instant and
    // the expiry instant coincide and the warning rung is unreachable.
    warn_after.min(lease_timeout_secs.saturating_sub(1))
}

/// Validates the identity a hard cancellation would author its terminal
/// receipt with, by the grounds it rests on.
///
/// An OWNER is an ordinary actor and is held to the ordinary actor rules,
/// including the refusal to claim the reserved runtime name. The two RUNTIME
/// grounds legitimately carry [`ATTEMPT_RUNTIME_ACTOR`], so they are validated
/// as a plain actor name.
fn validate_force_authority(authority: &ForceCancelAuthority) -> Result<()> {
    match authority.grounds() {
        ForceCancelGrounds::Owner => validate_cancel_actor(authority.actor()),
        ForceCancelGrounds::LeaseExpiry | ForceCancelGrounds::Criticality => {
            validate_intervention_actor(authority.actor())
        }
    }
}

/// Applies a terminal, runtime-authored hard cancellation in place.
///
/// `actor` comes from the [`super::types::ForceCancelAuthority`], never from
/// request text, and the reason rides the cancellation receipt rather than
/// `last_error` — a cancelled row is not a failed one.
fn force_cancel_record(
    record: &mut AttemptRecord,
    grounds: ForceCancelGrounds,
    actor: String,
    reason: Option<String>,
    now: u64,
) -> Result<()> {
    let trigger = record.cancel_state.landing.as_ref().map(|l| l.trigger);
    record.state = AttemptState::Cancelled;
    record.lease_owner = None;
    record.scheduled_at = None;
    record.backoff_until = None;
    record.last_error = None;
    record.updated_at = now;
    record.cancel_state.pressure.pending = 0;
    record.cancel_state.cancellation = Some(AttemptCancellation {
        mode: CancelMode::Forced,
        grounds: Some(grounds),
        actor: actor.clone(),
        at: now,
        reason: reason.clone(),
        trigger,
        reserve_units: record.cancel_state.reserve.reserve_units,
        reserve_spent_units: record.cancel_state.reserve.spent_units,
    });
    let resume_point = record.cancel_state.resume_point.clone();
    let reserve_spent_units = record.cancel_state.reserve.spent_units;
    append_cancel_receipt(
        record,
        AttemptCancelReceiptKind::ForceCancelled,
        actor,
        CancelReceiptDraft {
            trigger,
            grounds: Some(grounds),
            reason,
            resume_point,
            reserve_units: reserve_spent_units,
            ..CancelReceiptDraft::default()
        },
        now,
    )
}

/// Mints the successor row a landing hands off to.
///
/// It is linked by `retry_of`, the same explicit row link a retry uses, so
/// every existing surface that reduces a chain to its live HEAD — run-tree
/// parenting, `tasks.cancel` membership, terminal-status folding — treats the
/// landed row as superseded history without a second lineage concept.
fn landing_successor(source: &AttemptRecord, scheduled_at: Option<u64>, now: u64) -> AttemptRecord {
    AttemptRecord {
        id: AttemptId::now(),
        kind: source.kind.clone(),
        payload: source.payload.clone(),
        state: if scheduled_at.is_some() {
            AttemptState::Scheduled
        } else {
            AttemptState::Queued
        },
        lease_owner: None,
        attempt_count: 0,
        claimed_at: None,
        scheduled_at,
        retry_of: Some(source.id),
        backoff_until: None,
        last_error: None,
        task_ref: source.task_ref.clone(),
        run_id: source.run_id.clone(),
        dedupe_key: source.dedupe_key.clone(),
        created_at: now,
        updated_at: now,
        events: Vec::new(),
        manifest: Vec::new(),
        cancel_state: AttemptCancelState {
            // The whole point of a designed landing: the successor starts from
            // the exact recorded point, with a fresh reserve on the same dial.
            resume_point: source.cancel_state.resume_point.clone(),
            reserve: AttemptLandingReserve {
                spent_units: 0,
                ..source.cancel_state.reserve
            },
            ..AttemptCancelState::default()
        },
    }
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
