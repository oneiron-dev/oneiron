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
    DedupeIndexKeys, READY_KEY_LEN, decode_ready_key, decode_record, encode_record, lease_expired,
    legacy_dedupe_index_key, ready_at, ready_key, validate_dedupe_record, waiting_on_backoff,
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
    validate_manifest_entry, validate_optional_dedupe, validate_optional_dedupe_actor_ref,
    validate_optional_failure_reason, validate_optional_intervention_note,
    validate_optional_run_id, validate_transition_lease,
};

const RETRY_REASON_LEASE_TIMEOUT: &str = "lease_timeout";
/// A dedupe index entry pointing at a row whose actor scope is not the one the
/// key family named. Reported as corruption, never as a dedupe miss: silently
/// enqueueing a second live row would be the exact double-send the index is
/// there to prevent.
const ERR_DEDUPE_ACTOR_MISMATCH: &str = "dedupe index points at a different actor scope";
/// Stable reason stamped on a retried source row when the caller supplied none.
pub(super) const RETRY_REASON_UNSPECIFIED: &str = "retry";
const CLAIM_KIND_WRITE_RETRY_LIMIT: usize = 3;
const DREAMER_RUN_ROOT_CLIMB_LIMIT: usize = 64;
/// Point reads one [`AttemptQueue::retry_chain_depth`] walk may spend. A
/// lineage this long is already past every backoff ceiling that reads it, so
/// the depth saturates here instead of letting a walk grow with the row set.
pub(super) const RETRY_CHAIN_DEPTH_LIMIT: u32 = 1_024;
/// A `retry_of` link naming a row this queue does not hold.
pub(super) const ERR_RETRY_CHAIN_MISSING_ROW: &str = "retry chain names a missing attempt";
/// A `retry_of` link returning to a row already on the walk.
pub(super) const ERR_RETRY_CHAIN_CYCLE: &str = "retry chain cycles";
/// A `retry_of` link naming an existing row that is not a try of this attempt.
pub(super) const ERR_RETRY_CHAIN_MISMATCH: &str = "retry chain links unrelated attempts";

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
        // This public door is actorless, and stays that way: every caller
        // reaching it keeps the exact v1 key family, its pre-v1 raw fallback,
        // and that fallback's self-heal — byte-identical to before the actor
        // axis existed.
        let actor_ref: Option<&str> = None;
        validate_kind(&input.kind)?;
        validate_optional_dedupe(input.dedupe_key.as_deref())?;
        validate_optional_dedupe_actor_ref(actor_ref)?;
        validate_optional_run_id(input.run_id.as_deref())?;

        if let Some(dedupe_key) = input.dedupe_key.as_deref() {
            let keys = DedupeIndexKeys::new(&input.kind, actor_ref, dedupe_key);
            let rtxn = self.store.env.read_txn()?;
            if let Some(record) = self.read_existing_dedupe_in_read_txn(
                &rtxn,
                &keys.primary[..],
                &input.kind,
                actor_ref,
                dedupe_key,
            )? {
                return Ok(EnqueueOutcome::Existing(record));
            }
        }

        let mut wtxn = self.store.env.write_txn()?;
        let outcome = self
            .enqueue_with_task_ref_and_dedupe_actor_in_txn(&mut wtxn, input, task_ref, actor_ref)?;
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
        self.enqueue_with_task_ref_and_dedupe_actor_in_txn(wtxn, input, None, None)
    }

    /// Transaction-composable enqueue with an owning TASK backlink.
    pub(crate) fn enqueue_with_task_ref_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: EnqueueAttempt,
        task_ref: Option<String>,
    ) -> Result<EnqueueOutcome> {
        self.enqueue_with_task_ref_and_dedupe_actor_in_txn(wtxn, input, task_ref, None)
    }

    /// Transaction-composable enqueue that scopes the advisory dedupe index to
    /// one actor.
    ///
    /// The scope is NOT part of [`EnqueueAttempt`] and never comes from caller
    /// content: a caller that has an authenticated actor passes it here, and
    /// every other caller keeps the actorless key family unchanged. Two actors
    /// sharing one client key therefore occupy disjoint entries, instead of the
    /// second one silently coalescing onto the first one's pending row.
    pub(crate) fn enqueue_with_task_ref_and_dedupe_actor_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: EnqueueAttempt,
        task_ref: Option<String>,
        dedupe_actor_ref: Option<&str>,
    ) -> Result<EnqueueOutcome> {
        validate_kind(&input.kind)?;
        validate_optional_dedupe(input.dedupe_key.as_deref())?;
        validate_optional_dedupe_actor_ref(dedupe_actor_ref)?;
        validate_optional_run_id(input.run_id.as_deref())?;

        // Key-gated persistence: with no key there is no index entry to scope,
        // so a scope offered anyway is normalized away rather than written into
        // a row that decode would then refuse.
        let persisted_actor_ref = input
            .dedupe_key
            .as_ref()
            .and_then(|_| dedupe_actor_ref.map(str::to_owned));
        let scoped_actor_ref = persisted_actor_ref.as_deref();
        let dedupe_keys = input
            .dedupe_key
            .as_deref()
            .map(|dedupe_key| DedupeIndexKeys::new(&input.kind, scoped_actor_ref, dedupe_key));
        if let (Some(dedupe_key), Some(keys)) = (input.dedupe_key.as_deref(), dedupe_keys.as_ref())
            && let Some(record) = self.read_existing_dedupe_in_write_txn(
                wtxn,
                keys,
                &input.kind,
                scoped_actor_ref,
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
            dedupe_actor_ref: persisted_actor_ref,
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
        // A new row writes its OWN family only. An actor-scoped row never
        // manufactures a v1 entry, which would re-create the actor-blind
        // collision this key family exists to end.
        if let Some(keys) = dedupe_keys.as_ref() {
            self.store
                .attempt_dedupe
                .put(wtxn, &keys.primary[..], record.id.as_bytes())?;
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

    /// Counts the retries that precede `id` by walking its `retry_of` lineage.
    ///
    /// A first try is depth 0 and every `retry_of` hop adds one. [`Self::retry`]
    /// mints a NEW row whose `attempt_count` restarts at zero, so the lineage
    /// is the only honest logical retry counter: a caller spacing retries must
    /// read the depth here rather than infer one from a per-row lease counter.
    ///
    /// Missing rows, cycles, and content-inconsistent hops encountered during
    /// the bounded walk fail CLOSED with [`Error::InvalidAttemptQueueRecord`],
    /// never a silently short depth that would collapse a long backoff onto
    /// its first rung. Every visited hop compares six fields: `kind`, `payload`,
    /// `task_ref`, `run_id`, `dedupe_key`, and `dedupe_actor_ref`. This checks
    /// content consistency, not general chain uniqueness: unrelated rows with
    /// identical values for all six fields are indistinguishable. To distinguish
    /// independent roots, they must differ on at least one of these fields.
    /// The durable connector satisfies this prerequisite with a unique
    /// `task_ref` per independent root.
    ///
    /// The walk reads the initial row plus at most `RETRY_CHAIN_DEPTH_LIMIT`
    /// (1,024) parent rows. Hop depth saturates at 1,024, so a legitimately vast
    /// lineage is bounded work rather than an error. All rows read one snapshot,
    /// so a concurrent retry cannot make the walk observe half of two different
    /// chains.
    pub fn retry_chain_depth(&self, id: AttemptId) -> Result<u32> {
        let rtxn = self.store.env.read_txn()?;
        let mut visited = HashSet::from([id]);
        let mut child = self.retry_chain_record_in_txn(&rtxn, id)?;
        let mut depth = 0_u32;
        while let Some(parent_id) = child.retry_of {
            // A revisit is a CYCLE before it is anything else: a row already on
            // the walk trivially matches itself on identity, so the field
            // compare below could never be the one to stop an endless loop.
            if !visited.insert(parent_id) {
                return Err(Error::InvalidAttemptQueueRecord(ERR_RETRY_CHAIN_CYCLE));
            }
            let parent = self.retry_chain_record_in_txn(&rtxn, parent_id)?;
            if !retries_the_same_attempt(&child, &parent) {
                return Err(Error::InvalidAttemptQueueRecord(ERR_RETRY_CHAIN_MISMATCH));
            }
            depth = depth.saturating_add(1);
            if depth >= RETRY_CHAIN_DEPTH_LIMIT {
                return Ok(RETRY_CHAIN_DEPTH_LIMIT);
            }
            child = parent;
        }
        Ok(depth)
    }

    /// One row of the lineage walk: it must exist, or the chain is broken.
    ///
    /// Yields the whole decoded record, not just its link, so the hop that
    /// follows can check parent-child identity within the same one read and
    /// one decode this walk already spends per visited row.
    fn retry_chain_record_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: AttemptId,
    ) -> Result<AttemptRecord> {
        let Some(raw) = self.store.attempt_records.get(rtxn, id.as_bytes())? else {
            return Err(Error::InvalidAttemptQueueRecord(
                ERR_RETRY_CHAIN_MISSING_ROW,
            ));
        };
        decode_record(&raw, id)
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
        expected_dedupe_actor_ref: Option<&str>,
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
        if record.dedupe_actor_ref.as_deref() != expected_dedupe_actor_ref {
            return Err(Error::InvalidAttemptQueueRecord(ERR_DEDUPE_ACTOR_MISMATCH));
        }
        if !record.state.is_pending() {
            return Ok(None);
        }
        Ok(Some(record))
    }

    /// Resolves a live dedupe hit in family order, checking the actor axis
    /// per path.
    ///
    /// An ACTOR-SCOPED request reads its own v2 entry, then the actorless v1
    /// entry, then the pre-v1 raw key. A pending legacy row has no trustworthy
    /// actor axis, so it stays the conservative winner until its chain
    /// terminalizes — returned as a hit without rewriting the row, promoting
    /// either index, or running the actorless self-heal.
    ///
    /// An ACTORLESS request keeps exactly today's behavior: the v1 entry, then
    /// the pre-v1 raw key with its landed raw→v1 self-heal. It never
    /// manufactures an actor scope.
    fn read_existing_dedupe_in_write_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        keys: &DedupeIndexKeys,
        kind: &str,
        dedupe_actor_ref: Option<&str>,
        dedupe_key: &str,
    ) -> Result<Option<AttemptRecord>> {
        if let Some(record) = self.read_existing_dedupe_entry_in_write_txn(
            txn,
            &keys.primary[..],
            kind,
            dedupe_actor_ref,
            dedupe_key,
        )? {
            return Ok(Some(record));
        }

        let legacy_key = legacy_dedupe_index_key(kind, dedupe_key);
        match keys.fallback_v1 {
            // Actor-scoped: both legacy families are READ-ONLY here. A pending
            // actorless row keeps the key until its chain terminalizes, and
            // nothing about it is rewritten or promoted on the way out.
            Some(fallback_v1) => {
                if let Some(record) = self.read_existing_dedupe_entry_in_write_txn(
                    txn,
                    &fallback_v1[..],
                    kind,
                    None,
                    dedupe_key,
                )? {
                    return Ok(Some(record));
                }
                self.read_existing_dedupe_entry_in_write_txn(
                    txn,
                    &legacy_key,
                    kind,
                    None,
                    dedupe_key,
                )
            }
            // Actorless: today's pre-v1 raw fallback, including its landed
            // raw -> v1 index self-heal.
            None => {
                let Some(record) = self.read_existing_dedupe_entry_in_write_txn(
                    txn,
                    &legacy_key,
                    kind,
                    None,
                    dedupe_key,
                )?
                else {
                    return Ok(None);
                };
                self.store
                    .attempt_dedupe
                    .put(txn, &keys.primary[..], record.id.as_bytes())?;
                self.store.attempt_dedupe.delete(txn, &legacy_key)?;
                Ok(Some(record))
            }
        }
    }

    /// Reads one index entry, reaping it when it is verifiably stale.
    ///
    /// Reaping and terminal cleanup are distinct: this path deletes the entry
    /// it just examined and found dead, whichever family it belongs to, while
    /// cleanup derives keys only from a record's own persisted scope. A kind,
    /// key, or actor mismatch is corruption, never a miss.
    fn read_existing_dedupe_entry_in_write_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        index_key: &[u8],
        kind: &str,
        expected_dedupe_actor_ref: Option<&str>,
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
        if record.dedupe_actor_ref.as_deref() != expected_dedupe_actor_ref {
            return Err(Error::InvalidAttemptQueueRecord(ERR_DEDUPE_ACTOR_MISMATCH));
        }
        if !record.state.is_pending() {
            self.store.attempt_dedupe.delete(txn, index_key)?;
            return Ok(None);
        }
        Ok(Some(record))
    }

    /// Retires the index entries a settled row OWNS.
    ///
    /// Ownership follows the row's persisted scope: an actor-scoped row owns
    /// exactly its own v2 entry, because the v1 and pre-v1 raw entries may
    /// still belong to another actor's live legacy chain. An actorless row owns
    /// both of those, exactly as before.
    pub(super) fn delete_dedupe_entry_for_record(
        &self,
        txn: &mut heed::RwTxn<'_>,
        record: &AttemptRecord,
    ) -> Result<()> {
        if let Some(dedupe_key) = record.dedupe_key.as_deref() {
            let keys =
                DedupeIndexKeys::new(&record.kind, record.dedupe_actor_ref.as_deref(), dedupe_key);
            self.store.attempt_dedupe.delete(txn, &keys.primary[..])?;
            if record.dedupe_actor_ref.is_none() {
                let legacy_key = legacy_dedupe_index_key(&record.kind, dedupe_key);
                self.store.attempt_dedupe.delete(txn, &legacy_key)?;
            }
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

/// Whether a `retry_of` link joins two tries of the SAME attempt.
///
/// Both writers of that link — [`AttemptQueue::retry`] and the landing
/// successor in [`super::cancel`] — copy exactly these six fields verbatim
/// from the source row to the row that supersedes it, so a hop differing on
/// any of them is corruption by construction rather than a lineage. Nothing
/// else in the row is comparable: state, lease, counters, timestamps and the
/// event/manifest/cancel logs are all EXPECTED to diverge between a finalized
/// source and its fresh successor, which is why the link cannot be checked by
/// record equality.
fn retries_the_same_attempt(child: &AttemptRecord, parent: &AttemptRecord) -> bool {
    child.kind == parent.kind
        && child.payload == parent.payload
        && child.task_ref == parent.task_ref
        && child.run_id == parent.run_id
        && child.dedupe_key == parent.dedupe_key
        && child.dedupe_actor_ref == parent.dedupe_actor_ref
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
