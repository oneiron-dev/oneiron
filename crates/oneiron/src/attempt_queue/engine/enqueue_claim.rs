//! Enqueue doors plus kind-scoped claim machinery and read-repair scans.

use std::collections::HashSet;

use crate::Vault;
use crate::attempt_queue::cancel::AttemptCancelState;
use crate::attempt_queue::encoding::{
    DedupeIndexKeys, READY_KEY_LEN, decode_ready_key, decode_record, encode_record, ready_at,
    ready_key,
};
use crate::attempt_queue::types::{
    AttemptId, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome, EnqueueAttempt,
    EnqueueOutcome,
};
use crate::attempt_queue::validate::{
    lease_claimed_record, validate_kind, validate_lease_owner, validate_optional_dedupe,
    validate_optional_dedupe_actor_ref, validate_optional_run_id,
};
use crate::error::Result;

use super::AttemptQueue;
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
const CLAIM_KIND_WRITE_RETRY_LIMIT: usize = 3;
/// A dedupe index entry pointing at a row whose actor scope is not the one the
/// key family named. Reported as corruption, never as a dedupe miss: silently
/// enqueueing a second live row would be the exact double-send the index is
/// there to prevent.
pub(super) const ERR_DEDUPE_ACTOR_MISMATCH: &str = "dedupe index points at a different actor scope";
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
            result_ref: None,
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
}
