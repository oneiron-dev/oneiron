//! Generic LMDB-backed background job queue.
//!
//! This is intentionally mechanical storage state only: enqueue, claim,
//! complete, fail, and retry transition LMDB rows atomically, while execution
//! policy, timeout cleanup, and metrics stay outside this module.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

use crate::Vault;
use crate::error::{Error, Result};
use crate::store::Store;

const JOB_RECORD_VERSION: u8 = 1;
const DEDUPE_DOMAIN: &[u8] = b"oneiron.job_queue.dedupe.v1\0";
const DEDUPE_INDEX_KEY_LEN: usize = 32;
const READY_KEY_LEN: usize = 24;
const MAX_KIND_LEN: usize = 128;
const MAX_DEDUPE_KEY_LEN: usize = 512;
const MAX_FAILURE_REASON_LEN: usize = 2048;
const MAX_LEASE_OWNER_LEN: usize = 128;
const MAX_RUN_ID_LEN: usize = 128;
const ERR_EMPTY_KIND: &str = "kind must not be empty";
const ERR_KIND_TOO_LONG: &str = "kind exceeds 128 bytes";
const ERR_DEDUPE_KEY_EMPTY: &str = "dedupe key must not be empty";
const ERR_DEDUPE_KEY_TOO_LONG: &str = "dedupe key exceeds 512 bytes";
const ERR_FAILURE_REASON_EMPTY: &str = "failure reason must not be empty";
const ERR_FAILURE_REASON_TOO_LONG: &str = "failure reason exceeds 2048 bytes";
const ERR_LEASE_OWNER_EMPTY: &str = "lease owner must not be empty";
const ERR_LEASE_OWNER_TOO_LONG: &str = "lease owner exceeds 128 bytes";
const ERR_RUN_ID_EMPTY: &str = "run id must not be empty";
const ERR_RUN_ID_TOO_LONG: &str = "run id exceeds 128 bytes";
const ERR_JOB_ID_LEN: &str = "job id must be 16 bytes";
const ERR_DEDUPE_KIND_MISMATCH: &str = "dedupe index points at a different job kind";
const ERR_READY_KEY_LEN: &str = "ready index key must be 24 bytes";

/// Stable identifier for a queued job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JobId {
    bytes: [u8; 16],
}

impl JobId {
    /// Creates a new time-sortable v7 UUID-backed job id.
    #[must_use]
    pub fn now() -> Self {
        Self {
            bytes: Uuid::now_v7().into_bytes(),
        }
    }

    /// Returns the raw 16-byte storage key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.bytes
    }

    /// Parses a raw 16-byte storage key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; 16] = bytes
            .try_into()
            .map_err(|_| Error::InvalidJobQueueRecord(ERR_JOB_ID_LEN))?;
        Ok(Self { bytes })
    }
}

/// Durable lifecycle state persisted on each job row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum JobState {
    Queued,
    Leased,
    Completed,
    Failed,
}

impl JobState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Leased => "leased",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    const fn is_pending(self) -> bool {
        matches!(self, Self::Queued | Self::Leased)
    }
}

/// Durable job row stored in LMDB.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecord {
    pub id: JobId,
    pub kind: String,
    pub payload: Vec<u8>,
    pub state: JobState,
    pub lease_owner: Option<String>,
    pub attempt_count: u32,
    #[serde(default)]
    pub backoff_until: Option<u64>,
    #[serde(default)]
    pub last_error: Option<String>,
    pub run_id: Option<String>,
    pub dedupe_key: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Input for enqueueing a job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnqueueJob {
    pub kind: String,
    pub payload: Vec<u8>,
    pub dedupe_key: Option<String>,
    pub run_id: Option<String>,
    pub now: u64,
}

/// Typed enqueue outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnqueueOutcome {
    Enqueued(JobRecord),
    Existing(JobRecord),
}

/// Input for atomically claiming the next queued job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimJob {
    pub lease_owner: String,
    pub now: u64,
}

/// Typed claim outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClaimOutcome {
    Empty,
    Claimed(JobRecord),
}

/// Input for completing a leased job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteJob {
    pub id: JobId,
    pub now: u64,
}

/// Typed complete outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompleteOutcome {
    Completed(JobRecord),
    AlreadyCompleted(JobRecord),
}

/// Input for failing a leased job terminally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailJob {
    pub id: JobId,
    pub reason: String,
    pub now: u64,
}

/// Typed fail outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FailOutcome {
    Failed(JobRecord),
    AlreadyFailed(JobRecord),
}

/// Input for returning a leased job to the ready index after a retryable
/// attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryJob {
    pub id: JobId,
    pub backoff_until: u64,
    pub last_error: Option<String>,
    pub now: u64,
}

/// Typed retry outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetryOutcome {
    Retried(JobRecord),
}

/// Queue handle over a vault store.
pub struct JobQueue<'a> {
    store: &'a Store,
}

impl<'a> JobQueue<'a> {
    /// Opens a queue handle over an already-open vault.
    #[must_use]
    pub fn new(vault: &'a Vault) -> Self {
        Self {
            store: &vault.store,
        }
    }

    /// Enqueues a job, returning an existing row when the caller-supplied
    /// dedupe key already maps to a job.
    pub fn enqueue(&self, input: EnqueueJob) -> Result<EnqueueOutcome> {
        validate_kind(&input.kind)?;
        validate_optional_dedupe(input.dedupe_key.as_deref())?;
        validate_optional_run_id(input.run_id.as_deref())?;

        let dedupe_index_keys = input
            .dedupe_key
            .as_deref()
            .map(|dedupe_key| DedupeIndexKeys::new(&input.kind, dedupe_key));
        if let (Some(dedupe_key), Some(index_keys)) =
            (input.dedupe_key.as_deref(), dedupe_index_keys.as_ref())
        {
            let rtxn = self.store.env.read_txn()?;
            if let Some(record) = self.read_existing_dedupe_in_read_txn(
                &rtxn,
                &index_keys.blake3[..],
                &input.kind,
                dedupe_key,
            )? {
                return Ok(EnqueueOutcome::Existing(record));
            }
        }

        let mut wtxn = self.store.env.write_txn()?;
        if let (Some(dedupe_key), Some(index_keys)) =
            (input.dedupe_key.as_deref(), dedupe_index_keys.as_ref())
            && let Some(record) = self.read_existing_dedupe_in_write_txn(
                &mut wtxn,
                index_keys,
                &input.kind,
                dedupe_key,
            )?
        {
            wtxn.commit()?;
            return Ok(EnqueueOutcome::Existing(record));
        }

        let record = JobRecord {
            id: JobId::now(),
            kind: input.kind,
            payload: input.payload,
            state: JobState::Queued,
            lease_owner: None,
            attempt_count: 0,
            backoff_until: None,
            last_error: None,
            run_id: input.run_id,
            dedupe_key: input.dedupe_key,
            created_at: input.now,
            updated_at: input.now,
        };

        let encoded = encode_record(&record)?;
        self.store
            .job_records
            .put(&mut wtxn, record.id.as_bytes(), &encoded)?;
        let ready_key = ready_key(ready_at(&record), record.id);
        self.store
            .job_ready
            .put(&mut wtxn, &ready_key, record.id.as_bytes())?;
        if let Some(index_keys) = dedupe_index_keys.as_ref() {
            self.store
                .job_dedupe
                .put(&mut wtxn, &index_keys.blake3[..], record.id.as_bytes())?;
        }
        wtxn.commit()?;

        Ok(EnqueueOutcome::Enqueued(record))
    }

    /// Atomically claims the oldest queued job under LMDB's single-writer
    /// invariant.
    pub fn claim(&self, input: ClaimJob) -> Result<ClaimOutcome> {
        validate_lease_owner(&input.lease_owner)?;

        let mut wtxn = self.store.env.write_txn()?;
        let mut stale_ready_keys = Vec::new();
        let mut ready_replacements = Vec::new();
        let mut stale_missing_record_ids = HashSet::new();
        let mut claimed = None;
        for row in self.store.job_ready.iter(&wtxn)? {
            let (key, value) = row?;
            let (key_ready_at, key_id) = decode_ready_key(key)?;
            if key_ready_at > input.now {
                break;
            }
            let id = JobId::from_bytes(value)?;
            if id != key_id {
                stale_ready_keys.push(key.to_vec());
                continue;
            }
            let Some(raw_record) = self.store.job_records.get(&wtxn, id.as_bytes())? else {
                stale_missing_record_ids.insert(id);
                stale_ready_keys.push(key.to_vec());
                continue;
            };
            let mut record = decode_record(raw_record, id)?;
            if record.state != JobState::Queued {
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
            }
            record.state = JobState::Leased;
            record.lease_owner = Some(input.lease_owner.clone());
            record.attempt_count = record
                .attempt_count
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("job attempt count"))?;
            record.backoff_until = None;
            record.updated_at = input.now;
            claimed = Some((key.to_vec(), id, record));
            break;
        }

        self.delete_dedupe_entries_for_ids(&mut wtxn, &stale_missing_record_ids)?;
        for key in stale_ready_keys {
            self.store.job_ready.delete(&mut wtxn, &key)?;
        }
        for (key, id) in ready_replacements {
            self.store.job_ready.put(&mut wtxn, &key, id.as_bytes())?;
        }

        let Some((ready_key, id, record)) = claimed else {
            wtxn.commit()?;
            return Ok(ClaimOutcome::Empty);
        };

        self.store.job_ready.delete(&mut wtxn, &ready_key)?;
        let encoded = encode_record(&record)?;
        self.store
            .job_records
            .put(&mut wtxn, id.as_bytes(), &encoded)?;
        wtxn.commit()?;

        Ok(ClaimOutcome::Claimed(record))
    }

    /// Marks a leased job complete. Completing an already-completed job is an
    /// idempotent success; all other states are rejected.
    pub fn complete(&self, input: CompleteJob) -> Result<CompleteOutcome> {
        let mut wtxn = self.store.env.write_txn()?;
        let Some(raw_record) = self.store.job_records.get(&wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("complete", "missing"));
        };
        let mut record = decode_record(raw_record, input.id)?;
        match record.state {
            JobState::Completed => {
                wtxn.commit()?;
                Ok(CompleteOutcome::AlreadyCompleted(record))
            }
            JobState::Leased => {
                record.state = JobState::Completed;
                record.lease_owner = None;
                record.backoff_until = None;
                record.last_error = None;
                record.updated_at = input.now;
                self.delete_dedupe_entry_for_record(&mut wtxn, &record)?;
                let encoded = encode_record(&record)?;
                self.store
                    .job_records
                    .put(&mut wtxn, record.id.as_bytes(), &encoded)?;
                wtxn.commit()?;
                Ok(CompleteOutcome::Completed(record))
            }
            state => Err(invalid_transition("complete", state.as_str())),
        }
    }

    /// Marks a leased job terminally failed. Failing an already-failed job is
    /// an idempotent success; all other states are rejected.
    pub fn fail(&self, input: FailJob) -> Result<FailOutcome> {
        validate_failure_reason(&input.reason)?;

        let mut wtxn = self.store.env.write_txn()?;
        let Some(raw_record) = self.store.job_records.get(&wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("fail", "missing"));
        };
        let mut record = decode_record(raw_record, input.id)?;
        match record.state {
            JobState::Failed => {
                wtxn.commit()?;
                Ok(FailOutcome::AlreadyFailed(record))
            }
            JobState::Leased => {
                record.state = JobState::Failed;
                record.lease_owner = None;
                record.backoff_until = None;
                record.last_error = Some(input.reason);
                record.updated_at = input.now;
                self.delete_dedupe_entry_for_record(&mut wtxn, &record)?;
                let encoded = encode_record(&record)?;
                self.store
                    .job_records
                    .put(&mut wtxn, record.id.as_bytes(), &encoded)?;
                wtxn.commit()?;
                Ok(FailOutcome::Failed(record))
            }
            state => Err(invalid_transition("fail", state.as_str())),
        }
    }

    /// Requeues a leased job with explicit backoff state after a retryable
    /// attempt. The original payload, run id, and advisory dedupe key stay on
    /// the same durable row.
    pub fn retry(&self, input: RetryJob) -> Result<RetryOutcome> {
        validate_optional_failure_reason(input.last_error.as_deref())?;

        let mut wtxn = self.store.env.write_txn()?;
        let Some(raw_record) = self.store.job_records.get(&wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("retry", "missing"));
        };
        let mut record = decode_record(raw_record, input.id)?;
        match record.state {
            JobState::Leased => {
                record.state = JobState::Queued;
                record.lease_owner = None;
                record.backoff_until = Some(input.backoff_until);
                record.last_error = input.last_error;
                record.updated_at = input.now;
                let encoded = encode_record(&record)?;
                self.store
                    .job_records
                    .put(&mut wtxn, record.id.as_bytes(), &encoded)?;
                let ready_key = ready_key(ready_at(&record), record.id);
                self.store
                    .job_ready
                    .put(&mut wtxn, &ready_key, record.id.as_bytes())?;
                wtxn.commit()?;
                Ok(RetryOutcome::Retried(record))
            }
            state => Err(invalid_transition("retry", state.as_str())),
        }
    }

    /// Reads a job by id.
    pub fn get(&self, id: JobId) -> Result<Option<JobRecord>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.job_records.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        decode_record(raw, id).map(Some)
    }

    fn read_existing_dedupe_in_read_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        index_key: &[u8],
        kind: &str,
        dedupe_key: &str,
    ) -> Result<Option<JobRecord>> {
        let Some(existing_id) = self.store.job_dedupe.get(txn, index_key)? else {
            return Ok(None);
        };
        let id = JobId::from_bytes(existing_id)?;
        let Some(raw) = self.store.job_records.get(txn, id.as_bytes())? else {
            return Ok(None);
        };
        let record = decode_record(raw, id)?;
        validate_dedupe_record(&record, kind, dedupe_key)?;
        if !record.state.is_pending() {
            return Ok(None);
        }
        Ok(Some(record))
    }

    fn read_existing_dedupe_in_write_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        index_keys: &DedupeIndexKeys,
        kind: &str,
        dedupe_key: &str,
    ) -> Result<Option<JobRecord>> {
        if let Some(record) = self.read_existing_dedupe_entry_in_write_txn(
            txn,
            &index_keys.blake3[..],
            kind,
            dedupe_key,
        )? {
            return Ok(Some(record));
        }

        let Some(record) = self.read_existing_dedupe_entry_in_write_txn(
            txn,
            &index_keys.legacy,
            kind,
            dedupe_key,
        )?
        else {
            return Ok(None);
        };
        self.store
            .job_dedupe
            .put(txn, &index_keys.blake3[..], record.id.as_bytes())?;
        self.store.job_dedupe.delete(txn, &index_keys.legacy)?;
        Ok(Some(record))
    }

    fn read_existing_dedupe_entry_in_write_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        index_key: &[u8],
        kind: &str,
        dedupe_key: &str,
    ) -> Result<Option<JobRecord>> {
        let Some(existing_id) = self.store.job_dedupe.get(txn, index_key)? else {
            return Ok(None);
        };
        let id = JobId::from_bytes(existing_id)?;
        let Some(raw) = self.store.job_records.get(txn, id.as_bytes())? else {
            self.store.job_dedupe.delete(txn, index_key)?;
            return Ok(None);
        };
        let record = decode_record(raw, id)?;
        validate_dedupe_record(&record, kind, dedupe_key)?;
        if !record.state.is_pending() {
            self.store.job_dedupe.delete(txn, index_key)?;
            return Ok(None);
        }
        Ok(Some(record))
    }

    fn delete_dedupe_entry_for_record(
        &self,
        txn: &mut heed::RwTxn<'_>,
        record: &JobRecord,
    ) -> Result<()> {
        if let Some(dedupe_key) = record.dedupe_key.as_deref() {
            let index_keys = DedupeIndexKeys::new(&record.kind, dedupe_key);
            self.store.job_dedupe.delete(txn, &index_keys.blake3[..])?;
            self.store.job_dedupe.delete(txn, &index_keys.legacy)?;
        }
        Ok(())
    }

    fn delete_dedupe_entries_for_ids(
        &self,
        txn: &mut heed::RwTxn<'_>,
        ids: &HashSet<JobId>,
    ) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let mut keys = Vec::new();
        for row in self.store.job_dedupe.iter(txn)? {
            let (key, value) = row?;
            let id = JobId::from_bytes(value)?;
            if ids.contains(&id) {
                keys.push(key.to_vec());
            }
        }
        for key in keys {
            self.store.job_dedupe.delete(txn, &key)?;
        }
        Ok(())
    }
}

fn validate_kind(kind: &str) -> Result<()> {
    if kind.is_empty() {
        return Err(Error::InvalidJobQueueRecord(ERR_EMPTY_KIND));
    }
    if kind.len() > MAX_KIND_LEN {
        return Err(Error::InvalidJobQueueRecord(ERR_KIND_TOO_LONG));
    }
    Ok(())
}

fn validate_optional_dedupe(dedupe_key: Option<&str>) -> Result<()> {
    if let Some(dedupe_key) = dedupe_key {
        if dedupe_key.is_empty() {
            return Err(Error::InvalidJobQueueRecord(ERR_DEDUPE_KEY_EMPTY));
        }
        if dedupe_key.len() > MAX_DEDUPE_KEY_LEN {
            return Err(Error::InvalidJobQueueRecord(ERR_DEDUPE_KEY_TOO_LONG));
        }
    }
    Ok(())
}

fn validate_failure_reason(reason: &str) -> Result<()> {
    validate_optional_failure_reason(Some(reason))
}

fn validate_optional_failure_reason(reason: Option<&str>) -> Result<()> {
    if let Some(reason) = reason {
        if reason.is_empty() {
            return Err(Error::InvalidJobQueueRecord(ERR_FAILURE_REASON_EMPTY));
        }
        if reason.len() > MAX_FAILURE_REASON_LEN {
            return Err(Error::InvalidJobQueueRecord(ERR_FAILURE_REASON_TOO_LONG));
        }
    }
    Ok(())
}

fn validate_optional_run_id(run_id: Option<&str>) -> Result<()> {
    if let Some(run_id) = run_id {
        if run_id.is_empty() {
            return Err(Error::InvalidJobQueueRecord(ERR_RUN_ID_EMPTY));
        }
        if run_id.len() > MAX_RUN_ID_LEN {
            return Err(Error::InvalidJobQueueRecord(ERR_RUN_ID_TOO_LONG));
        }
    }
    Ok(())
}

fn validate_lease_owner(lease_owner: &str) -> Result<()> {
    if lease_owner.is_empty() {
        return Err(Error::InvalidJobQueueRecord(ERR_LEASE_OWNER_EMPTY));
    }
    if lease_owner.len() > MAX_LEASE_OWNER_LEN {
        return Err(Error::InvalidJobQueueRecord(ERR_LEASE_OWNER_TOO_LONG));
    }
    Ok(())
}

fn validate_dedupe_record(record: &JobRecord, kind: &str, dedupe_key: &str) -> Result<()> {
    if record.kind != kind {
        return Err(Error::InvalidJobQueueRecord(ERR_DEDUPE_KIND_MISMATCH));
    }
    if record.dedupe_key.as_deref() != Some(dedupe_key) {
        return Err(Error::InvalidJobQueueRecord(
            "dedupe index points at a job with a different dedupe key",
        ));
    }
    Ok(())
}

struct DedupeIndexKeys {
    blake3: [u8; DEDUPE_INDEX_KEY_LEN],
    legacy: Vec<u8>,
}

impl DedupeIndexKeys {
    fn new(kind: &str, dedupe_key: &str) -> Self {
        Self {
            blake3: dedupe_index_key(kind, dedupe_key),
            legacy: legacy_dedupe_index_key(kind, dedupe_key),
        }
    }
}

fn dedupe_index_key(kind: &str, dedupe_key: &str) -> [u8; DEDUPE_INDEX_KEY_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DEDUPE_DOMAIN);
    hasher.update(&(kind.len() as u16).to_be_bytes());
    hasher.update(kind.as_bytes());
    hasher.update(&(dedupe_key.len() as u16).to_be_bytes());
    hasher.update(dedupe_key.as_bytes());
    *hasher.finalize().as_bytes()
}

fn legacy_dedupe_index_key(kind: &str, dedupe_key: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + kind.len() + dedupe_key.len());
    key.extend_from_slice(&(kind.len() as u16).to_be_bytes());
    key.extend_from_slice(kind.as_bytes());
    key.extend_from_slice(dedupe_key.as_bytes());
    key
}

fn ready_at(record: &JobRecord) -> u64 {
    record.backoff_until.unwrap_or(record.created_at)
}

fn ready_key(ready_at: u64, id: JobId) -> [u8; READY_KEY_LEN] {
    let mut key = [0_u8; READY_KEY_LEN];
    key[..8].copy_from_slice(&ready_at.to_be_bytes());
    key[8..].copy_from_slice(id.as_bytes());
    key
}

fn decode_ready_key(bytes: &[u8]) -> Result<(u64, JobId)> {
    if bytes.len() != READY_KEY_LEN {
        return Err(Error::InvalidJobQueueRecord(ERR_READY_KEY_LEN));
    }
    let mut created_at = [0_u8; 8];
    created_at.copy_from_slice(&bytes[..8]);
    Ok((
        u64::from_be_bytes(created_at),
        JobId::from_bytes(&bytes[8..])?,
    ))
}

fn encode_record(record: &JobRecord) -> Result<Vec<u8>> {
    let mut encoded = vec![JOB_RECORD_VERSION];
    let mut body = rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvalidJobQueueRecord("failed to encode job record"))?;
    encoded.append(&mut body);
    Ok(encoded)
}

fn decode_record(raw: &[u8], expected_id: JobId) -> Result<JobRecord> {
    let Some((&version, body)) = raw.split_first() else {
        return Err(Error::InvalidJobQueueRecord("missing job record version"));
    };
    if version != JOB_RECORD_VERSION {
        return Err(Error::InvalidJobQueueRecord(
            "unsupported job record version",
        ));
    }
    let record: JobRecord = rmp_serde::from_slice(body)
        .map_err(|_| Error::InvalidJobQueueRecord("failed to decode job record"))?;
    if record.id != expected_id {
        return Err(Error::InvalidJobQueueRecord("job_records key/id mismatch"));
    }
    validate_kind(&record.kind)?;
    validate_optional_dedupe(record.dedupe_key.as_deref())?;
    validate_optional_run_id(record.run_id.as_deref())?;
    validate_optional_failure_reason(record.last_error.as_deref())?;
    if let Some(lease_owner) = record.lease_owner.as_deref() {
        validate_lease_owner(lease_owner)?;
    }
    match record.state {
        JobState::Queued if record.lease_owner.is_some() => {
            return Err(Error::InvalidJobQueueRecord(
                "queued job must not have a lease owner",
            ));
        }
        JobState::Leased if record.lease_owner.is_none() => {
            return Err(Error::InvalidJobQueueRecord(
                "leased job must have a lease owner",
            ));
        }
        JobState::Leased if record.backoff_until.is_some() => {
            return Err(Error::InvalidJobQueueRecord(
                "leased job must not have backoff state",
            ));
        }
        JobState::Completed | JobState::Failed if record.lease_owner.is_some() => {
            return Err(Error::InvalidJobQueueRecord(
                "terminal job must not have a lease owner",
            ));
        }
        JobState::Completed | JobState::Failed if record.backoff_until.is_some() => {
            return Err(Error::InvalidJobQueueRecord(
                "terminal job must not have backoff state",
            ));
        }
        JobState::Completed if record.last_error.is_some() => {
            return Err(Error::InvalidJobQueueRecord(
                "completed job must not have a failure reason",
            ));
        }
        JobState::Failed if record.last_error.is_none() => {
            return Err(Error::InvalidJobQueueRecord(
                "failed job must have a failure reason",
            ));
        }
        _ => {}
    }
    Ok(record)
}

fn invalid_transition(action: &'static str, state: &'static str) -> Error {
    Error::InvalidJobQueueTransition { action, state }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Vault, VaultConfig};

    fn open_queue() -> (tempfile::TempDir, Vault) {
        crate::test_util::open_test_vault_with(VaultConfig::device())
    }

    fn enqueue(kind: &str, dedupe_key: Option<&str>, now: u64) -> EnqueueJob {
        EnqueueJob {
            kind: kind.to_owned(),
            payload: format!("payload-{now}").into_bytes(),
            dedupe_key: dedupe_key.map(str::to_owned),
            run_id: Some(format!("run-{now}")),
            now,
        }
    }

    fn assert_invalid_transition(err: Error, action: &'static str, state: &'static str) {
        assert!(matches!(
            err,
            Error::InvalidJobQueueTransition {
                action: got_action,
                state: got_state,
            } if got_action == action && got_state == state
        ));
    }

    #[test]
    fn job_queue_enqueue_persists_required_fields() -> Result<()> {
        let (_dir, vault) = open_queue();
        let queue = JobQueue::new(&vault);

        let EnqueueOutcome::Enqueued(job) =
            queue.enqueue(enqueue("claim_extraction", Some("turn:1"), 10))?
        else {
            panic!("expected new job");
        };

        let persisted = queue.get(job.id)?.expect("persisted job");
        assert_eq!(persisted.kind, "claim_extraction");
        assert_eq!(persisted.payload, b"payload-10");
        assert_eq!(persisted.state, JobState::Queued);
        assert_eq!(persisted.lease_owner, None);
        assert_eq!(persisted.attempt_count, 0);
        assert_eq!(persisted.backoff_until, None);
        assert_eq!(persisted.last_error, None);
        assert_eq!(persisted.run_id.as_deref(), Some("run-10"));
        assert_eq!(persisted.dedupe_key.as_deref(), Some("turn:1"));
        assert_eq!(persisted.created_at, 10);
        assert_eq!(persisted.updated_at, 10);

        Ok(())
    }

    #[test]
    fn job_queue_enqueue_is_idempotent_for_dedupe_key() -> Result<()> {
        let (_dir, vault) = open_queue();
        let queue = JobQueue::new(&vault);

        let EnqueueOutcome::Enqueued(first) =
            queue.enqueue(enqueue("claim_extraction", Some("same"), 10))?
        else {
            panic!("expected first enqueue");
        };
        let EnqueueOutcome::Existing(second) =
            queue.enqueue(enqueue("claim_extraction", Some("same"), 20))?
        else {
            panic!("expected existing enqueue");
        };

        assert_eq!(second.id, first.id);
        assert_eq!(second.payload, first.payload);
        assert_eq!(second.created_at, 10);

        Ok(())
    }

    #[test]
    fn job_queue_enqueue_uses_blake3_advisory_dedupe_key() -> Result<()> {
        let (_dir, vault) = open_queue();
        let queue = JobQueue::new(&vault);

        let EnqueueOutcome::Enqueued(job) =
            queue.enqueue(enqueue("claim_extraction", Some("same"), 10))?
        else {
            panic!("expected enqueue");
        };

        let index_key = dedupe_index_key("claim_extraction", "same");
        assert_eq!(index_key.len(), DEDUPE_INDEX_KEY_LEN);
        assert_ne!(index_key.as_slice(), b"\0\x10claim_extractionsame");

        let rtxn = vault.store.env.read_txn()?;
        let stored_id = vault
            .store
            .job_dedupe
            .get(&rtxn, &index_key)?
            .expect("dedupe row");
        assert_eq!(JobId::from_bytes(stored_id)?, job.id);

        Ok(())
    }

    #[test]
    fn job_queue_enqueue_self_heals_legacy_dedupe_index_key() -> Result<()> {
        let (_dir, vault) = open_queue();
        let queue = JobQueue::new(&vault);

        let EnqueueOutcome::Enqueued(job) =
            queue.enqueue(enqueue("claim_extraction", Some("same"), 10))?
        else {
            panic!("expected enqueue");
        };
        let blake3_key = dedupe_index_key("claim_extraction", "same");
        let legacy_key = legacy_dedupe_index_key("claim_extraction", "same");
        {
            let mut wtxn = vault.store.env.write_txn()?;
            vault.store.job_dedupe.delete(&mut wtxn, &blake3_key)?;
            vault
                .store
                .job_dedupe
                .put(&mut wtxn, &legacy_key, job.id.as_bytes())?;
            wtxn.commit()?;
        }

        let EnqueueOutcome::Existing(existing) =
            queue.enqueue(enqueue("claim_extraction", Some("same"), 20))?
        else {
            panic!("expected legacy dedupe hit");
        };
        assert_eq!(existing.id, job.id);

        let rtxn = vault.store.env.read_txn()?;
        let stored_id = vault
            .store
            .job_dedupe
            .get(&rtxn, &blake3_key)?
            .expect("self-healed BLAKE3 dedupe row");
        assert_eq!(JobId::from_bytes(stored_id)?, job.id);
        assert!(vault.store.job_dedupe.get(&rtxn, &legacy_key)?.is_none());

        Ok(())
    }

    #[test]
    fn job_queue_dedupe_key_is_scoped_by_kind() -> Result<()> {
        let (_dir, vault) = open_queue();
        let queue = JobQueue::new(&vault);

        let EnqueueOutcome::Enqueued(first) =
            queue.enqueue(enqueue("claim_extraction", Some("same"), 10))?
        else {
            panic!("expected first enqueue");
        };
        let EnqueueOutcome::Enqueued(second) =
            queue.enqueue(enqueue("signal_extraction", Some("same"), 20))?
        else {
            panic!("expected separate kind-scoped enqueue");
        };
        let EnqueueOutcome::Existing(third) =
            queue.enqueue(enqueue("claim_extraction", Some("same"), 30))?
        else {
            panic!("expected existing enqueue for matching kind");
        };

        assert_ne!(second.id, first.id);
        assert_eq!(third.id, first.id);
        assert_eq!(third.kind, "claim_extraction");

        Ok(())
    }

    #[test]
    fn job_queue_claim_is_atomic_and_returns_typed_states() -> Result<()> {
        let (_dir, vault) = open_queue();
        let queue = JobQueue::new(&vault);

        assert_eq!(
            queue.claim(ClaimJob {
                lease_owner: "worker-a".to_owned(),
                now: 10,
            })?,
            ClaimOutcome::Empty
        );

        let EnqueueOutcome::Enqueued(first) = queue.enqueue(enqueue("first", None, 10))? else {
            panic!("expected first enqueue");
        };
        let EnqueueOutcome::Enqueued(second) = queue.enqueue(enqueue("second", None, 20))? else {
            panic!("expected second enqueue");
        };

        let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimJob {
            lease_owner: "worker-a".to_owned(),
            now: 30,
        })?
        else {
            panic!("expected claimed job");
        };
        assert_eq!(claimed.id, first.id);
        assert_eq!(claimed.state, JobState::Leased);
        assert_eq!(claimed.lease_owner.as_deref(), Some("worker-a"));
        assert_eq!(claimed.attempt_count, 1);
        assert_eq!(claimed.updated_at, 30);

        let persisted = queue.get(first.id)?.expect("claimed job persisted");
        assert_eq!(persisted, claimed);

        let ClaimOutcome::Claimed(next) = queue.claim(ClaimJob {
            lease_owner: "worker-b".to_owned(),
            now: 40,
        })?
        else {
            panic!("expected second claimed job");
        };
        assert_eq!(next.id, second.id);

        assert_eq!(
            queue.claim(ClaimJob {
                lease_owner: "worker-c".to_owned(),
                now: 50,
            })?,
            ClaimOutcome::Empty
        );

        Ok(())
    }

    #[test]
    fn job_queue_claim_cleans_ready_key_id_mismatch_and_continues() -> Result<()> {
        let (_dir, vault) = open_queue();
        let queue = JobQueue::new(&vault);

        let EnqueueOutcome::Enqueued(job) = queue.enqueue(enqueue("first", None, 10))? else {
            panic!("expected enqueue");
        };
        let stale_ready_key = ready_key(5, JobId::now());
        {
            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .job_ready
                .put(&mut wtxn, &stale_ready_key, job.id.as_bytes())?;
            wtxn.commit()?;
        }

        let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimJob {
            lease_owner: "worker-a".to_owned(),
            now: 20,
        })?
        else {
            panic!("expected claim past stale ready row");
        };
        assert_eq!(claimed.id, job.id);

        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .job_ready
                .get(&rtxn, &stale_ready_key)?
                .is_none()
        );

        Ok(())
    }

    #[test]
    fn job_queue_transitions_complete_is_idempotent_and_rejects_invalid_states() -> Result<()> {
        let (_dir, vault) = open_queue();
        let queue = JobQueue::new(&vault);

        let EnqueueOutcome::Enqueued(job) =
            queue.enqueue(enqueue("claim_extraction", Some("turn:complete"), 10))?
        else {
            panic!("expected enqueue");
        };

        let queued_complete = queue
            .complete(CompleteJob {
                id: job.id,
                now: 11,
            })
            .unwrap_err();
        assert_invalid_transition(queued_complete, "complete", "queued");

        let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimJob {
            lease_owner: "worker-a".to_owned(),
            now: 20,
        })?
        else {
            panic!("expected claimed job");
        };
        assert_eq!(claimed.id, job.id);

        let CompleteOutcome::Completed(completed) = queue.complete(CompleteJob {
            id: job.id,
            now: 30,
        })?
        else {
            panic!("expected complete");
        };
        assert_eq!(completed.state, JobState::Completed);
        assert_eq!(completed.lease_owner, None);
        assert_eq!(completed.backoff_until, None);
        assert_eq!(completed.last_error, None);
        assert_eq!(completed.payload, b"payload-10");
        assert_eq!(completed.run_id.as_deref(), Some("run-10"));
        assert_eq!(completed.dedupe_key.as_deref(), Some("turn:complete"));
        assert_eq!(completed.updated_at, 30);

        let CompleteOutcome::AlreadyCompleted(again) = queue.complete(CompleteJob {
            id: job.id,
            now: 40,
        })?
        else {
            panic!("expected idempotent complete");
        };
        assert_eq!(again.updated_at, 30);

        let completed_fail = queue
            .fail(FailJob {
                id: job.id,
                reason: "boom".to_owned(),
                now: 50,
            })
            .unwrap_err();
        assert_invalid_transition(completed_fail, "fail", "completed");

        let completed_retry = queue
            .retry(RetryJob {
                id: job.id,
                backoff_until: 60,
                last_error: Some("retryable".to_owned()),
                now: 50,
            })
            .unwrap_err();
        assert_invalid_transition(completed_retry, "retry", "completed");

        let EnqueueOutcome::Enqueued(replacement) =
            queue.enqueue(enqueue("claim_extraction", Some("turn:complete"), 60))?
        else {
            panic!("terminal dedupe key should be reusable");
        };
        assert_ne!(replacement.id, job.id);

        Ok(())
    }

    #[test]
    fn job_queue_transitions_fail_is_idempotent_and_rejects_invalid_states() -> Result<()> {
        let (_dir, vault) = open_queue();
        let queue = JobQueue::new(&vault);

        let EnqueueOutcome::Enqueued(job) =
            queue.enqueue(enqueue("claim_extraction", Some("turn:fail"), 10))?
        else {
            panic!("expected enqueue");
        };

        let queued_fail = queue
            .fail(FailJob {
                id: job.id,
                reason: "boom".to_owned(),
                now: 11,
            })
            .unwrap_err();
        assert_invalid_transition(queued_fail, "fail", "queued");

        let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimJob {
            lease_owner: "worker-a".to_owned(),
            now: 20,
        })?
        else {
            panic!("expected claimed job");
        };
        assert_eq!(claimed.id, job.id);

        let FailOutcome::Failed(failed) = queue.fail(FailJob {
            id: job.id,
            reason: "fatal".to_owned(),
            now: 30,
        })?
        else {
            panic!("expected fail");
        };
        assert_eq!(failed.state, JobState::Failed);
        assert_eq!(failed.lease_owner, None);
        assert_eq!(failed.backoff_until, None);
        assert_eq!(failed.last_error.as_deref(), Some("fatal"));
        assert_eq!(failed.payload, b"payload-10");
        assert_eq!(failed.run_id.as_deref(), Some("run-10"));
        assert_eq!(failed.dedupe_key.as_deref(), Some("turn:fail"));

        let FailOutcome::AlreadyFailed(again) = queue.fail(FailJob {
            id: job.id,
            reason: "different".to_owned(),
            now: 40,
        })?
        else {
            panic!("expected idempotent fail");
        };
        assert_eq!(again.updated_at, 30);
        assert_eq!(again.last_error.as_deref(), Some("fatal"));

        let failed_complete = queue
            .complete(CompleteJob {
                id: job.id,
                now: 50,
            })
            .unwrap_err();
        assert_invalid_transition(failed_complete, "complete", "failed");

        let EnqueueOutcome::Enqueued(replacement) =
            queue.enqueue(enqueue("claim_extraction", Some("turn:fail"), 60))?
        else {
            panic!("terminal dedupe key should be reusable");
        };
        assert_ne!(replacement.id, job.id);

        Ok(())
    }

    #[test]
    fn job_queue_transitions_reject_empty_failure_reasons() -> Result<()> {
        let (_dir, vault) = open_queue();
        let queue = JobQueue::new(&vault);

        let EnqueueOutcome::Enqueued(job) =
            queue.enqueue(enqueue("claim_extraction", Some("turn:empty-fail"), 10))?
        else {
            panic!("expected enqueue");
        };
        let ClaimOutcome::Claimed(mut claimed) = queue.claim(ClaimJob {
            lease_owner: "worker-a".to_owned(),
            now: 20,
        })?
        else {
            panic!("expected claim");
        };

        let err = queue
            .fail(FailJob {
                id: job.id,
                reason: String::new(),
                now: 30,
            })
            .unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidJobQueueRecord(ERR_FAILURE_REASON_EMPTY)
        ));

        claimed.state = JobState::Failed;
        claimed.lease_owner = None;
        claimed.last_error = Some(String::new());
        let encoded = encode_record(&claimed)?;
        {
            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .job_records
                .put(&mut wtxn, claimed.id.as_bytes(), &encoded)?;
            wtxn.commit()?;
        }

        let err = queue.get(claimed.id).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidJobQueueRecord(ERR_FAILURE_REASON_EMPTY)
        ));

        Ok(())
    }

    #[test]
    fn job_queue_transitions_retry_preserves_payload_provenance_and_backoff() -> Result<()> {
        let (_dir, vault) = open_queue();
        let queue = JobQueue::new(&vault);

        let EnqueueOutcome::Enqueued(job) =
            queue.enqueue(enqueue("claim_extraction", Some("turn:retry"), 10))?
        else {
            panic!("expected enqueue");
        };

        let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimJob {
            lease_owner: "worker-a".to_owned(),
            now: 20,
        })?
        else {
            panic!("expected claimed job");
        };
        assert_eq!(claimed.id, job.id);
        assert_eq!(claimed.attempt_count, 1);

        let RetryOutcome::Retried(retried) = queue.retry(RetryJob {
            id: job.id,
            backoff_until: 100,
            last_error: Some("rate limited".to_owned()),
            now: 30,
        })?;
        assert_eq!(retried.id, job.id);
        assert_eq!(retried.state, JobState::Queued);
        assert_eq!(retried.lease_owner, None);
        assert_eq!(retried.attempt_count, 1);
        assert_eq!(retried.backoff_until, Some(100));
        assert_eq!(retried.last_error.as_deref(), Some("rate limited"));
        assert_eq!(retried.payload, b"payload-10");
        assert_eq!(retried.run_id.as_deref(), Some("run-10"));
        assert_eq!(retried.dedupe_key.as_deref(), Some("turn:retry"));

        let EnqueueOutcome::Existing(duplicate_pending) =
            queue.enqueue(enqueue("claim_extraction", Some("turn:retry"), 40))?
        else {
            panic!("pending dedupe key should coalesce");
        };
        assert_eq!(duplicate_pending.id, job.id);

        assert_eq!(
            queue.claim(ClaimJob {
                lease_owner: "worker-b".to_owned(),
                now: 99,
            })?,
            ClaimOutcome::Empty
        );

        let ClaimOutcome::Claimed(second_attempt) = queue.claim(ClaimJob {
            lease_owner: "worker-b".to_owned(),
            now: 100,
        })?
        else {
            panic!("expected claim after backoff");
        };
        assert_eq!(second_attempt.id, job.id);
        assert_eq!(second_attempt.attempt_count, 2);
        assert_eq!(second_attempt.backoff_until, None);
        assert_eq!(second_attempt.last_error.as_deref(), Some("rate limited"));
        assert_eq!(second_attempt.payload, b"payload-10");
        assert_eq!(second_attempt.run_id.as_deref(), Some("run-10"));
        assert_eq!(second_attempt.dedupe_key.as_deref(), Some("turn:retry"));

        Ok(())
    }

    #[test]
    fn job_queue_claim_cleans_missing_record_ready_and_dedupe() -> Result<()> {
        let (_dir, vault) = open_queue();
        let queue = JobQueue::new(&vault);

        let EnqueueOutcome::Enqueued(first) =
            queue.enqueue(enqueue("claim_extraction", Some("turn:missing"), 10))?
        else {
            panic!("expected enqueue");
        };
        let EnqueueOutcome::Enqueued(second) =
            queue.enqueue(enqueue("claim_extraction", Some("turn:missing-too"), 11))?
        else {
            panic!("expected enqueue");
        };
        {
            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .job_records
                .delete(&mut wtxn, first.id.as_bytes())?;
            vault
                .store
                .job_records
                .delete(&mut wtxn, second.id.as_bytes())?;
            wtxn.commit()?;
        }

        assert_eq!(
            queue.claim(ClaimJob {
                lease_owner: "worker-a".to_owned(),
                now: 20,
            })?,
            ClaimOutcome::Empty
        );

        let index_key = dedupe_index_key("claim_extraction", "turn:missing");
        let second_index_key = dedupe_index_key("claim_extraction", "turn:missing-too");
        {
            let rtxn = vault.store.env.read_txn()?;
            assert!(vault.store.job_ready.iter(&rtxn)?.next().is_none());
            assert!(vault.store.job_dedupe.get(&rtxn, &index_key)?.is_none());
            assert!(
                vault
                    .store
                    .job_dedupe
                    .get(&rtxn, &second_index_key)?
                    .is_none()
            );
        }

        let EnqueueOutcome::Enqueued(replacement) =
            queue.enqueue(enqueue("claim_extraction", Some("turn:missing"), 30))?
        else {
            panic!("expected stale dedupe key to be reusable");
        };
        assert_ne!(replacement.id, first.id);

        Ok(())
    }

    #[test]
    fn job_queue_decode_fails_closed_on_record_key_id_mismatch() -> Result<()> {
        let (_dir, vault) = open_queue();
        let queue = JobQueue::new(&vault);

        let EnqueueOutcome::Enqueued(job) = queue.enqueue(enqueue("claim_extraction", None, 10))?
        else {
            panic!("expected enqueue");
        };
        let mut corrupt = job.clone();
        corrupt.id = JobId::now();
        let encoded = encode_record(&corrupt)?;
        {
            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .job_records
                .put(&mut wtxn, job.id.as_bytes(), &encoded)?;
            wtxn.commit()?;
        }

        let err = queue
            .claim(ClaimJob {
                lease_owner: "worker-a".to_owned(),
                now: 20,
            })
            .unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidJobQueueRecord("job_records key/id mismatch")
        ));

        Ok(())
    }

    #[test]
    fn job_queue_decode_fails_closed_on_lease_owner_state_mismatch() -> Result<()> {
        let (_dir, vault) = open_queue();
        let queue = JobQueue::new(&vault);

        let EnqueueOutcome::Enqueued(job) = queue.enqueue(enqueue("claim_extraction", None, 10))?
        else {
            panic!("expected enqueue");
        };
        let mut corrupt = job.clone();
        corrupt.state = JobState::Leased;
        corrupt.lease_owner = None;
        let encoded = encode_record(&corrupt)?;
        {
            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .job_records
                .put(&mut wtxn, job.id.as_bytes(), &encoded)?;
            wtxn.commit()?;
        }

        let err = queue.get(job.id).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidJobQueueRecord("leased job must have a lease owner")
        ));

        Ok(())
    }

    #[test]
    fn ready_key_round_trips() -> Result<()> {
        let id = JobId::now();
        let key = ready_key(42, id);
        assert_eq!(decode_ready_key(&key)?, (42, id));
        Ok(())
    }
}
