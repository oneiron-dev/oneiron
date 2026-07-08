//! Generic LMDB-backed background job queue.
//!
//! This is intentionally mechanical storage state only: enqueue, claim,
//! complete, fail, retry, and lease cleanup transition LMDB rows atomically,
//! while execution policy stays outside this module.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use uuid::Uuid;

use crate::Vault;
use crate::error::{Error, Result};
use crate::store::Store;

const JOB_RECORD_VERSION: u8 = 2;
const DEDUPE_DOMAIN: &[u8] = b"oneiron.job_queue.dedupe.v1\0";
const DEDUPE_INDEX_KEY_LEN: usize = 32;
const READY_KEY_LEN: usize = 24;
const MAX_KIND_LEN: usize = 128;
const MAX_DEDUPE_KEY_LEN: usize = 512;
const MAX_FAILURE_REASON_LEN: usize = 2048;
const MAX_LEASE_OWNER_LEN: usize = 128;
const MAX_RUN_ID_LEN: usize = 128;
const MAX_INTERVENTION_ACTOR_LEN: usize = 128;
const MAX_INTERVENTION_NOTE_LEN: usize = 2048;
const MAX_JOB_EVENTS_PER_RECORD: usize = 256;
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
const ERR_INTERVENTION_ACTOR_EMPTY: &str = "intervention actor must not be empty";
const ERR_INTERVENTION_ACTOR_TOO_LONG: &str = "intervention actor exceeds 128 bytes";
const ERR_INTERVENTION_NOTE_EMPTY: &str = "intervention note must not be empty";
const ERR_INTERVENTION_NOTE_TOO_LONG: &str = "intervention note exceeds 2048 bytes";
const ERR_JOB_ID_LEN: &str = "job id must be 16 bytes";
const ERR_DEDUPE_KIND_MISMATCH: &str = "dedupe index points at a different job kind";
const ERR_READY_KEY_LEN: &str = "ready index key must be 24 bytes";
const ERR_LEASE_TIMEOUT_ZERO: &str = "lease timeout must be > 0";
const RETRY_REASON_LEASE_TIMEOUT: &str = "lease_timeout";
const JOB_QUEUE_RETRY_REASON_COUNT: usize = 2;
static JOB_QUEUE_CLEANUP_RUNS: AtomicU64 = AtomicU64::new(0);
static JOB_QUEUE_CLEANUP_STALE_REQUEUED: AtomicU64 = AtomicU64::new(0);
static JOB_QUEUE_CLEANUP_RETRY_REASON_COUNTERS: [AtomicU64; JOB_QUEUE_RETRY_REASON_COUNT] =
    [AtomicU64::new(0), AtomicU64::new(0)];
const CLAIM_KIND_WRITE_RETRY_LIMIT: usize = 3;

#[derive(Debug, Default)]
struct ClaimKindReadScan {
    stale_ready_keys: Vec<Vec<u8>>,
    ready_replacements: Vec<([u8; READY_KEY_LEN], JobId)>,
    stale_missing_record_ids: HashSet<JobId>,
    candidate: Option<ClaimKindCandidate>,
}

#[derive(Debug)]
struct ClaimKindCandidate {
    ready_key: Vec<u8>,
    id: JobId,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum ClaimKindWriteAttempt {
    Claimed(JobRecord),
    Empty,
    Retry,
}

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
    Paused,
    Completed,
    Failed,
    Cancelled,
}

impl JobState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Leased => "leased",
            Self::Paused => "paused",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    const fn is_pending(self) -> bool {
        matches!(self, Self::Queued | Self::Leased | Self::Paused)
    }
}

/// Durable intervention kind recorded on a job row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobInterventionKind {
    Interrupt,
    Pause,
    Resume,
    Cancel,
}

impl JobInterventionKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Interrupt => "interrupt",
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Cancel => "cancel",
        }
    }
}

/// Durable intervention event appended to a job row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobEvent {
    pub sequence: u64,
    pub at: u64,
    pub actor: String,
    pub kind: JobInterventionKind,
    #[serde(default)]
    pub note: Option<String>,
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
    pub claimed_at: Option<u64>,
    #[serde(default)]
    pub backoff_until: Option<u64>,
    #[serde(default)]
    pub last_error: Option<String>,
    pub run_id: Option<String>,
    pub dedupe_key: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(default)]
    pub events: Vec<JobEvent>,
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
#[allow(clippy::large_enum_variant)]
pub enum ClaimOutcome {
    Empty,
    Claimed(JobRecord),
}

/// Input for completing a leased job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteJob {
    pub id: JobId,
    pub lease_owner: String,
    pub attempt_count: u32,
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
    pub lease_owner: String,
    pub attempt_count: u32,
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
    pub lease_owner: String,
    pub attempt_count: u32,
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

/// Input for interrupting, pausing, resuming, or cancelling a job row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterveneJob {
    pub id: JobId,
    pub kind: JobInterventionKind,
    pub actor: String,
    pub note: Option<String>,
    pub now: u64,
}

/// Observable effect of an intervention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobInterventionEffect {
    Interrupted,
    Paused,
    AlreadyPaused,
    Resumed,
    AlreadyResumed,
    Cancelled,
    AlreadyCancelled,
}

impl JobInterventionEffect {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Interrupted => "interrupted",
            Self::Paused => "paused",
            Self::AlreadyPaused => "already_paused",
            Self::Resumed => "resumed",
            Self::AlreadyResumed => "already_resumed",
            Self::Cancelled => "cancelled",
            Self::AlreadyCancelled => "already_cancelled",
        }
    }
}

/// Typed intervention outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterveneOutcome {
    pub effect: JobInterventionEffect,
    pub record: JobRecord,
}

/// Input for returning stale leased jobs to the ready index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupJobLeases {
    /// Current wall-clock seconds chosen by the caller.
    pub now: u64,
    /// A leased job expires when `now - updated_at >= lease_timeout_secs`.
    pub lease_timeout_secs: u64,
}

/// Privacy-stable retry reason classes reported by job-queue cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum JobQueueRetryReason {
    LeaseTimeout,
    RetryBackoff,
}

impl JobQueueRetryReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LeaseTimeout => "lease_timeout",
            Self::RetryBackoff => "retry_backoff",
        }
    }

    const fn metric_index(self) -> usize {
        match self {
            Self::LeaseTimeout => 0,
            Self::RetryBackoff => 1,
        }
    }

    const fn metric_values() -> [Self; JOB_QUEUE_RETRY_REASON_COUNT] {
        [Self::LeaseTimeout, Self::RetryBackoff]
    }
}

/// Count for one privacy-stable retry reason class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobQueueRetryReasonCount {
    pub reason: JobQueueRetryReason,
    pub count: u64,
}

impl JobQueueRetryReasonCount {
    const fn zero(reason: JobQueueRetryReason) -> Self {
        Self { reason, count: 0 }
    }
}

/// Queue cleanup report shaped for runner and run-tree surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobQueueCleanupReport {
    pub pending: u64,
    pub running: u64,
    pub failed: u64,
    pub done: u64,
    pub stale_requeued: u64,
    pub retry_reasons: [JobQueueRetryReasonCount; JOB_QUEUE_RETRY_REASON_COUNT],
}

impl Default for JobQueueCleanupReport {
    fn default() -> Self {
        Self {
            pending: 0,
            running: 0,
            failed: 0,
            done: 0,
            stale_requeued: 0,
            retry_reasons: JobQueueRetryReason::metric_values().map(JobQueueRetryReasonCount::zero),
        }
    }
}

impl JobQueueCleanupReport {
    #[must_use]
    pub fn retry_reason_count(&self, reason: JobQueueRetryReason) -> u64 {
        self.retry_reasons[reason.metric_index()].count
    }

    fn increment_retry_reason(&mut self, reason: JobQueueRetryReason) {
        self.retry_reasons[reason.metric_index()].count += 1;
    }
}

/// In-process cleanup counters with stable, content-free labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobQueueCleanupMetricsSnapshot {
    pub runs: u64,
    pub stale_requeued: u64,
    pub retry_reasons: [JobQueueRetryReasonCount; JOB_QUEUE_RETRY_REASON_COUNT],
}

/// Returns process-local job-queue cleanup counters.
#[must_use]
pub fn job_queue_cleanup_metrics_snapshot() -> JobQueueCleanupMetricsSnapshot {
    JobQueueCleanupMetricsSnapshot {
        runs: JOB_QUEUE_CLEANUP_RUNS.load(AtomicOrdering::Relaxed),
        stale_requeued: JOB_QUEUE_CLEANUP_STALE_REQUEUED.load(AtomicOrdering::Relaxed),
        retry_reasons: JobQueueRetryReason::metric_values().map(|reason| {
            JobQueueRetryReasonCount {
                reason,
                count: JOB_QUEUE_CLEANUP_RETRY_REASON_COUNTERS[reason.metric_index()]
                    .load(AtomicOrdering::Relaxed),
            }
        }),
    }
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
        let outcome = self.enqueue_in_txn(&mut wtxn, input)?;
        wtxn.commit()?;

        Ok(outcome)
    }

    /// Enqueues a job into a caller-owned write transaction.
    ///
    /// The caller owns commit/abort. This is used by higher-level private
    /// runner stores that need to co-commit their own local indexes with the
    /// generic job row.
    pub(crate) fn enqueue_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: EnqueueJob,
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

        let record = JobRecord {
            id: JobId::now(),
            kind: input.kind,
            payload: input.payload,
            state: JobState::Queued,
            lease_owner: None,
            attempt_count: 0,
            claimed_at: None,
            backoff_until: None,
            last_error: None,
            run_id: input.run_id,
            dedupe_key: input.dedupe_key,
            created_at: input.now,
            updated_at: input.now,
            events: Vec::new(),
        };

        let encoded = encode_record(&record)?;
        self.store
            .job_records
            .put(wtxn, record.id.as_bytes(), &encoded)?;
        let ready_key = ready_key(ready_at(&record), record.id);
        self.store
            .job_ready
            .put(wtxn, &ready_key, record.id.as_bytes())?;
        if let Some(index_key) = dedupe_blake3_key.as_ref() {
            self.store
                .job_dedupe
                .put(wtxn, &index_key.blake3[..], record.id.as_bytes())?;
        }

        Ok(EnqueueOutcome::Enqueued(record))
    }

    /// Atomically claims the oldest queued job under LMDB's single-writer
    /// invariant.
    pub fn claim(&self, input: ClaimJob) -> Result<ClaimOutcome> {
        self.claim_matching(input, None)
    }

    /// Atomically claims the oldest queued job with the requested kind.
    ///
    /// Non-matching queued jobs remain ready for their own workers; malformed
    /// ready rows and stale indexes are still repaired while scanning.
    pub fn claim_kind(&self, kind: &str, input: ClaimJob) -> Result<ClaimOutcome> {
        validate_kind(kind)?;
        validate_lease_owner(&input.lease_owner)?;
        self.claim_kind_with_read_scan(kind, input)
    }

    /// Claims the oldest queued job with the requested kind in a caller-owned
    /// write transaction.
    ///
    /// The caller owns commit/abort. This path intentionally uses the
    /// write-transaction scan so higher-level stores can co-commit the lease
    /// with their own local state.
    pub(crate) fn claim_kind_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        kind: &str,
        input: ClaimJob,
    ) -> Result<ClaimOutcome> {
        validate_kind(kind)?;
        self.claim_matching_in_txn(wtxn, input, Some(kind))
    }

    /// Repairs ready/dedupe rows while returning the oldest claimable job id of
    /// this kind, without leasing it.
    pub(crate) fn ready_kind_candidate_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        kind: &str,
        now: u64,
    ) -> Result<Option<JobId>> {
        validate_kind(kind)?;

        let mut scan = ClaimKindReadScan::default();
        for row in self.store.job_ready.iter(&*wtxn)? {
            let (key, value) = row?;
            let Ok((key_ready_at, key_id)) = decode_ready_key(key) else {
                scan.stale_ready_keys.push(key.to_vec());
                continue;
            };
            let Ok(id) = JobId::from_bytes(value) else {
                scan.stale_ready_keys.push(key.to_vec());
                continue;
            };
            if id != key_id {
                scan.stale_ready_keys.push(key.to_vec());
                continue;
            }
            let Some(raw_record) = self.store.job_records.get(&*wtxn, id.as_bytes())? else {
                scan.stale_missing_record_ids.insert(id);
                scan.stale_ready_keys.push(key.to_vec());
                continue;
            };
            let record = decode_record(raw_record, id)?;
            if record.state != JobState::Queued {
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

    fn claim_kind_with_read_scan(&self, kind: &str, input: ClaimJob) -> Result<ClaimOutcome> {
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
        for row in self.store.job_ready.iter(&rtxn)? {
            let (key, value) = row?;
            let Ok((key_ready_at, key_id)) = decode_ready_key(key) else {
                scan.stale_ready_keys.push(key.to_vec());
                continue;
            };
            let Ok(id) = JobId::from_bytes(value) else {
                scan.stale_ready_keys.push(key.to_vec());
                continue;
            };
            if id != key_id {
                scan.stale_ready_keys.push(key.to_vec());
                continue;
            }
            let Some(raw_record) = self.store.job_records.get(&rtxn, id.as_bytes())? else {
                scan.stale_missing_record_ids.insert(id);
                scan.stale_ready_keys.push(key.to_vec());
                continue;
            };
            let record = decode_record(raw_record, id)?;
            if record.state != JobState::Queued {
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
        input: &ClaimJob,
        scan: ClaimKindReadScan,
    ) -> Result<ClaimKindWriteAttempt> {
        let mut wtxn = self.store.env.write_txn()?;
        let mut claimed = None;
        if let Some(candidate) = scan.candidate.as_ref() {
            let Some(value) = self.store.job_ready.get(&wtxn, &candidate.ready_key)? else {
                self.apply_claim_kind_read_repairs(&mut wtxn, scan)?;
                wtxn.commit()?;
                return Ok(ClaimKindWriteAttempt::Retry);
            };
            let Ok(id) = JobId::from_bytes(value) else {
                self.apply_claim_kind_read_repairs(&mut wtxn, scan)?;
                wtxn.commit()?;
                return Ok(ClaimKindWriteAttempt::Retry);
            };
            if id != candidate.id {
                self.apply_claim_kind_read_repairs(&mut wtxn, scan)?;
                wtxn.commit()?;
                return Ok(ClaimKindWriteAttempt::Retry);
            }
            let Some(raw_record) = self.store.job_records.get(&wtxn, id.as_bytes())? else {
                self.apply_claim_kind_read_repairs(&mut wtxn, scan)?;
                wtxn.commit()?;
                return Ok(ClaimKindWriteAttempt::Retry);
            };
            let mut record = decode_record(raw_record, id)?;
            if record.state != JobState::Queued
                || ready_at(&record) > input.now
                || record.kind != kind
            {
                self.apply_claim_kind_read_repairs(&mut wtxn, scan)?;
                wtxn.commit()?;
                return Ok(ClaimKindWriteAttempt::Retry);
            }
            record.state = JobState::Leased;
            record.lease_owner = Some(input.lease_owner.clone());
            record.attempt_count = record
                .attempt_count
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("job attempt count"))?;
            if record.claimed_at.is_none() {
                record.claimed_at = Some(input.now);
            }
            record.backoff_until = None;
            record.updated_at = input.now;
            claimed = Some((candidate.ready_key.clone(), id, record));
        }

        self.apply_claim_kind_read_repairs(&mut wtxn, scan)?;

        let Some((ready_key, id, record)) = claimed else {
            wtxn.commit()?;
            return Ok(ClaimKindWriteAttempt::Empty);
        };

        self.store.job_ready.delete(&mut wtxn, &ready_key)?;
        let encoded = encode_record(&record)?;
        self.store
            .job_records
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
            self.store.job_ready.delete(wtxn, &key)?;
        }
        for (key, id) in scan.ready_replacements {
            self.store.job_ready.put(wtxn, &key, id.as_bytes())?;
        }
        Ok(())
    }

    fn claim_matching(&self, input: ClaimJob, kind_filter: Option<&str>) -> Result<ClaimOutcome> {
        validate_lease_owner(&input.lease_owner)?;

        let mut wtxn = self.store.env.write_txn()?;
        let outcome = self.claim_matching_in_txn(&mut wtxn, input, kind_filter)?;
        wtxn.commit()?;

        Ok(outcome)
    }

    fn claim_matching_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: ClaimJob,
        kind_filter: Option<&str>,
    ) -> Result<ClaimOutcome> {
        validate_lease_owner(&input.lease_owner)?;

        let mut stale_ready_keys = Vec::new();
        let mut ready_replacements = Vec::new();
        let mut stale_missing_record_ids = HashSet::new();
        let mut claimed = None;
        for row in self.store.job_ready.iter(&*wtxn)? {
            let (key, value) = row?;
            let Ok((key_ready_at, key_id)) = decode_ready_key(key) else {
                stale_ready_keys.push(key.to_vec());
                continue;
            };
            let Ok(id) = JobId::from_bytes(value) else {
                stale_ready_keys.push(key.to_vec());
                continue;
            };
            if id != key_id {
                stale_ready_keys.push(key.to_vec());
                continue;
            }
            let Some(raw_record) = self.store.job_records.get(&*wtxn, id.as_bytes())? else {
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
            } else if record_ready_at > input.now {
                continue;
            }
            if kind_filter.is_some_and(|kind| record.kind != kind) {
                if record_ready_at != key_ready_at {
                    ready_replacements.push((ready_key(record_ready_at, id), id));
                }
                continue;
            }
            record.state = JobState::Leased;
            record.lease_owner = Some(input.lease_owner.clone());
            record.attempt_count = record
                .attempt_count
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("job attempt count"))?;
            if record.claimed_at.is_none() {
                record.claimed_at = Some(input.now);
            }
            record.backoff_until = None;
            record.updated_at = input.now;
            claimed = Some((key.to_vec(), id, record));
            break;
        }

        self.delete_dedupe_entries_for_ids(wtxn, &stale_missing_record_ids)?;
        for key in stale_ready_keys {
            self.store.job_ready.delete(wtxn, &key)?;
        }
        for (key, id) in ready_replacements {
            self.store.job_ready.put(wtxn, &key, id.as_bytes())?;
        }

        let Some((ready_key, id, record)) = claimed else {
            return Ok(ClaimOutcome::Empty);
        };

        self.store.job_ready.delete(wtxn, &ready_key)?;
        let encoded = encode_record(&record)?;
        self.store.job_records.put(wtxn, id.as_bytes(), &encoded)?;

        Ok(ClaimOutcome::Claimed(record))
    }

    /// Marks a leased job complete. Completing an already-completed job is an
    /// idempotent success; all other states are rejected.
    pub fn complete(&self, input: CompleteJob) -> Result<CompleteOutcome> {
        {
            let rtxn = self.store.env.read_txn()?;
            let Some(raw_record) = self.store.job_records.get(&rtxn, input.id.as_bytes())? else {
                return Err(invalid_transition("complete", "missing"));
            };
            let record = decode_record(raw_record, input.id)?;
            if record.state == JobState::Completed {
                return Ok(CompleteOutcome::AlreadyCompleted(record));
            }
        }

        let mut wtxn = self.store.env.write_txn()?;
        let Some(raw_record) = self.store.job_records.get(&wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("complete", "missing"));
        };
        let mut record = decode_record(raw_record, input.id)?;
        match record.state {
            JobState::Completed => Ok(CompleteOutcome::AlreadyCompleted(record)),
            JobState::Leased => {
                validate_lease_owner(&input.lease_owner)?;
                validate_transition_lease(
                    &record,
                    &input.lease_owner,
                    input.attempt_count,
                    "complete",
                )?;
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
        {
            let rtxn = self.store.env.read_txn()?;
            let Some(raw_record) = self.store.job_records.get(&rtxn, input.id.as_bytes())? else {
                return Err(invalid_transition("fail", "missing"));
            };
            let record = decode_record(raw_record, input.id)?;
            if record.state == JobState::Failed {
                return Ok(FailOutcome::AlreadyFailed(record));
            }
        }

        let mut wtxn = self.store.env.write_txn()?;
        let Some(raw_record) = self.store.job_records.get(&wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("fail", "missing"));
        };
        let mut record = decode_record(raw_record, input.id)?;
        match record.state {
            JobState::Failed => Ok(FailOutcome::AlreadyFailed(record)),
            JobState::Leased => {
                validate_lease_owner(&input.lease_owner)?;
                validate_transition_lease(
                    &record,
                    &input.lease_owner,
                    input.attempt_count,
                    "fail",
                )?;
                validate_failure_reason(&input.reason)?;
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
        let mut wtxn = self.store.env.write_txn()?;
        let Some(raw_record) = self.store.job_records.get(&wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("retry", "missing"));
        };
        let mut record = decode_record(raw_record, input.id)?;
        match record.state {
            JobState::Leased => {
                validate_lease_owner(&input.lease_owner)?;
                validate_transition_lease(
                    &record,
                    &input.lease_owner,
                    input.attempt_count,
                    "retry",
                )?;
                validate_optional_failure_reason(input.last_error.as_deref())?;
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

    /// Applies a durable operator intervention to a job row. Pause removes a
    /// queued row from the ready index, resume restores it, cancel makes a
    /// queued or paused row terminal, and interrupt records an event without
    /// changing claimability.
    pub fn intervene(&self, input: InterveneJob) -> Result<InterveneOutcome> {
        let mut wtxn = self.store.env.write_txn()?;
        let outcome = self.intervene_in_txn(&mut wtxn, input)?;
        wtxn.commit()?;
        Ok(outcome)
    }

    pub(crate) fn intervene_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: InterveneJob,
    ) -> Result<InterveneOutcome> {
        validate_intervention_actor(&input.actor)?;
        validate_optional_intervention_note(input.note.as_deref())?;

        let Some(raw_record) = self.store.job_records.get(wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition(input.kind.as_str(), "missing"));
        };
        let mut record = decode_record(raw_record, input.id)?;

        let effect = match input.kind {
            JobInterventionKind::Interrupt => match record.state {
                JobState::Queued | JobState::Leased | JobState::Paused => {
                    append_job_event(&mut record, input.kind, input.actor, input.note, input.now)?;
                    record.updated_at = input.now;
                    JobInterventionEffect::Interrupted
                }
                state => return Err(invalid_transition(input.kind.as_str(), state.as_str())),
            },
            JobInterventionKind::Pause => match record.state {
                JobState::Paused => JobInterventionEffect::AlreadyPaused,
                JobState::Queued => {
                    self.delete_ready_entry_for_record(wtxn, &record)?;
                    append_job_event(&mut record, input.kind, input.actor, input.note, input.now)?;
                    record.state = JobState::Paused;
                    record.lease_owner = None;
                    record.updated_at = input.now;
                    JobInterventionEffect::Paused
                }
                state => return Err(invalid_transition(input.kind.as_str(), state.as_str())),
            },
            JobInterventionKind::Resume => match record.state {
                JobState::Paused => {
                    self.delete_ready_entry_for_record(wtxn, &record)?;
                    append_job_event(&mut record, input.kind, input.actor, input.note, input.now)?;
                    record.state = JobState::Queued;
                    record.lease_owner = None;
                    record.updated_at = input.now;
                    let ready_key = ready_key(ready_at(&record), record.id);
                    self.store
                        .job_ready
                        .put(wtxn, &ready_key, record.id.as_bytes())?;
                    JobInterventionEffect::Resumed
                }
                JobState::Queued | JobState::Leased => JobInterventionEffect::AlreadyResumed,
                state => return Err(invalid_transition(input.kind.as_str(), state.as_str())),
            },
            JobInterventionKind::Cancel => match record.state {
                JobState::Cancelled => JobInterventionEffect::AlreadyCancelled,
                JobState::Queued | JobState::Paused => {
                    self.delete_ready_entry_for_record(wtxn, &record)?;
                    append_job_event(&mut record, input.kind, input.actor, input.note, input.now)?;
                    record.state = JobState::Cancelled;
                    record.lease_owner = None;
                    record.backoff_until = None;
                    record.last_error = None;
                    record.updated_at = input.now;
                    self.delete_dedupe_entry_for_record(wtxn, &record)?;
                    JobInterventionEffect::Cancelled
                }
                state => return Err(invalid_transition(input.kind.as_str(), state.as_str())),
            },
        };

        let encoded = encode_record(&record)?;
        self.store
            .job_records
            .put(wtxn, record.id.as_bytes(), &encoded)?;

        Ok(InterveneOutcome { effect, record })
    }

    /// Returns expired leases to the ready index under LMDB's single-writer
    /// invariant. Cleanup never assigns a replacement owner; reclaim still
    /// happens through [`Self::claim`]'s atomic admission step.
    pub fn cleanup_leases(&self, input: CleanupJobLeases) -> Result<JobQueueCleanupReport> {
        validate_cleanup_leases_input(&input)?;

        let rtxn = self.store.env.read_txn()?;
        let mut report = JobQueueCleanupReport::default();
        let mut expired_candidates = Vec::new();

        for row in self.store.job_records.iter(&rtxn)? {
            let (key, raw_record) = row?;
            let id = JobId::from_bytes(key)?;
            let record = decode_record(raw_record, id)?;
            match record.state {
                JobState::Queued => {
                    report.pending += 1;
                    if record.backoff_until.is_some() {
                        report.increment_retry_reason(JobQueueRetryReason::RetryBackoff);
                    }
                }
                JobState::Paused => {
                    report.pending += 1;
                    if record.backoff_until.is_some() {
                        report.increment_retry_reason(JobQueueRetryReason::RetryBackoff);
                    }
                }
                JobState::Leased if lease_expired(&record, input.now, input.lease_timeout_secs) => {
                    report.running += 1;
                    expired_candidates.push(id);
                }
                JobState::Leased => {
                    report.running += 1;
                }
                JobState::Completed => {
                    report.done += 1;
                }
                JobState::Failed => {
                    report.failed += 1;
                }
                JobState::Cancelled => {
                    report.done += 1;
                }
            }
        }
        drop(rtxn);

        if !expired_candidates.is_empty() {
            let mut wtxn = self.store.env.write_txn()?;
            for id in expired_candidates {
                let Some(raw_record) = self.store.job_records.get(&wtxn, id.as_bytes())? else {
                    mark_rechecked_candidate_not_running(&mut report);
                    continue;
                };
                let mut record = decode_record(raw_record, id)?;
                match record.state {
                    JobState::Leased
                        if lease_expired(&record, input.now, input.lease_timeout_secs) =>
                    {
                        record.state = JobState::Queued;
                        record.lease_owner = None;
                        record.backoff_until = None;
                        record.last_error = Some(RETRY_REASON_LEASE_TIMEOUT.to_owned());
                        record.updated_at = input.now;
                        let encoded = encode_record(&record)?;
                        self.store
                            .job_records
                            .put(&mut wtxn, record.id.as_bytes(), &encoded)?;
                        let ready_key = ready_key(ready_at(&record), record.id);
                        self.store
                            .job_ready
                            .put(&mut wtxn, &ready_key, record.id.as_bytes())?;
                        mark_rechecked_candidate_not_running(&mut report);
                        report.pending += 1;
                        report.stale_requeued += 1;
                        report.increment_retry_reason(JobQueueRetryReason::LeaseTimeout);
                    }
                    JobState::Leased => {}
                    JobState::Queued => {
                        mark_rechecked_candidate_not_running(&mut report);
                        report.pending += 1;
                        if record.backoff_until.is_some() {
                            report.increment_retry_reason(JobQueueRetryReason::RetryBackoff);
                        }
                    }
                    JobState::Paused => {
                        mark_rechecked_candidate_not_running(&mut report);
                        report.pending += 1;
                        if record.backoff_until.is_some() {
                            report.increment_retry_reason(JobQueueRetryReason::RetryBackoff);
                        }
                    }
                    JobState::Completed => {
                        mark_rechecked_candidate_not_running(&mut report);
                        report.done += 1;
                    }
                    JobState::Failed => {
                        mark_rechecked_candidate_not_running(&mut report);
                        report.failed += 1;
                    }
                    JobState::Cancelled => {
                        mark_rechecked_candidate_not_running(&mut report);
                        report.done += 1;
                    }
                }
            }
            wtxn.commit()?;
        }

        record_job_queue_cleanup_metrics(&report);
        emit_job_queue_cleanup_span(&input, &report);
        Ok(report)
    }

    /// Reads a job by id.
    pub fn get(&self, id: JobId) -> Result<Option<JobRecord>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.job_records.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        decode_record(raw, id).map(Some)
    }

    /// Reads all persisted job rows in deterministic creation order.
    pub fn list(&self) -> Result<Vec<JobRecord>> {
        let rtxn = self.store.env.read_txn()?;
        let mut records = Vec::new();
        for row in self.store.job_records.iter(&rtxn)? {
            let (key, raw_record) = row?;
            let id = JobId::from_bytes(key)?;
            records.push(decode_record(raw_record, id)?);
        }
        records.sort_by(job_record_order);
        Ok(records)
    }

    /// Reads persisted job rows for one run id in deterministic creation order.
    pub fn list_run(&self, run_id: &str) -> Result<Vec<JobRecord>> {
        validate_optional_run_id(Some(run_id))?;
        let rtxn = self.store.env.read_txn()?;
        let mut records = Vec::new();
        for row in self.store.job_records.iter(&rtxn)? {
            let (key, raw_record) = row?;
            let id = JobId::from_bytes(key)?;
            let record = decode_record(raw_record, id)?;
            if record.run_id.as_deref() == Some(run_id) {
                records.push(record);
            }
        }
        records.sort_by(job_record_order);
        Ok(records)
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
        blake3_key: &[u8],
        kind: &str,
        dedupe_key: &str,
    ) -> Result<Option<JobRecord>> {
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
            .job_dedupe
            .put(txn, blake3_key, record.id.as_bytes())?;
        self.store.job_dedupe.delete(txn, &legacy_key)?;
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
            let blake3_key = dedupe_index_key(&record.kind, dedupe_key);
            let legacy_key = legacy_dedupe_index_key(&record.kind, dedupe_key);
            self.store.job_dedupe.delete(txn, &blake3_key[..])?;
            self.store.job_dedupe.delete(txn, &legacy_key)?;
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

    fn delete_ready_entry_for_record(
        &self,
        txn: &mut heed::RwTxn<'_>,
        record: &JobRecord,
    ) -> Result<()> {
        self.store
            .job_ready
            .delete(txn, &ready_key(ready_at(record), record.id))?;
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

fn validate_intervention_actor(actor: &str) -> Result<()> {
    if actor.is_empty() {
        return Err(Error::InvalidJobQueueRecord(ERR_INTERVENTION_ACTOR_EMPTY));
    }
    if actor.len() > MAX_INTERVENTION_ACTOR_LEN {
        return Err(Error::InvalidJobQueueRecord(
            ERR_INTERVENTION_ACTOR_TOO_LONG,
        ));
    }
    Ok(())
}

fn validate_optional_intervention_note(note: Option<&str>) -> Result<()> {
    if let Some(note) = note {
        if note.is_empty() {
            return Err(Error::InvalidJobQueueRecord(ERR_INTERVENTION_NOTE_EMPTY));
        }
        if note.len() > MAX_INTERVENTION_NOTE_LEN {
            return Err(Error::InvalidJobQueueRecord(ERR_INTERVENTION_NOTE_TOO_LONG));
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

fn validate_cleanup_leases_input(input: &CleanupJobLeases) -> Result<()> {
    if input.lease_timeout_secs == 0 {
        return Err(Error::InvalidJobQueueRecord(ERR_LEASE_TIMEOUT_ZERO));
    }
    Ok(())
}

fn validate_transition_lease(
    record: &JobRecord,
    lease_owner: &str,
    attempt_count: u32,
    action: &'static str,
) -> Result<()> {
    if record.lease_owner.as_deref() != Some(lease_owner) {
        return Err(invalid_transition(action, "leased_by_other"));
    }
    if record.attempt_count != attempt_count {
        return Err(invalid_transition(action, "stale_attempt"));
    }
    Ok(())
}

fn validate_job_events(events: &[JobEvent]) -> Result<()> {
    let mut previous_sequence = 0;
    for event in events {
        if event.sequence == 0 || event.sequence <= previous_sequence {
            return Err(Error::InvalidJobQueueRecord(
                "job event sequence must be strictly increasing",
            ));
        }
        validate_intervention_actor(&event.actor)?;
        validate_optional_intervention_note(event.note.as_deref())?;
        previous_sequence = event.sequence;
    }
    Ok(())
}

fn append_job_event(
    record: &mut JobRecord,
    kind: JobInterventionKind,
    actor: String,
    note: Option<String>,
    now: u64,
) -> Result<()> {
    let sequence = match record.events.last() {
        Some(event) => event
            .sequence
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("job event sequence"))?,
        None => 1,
    };
    record.events.push(JobEvent {
        sequence,
        at: now,
        actor,
        kind,
        note,
    });
    if record.events.len() > MAX_JOB_EVENTS_PER_RECORD {
        let excess = record.events.len() - MAX_JOB_EVENTS_PER_RECORD;
        record.events.drain(0..excess);
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
}

impl DedupeIndexKeys {
    fn new(kind: &str, dedupe_key: &str) -> Self {
        Self {
            blake3: dedupe_index_key(kind, dedupe_key),
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
    record.backoff_until.unwrap_or(0)
}

fn lease_expired(record: &JobRecord, now: u64, lease_timeout_secs: u64) -> bool {
    now.checked_sub(record.updated_at)
        .is_some_and(|age| age >= lease_timeout_secs)
}

fn mark_rechecked_candidate_not_running(report: &mut JobQueueCleanupReport) {
    report.running = report.running.saturating_sub(1);
}

pub(crate) fn job_record_order(left: &JobRecord, right: &JobRecord) -> std::cmp::Ordering {
    left.created_at
        .cmp(&right.created_at)
        .then_with(|| left.id.as_bytes().cmp(right.id.as_bytes()))
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
    validate_job_events(&record.events)?;
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
        JobState::Paused if record.lease_owner.is_some() => {
            return Err(Error::InvalidJobQueueRecord(
                "paused job must not have a lease owner",
            ));
        }
        JobState::Completed | JobState::Failed | JobState::Cancelled
            if record.lease_owner.is_some() =>
        {
            return Err(Error::InvalidJobQueueRecord(
                "terminal job must not have a lease owner",
            ));
        }
        JobState::Completed | JobState::Failed | JobState::Cancelled
            if record.backoff_until.is_some() =>
        {
            return Err(Error::InvalidJobQueueRecord(
                "terminal job must not have backoff state",
            ));
        }
        JobState::Completed | JobState::Cancelled if record.last_error.is_some() => {
            return Err(Error::InvalidJobQueueRecord(
                "non-failed terminal job must not have a failure reason",
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

fn record_job_queue_cleanup_metrics(report: &JobQueueCleanupReport) {
    JOB_QUEUE_CLEANUP_RUNS.fetch_add(1, AtomicOrdering::Relaxed);
    JOB_QUEUE_CLEANUP_STALE_REQUEUED.fetch_add(report.stale_requeued, AtomicOrdering::Relaxed);
    for counter in report.retry_reasons {
        JOB_QUEUE_CLEANUP_RETRY_REASON_COUNTERS[counter.reason.metric_index()]
            .fetch_add(counter.count, AtomicOrdering::Relaxed);
    }
}

fn emit_job_queue_cleanup_span(input: &CleanupJobLeases, report: &JobQueueCleanupReport) {
    let retry_lease_timeout = report.retry_reason_count(JobQueueRetryReason::LeaseTimeout);
    let retry_backoff = report.retry_reason_count(JobQueueRetryReason::RetryBackoff);
    let span = tracing::info_span!(
        target: "oneiron::job_queue",
        "job_queue_cleanup",
        lease_timeout_secs = input.lease_timeout_secs,
        pending = report.pending,
        running = report.running,
        failed = report.failed,
        done = report.done,
        stale_requeued = report.stale_requeued,
        retry_lease_timeout,
        retry_backoff,
    );
    let _entered = span.enter();
    tracing::info!(
        target: "oneiron::job_queue",
        pending = report.pending,
        running = report.running,
        failed = report.failed,
        done = report.done,
        stale_requeued = report.stale_requeued,
        retry_lease_timeout,
        retry_backoff,
        "job queue cleanup completed"
    );
}

#[cfg(test)]
mod tests;
