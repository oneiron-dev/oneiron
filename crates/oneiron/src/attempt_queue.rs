//! Generic LMDB-backed background attempt queue.
//!
//! This is intentionally mechanical storage state only: enqueue, claim,
//! complete, fail, retry, and lease cleanup transition LMDB rows atomically,
//! while execution policy stays outside this module.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use uuid::Uuid;

use crate::Vault;
use crate::dreamer_runner::{
    DREAMER_RUNNER_ATTEMPT_KIND, DreamerAttemptPayload, decode_dreamer_attempt_payload,
};
use crate::error::{Error, Result};
use crate::store::Store;

/// Receipt-family ABI-pin rule: changing this requires a
/// [`crate::store::STORAGE_ABI_VERSION`] bump.
pub(crate) const ATTEMPT_RECORD_VERSION: u8 = 2;
// Storage/wire keys keep the legacy "job" spelling; ONE-1714 renamed code only.
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
const MAX_ATTEMPT_EVENTS_PER_RECORD: usize = 256;
/// Defensive cap on [`AttemptRecord::manifest`] rows.
///
/// Deliberately NOT the [`MAX_ATTEMPT_EVENTS_PER_RECORD`] semantics: the
/// events field DRAINS its oldest rows above the cap, which would silently
/// violate the ARCH-0053 §3 append-only manifest invariant (an attribution
/// projector cannot tell a dropped skill from one that was never loaded).
/// The manifest door instead REFUSES at this cap — fail loud, never drain.
pub const MAX_ATTEMPT_MANIFEST_ENTRIES: usize = 4096;
const MAX_MANIFEST_REFERENCE_LEN: usize = 512;
const MAX_MANIFEST_VERSION_LEN: usize = 128;
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
const ERR_MANIFEST_REFERENCE_EMPTY: &str = "manifest reference must not be empty";
const ERR_MANIFEST_REFERENCE_TOO_LONG: &str = "manifest reference exceeds 512 bytes";
const ERR_MANIFEST_VERSION_EMPTY: &str = "manifest version must not be empty";
const ERR_MANIFEST_VERSION_TOO_LONG: &str = "manifest version exceeds 128 bytes";
const ERR_MANIFEST_FULL: &str = "attempt manifest is full; entries are never dropped";
const ERR_ATTEMPT_ID_LEN: &str = "attempt id must be 16 bytes";
const ERR_DEDUPE_KIND_MISMATCH: &str = "dedupe index points at a different attempt kind";
const ERR_READY_KEY_LEN: &str = "ready index key must be 24 bytes";
const ERR_LEASE_TIMEOUT_ZERO: &str = "lease timeout must be > 0";
const RETRY_REASON_LEASE_TIMEOUT: &str = "lease_timeout";
const ATTEMPT_QUEUE_RETRY_REASON_COUNT: usize = 2;
static ATTEMPT_QUEUE_CLEANUP_RUNS: AtomicU64 = AtomicU64::new(0);
static ATTEMPT_QUEUE_CLEANUP_STALE_REQUEUED: AtomicU64 = AtomicU64::new(0);
static ATTEMPT_QUEUE_CLEANUP_RETRY_REASON_COUNTERS: [AtomicU64; ATTEMPT_QUEUE_RETRY_REASON_COUNT] =
    [AtomicU64::new(0), AtomicU64::new(0)];
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

/// Stable identifier for a queued attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AttemptId {
    bytes: [u8; 16],
}

impl AttemptId {
    /// Creates a new time-sortable v7 UUID-backed attempt id.
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
            .map_err(|_| Error::InvalidAttemptQueueRecord(ERR_ATTEMPT_ID_LEN))?;
        Ok(Self { bytes })
    }
}

/// Durable lifecycle state persisted on each attempt row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AttemptState {
    Queued,
    Leased,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

impl AttemptState {
    pub(crate) const fn as_str(self) -> &'static str {
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

/// Durable intervention kind recorded on an attempt row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptInterventionKind {
    Interrupt,
    Pause,
    Resume,
    Cancel,
}

impl AttemptInterventionKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Interrupt => "interrupt",
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Cancel => "cancel",
        }
    }
}

/// Durable intervention event appended to an attempt row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptEvent {
    pub sequence: u64,
    pub at: u64,
    pub actor: String,
    pub kind: AttemptInterventionKind,
    #[serde(default)]
    pub note: Option<String>,
}

/// What one [`ManifestEntry`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ManifestKind {
    /// A SKILL pulled into the attempt's pack (`skill_id` + version).
    Skill,
    /// An `actor.*` claim row loaded into the attempt's pack.
    ActorClaim,
}

impl ManifestKind {
    /// Returns the stable wire string for this manifest kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Skill => "skill",
            Self::ActorClaim => "actor_claim",
        }
    }
}

/// One append-only row of an attempt's PACK MANIFEST (ARCH-0053 §2/§3).
///
/// The pack is alive: the tier-1 index is stamped at `t0` and every mid-run
/// tier-2 body pull appends its own row WHEN it happens, so the terminal
/// receipt carries the full accumulated manifest and attribution can name
/// what was actually loaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub kind: ManifestKind,
    /// The loaded thing's stable identity (`skill_id`, claim id hex, …).
    pub reference: String,
    /// The loaded revision (`SkillRecord::version`, a claim revision, …).
    pub version: String,
    /// Unix seconds at which the pack loaded it.
    pub at: u64,
}

impl ManifestEntry {
    /// Builds one manifest row.
    #[must_use]
    pub fn new(
        kind: ManifestKind,
        reference: impl Into<String>,
        version: impl Into<String>,
        at: u64,
    ) -> Self {
        Self {
            kind,
            reference: reference.into(),
            version: version.into(),
            at,
        }
    }

    /// The `reference@version` wire form the terminal receipt projects.
    #[must_use]
    pub fn wire_form(&self) -> String {
        format!("{}@{}", self.reference, self.version)
    }
}

/// Durable attempt row stored in LMDB.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptRecord {
    pub id: AttemptId,
    pub kind: String,
    pub payload: Vec<u8>,
    pub state: AttemptState,
    pub lease_owner: Option<String>,
    pub attempt_count: u32,
    #[serde(default)]
    pub claimed_at: Option<u64>,
    #[serde(default)]
    pub backoff_until: Option<u64>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub task_ref: Option<String>,
    pub run_id: Option<String>,
    pub dedupe_key: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(default)]
    pub events: Vec<AttemptEvent>,
    /// ARCH-0053 §2/§3 PACK MANIFEST: append-only, parallel to `events` and
    /// deliberately NOT folded into it (`AttemptEvent` is the closed
    /// four-variant intervention record). Rows without the key decode empty,
    /// so no migration is needed.
    #[serde(default)]
    pub manifest: Vec<ManifestEntry>,
}

impl AttemptRecord {
    /// The attempt's accumulated pack manifest, in append order.
    #[must_use]
    pub fn manifest(&self) -> &[ManifestEntry] {
        &self.manifest
    }
}

/// Input for enqueueing an attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnqueueAttempt {
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
    Enqueued(AttemptRecord),
    Existing(AttemptRecord),
}

/// Input for atomically claiming the next queued attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimAttempt {
    pub lease_owner: String,
    pub now: u64,
}

/// Typed claim outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum ClaimOutcome {
    Empty,
    Claimed(AttemptRecord),
}

/// Input for completing a leased attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteAttempt {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub now: u64,
}

/// Typed complete outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompleteOutcome {
    Completed(AttemptRecord),
    AlreadyCompleted(AttemptRecord),
}

/// Input for failing a leased attempt terminally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailAttempt {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub reason: String,
    pub now: u64,
}

/// Typed fail outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FailOutcome {
    Failed(AttemptRecord),
    AlreadyFailed(AttemptRecord),
}

/// Input for returning a leased attempt to the ready index after a retryable
/// attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryAttempt {
    pub id: AttemptId,
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
    Retried(AttemptRecord),
}

/// Input for interrupting, pausing, resuming, or cancelling an attempt row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterveneAttempt {
    pub id: AttemptId,
    pub kind: AttemptInterventionKind,
    pub actor: String,
    pub note: Option<String>,
    pub now: u64,
}

/// Observable effect of an intervention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptInterventionEffect {
    Interrupted,
    Paused,
    AlreadyPaused,
    Resumed,
    AlreadyResumed,
    Cancelled,
    AlreadyCancelled,
}

impl AttemptInterventionEffect {
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
    pub effect: AttemptInterventionEffect,
    pub record: AttemptRecord,
}

/// Input for returning stale leased attempts to the ready index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupAttemptLeases {
    /// Current wall-clock seconds chosen by the caller.
    pub now: u64,
    /// A leased attempt expires when `now - updated_at >= lease_timeout_secs`.
    pub lease_timeout_secs: u64,
}

/// Privacy-stable retry reason classes reported by attempt-queue cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AttemptQueueRetryReason {
    LeaseTimeout,
    RetryBackoff,
}

impl AttemptQueueRetryReason {
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

    const fn metric_values() -> [Self; ATTEMPT_QUEUE_RETRY_REASON_COUNT] {
        [Self::LeaseTimeout, Self::RetryBackoff]
    }
}

/// Count for one privacy-stable retry reason class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttemptQueueRetryReasonCount {
    pub reason: AttemptQueueRetryReason,
    pub count: u64,
}

impl AttemptQueueRetryReasonCount {
    const fn zero(reason: AttemptQueueRetryReason) -> Self {
        Self { reason, count: 0 }
    }
}

/// Queue cleanup report shaped for runner and run-tree surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttemptQueueCleanupReport {
    pub pending: u64,
    pub running: u64,
    pub failed: u64,
    pub done: u64,
    pub stale_requeued: u64,
    pub retry_reasons: [AttemptQueueRetryReasonCount; ATTEMPT_QUEUE_RETRY_REASON_COUNT],
}

impl Default for AttemptQueueCleanupReport {
    fn default() -> Self {
        Self {
            pending: 0,
            running: 0,
            failed: 0,
            done: 0,
            stale_requeued: 0,
            retry_reasons: AttemptQueueRetryReason::metric_values()
                .map(AttemptQueueRetryReasonCount::zero),
        }
    }
}

impl AttemptQueueCleanupReport {
    #[must_use]
    pub fn retry_reason_count(&self, reason: AttemptQueueRetryReason) -> u64 {
        self.retry_reasons[reason.metric_index()].count
    }

    fn increment_retry_reason(&mut self, reason: AttemptQueueRetryReason) {
        self.retry_reasons[reason.metric_index()].count += 1;
    }
}

/// In-process cleanup counters with stable, content-free labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptQueueCleanupMetricsSnapshot {
    pub runs: u64,
    pub stale_requeued: u64,
    pub retry_reasons: [AttemptQueueRetryReasonCount; ATTEMPT_QUEUE_RETRY_REASON_COUNT],
}

/// Returns process-local attempt-queue cleanup counters.
#[must_use]
pub fn attempt_queue_cleanup_metrics_snapshot() -> AttemptQueueCleanupMetricsSnapshot {
    AttemptQueueCleanupMetricsSnapshot {
        runs: ATTEMPT_QUEUE_CLEANUP_RUNS.load(AtomicOrdering::Relaxed),
        stale_requeued: ATTEMPT_QUEUE_CLEANUP_STALE_REQUEUED.load(AtomicOrdering::Relaxed),
        retry_reasons: AttemptQueueRetryReason::metric_values().map(|reason| {
            AttemptQueueRetryReasonCount {
                reason,
                count: ATTEMPT_QUEUE_CLEANUP_RETRY_REASON_COUNTERS[reason.metric_index()]
                    .load(AtomicOrdering::Relaxed),
            }
        }),
    }
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
            backoff_until: None,
            last_error: None,
            task_ref,
            run_id: input.run_id,
            dedupe_key: input.dedupe_key,
            created_at: input.now,
            updated_at: input.now,
            events: Vec::new(),
            manifest: Vec::new(),
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
            if record.state != AttemptState::Queued {
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
            if record.state != AttemptState::Queued {
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
            if record.state != AttemptState::Queued
                || ready_at(&record) > input.now
                || record.kind != kind
            {
                self.apply_claim_kind_read_repairs(&mut wtxn, scan)?;
                wtxn.commit()?;
                return Ok(ClaimKindWriteAttempt::Retry);
            }
            record.state = AttemptState::Leased;
            record.lease_owner = Some(input.lease_owner.clone());
            record.attempt_count = record
                .attempt_count
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("attempt lease count"))?;
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
            if record.state != AttemptState::Queued {
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
            record.state = AttemptState::Leased;
            record.lease_owner = Some(input.lease_owner.clone());
            record.attempt_count = record
                .attempt_count
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("attempt lease count"))?;
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

    /// Requeues a leased attempt with explicit backoff state after a retryable
    /// attempt. The original payload, run id, and advisory dedupe key stay on
    /// the same durable row.
    pub fn retry(&self, input: RetryAttempt) -> Result<RetryOutcome> {
        let mut wtxn = self.store.env.write_txn()?;
        let Some(raw_record) = self.store.attempt_records.get(&wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("retry", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        match record.state {
            AttemptState::Leased => {
                validate_lease_owner(&input.lease_owner)?;
                validate_transition_lease(
                    &record,
                    &input.lease_owner,
                    input.attempt_count,
                    "retry",
                )?;
                validate_optional_failure_reason(input.last_error.as_deref())?;
                record.state = AttemptState::Queued;
                record.lease_owner = None;
                record.backoff_until = Some(input.backoff_until);
                record.last_error = input.last_error;
                record.updated_at = input.now;
                let encoded = encode_record(&record)?;
                self.store
                    .attempt_records
                    .put(&mut wtxn, record.id.as_bytes(), &encoded)?;
                let ready_key = ready_key(ready_at(&record), record.id);
                self.store
                    .attempt_ready
                    .put(&mut wtxn, &ready_key, record.id.as_bytes())?;
                wtxn.commit()?;
                Ok(RetryOutcome::Retried(record))
            }
            state => Err(invalid_transition("retry", state.as_str())),
        }
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
                AttemptState::Queued | AttemptState::Leased | AttemptState::Paused => {
                    append_attempt_event(
                        &mut record,
                        input.kind,
                        input.actor,
                        input.note,
                        input.now,
                    )?;
                    record.updated_at = input.now;
                    AttemptInterventionEffect::Interrupted
                }
                state => return Err(invalid_transition(input.kind.as_str(), state.as_str())),
            },
            AttemptInterventionKind::Pause => match record.state {
                AttemptState::Paused => AttemptInterventionEffect::AlreadyPaused,
                AttemptState::Queued => {
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
                    record.state = AttemptState::Queued;
                    record.lease_owner = None;
                    record.updated_at = input.now;
                    let ready_key = ready_key(ready_at(&record), record.id);
                    self.store
                        .attempt_ready
                        .put(wtxn, &ready_key, record.id.as_bytes())?;
                    AttemptInterventionEffect::Resumed
                }
                AttemptState::Queued | AttemptState::Leased => {
                    AttemptInterventionEffect::AlreadyResumed
                }
                state => return Err(invalid_transition(input.kind.as_str(), state.as_str())),
            },
            AttemptInterventionKind::Cancel => match record.state {
                AttemptState::Cancelled => AttemptInterventionEffect::AlreadyCancelled,
                AttemptState::Queued | AttemptState::Paused => {
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
                AttemptState::Queued => {
                    report.pending += 1;
                    if record.backoff_until.is_some() {
                        report.increment_retry_reason(AttemptQueueRetryReason::RetryBackoff);
                    }
                }
                AttemptState::Paused => {
                    report.pending += 1;
                    if record.backoff_until.is_some() {
                        report.increment_retry_reason(AttemptQueueRetryReason::RetryBackoff);
                    }
                }
                AttemptState::Leased
                    if lease_expired(&record, input.now, input.lease_timeout_secs) =>
                {
                    report.running += 1;
                    expired_candidates.push(id);
                }
                AttemptState::Leased => {
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
                        record.state = AttemptState::Queued;
                        record.lease_owner = None;
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
                    AttemptState::Leased => {}
                    AttemptState::Queued => {
                        mark_rechecked_candidate_not_running(&mut report);
                        report.pending += 1;
                        if record.backoff_until.is_some() {
                            report.increment_retry_reason(AttemptQueueRetryReason::RetryBackoff);
                        }
                    }
                    AttemptState::Paused => {
                        mark_rechecked_candidate_not_running(&mut report);
                        report.pending += 1;
                        if record.backoff_until.is_some() {
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

fn validate_kind(kind: &str) -> Result<()> {
    if kind.is_empty() {
        return Err(Error::InvalidAttemptQueueRecord(ERR_EMPTY_KIND));
    }
    if kind.len() > MAX_KIND_LEN {
        return Err(Error::InvalidAttemptQueueRecord(ERR_KIND_TOO_LONG));
    }
    Ok(())
}

fn validate_optional_dedupe(dedupe_key: Option<&str>) -> Result<()> {
    if let Some(dedupe_key) = dedupe_key {
        if dedupe_key.is_empty() {
            return Err(Error::InvalidAttemptQueueRecord(ERR_DEDUPE_KEY_EMPTY));
        }
        if dedupe_key.len() > MAX_DEDUPE_KEY_LEN {
            return Err(Error::InvalidAttemptQueueRecord(ERR_DEDUPE_KEY_TOO_LONG));
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
            return Err(Error::InvalidAttemptQueueRecord(ERR_FAILURE_REASON_EMPTY));
        }
        if reason.len() > MAX_FAILURE_REASON_LEN {
            return Err(Error::InvalidAttemptQueueRecord(
                ERR_FAILURE_REASON_TOO_LONG,
            ));
        }
    }
    Ok(())
}

fn validate_optional_run_id(run_id: Option<&str>) -> Result<()> {
    if let Some(run_id) = run_id {
        if run_id.is_empty() {
            return Err(Error::InvalidAttemptQueueRecord(ERR_RUN_ID_EMPTY));
        }
        if run_id.len() > MAX_RUN_ID_LEN {
            return Err(Error::InvalidAttemptQueueRecord(ERR_RUN_ID_TOO_LONG));
        }
    }
    Ok(())
}

fn validate_intervention_actor(actor: &str) -> Result<()> {
    if actor.is_empty() {
        return Err(Error::InvalidAttemptQueueRecord(
            ERR_INTERVENTION_ACTOR_EMPTY,
        ));
    }
    if actor.len() > MAX_INTERVENTION_ACTOR_LEN {
        return Err(Error::InvalidAttemptQueueRecord(
            ERR_INTERVENTION_ACTOR_TOO_LONG,
        ));
    }
    Ok(())
}

fn validate_optional_intervention_note(note: Option<&str>) -> Result<()> {
    if let Some(note) = note {
        if note.is_empty() {
            return Err(Error::InvalidAttemptQueueRecord(
                ERR_INTERVENTION_NOTE_EMPTY,
            ));
        }
        if note.len() > MAX_INTERVENTION_NOTE_LEN {
            return Err(Error::InvalidAttemptQueueRecord(
                ERR_INTERVENTION_NOTE_TOO_LONG,
            ));
        }
    }
    Ok(())
}

fn validate_lease_owner(lease_owner: &str) -> Result<()> {
    if lease_owner.is_empty() {
        return Err(Error::InvalidAttemptQueueRecord(ERR_LEASE_OWNER_EMPTY));
    }
    if lease_owner.len() > MAX_LEASE_OWNER_LEN {
        return Err(Error::InvalidAttemptQueueRecord(ERR_LEASE_OWNER_TOO_LONG));
    }
    Ok(())
}

fn validate_cleanup_leases_input(input: &CleanupAttemptLeases) -> Result<()> {
    if input.lease_timeout_secs == 0 {
        return Err(Error::InvalidAttemptQueueRecord(ERR_LEASE_TIMEOUT_ZERO));
    }
    Ok(())
}

fn validate_transition_lease(
    record: &AttemptRecord,
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

fn validate_attempt_events(events: &[AttemptEvent]) -> Result<()> {
    let mut previous_sequence = 0;
    for event in events {
        if event.sequence == 0 || event.sequence <= previous_sequence {
            return Err(Error::InvalidAttemptQueueRecord(
                "attempt event sequence must be strictly increasing",
            ));
        }
        validate_intervention_actor(&event.actor)?;
        validate_optional_intervention_note(event.note.as_deref())?;
        previous_sequence = event.sequence;
    }
    Ok(())
}

fn validate_manifest_entry(entry: &ManifestEntry) -> Result<()> {
    if entry.reference.is_empty() {
        return Err(Error::InvalidAttemptQueueRecord(
            ERR_MANIFEST_REFERENCE_EMPTY,
        ));
    }
    if entry.reference.len() > MAX_MANIFEST_REFERENCE_LEN {
        return Err(Error::InvalidAttemptQueueRecord(
            ERR_MANIFEST_REFERENCE_TOO_LONG,
        ));
    }
    if entry.version.is_empty() {
        return Err(Error::InvalidAttemptQueueRecord(ERR_MANIFEST_VERSION_EMPTY));
    }
    if entry.version.len() > MAX_MANIFEST_VERSION_LEN {
        return Err(Error::InvalidAttemptQueueRecord(
            ERR_MANIFEST_VERSION_TOO_LONG,
        ));
    }
    Ok(())
}

fn validate_attempt_manifest(manifest: &[ManifestEntry]) -> Result<()> {
    if manifest.len() > MAX_ATTEMPT_MANIFEST_ENTRIES {
        return Err(Error::InvalidAttemptQueueRecord(ERR_MANIFEST_FULL));
    }
    for entry in manifest {
        validate_manifest_entry(entry)?;
    }
    Ok(())
}

fn append_attempt_event(
    record: &mut AttemptRecord,
    kind: AttemptInterventionKind,
    actor: String,
    note: Option<String>,
    now: u64,
) -> Result<()> {
    let sequence = match record.events.last() {
        Some(event) => event
            .sequence
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("attempt event sequence"))?,
        None => 1,
    };
    record.events.push(AttemptEvent {
        sequence,
        at: now,
        actor,
        kind,
        note,
    });
    if record.events.len() > MAX_ATTEMPT_EVENTS_PER_RECORD {
        let excess = record.events.len() - MAX_ATTEMPT_EVENTS_PER_RECORD;
        record.events.drain(0..excess);
    }
    Ok(())
}

fn validate_dedupe_record(record: &AttemptRecord, kind: &str, dedupe_key: &str) -> Result<()> {
    if record.kind != kind {
        return Err(Error::InvalidAttemptQueueRecord(ERR_DEDUPE_KIND_MISMATCH));
    }
    if record.dedupe_key.as_deref() != Some(dedupe_key) {
        return Err(Error::InvalidAttemptQueueRecord(
            "dedupe index points at an attempt with a different dedupe key",
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

fn ready_at(record: &AttemptRecord) -> u64 {
    record.backoff_until.unwrap_or(0)
}

fn lease_expired(record: &AttemptRecord, now: u64, lease_timeout_secs: u64) -> bool {
    now.checked_sub(record.updated_at)
        .is_some_and(|age| age >= lease_timeout_secs)
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

pub(crate) fn attempt_record_order(
    left: &AttemptRecord,
    right: &AttemptRecord,
) -> std::cmp::Ordering {
    left.created_at
        .cmp(&right.created_at)
        .then_with(|| left.id.as_bytes().cmp(right.id.as_bytes()))
}

fn ready_key(ready_at: u64, id: AttemptId) -> [u8; READY_KEY_LEN] {
    let mut key = [0_u8; READY_KEY_LEN];
    key[..8].copy_from_slice(&ready_at.to_be_bytes());
    key[8..].copy_from_slice(id.as_bytes());
    key
}

fn decode_ready_key(bytes: &[u8]) -> Result<(u64, AttemptId)> {
    if bytes.len() != READY_KEY_LEN {
        return Err(Error::InvalidAttemptQueueRecord(ERR_READY_KEY_LEN));
    }
    let mut created_at = [0_u8; 8];
    created_at.copy_from_slice(&bytes[..8]);
    Ok((
        u64::from_be_bytes(created_at),
        AttemptId::from_bytes(&bytes[8..])?,
    ))
}

fn encode_record(record: &AttemptRecord) -> Result<Vec<u8>> {
    let mut encoded = vec![ATTEMPT_RECORD_VERSION];
    let mut body = rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvalidAttemptQueueRecord("failed to encode attempt record"))?;
    encoded.append(&mut body);
    Ok(encoded)
}

pub(crate) fn decode_record(raw: &[u8], expected_id: AttemptId) -> Result<AttemptRecord> {
    let Some((&version, body)) = raw.split_first() else {
        return Err(Error::InvalidAttemptQueueRecord(
            "missing attempt record version",
        ));
    };
    if version != ATTEMPT_RECORD_VERSION {
        return Err(Error::InvalidAttemptQueueRecord(
            "unsupported attempt record version",
        ));
    }
    let record: AttemptRecord = rmp_serde::from_slice(body)
        .map_err(|_| Error::InvalidAttemptQueueRecord("failed to decode attempt record"))?;
    if record.id != expected_id {
        return Err(Error::InvalidAttemptQueueRecord(
            "job_records key/id mismatch",
        ));
    }
    validate_kind(&record.kind)?;
    validate_optional_dedupe(record.dedupe_key.as_deref())?;
    validate_optional_run_id(record.run_id.as_deref())?;
    validate_optional_failure_reason(record.last_error.as_deref())?;
    validate_attempt_events(&record.events)?;
    validate_attempt_manifest(&record.manifest)?;
    if let Some(lease_owner) = record.lease_owner.as_deref() {
        validate_lease_owner(lease_owner)?;
    }
    match record.state {
        AttemptState::Queued if record.lease_owner.is_some() => {
            return Err(Error::InvalidAttemptQueueRecord(
                "queued attempt must not have a lease owner",
            ));
        }
        AttemptState::Leased if record.lease_owner.is_none() => {
            return Err(Error::InvalidAttemptQueueRecord(
                "leased attempt must have a lease owner",
            ));
        }
        AttemptState::Leased if record.backoff_until.is_some() => {
            return Err(Error::InvalidAttemptQueueRecord(
                "leased attempt must not have backoff state",
            ));
        }
        AttemptState::Paused if record.lease_owner.is_some() => {
            return Err(Error::InvalidAttemptQueueRecord(
                "paused attempt must not have a lease owner",
            ));
        }
        AttemptState::Completed | AttemptState::Failed | AttemptState::Cancelled
            if record.lease_owner.is_some() =>
        {
            return Err(Error::InvalidAttemptQueueRecord(
                "terminal attempt must not have a lease owner",
            ));
        }
        AttemptState::Completed | AttemptState::Failed | AttemptState::Cancelled
            if record.backoff_until.is_some() =>
        {
            return Err(Error::InvalidAttemptQueueRecord(
                "terminal attempt must not have backoff state",
            ));
        }
        AttemptState::Completed | AttemptState::Cancelled if record.last_error.is_some() => {
            return Err(Error::InvalidAttemptQueueRecord(
                "non-failed terminal attempt must not have a failure reason",
            ));
        }
        AttemptState::Failed if record.last_error.is_none() => {
            return Err(Error::InvalidAttemptQueueRecord(
                "failed attempt must have a failure reason",
            ));
        }
        _ => {}
    }
    Ok(record)
}

fn invalid_transition(action: &'static str, state: &'static str) -> Error {
    Error::InvalidAttemptQueueTransition { action, state }
}

fn record_attempt_queue_cleanup_metrics(report: &AttemptQueueCleanupReport) {
    ATTEMPT_QUEUE_CLEANUP_RUNS.fetch_add(1, AtomicOrdering::Relaxed);
    ATTEMPT_QUEUE_CLEANUP_STALE_REQUEUED.fetch_add(report.stale_requeued, AtomicOrdering::Relaxed);
    for counter in report.retry_reasons {
        ATTEMPT_QUEUE_CLEANUP_RETRY_REASON_COUNTERS[counter.reason.metric_index()]
            .fetch_add(counter.count, AtomicOrdering::Relaxed);
    }
}

fn emit_attempt_queue_cleanup_span(
    input: &CleanupAttemptLeases,
    report: &AttemptQueueCleanupReport,
) {
    let retry_lease_timeout = report.retry_reason_count(AttemptQueueRetryReason::LeaseTimeout);
    let retry_backoff = report.retry_reason_count(AttemptQueueRetryReason::RetryBackoff);
    let span = tracing::info_span!(
        target: "oneiron::attempt_queue",
        "attempt_queue_cleanup",
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
        target: "oneiron::attempt_queue",
        pending = report.pending,
        running = report.running,
        failed = report.failed,
        done = report.done,
        stale_requeued = report.stale_requeued,
        retry_lease_timeout,
        retry_backoff,
        "attempt queue cleanup completed"
    );
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod one_1695_tests {
    use super::*;

    #[derive(serde::Serialize)]
    struct LegacyAttemptRecord {
        id: AttemptId,
        kind: String,
        payload: Vec<u8>,
        state: AttemptState,
        lease_owner: Option<String>,
        attempt_count: u32,
        claimed_at: Option<u64>,
        backoff_until: Option<u64>,
        last_error: Option<String>,
        run_id: Option<String>,
        dedupe_key: Option<String>,
        created_at: u64,
        updated_at: u64,
        events: Vec<AttemptEvent>,
    }

    fn record(task_ref: Option<&str>) -> AttemptRecord {
        AttemptRecord {
            id: AttemptId::from_bytes(&[0x42; 16]).expect("attempt id from 16 bytes"),
            kind: "sync".to_owned(),
            payload: b"payload".to_vec(),
            state: AttemptState::Queued,
            lease_owner: None,
            attempt_count: 0,
            claimed_at: None,
            backoff_until: None,
            last_error: None,
            task_ref: task_ref.map(str::to_owned),
            run_id: Some("run-owner".to_owned()),
            dedupe_key: Some("owner-job".to_owned()),
            created_at: 10,
            updated_at: 10,
            events: Vec::new(),
            manifest: Vec::new(),
        }
    }

    #[test]
    fn task_ref_serde_round_trips() {
        let expected = record(Some("tk_owner"));
        let encoded = rmp_serde::to_vec_named(&expected).expect("serialize attempt record");
        let decoded: AttemptRecord =
            rmp_serde::from_slice(&encoded).expect("deserialize attempt record");

        assert_eq!(decoded, expected);
    }

    #[test]
    fn task_ref_defaults_when_legacy_record_omits_key() -> Result<()> {
        let current = record(None);
        let legacy = LegacyAttemptRecord {
            id: current.id,
            kind: current.kind,
            payload: current.payload,
            state: current.state,
            lease_owner: current.lease_owner,
            attempt_count: current.attempt_count,
            claimed_at: current.claimed_at,
            backoff_until: current.backoff_until,
            last_error: current.last_error,
            run_id: current.run_id,
            dedupe_key: current.dedupe_key,
            created_at: current.created_at,
            updated_at: current.updated_at,
            events: current.events,
        };
        let mut encoded = vec![ATTEMPT_RECORD_VERSION];
        encoded.extend(
            rmp_serde::to_vec_named(&legacy).expect("serialize legacy attempt record without key"),
        );

        let decoded = decode_record(&encoded, legacy.id)?;

        assert_eq!(decoded.task_ref, None);
        Ok(())
    }

    #[test]
    fn attempt_queue_sets_and_reads_optional_task_ref() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
        let queue = AttemptQueue::new(&vault);
        let input = |now| EnqueueAttempt {
            kind: "sync".to_owned(),
            payload: format!("payload-{now}").into_bytes(),
            dedupe_key: None,
            run_id: None,
            now,
        };

        queue.enqueue_with_task_ref(input(10), Some("tk_owner".to_owned()))?;
        queue.enqueue(input(20))?;

        let records = queue.list()?;
        assert_eq!(records.len(), 2);
        assert_eq!(
            records
                .iter()
                .filter(|record| record.task_ref.is_some())
                .count(),
            1
        );
        assert_eq!(records[0].task_ref.as_deref(), Some("tk_owner"));
        assert_eq!(records[1].task_ref, None);
        Ok(())
    }
}
