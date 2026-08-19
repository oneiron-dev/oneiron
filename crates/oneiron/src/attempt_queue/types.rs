//! Durable wire, verb-input, and outcome types for the attempt queue.
//!
//! Storage mechanics live in [`super::encoding`], input validation in
//! [`super::validate`], and the queue handle itself in [`super::engine`].

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Error, Result};

/// Receipt-family ABI-pin rule: changing this requires a
/// [`crate::store::STORAGE_ABI_VERSION`] bump.
pub(crate) const ATTEMPT_RECORD_VERSION: u8 = 2;
const ERR_ATTEMPT_ID_LEN: &str = "attempt id must be 16 bytes";
pub(super) const MAX_ATTEMPT_EVENTS_PER_RECORD: usize = 256;
/// Defensive cap on [`AttemptRecord::manifest`] rows.
///
/// Deliberately NOT the `MAX_ATTEMPT_EVENTS_PER_RECORD` semantics: the
/// events field DRAINS its oldest rows above the cap, which would silently
/// violate the ARCH-0053 §3 append-only manifest invariant (an attribution
/// projector cannot tell a dropped skill from one that was never loaded).
/// The manifest door instead REFUSES at this cap — fail loud, never drain.
pub const MAX_ATTEMPT_MANIFEST_ENTRIES: usize = 4096;
pub(super) const ATTEMPT_QUEUE_RETRY_REASON_COUNT: usize = 2;

/// Stable identifier for a queued attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AttemptId {
    pub(super) bytes: [u8; 16],
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
    // Append-only: persisted unit-enum variants are encoded by index, so a new
    // variant may only be added AFTER every existing one. Reordering would
    // silently re-map already-written rows.
    /// Minted by [`crate::attempt_queue::AttemptQueue::retry`]: a fresh try
    /// waiting for its `scheduled_at` instant. Claimable only once
    /// `now >= scheduled_at`.
    Scheduled,
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
            Self::Scheduled => "scheduled",
        }
    }

    /// True while the row can still reach a terminal state, so it still owns
    /// its advisory dedupe entry.
    pub(super) const fn is_pending(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Leased | Self::Paused | Self::Scheduled
        )
    }

    /// True for the two states a ready-index row may legitimately sit in.
    pub(super) const fn is_ready_indexed(self) -> bool {
        matches!(self, Self::Queued | Self::Scheduled)
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
    pub(super) const fn as_str(self) -> &'static str {
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

    /// Splits a [`Self::wire_form`] string back into `(reference, version)`.
    ///
    /// The delimiter is the FIRST `@` (owner ruling R-20260807-04). The
    /// grammar is asymmetric on purpose: a reference may not contain `@` —
    /// `validate::validate_manifest_entry` refuses one at the door — while a
    /// VERSION may, so `s@1@beta` is the skill `s` at revision
    /// `1@beta`. Splitting from the right instead read that row as skill `s@1`
    /// at revision `beta`, attributing an outcome to a skill that never
    /// existed.
    ///
    /// Returns `None` for a string carrying no `@` at all, which is not a
    /// wire form.
    #[must_use]
    pub fn parse_wire_form(wire_form: &str) -> Option<(&str, &str)> {
        wire_form.split_once('@')
    }
}

/// Durable attempt row stored in LMDB.
///
/// One synced TASK owns N node-local ATTEMPT rows. A retry never mutates a
/// failed try back into a ready one: it finalizes the source and mints a fresh
/// row linked by [`AttemptRecord::retry_of`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptRecord {
    pub id: AttemptId,
    pub kind: String,
    pub payload: Vec<u8>,
    pub state: AttemptState,
    pub lease_owner: Option<String>,
    /// Lease-generation fence WITHIN this one try. It does not count logical
    /// retries — those are separate rows.
    pub attempt_count: u32,
    #[serde(default)]
    pub claimed_at: Option<u64>,
    /// Instant a [`AttemptState::Scheduled`] row becomes claimable.
    #[serde(default)]
    pub scheduled_at: Option<u64>,
    /// The try this row retries, when it was minted by
    /// [`crate::attempt_queue::AttemptQueue::retry`].
    #[serde(default)]
    pub retry_of: Option<AttemptId>,
    /// Legacy read compatibility only. Rows written before ONE-1795 carry their
    /// readiness instant here; new retry rows use `scheduled_at`.
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

/// Input for finalizing a leased attempt and scheduling its next try.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryAttempt {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    /// Field spelling is retained for source compatibility; it becomes the new
    /// row's `scheduled_at`.
    pub backoff_until: u64,
    pub last_error: Option<String>,
    pub now: u64,
}

/// Typed retry outcome, carrying the newly scheduled try (not the finalized
/// source, which stays point-readable by its own id).
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

    pub(super) const fn metric_index(self) -> usize {
        match self {
            Self::LeaseTimeout => 0,
            Self::RetryBackoff => 1,
        }
    }

    pub(super) const fn metric_values() -> [Self; ATTEMPT_QUEUE_RETRY_REASON_COUNT] {
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

    pub(super) fn increment_retry_reason(&mut self, reason: AttemptQueueRetryReason) {
        self.retry_reasons[reason.metric_index()].count += 1;
    }
}

pub(crate) fn attempt_record_order(
    left: &AttemptRecord,
    right: &AttemptRecord,
) -> std::cmp::Ordering {
    left.created_at
        .cmp(&right.created_at)
        .then_with(|| left.id.as_bytes().cmp(right.id.as_bytes()))
}
