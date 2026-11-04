//! Durable wire, verb-input, and outcome types for the attempt queue.
//!
//! Storage mechanics live in [`super::encoding`], input validation in
//! [`super::validate`], and the queue handle itself in [`super::engine`]. The
//! ONE-1896 graceful-cancel rows and verbs are their own concern and live in
//! [`super::cancel`].

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Error, Result};

use super::cancel::{
    AttemptCancelPressure, AttemptCancelReceipt, AttemptCancelState, AttemptCancellation,
    AttemptLanding, AttemptLandingReserve, AttemptResumePoint,
};
use crate::error::ArtifactError;

mod cleanup;
mod exhaust;
mod hold;
pub use cleanup::{
    AttemptQueueCleanupReport, AttemptQueueRetryReason, AttemptQueueRetryReasonCount,
    CleanupAttemptLeases,
};
pub use exhaust::AttemptTerminalExhaust;
pub(crate) use hold::AttemptPause;

/// Receipt-family ABI-pin rule: changing this requires a
/// [`crate::store::STORAGE_ABI_VERSION`] bump.
pub(crate) const ATTEMPT_RECORD_VERSION: u8 = 3;
const ERR_ATTEMPT_ID_LEN: &str = "attempt id must be 16 bytes";
pub(super) const MAX_ATTEMPT_EVENTS_PER_RECORD: usize = 256;
pub(super) use crate::store::attempt_cleanup::ATTEMPT_QUEUE_RETRY_REASON_COUNT;

/// Stable identifier for a queued attempt.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
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
        let bytes: [u8; 16] = bytes.try_into().map_err(|_| {
            Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(ERR_ATTEMPT_ID_LEN))
        })?;
        Ok(Self { bytes })
    }
}

/// `AttemptId` is a foreign (same-crate) value type to any side table that
/// stores a bare attempt reference as its row's raw 16 bytes (as opposed to
/// keying on it, which `llm::step::types` already binds via `SideKey`).
impl crate::side_table::RawValue for AttemptId {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, crate::side_table::CodecError> {
        Ok(self.as_bytes().to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, crate::side_table::CodecError> {
        Ok(Self::from_bytes(bytes)?)
    }
}

pub use crate::store::attempt_result::AttemptResultRef;

/// Durable lifecycle state persisted on each attempt row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
    /// ONE-1896: the worker accepted a stop and is finishing. It still HOLDS
    /// its lease, so it is neither queued work nor terminal work, and it is
    /// deliberately not [`Self::Completed`] — a landing is an honest,
    /// resumable stop, not a delivered result.
    Landing,
    /// The executor stopped without delivering a result and without anyone
    /// stopping it. Terminal, and deliberately not [`Self::Failed`]: nothing
    /// reported a fault, the work simply stopped being carried. Deliberately
    /// not [`Self::Cancelled`] either: no operator or authority asked for it.
    ///
    /// An abandoned row always names the last durable exhaust it produced
    /// through [`AttemptRecord::result_ref`], so the stop is auditable even
    /// though nothing completed.
    Abandoned,
}

impl AttemptState {
    /// Returns the stable wire string for this attempt state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Leased => "leased",
            Self::Paused => "paused",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Scheduled => "scheduled",
            Self::Landing => "landing",
            Self::Abandoned => "abandoned",
        }
    }

    /// True while the row can still reach a terminal state, so it still owns
    /// its advisory dedupe entry.
    ///
    /// [`Self::Abandoned`] is absent: it IS a terminal state, so an abandoned
    /// row keeps no dedupe claim and can never re-enter queued or leased work.
    pub(super) const fn is_pending(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Leased | Self::Paused | Self::Scheduled | Self::Landing
        )
    }

    /// True for the two states a ready-index row may legitimately sit in.
    ///
    /// [`Self::Landing`] is deliberately absent: a landing attempt owns a live
    /// lease and is doing bounded finishing work, so handing it out as ordinary
    /// queued work would run it twice.
    pub(super) const fn is_ready_indexed(self) -> bool {
        matches!(self, Self::Queued | Self::Scheduled)
    }

    /// True while a worker holds this row's lease and runtime.
    #[must_use]
    pub const fn is_running(self) -> bool {
        matches!(self, Self::Leased | Self::Landing)
    }

    /// True once the row can never transition again.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::Abandoned
        )
    }
}

pub use crate::store::attempt_inputs::{AttemptEvent, AttemptInterventionKind};

pub use crate::store::attempt_manifest::{ManifestEntry, ManifestKind};

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
    /// Tries of this row's lineage that a compaction deleted between this row
    /// and the one it retries (`retry_of`), or before it when it retries
    /// none. The lineage depth counts each as a hop, so backoff reads as
    /// before. Absent from the encoded row while zero.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub folded_retries: u32,
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
    /// Optional actor scope of `dedupe_key`, so two actors sharing one client
    /// key occupy disjoint index entries.
    ///
    /// Key-gated and additive: it is persisted only alongside a `dedupe_key`
    /// (a row without a key is always actorless), and rows written before it
    /// existed decode as `None` under the unchanged record version. It is the
    /// scope terminal cleanup and retry-index transfer derive their key from,
    /// so neither has to consult a caller's state or decode a TASK payload.
    #[serde(default)]
    pub dedupe_actor_ref: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
    /// The terminal transition's instant, pinned so a later write cannot move it.
    /// `None` while the attempt is unsettled.
    pub settled_at: Option<u64>,
    #[serde(default)]
    pub events: Vec<AttemptEvent>,
    /// ARCH-0053 §2/§3 PACK MANIFEST: append-only, parallel to `events` and
    /// deliberately NOT folded into it (`AttemptEvent` is the closed
    /// four-variant intervention record). Rows without the key decode empty,
    /// so no migration is needed.
    #[serde(default)]
    pub manifest: Vec<ManifestEntry>,
    /// Immutable model id and revision of the executor that acted; absent on legacy attempts.
    #[serde(default)]
    pub executor_model: Option<String>,
    /// OF-541: the template seat its host configured the executor with,
    /// stamped in one write with `executor_model`, the model that seat ran.
    /// Absent when no run stamped the pair.
    #[serde(default)]
    pub executor_seat: Option<String>,
    /// OF-578: the functional role the host ran the attempt as, frozen with
    /// `executor_model` and `executor_seat` under the same lease. `None` for
    /// work no role ran.
    #[serde(default)]
    pub executor_role: Option<crate::model_binding::ModelRole>,
    /// FIX 7720: a seatless planned child's first pick, route and exactness,
    /// written once with `executor_model` under its lease before its pack
    /// loads. `None` for any other run; a fresh retry decides its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub planned_binding: Option<PlannedBinding>,
    /// FIX 6934: the rows its producers read its inputs from while it ran,
    /// copied onto its terminal pack receipt. Absent while none recorded a
    /// set, so a row written before the field reads the same, unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_set: Option<super::AttemptReadSet>,
    /// ONE-1896 two-rung graceful-cancel lifecycle: landing, resume point,
    /// terminal cancellation receipt, cancel pressure, and reserve accounting.
    /// Rows without the key decode as the default, so no migration is needed.
    #[serde(default)]
    pub cancel_state: AttemptCancelState,
    /// The artifact version this try's durable output lives in, once one
    /// exists. Cross-executor and deliberately not BYOA-specific: any executor
    /// that produces a durable result names it here.
    ///
    /// Rows written before this field existed decode as `None`, so no
    /// migration is needed and an old row stays byte-identically readable.
    #[serde(default)]
    pub result_ref: Option<AttemptResultRef>,
    /// Branch-addressed control inbox and settled replay receipts.
    #[serde(default)]
    pub signals: Vec<crate::attempt_queue::run_signal::RunBranchSignal>,
    /// Durable ask handles, including partial replies, for this branch only.
    #[serde(default)]
    pub asks: Vec<crate::attempt_queue::run_signal::RunAsk>,
    /// Operator-selected placement, separate from the immutable executor payload.
    #[serde(default)]
    pub placement: Option<AttemptPlacement>,
    /// FIX 5240: each failure a same-intent requeue kept, oldest first.
    #[serde(default)]
    pub history: Vec<super::RequeuedFailure>,
    /// FIX 9579: the pause this row is held under while paused, kept here so
    /// a pruned event history never loses it. `None` while not paused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) active_pause: Option<AttemptPause>,
    /// FIX 9578: what this try left behind, written with the row that
    /// settles it. `None` until it settles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) terminal_exhaust: Option<AttemptTerminalExhaust>,
    /// FIX 10066: the keyed fingerprint of each signal the side-row wall
    /// masked, by its key, so an identical retry still matches.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) signal_intents: Vec<crate::attempt_queue::run_signal::SignalIntent>,
}

impl AttemptRecord {
    pub(crate) fn accepts_worker(&self, worker: &str) -> bool {
        self.placement
            .as_ref()
            .and_then(|p| p.worker.as_deref())
            .is_none_or(|assigned| assigned == worker)
    }

    /// The attempt's accumulated pack manifest, in append order.
    #[must_use]
    pub fn manifest(&self) -> &[ManifestEntry] {
        &self.manifest
    }

    /// The append-only graceful-cancel evidence, in append order.
    #[must_use]
    pub fn cancel_receipts(&self) -> &[AttemptCancelReceipt] {
        &self.cancel_state.receipts
    }

    /// The artifact version this try's durable output lives in, once one
    /// exists.
    #[must_use]
    pub const fn result_ref(&self) -> Option<&AttemptResultRef> {
        self.result_ref.as_ref()
    }

    /// The durable landing record, present while landing and preserved on a
    /// row that landed.
    #[must_use]
    pub const fn landing(&self) -> Option<&AttemptLanding> {
        self.cancel_state.landing.as_ref()
    }

    /// The exact point a successor resumes from, once recorded.
    #[must_use]
    pub const fn resume_point(&self) -> Option<&AttemptResumePoint> {
        self.cancel_state.resume_point.as_ref()
    }

    /// The terminal cancellation receipt, when this row was cancelled.
    #[must_use]
    pub const fn cancellation(&self) -> Option<&AttemptCancellation> {
        self.cancel_state.cancellation.as_ref()
    }

    /// This attempt's landing reserve accounting.
    #[must_use]
    pub const fn landing_reserve(&self) -> AttemptLandingReserve {
        self.cancel_state.reserve
    }

    /// The limit an ordinary execution meter for this attempt must use: the
    /// dialed budget MINUS the landing reserve.
    #[must_use]
    pub const fn ordinary_budget_limit_units(&self) -> u64 {
        self.cancel_state.reserve.ordinary_limit_units()
    }

    /// Soft-request pressure counters.
    #[must_use]
    pub const fn cancel_pressure(&self) -> AttemptCancelPressure {
        self.cancel_state.pressure
    }

    /// True once repeated refusal of soft requests is an observable pathology.
    #[must_use]
    pub const fn soft_cancel_pathology(&self) -> bool {
        self.cancel_state.pressure.is_pathological()
    }
}

pub use crate::store::attempt_inputs::EnqueueAttempt;

/// Typed enqueue outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnqueueOutcome {
    Enqueued(AttemptRecord),
    Existing(AttemptRecord),
}

pub use crate::store::attempt_inputs::ClaimAttempt;

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

/// Input for naming the artifact version a live attempt's result lives in.
///
/// Attaching a result is deliberately its own verb rather than a field on
/// [`CompleteAttempt`]: the exhaust an executor produces is durable BEFORE the
/// row settles, and an executor that then stops without completing must still
/// point at it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetAttemptResult {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub result_ref: AttemptResultRef,
    pub now: u64,
}

/// Input for abandoning a live attempt: it stopped without delivering, and
/// nobody stopped it.
///
/// The result reference is REQUIRED, not optional. An abandonment with nothing
/// to point at would be indistinguishable from a lost row, and the whole point
/// of the state is that the stop stays auditable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbandonAttempt {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub result_ref: AttemptResultRef,
    pub reason: String,
    pub now: u64,
}

/// Typed abandon outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AbandonOutcome {
    Abandoned(AttemptRecord),
    AlreadyAbandoned(AttemptRecord),
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

/// Operator-selected worker and parent. An absent worker keeps ordinary claiming;
/// an absent parent makes the attempt a root. The executor kind never changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptPlacement {
    pub worker: Option<String>,
    pub parent: Option<AttemptId>,
}

/// A seatless planned child's binding (FIX 7720/7721/7723): its plan's pick,
/// the route it runs on and whether it runs that pick exactly, frozen once
/// beside the executor model it runs. Every later entry of the try reuses it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedBinding {
    pub pick: oneiron_model::llm::ModelId,
    pub locality: oneiron_model::llm::ModelLocality,
    pub exactness: PlannedExactness,
    /// The try whose run a continuation forks (FIX 3694), when it is one.
    pub source: Option<AttemptId>,
}

/// Whether a planned child runs its pick exactly, as its binding records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannedExactness {
    /// Its provider routes the pick exactly and its list holds it.
    Exact,
    /// Its provider's own model runs; a call another model answers is marked.
    NonExact,
    /// A continuation whose source recorded no exactness: run as not exact,
    /// never guessed from today's catalog.
    Inherited,
}

pub use crate::store::attempt_inputs::AttemptInterventionEffect;

/// Typed intervention outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterveneOutcome {
    pub effect: AttemptInterventionEffect,
    pub record: AttemptRecord,
}

pub(crate) fn attempt_record_order(
    left: &AttemptRecord,
    right: &AttemptRecord,
) -> std::cmp::Ordering {
    left.created_at
        .cmp(&right.created_at)
        .then_with(|| left.id.as_bytes().cmp(right.id.as_bytes()))
}

/// Serde skip predicate: a lineage no compaction touched says so by omission,
/// so its rows encode as they did before the field existed.
#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if hands the field by reference"
)]
fn is_zero(value: &u32) -> bool {
    *value == 0
}
