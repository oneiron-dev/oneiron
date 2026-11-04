//! The durable attempt row (`AttemptRecord`) and the field types it alone
//! holds: its operator placement, a planned child's binding and exactness,
//! the rows its inputs were read from, the failures a requeue kept, the
//! pause it is held under and what a terminal try left behind. The attempt
//! queue (`attempt_queue`) encodes, validates, claims, settles and erases
//! these rows; the store layer reads and carries them.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::store::attempt_cancel::{AttemptCancelState, AttemptResumePoint};
use crate::store::attempt_id::AttemptId;
use crate::store::attempt_inputs::AttemptEvent;
use crate::store::attempt_manifest::ManifestEntry;
use crate::store::attempt_result::AttemptResultRef;
use crate::store::attempt_run_signal::{RunAsk, RunBranchSignal, SignalIntent};
use crate::store::attempt_state::AttemptState;

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
    pub executor_role: Option<oneiron_model::model_binding::ModelRole>,
    /// FIX 7720: a seatless planned child's first pick, route and exactness,
    /// written once with `executor_model` under its lease before its pack
    /// loads. `None` for any other run; a fresh retry decides its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub planned_binding: Option<PlannedBinding>,
    /// FIX 6934: the rows its producers read its inputs from while it ran,
    /// copied onto its terminal pack receipt. Absent while none recorded a
    /// set, so a row written before the field reads the same, unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_set: Option<AttemptReadSet>,
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
    pub signals: Vec<RunBranchSignal>,
    /// Durable ask handles, including partial replies, for this branch only.
    #[serde(default)]
    pub asks: Vec<RunAsk>,
    /// Operator-selected placement, separate from the immutable executor payload.
    #[serde(default)]
    pub placement: Option<AttemptPlacement>,
    /// FIX 5240: each failure a same-intent requeue kept, oldest first.
    #[serde(default)]
    pub history: Vec<RequeuedFailure>,
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
    pub(crate) signal_intents: Vec<SignalIntent>,
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

/// What an attempt's producers recorded of the rows its inputs were read
/// from. `rows` is the union of their reports, sorted and deduplicated;
/// `Some([])` when they read no vault row; `None`, unknown, once any
/// producer reported an unknown set or a producer reported undeclared.
/// `expected` holds the producers the owner declared, `reported` the ones
/// that reported (FIX 7073). An attempt no producer declared or recorded
/// keeps no read set at all, which its receipt keeps as unknown too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptReadSet {
    pub rows: Option<Vec<EntityId>>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub expected: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub reported: BTreeSet<String>,
}

/// One failed try a requeue kept on its row: when it was recorded, the lease
/// it ended and the worker's reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequeuedFailure {
    /// The vault's recorded instant the failure was kept at.
    pub at: u64,
    /// The owner of the lease the failure ended.
    pub lease_owner: String,
    /// That lease's generation within the row.
    pub attempt_count: u32,
    /// The worker's reason, as it gave it.
    pub reason: String,
}

/// Why a paused row is paused. A person's pause wins over every engine
/// hold: it replaces the hold on the row, so no hold's release resumes it,
/// and only a resume clears it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AttemptPause {
    /// An intervention's pause by any actor other than an engine hold's.
    Person,
    /// OF-368: the TASK answers a comment thread that is unattached.
    Annotation {
        artifact_id: EntityId,
        thread_id: EntityId,
    },
    /// OF-541: the run reached its spend cap.
    Budget,
    /// OF-393: the cut waits on its launch approval.
    Fanout { launch_ref: EntityId },
}

/// A terminal try's durable exhaust: the output references it attached
/// before it settled, explicitly empty when it attached none, and the resume
/// point it recorded, when it recorded one. Nothing here is made up: an
/// empty list is the record that no output exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptTerminalExhaust {
    /// The output references the try attached, in attach order; empty when
    /// it attached none.
    pub outputs: Vec<AttemptResultRef>,
    /// The resume point the try recorded, when it recorded one.
    #[serde(default)]
    pub frontier: Option<AttemptResumePoint>,
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
