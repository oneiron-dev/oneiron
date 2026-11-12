//! Moved from `crates/oneiron/src/feedback/triage/owner.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::feedback::triage::FeedbackTriageResult;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The owner's change of the binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageBindingRequest {
    /// The SKILL entity to bind; `None` unbinds.
    #[serde(default)]
    pub skill: Option<EntityId>,
    /// Queue the ordinary sweep on new inbox notes; false keeps batching.
    pub enqueue_on_intake: bool,
    /// The `revision` the owner's surface read: a binding that moved since
    /// is refused, and nothing changes.
    pub seen: u64,
}

/// The owner's run-now ask. It carries no plan, lease or stamp: the
/// production sweep runs.
#[derive(Clone, Debug, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageRunRequest {}

/// The sweep a run-now ask queued, or the queued one it joined.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageRun {
    /// 32 hex: the sweep's attempt.
    pub attempt: EntityId,
}

/// Which sweep's status to read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageStatusRequest {
    /// 32 hex: the sweep's attempt, as the run answered it.
    pub attempt: EntityId,
}

/// A revision whose evidence ASSET the owner erased, in erased form: its
/// name and any result committed before the erase, with no content,
/// revision digest or evidence id. No sweep queues it again, and its
/// evidence is never retained again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageErased {
    /// The source, as [`FeedbackTriageSourceRef::source`] names it.
    pub source: String,
    /// The item's id in its source, in decimal.
    pub id: String,
    /// Vault seconds a sweep settled it erased; `None` until one does.
    pub erased_at: Option<u64>,
    /// The result committed before the erase; `None` when it was erased
    /// unacknowledged.
    pub result: Option<FeedbackTriageResult>,
}

/// One long note's part/synthesis progress, over its current generation's
/// nodes (FIX 10307).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageProgress {
    /// Answered parts.
    pub parts_answered: u32,
    /// Parts in the current generation.
    pub parts_total: u32,
    /// Answered synthesis nodes.
    pub synthesis_answered: u32,
    /// Synthesis nodes in the current generation.
    pub synthesis_total: u32,
}
