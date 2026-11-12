//! Moved from `crates/oneiron/src/workspace_roster/rooms/upkeep_voice.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// `vault.rooms.upkeep.pending`: the caller's unvoiced room nudges, only
/// `room`'s when it names one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomUpkeepPendingRequest {
    #[serde(default)]
    pub room: Option<EntityId>,
}

/// One room upkeep nudge addressed to its host: refs and times only, as the
/// Coach filed them, never a turn's words.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RoomUpkeepNudge {
    /// The Coach's finding.
    pub finding: EntityId,
    pub room: EntityId,
    /// The quiet thread's root turn.
    pub thread: EntityId,
    /// The host it is addressed to.
    pub host: EntityId,
    /// When the thread last moved, as the Coach read it (Unix seconds).
    pub last_activity: u64,
    /// The thread's open TASKs, as the Coach read them.
    pub open_tasks: Vec<EntityId>,
    /// The finding's approval now: Proposed or Approved.
    pub approval: oneiron_contracts::claim::ClaimApprovalStatus,
}

/// `vault.rooms.upkeep.voice`: the host's own words for one nudge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomUpkeepVoiceRequest {
    pub finding: EntityId,
    pub content: String,
}
