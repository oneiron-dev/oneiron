//! Moved from `crates/oneiron/src/workspace_roster/room_leave.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Ends `person`'s current membership of `room`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomLeaveRequest {
    pub room: EntityId,
    pub person: EntityId,
}
