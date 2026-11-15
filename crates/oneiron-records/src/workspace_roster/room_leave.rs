//! Moved from `crates/oneiron/src/workspace_roster/room_leave.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::workspace_roster::room_leave::RoomLeaveRequest;
use serde::Deserialize;
use serde::Serialize;

/// The room's members once the leave committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomLeaveOutcome {
    pub member_ids: Vec<EntityId>,
}
