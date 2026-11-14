//! Moved from `crates/oneiron/src/workspace_roster/rooms/wake.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// One staged room wake: the room, the turn that woke the agent there, and
/// the agent. Refs only: no speaker, no words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomWake {
    pub room: EntityId,
    pub turn: EntityId,
    pub agent: EntityId,
}

impl RoomWake {
    /// The queue key every staging of this wake shares: one per (turn,
    /// agent).
    fn dedupe_key(&self) -> String {
        format!("rooms.wake:{}:{}", self.turn.to_hex(), self.agent.to_hex())
    }
}
