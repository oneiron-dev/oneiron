//! Moved from `crates/oneiron/src/workspace_roster/rooms/private_threads.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::workspace_roster::rooms::*;
use serde::Deserialize;
use serde::Serialize;

/// `vault.rooms.private_threads`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomPrivateThreadsRequest {
    /// The room, 32-hex.
    pub room_ref: String,
}

/// That one private thread of a room exists: these five facts, nothing
/// else of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivateThreadMetadata {
    /// The thread's root TURN, 32-hex.
    pub id: String,
    /// Who opened it, 32-hex; null once this vault erased them.
    pub creator: Option<String>,
    /// The root's own time, Unix seconds.
    pub created_at: u64,
    /// The time of its newest turn or audience TURN, Unix seconds.
    pub last_active_at: u64,
    /// How many are in its audience now.
    pub member_count: usize,
}
