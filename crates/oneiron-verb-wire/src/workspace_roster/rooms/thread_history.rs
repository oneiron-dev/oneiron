//! Moved from `crates/oneiron/src/workspace_roster/rooms/thread_history.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::workspace_roster::rooms::*;

/// One page of a room's turns, or of one thread of it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomMessagesRequest {
    pub room_ref: String,
    /// The `next_after` of the page before.
    #[serde(default)]
    pub after: Option<String>,
    /// Rows per page, positive; 256 when unset. A page holds at most 256;
    /// the rest follow through `next_after`.
    #[serde(default)]
    pub limit: Option<usize>,
    /// A thread of the room, by its root turn; `None` reads the room itself.
    #[serde(default)]
    pub thread_ref: Option<String>,
}
