//! Moved from `crates/oneiron/src/attempt_queue/turn_action_kind.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// What a queued turn action does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TurnAction {
    /// Resume generation on the same MESSAGE from its saved text.
    Continue,
    /// Answer the same user turn again in a new assistant TURN.
    Retry,
}
