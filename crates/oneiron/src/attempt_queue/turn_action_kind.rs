//! Action discriminator and kind of a queued conversation turn action.

use serde::{Deserialize, Serialize};

/// The attempt kind a host's turn-action worker claims.
pub const TURN_ACTION_ATTEMPT_KIND: &str = "conversation.turn_action";

/// What a queued turn action does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TurnAction {
    /// Resume generation on the same MESSAGE from its saved text.
    Continue,
    /// Answer the same user turn again in a new assistant TURN.
    Retry,
}
