//! Action discriminator and kind of a queued conversation turn action.

/// The attempt kind a host's turn-action worker claims.
pub const TURN_ACTION_ATTEMPT_KIND: &str = "conversation.turn_action";

#[doc(hidden)]
pub use oneiron_verb_wire::attempt_queue::turn_action_kind::TurnAction;
