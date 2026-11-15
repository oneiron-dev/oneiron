//! Moved from `crates/oneiron/src/attempt_queue/turn_action_kind.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::attempt_queue::turn_action_kind::TurnAction;

/// The attempt kind a host's turn-action worker claims.
pub const TURN_ACTION_ATTEMPT_KIND: &str = "conversation.turn_action";
