//! Moved from `crates/oneiron/src/conversation/turn_actions/rebind.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::attempt_queue::turn_action_kind::TurnAction;
use serde::Deserialize;
use serde::Serialize;

/// Names the queued turn action to rebind.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TurnActionRebindRequest {
    /// 32-hex id of the queued attempt, as its receipt named it.
    pub attempt_id: String,
}

/// A rebound turn action: the attempt, the turn it acts on, and both slips.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TurnActionRebindReceipt {
    pub action: TurnAction,
    /// 32-hex id of the assistant TURN acted on.
    pub turn_id: String,
    /// 32-hex id of the queued attempt.
    pub attempt_id: String,
    /// 64-hex id of the slip the action stood on before: its predecessor.
    pub predecessor_slip: String,
    /// 64-hex id of the slip it stands on now: the one this request was
    /// admitted on.
    pub successor_slip: String,
    /// A live owner of this vault asked the action: owner work.
    pub owner_work: bool,
}
