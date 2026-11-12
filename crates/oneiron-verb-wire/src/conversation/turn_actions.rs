//! Moved from `crates/oneiron/src/conversation/turn_actions.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::attempt_queue::turn_action_kind::TurnAction;
pub use crate::conversation::turn_actions::rebind::TurnActionRebindReceipt;
pub use crate::conversation::turn_actions::rebind::TurnActionRebindRequest;
use oneiron_authority::claim_history_handoff::CallerLocality;
use oneiron_authority::claim_history_handoff::ClaimReadStatus;
use oneiron_authority::claim_history_handoff::ScopedRead;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::edge::EdgeKind;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MEMORY_CODE_INVALID_STATE;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_store::attempt_inputs::EnqueueAttempt;
use serde::Deserialize;
use serde::Serialize;

/// Names the assistant TURN an action acts on.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TurnActionRequest {
    /// The assistant TURN: a short ref or a 32-hex id.
    pub turn_id: String,
}

/// A queued action: the attempt that will run it, never a claim that text
/// exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TurnActionReceipt {
    pub action: TurnAction,
    /// 32-hex id of the assistant TURN acted on.
    pub turn_id: String,
    /// 32-hex id of its generated MESSAGE.
    pub message_id: String,
    /// 32-hex id of the queued attempt.
    pub attempt_id: String,
}
pub mod rebind;
