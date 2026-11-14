//! Moved from `crates/oneiron/src/task_verb/ask_soft_confirm_types.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// A response to the notice, distinct from the original question's option ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaskAskConfirmationDecision {
    Approve,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskAskConfirmation {
    pub revision: u64,
    pub companion_answer_ref: EntityId,
    pub decision: TaskAskConfirmationDecision,
}
