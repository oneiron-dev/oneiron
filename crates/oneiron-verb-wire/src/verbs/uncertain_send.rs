//! Moved from `crates/oneiron/src/verbs/uncertain_send.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::outbound::connector_task::UncertainSendAnswerOutcome;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// `vault.outbound.uncertain_send.answer`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UncertainSendAnswer {
    /// The connector-send TASK the owner's ask names (32 hex).
    pub task_ref: EntityId,
    /// Whether the engine sends it once more.
    pub resend: bool,
}

/// `vault.outbound.uncertain_send.answer`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UncertainSendAnswered {
    pub task_ref: EntityId,
    /// What the answer asked for.
    pub resend: bool,
    /// What it came to.
    pub outcome: UncertainSendAnswerOutcome,
}
