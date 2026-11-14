//! Moved from `crates/oneiron/src/verbs/agent_run_effect.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::agent_dispatch::run_effects::AgentRunEffectAnswerOutcome;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// `vault.agent.run_effect.answer`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentRunEffectAnswer {
    /// The agent run TASK the owner's ask names (32 hex).
    pub task_ref: EntityId,
    /// The call's engine-stamped intent id the ask names (64 hex).
    pub intent_ref: String,
    /// Whether the run makes the call once more.
    pub resend: bool,
}

/// `vault.agent.run_effect.answer`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentRunEffectAnswered {
    pub task_ref: EntityId,
    pub intent_ref: String,
    /// What the answer asked for.
    pub resend: bool,
    /// What it came to.
    pub outcome: AgentRunEffectAnswerOutcome,
}
