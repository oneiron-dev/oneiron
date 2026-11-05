//! One model on an agent's model list (FIX 4472): the revision-pinned model
//! and the owner's words on when the agent runs on it.

use oneiron_model::llm::ModelId;
use serde::{Deserialize, Serialize};

/// One model on an agent's list: a revision-pinned model and the owner's
/// description of when the agent should run on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentModel {
    pub model_ref: ModelId,
    /// When the agent takes this model, in the owner's words. A wake's seat
    /// pick reads it first among the model's description lines.
    pub when: String,
}
