//! Moved from `crates/oneiron/src/code_run/dispatcher/workflow_dispatch/operations/agent_definition.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// A versioned composition reference, not an installed capability or grant.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentSkillInput {
    pub skill_id: String,
    #[serde(default)]
    pub min_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentMcpInput {
    pub key: String,
    #[serde(default)]
    pub min_version: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentScopeInput {
    #[default]
    All,
    Base,
    World {
        world: EntityId,
    },
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentCeilingInput {
    Auto,
    #[default]
    Proposed,
}
