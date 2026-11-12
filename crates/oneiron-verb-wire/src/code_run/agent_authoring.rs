//! Moved from `crates/oneiron/src/code_run/agent_authoring.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use serde_json::Value as JsonValue;

/// `vault.agents.put`'s row input: the new definition's id and the guest's
/// draft, which [`parse_agent_put_request`] reads.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPutInput {
    pub id: String,
    pub definition: serde_json::Value,
}

/// `vault.agents.put`'s row reply: the id written, and `active` or
/// `proposed`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPutOutput {
    pub id: String,
    pub disposition: String,
}
