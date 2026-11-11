//! The `vault.batch` row's input and receipt types (OF-181). The Vault door
//! that commits a batch is the engine's (`core_write` in `oneiron`).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::shape::CoreWriteTextField;

/// One entity put in a batch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoreBatchEntityInput {
    /// The entity's id; a fresh one when omitted.
    #[serde(default)]
    pub id: Option<String>,
    /// The entity type byte.
    #[serde(alias = "entityType")]
    pub entity_type: u8,
    #[serde(default, alias = "occurredStart")]
    pub occurred_start: Option<u64>,
    #[serde(default, alias = "occurredEnd")]
    pub occurred_end: Option<u64>,
    #[serde(default, alias = "learnedAt")]
    pub learned_at: Option<u64>,
    pub body: Value,
    #[serde(default)]
    pub text: Option<Vec<CoreWriteTextField>>,
}

/// The puts to commit atomically, as many as the caller names (Rule 5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoreBatchWriteInput {
    pub entities: Vec<CoreBatchEntityInput>,
}

/// One put a batch committed. `id` is the id the put was staged at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoreBatchEntityReceipt {
    pub id: String,
    pub entity_type: u8,
    /// For an agent's AGENT_DEF put, what its author writer made of it
    /// (ARCH-0053:20); absent for every other put.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_definition: Option<AgentDefinitionWriteReceipt>,
}

/// How the author writer stored an agent's AGENT_DEF put (ARCH-0053:20).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentDefinitionWriteDisposition {
    /// Stored at its id, approved: its agent runs under it.
    Active,
    /// Stored at its id as a proposal no dispatch runs.
    Proposed,
    /// A put that grants a stored definition more than its author's slice:
    /// stored as a new proposal at `proposal_id`; the stored definition at
    /// the staged id stays as it is.
    ProposedChange,
}

/// What the author writer made of one agent's AGENT_DEF put.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentDefinitionWriteReceipt {
    pub disposition: AgentDefinitionWriteDisposition,
    /// The proposal's id (hex) for a proposed change: the owner answers it
    /// through `vault.agents.proposed_changes.approve` or `.reject`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_id: Option<String>,
}

/// The puts a batch committed, in input order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoreBatchWriteReceipt {
    pub count: usize,
    pub entities: Vec<CoreBatchEntityReceipt>,
}

/// The grade a batch commits at, which its host selects from the
/// credential that sent it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreBatchCommit {
    Owner,
    BelowOwner,
}
