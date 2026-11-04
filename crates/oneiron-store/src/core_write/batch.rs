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

/// One put a batch committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoreBatchEntityReceipt {
    pub id: String,
    pub entity_type: u8,
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
