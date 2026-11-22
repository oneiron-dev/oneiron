//! Host compaction request and result records.

use oneiron_contracts::entity_id::EntityId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HostCompactResult {
    pub epoch: u64,
    pub summary: EntityId,
    pub text: String,
    pub keep_list: Vec<String>,
    pub first_turn: u64,
    pub last_turn: u64,
    /// How many rows of the request's working set the summary carries: each
    /// one that was live when the summary was minted.
    #[serde(default)]
    pub carried: u32,
}
