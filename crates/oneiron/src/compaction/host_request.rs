//! Host compaction request and result records.

use serde::{Deserialize, Serialize};
use crate::entity_id::EntityId;
use super::CompactionWindowMessage;

/// A conversation's host-rendered message window, with the lines that must
/// survive word for word. The session owns the resulting keyframe.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostCompactRequest {
    pub session_ref: EntityId,
    pub window: Vec<CompactionWindowMessage>,
    pub keep_list: Vec<String>,
    pub token_ceiling: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HostCompactResult {
    pub epoch: u64,
    pub summary: EntityId,
    pub text: String,
    pub keep_list: Vec<String>,
    pub first_turn: u64,
    pub last_turn: u64,
}

