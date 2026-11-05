//! Core half of `compaction::host_request`: its store-layer items live in `oneiron_store::compaction::host_request` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::compaction::host_request::*;

use super::CompactionWindowMessage;
use crate::entity_id::EntityId;
use serde::{Deserialize, Serialize};

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
