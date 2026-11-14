//! Moved from `crates/oneiron/src/compaction/host_request.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::compaction::driver::CompactionWindowMessage;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_store::compaction::host_request::*;
use serde::Deserialize;
use serde::Serialize;

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
