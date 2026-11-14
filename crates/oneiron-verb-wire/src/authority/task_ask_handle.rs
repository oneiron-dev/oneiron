//! Moved from `crates/oneiron/src/authority/task_ask_handle.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The group is an engine-authored TASK fact, not a local queue id. A
/// world-privacy request's id is its handle too, for its asker's wait (FIX
/// 4706).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskAskHandle {
    pub group_ref: EntityId,
}
