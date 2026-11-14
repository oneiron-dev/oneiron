//! Moved from `crates/oneiron/src/task_verb/highway_types.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Accept one TASK addressed to the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskAccept {
    pub task_ref: EntityId,
    pub intent_key: String,
}

/// Redo one TASK (FIX 3153): post a new TASK from its current brief and its
/// assignee, spec, label and parent. The TASK named is never written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskRedo {
    /// The TASK whose content the new one copies.
    pub task_ref: EntityId,
    /// The caller's idempotency key: one actor, TASK and key name one redo.
    pub intent_key: String,
}
