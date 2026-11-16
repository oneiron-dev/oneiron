//! Moved from `crates/oneiron/src/skill_attribution/contribution_targets.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The used edge an ancestor check measured, as recorded: each end `None`
/// once that entity is erased (FIX 8988).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckedEdge {
    pub derived: Option<EntityId>,
    pub source: Option<EntityId>,
}
