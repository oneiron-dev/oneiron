//! Moved from `crates/oneiron/src/edit_settle/undo.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The once-only undo of one kept proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeepUndo {
    pub proposal_ref: String,
    /// The version the Keep appended.
    pub kept_version: u64,
    /// The version the Keep was appended onto, whose bytes the undo restored.
    pub restored_version: u64,
    /// The new version the undo appended.
    pub version: u64,
    pub actor: EntityId,
    pub at: u64,
}
