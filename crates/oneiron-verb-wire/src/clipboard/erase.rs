//! Moved from `crates/oneiron/src/clipboard/erase.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Which ordinary Clipboard records the owner erases. Ranges are [from, before).
/// All empties the dedicated world; it retains the role's WORLD metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ClipboardErase {
    Clip { clip: EntityId },
    Range { from: u64, before: u64 },
    All,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClipboardEraseReport {
    /// Records the native hard-delete door completed. Not a delivery receipt
    /// and not a claim that the filesystem or retained backups shrank.
    pub erased: Vec<EntityId>,
}
