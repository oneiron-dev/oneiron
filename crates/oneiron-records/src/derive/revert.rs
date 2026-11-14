//! Moved from `crates/oneiron/src/derive/revert.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// What one batch revert did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeriveRevertReceipt {
    /// The batch.
    pub batch: EntityId,
    /// The items undone, by local name, in the order they were undone.
    pub reverted: Vec<String>,
    /// The items left standing, by local name, each with why.
    pub left: Vec<(String, String)>,
    /// The revert's receipt in the gate decision ledger.
    pub receipt: [u8; 16],
}
