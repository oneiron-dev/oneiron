//! Moved from `crates/oneiron/src/clipboard/intake.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// One ordinary clip, read back after the batch door's secret masking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClipboardEntry {
    pub clip: EntityId,
    pub copied_at: u64,
    pub text: String,
}
