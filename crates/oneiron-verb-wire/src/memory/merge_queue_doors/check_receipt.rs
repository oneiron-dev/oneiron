//! Moved from `crates/oneiron/src/memory/merge_queue_doors/check_receipt.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// One inputs reference of one checker work row to read.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeCheckReceiptRequest {
    /// An existing CODE_ARTIFACT whose stored pointer is a local folder.
    pub repo: EntityId,
    /// The work reference a checker door returned, 64 hex characters.
    pub work_ref: String,
    /// One of that work's `receipt_refs`: `queue-check:v1:<inputs digest>`.
    pub receipt_ref: String,
}
