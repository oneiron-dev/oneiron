//! Moved from `crates/oneiron/src/linear_sync/mirror_event.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::linear_sync::model::LinearMirrorReceipt;
use oneiron_contracts::entity_id::bytes_to_hex_lower;
pub use oneiron_verb_wire::linear_sync::mirror_event::LinearMirrorEvent;
use oneiron_verb_wire::linear_sync::model::LinearFieldConflict;
use serde::Deserialize;
use serde::Serialize;

/// One mirror operation's outcome, as a receipt and a row carry it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinearMirrorRecord {
    /// `linked`, `applied`, `noop` or `conflict`.
    pub status: String,
    /// `task_to_issue` or `issue_to_task`.
    pub direction: String,
    /// The stable operation id, in hex.
    pub operation_id: String,
    /// The fields both sides moved.
    pub conflicts: Vec<LinearFieldConflict>,
    /// The mirror's own stamp of the operation.
    pub mirrored_at: u64,
}

impl From<&LinearMirrorReceipt> for LinearMirrorRecord {
    fn from(receipt: &LinearMirrorReceipt) -> Self {
        Self {
            status: receipt.status.as_str().to_owned(),
            direction: receipt.direction.as_str().to_owned(),
            operation_id: bytes_to_hex_lower(&receipt.operation_id),
            conflicts: receipt.conflicts.clone(),
            mirrored_at: receipt.mirrored_at,
        }
    }
}
