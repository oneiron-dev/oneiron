//! The audited classification of a corrupt CLAIM (FIX 7800, ARCH-0038).
//!
//! An owner's maintenance pass may select a stored CLAIM whose non-empty body fails its strict
//! capture decode. Classifying it appends one REDACTION_AUDIT row of a second strict shape, the
//! repair event: ids, two times and a closed code, signed under the receipt transcript (OD-6).
//! It records a classification, never a deletion: it carries no completion time, no sweep, final
//! row or erase reader takes it for an erase receipt, and the typed receipt decoder refuses it,
//! which keeps it on this device (`reverse_remat_skip_redaction_receipt_mirror`). The erase it
//! unblocks names it, per record, in that erase's own `capture_failures`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::error::SyncError;
use oneiron_contracts::entity_id::EntityId;

/// The one event a repair event records.
pub const CORRUPT_CLAIM_RECLASSIFIED: &str = "corrupt_claim_reclassified";

/// The closed code a classification and the erase it unblocks record.
pub const CAPTURE_FAILED: &str = "capture_failed";

/// The pinned repair event keys in their one encoded order: `verification` last, as the
/// attestation transcript's tail splice needs.
pub const REPAIR_EVENT_KEYS: [&str; 7] = [
    "event",
    "request_id",
    "scope",
    "recorded_at",
    "generation",
    "error_code",
    "verification",
];

/// One record whose hard erase took the audited capture exception: its id, the closed
/// `capture_failed` code and the repair event that classified it, all opaque.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureFailure {
    pub entity_id: String,
    pub error_code: String,
    pub repair_receipt: String,
}

impl CaptureFailure {
    pub fn new(entity: &EntityId, repair_receipt: &EntityId) -> Self {
        Self {
            entity_id: entity.to_hex(),
            error_code: CAPTURE_FAILED.to_owned(),
            repair_receipt: repair_receipt.to_hex(),
        }
    }
}
