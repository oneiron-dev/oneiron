//! Moved from `crates/oneiron/src/memory/erase_sweep.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The `redaction:<hex>` receipt ref returned by an erase.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordEraseSweepRequest {
    pub receipt_ref: String,
}

/// Recorded times only: the deadline survives removal of the completed job.
/// No erased body, queued scope, retry error text or inferred deadline is released.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RecordEraseSweep {
    pub receipt_ref: String,
    pub request_id: String,
    pub requested_at: u64,
    pub sweep_queued_at: Option<u64>,
    pub deadline_at: Option<u64>,
    pub sweep_complete_at: Option<u64>,
    /// When the erase completed overall, from its signed final row: its
    /// sweep, if it queued one, and every custody retirement it bound had
    /// finished. `None` while either is pending (FIX 5844).
    pub erase_complete_at: Option<u64>,
    /// That final row's `redaction:<hex>` ref, once it is appended.
    pub final_ref: Option<String>,
    /// Where the receipt's bound custody retirements stand; absent only
    /// when the receipt bound none (explicit empty binding).
    pub custody: Option<RecordEraseCustody>,
}

/// The custody part of an erase (KS-4A2, KS-2A): `custody_retirement_complete`
/// once the receipt's bound retirements all finished, else
/// `custody_retirement_pending` with one coarse generic pending step. A
/// read-only status of the receipt's bound names, not an enumeration of
/// each detailed step. The committed erase stands either way.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RecordEraseCustody {
    pub state: String,
    pub pending: Vec<String>,
    /// What no erase reaches: bytes read before it.
    pub recall: String,
    /// "rollback not proven: no custody anchor configured" while no anchor
    /// is configured: completion then rests on every required target's
    /// acknowledgement alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}
