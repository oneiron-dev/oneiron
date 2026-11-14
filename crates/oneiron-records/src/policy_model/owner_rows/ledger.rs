//! Moved from `crates/oneiron/src/policy_model/owner_rows/ledger.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyProposalStatus {
    Pending,
    Approved { receipt_id: String, holder: String },
    Declined { holder: String },
}
