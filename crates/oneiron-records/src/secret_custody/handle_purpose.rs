//! Moved from `crates/oneiron/src/secret_custody/handle_purpose.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RwTxn;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The actual stored purpose, or a clear, and its owner-act receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretHandlePurposeSet {
    pub purpose: Option<String>,
    pub receipt: String,
}

/// A value-free purpose question derived from a newly found key's notice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretPurposeQuestion {
    pub record: EntityId,
    pub handle: String,
    pub name: String,
    pub label: Option<String>,
    pub suggested_label: Option<String>,
    pub kind: String,
    pub place: String,
    pub found_at: u64,
}
