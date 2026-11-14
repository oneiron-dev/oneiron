//! Moved from `crates/oneiron/src/store/legal_hold/use_limit.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use heed::RwTxn;
use serde::Deserialize;
use serde::Serialize;

/// A recipient's selected restriction. No hold, content, free-text
/// allegation, duration or automatic lift is implied by these codes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CooperativeRestriction {
    pub since: u64,
    pub reason_code: String,
    pub review_at: u64,
}
