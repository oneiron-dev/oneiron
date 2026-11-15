//! Moved from `crates/oneiron/src/consent/widen/mod.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// A proposal receipt confers no authority. It is not a ConsentGrant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WidenProposal {
    pub proposal_ref: String,
    pub canonical_delta: Vec<u8>,
    pub proposer: String,
    pub owner_ref: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub decision_id: [u8; 16],
}
