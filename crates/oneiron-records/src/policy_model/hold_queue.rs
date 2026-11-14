//! Moved from `crates/oneiron/src/policy_model/hold_queue.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldPolicyItem {
    pub queue_ref: String,
    pub row_ref: String,
    /// Authenticated principal reference assigned by the policy, not a display label.
    pub human: String,
    pub content_hash: [u8; 32],
    pub policy_frontier: [u8; 32],
    pub held_at: u64,
    pub receipt_ref: String,
    pub resolution: Option<PolicyHoldResolution>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyHoldResolution {
    Cleared,
    Declined,
}
