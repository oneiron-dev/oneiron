//! Moved from `crates/oneiron/src/policy_model/hold_queue.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::gate_reason::GateReceiptOutcome;
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

impl PolicyHoldResolution {
    /// The Gate receipt outcome an owner's ruling on a hold is recorded
    /// under (UC-03 D1 = A): a cleared hold reads `allow` until D2 spells an
    /// owner's yes `approved`, a declined one `rejected`. The ruling's word
    /// stays its reason code (`gate.policy_model.hold_cleared`,
    /// `gate.policy_model.hold_declined`).
    #[must_use]
    pub const fn ledger_outcome(self) -> GateReceiptOutcome {
        match self {
            Self::Cleared => GateReceiptOutcome::Allow,
            Self::Declined => GateReceiptOutcome::Rejected,
        }
    }
}
