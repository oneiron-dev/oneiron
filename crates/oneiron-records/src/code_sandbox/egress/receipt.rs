//! Moved from `crates/oneiron/src/code_sandbox/egress/receipt.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::policy_model::verdict::PolicyClassifyDecision;
use crate::policy_model::verdict::PolicyVerdictCategory;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EgressReceipt {
    pub run_id: EntityId,
    pub operation: String,
    pub url: String,
    pub content_hash: [u8; 32],
    pub content_bytes: u64,
    pub decision: PolicyClassifyDecision,
    pub category: PolicyVerdictCategory,
    pub policy_receipt: Option<String>,
}
