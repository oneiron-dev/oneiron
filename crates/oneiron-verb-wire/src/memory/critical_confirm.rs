//! Moved from `crates/oneiron/src/memory/critical_confirm.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::gate::confirm::CriticalWriteConfirmResolution;
use oneiron_authority::authority::CriticalWriteConfirmDisposition;
use oneiron_authority::authority::CriticalWriteConfirmState;
use oneiron_contracts::entity_id::bytes_to_hex_lower;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CriticalWriteConfirmPendingRequest {
    /// The candidate's gate decision ref (gate:<32-hex>).
    pub pending_operation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CriticalWriteConfirmRequest {
    pub pending_operation: String,
    /// The 32-hex nonce the pending read returned.
    pub nonce: String,
    /// The 64-hex policy frontier the pending read returned.
    pub read_frontier_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CriticalWriteConfirmReceiptRequest {
    /// The 64-hex confirmation id the pending read or settlement returned.
    pub confirm_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CriticalWriteConfirmAnswer {
    Clear,
    Decline,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CriticalWriteConfirmReceipt {
    /// The signed, fold-verified authority entry (authority:<64-hex>).
    pub receipt_ref: String,
    pub confirm_id: String,
    pub pending_operation: String,
    pub claim_ref: String,
    pub nonce: String,
    pub read_frontier_hash: String,
    pub effect_digest: String,
    pub expires_at: u64,
    pub disposition: CriticalWriteConfirmAnswer,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CriticalWriteConfirmSettlement {
    pub receipt: CriticalWriteConfirmReceipt,
    pub resolution: CriticalWriteConfirmResolution,
}

impl CriticalWriteConfirmReceipt {
    fn from_state(state: &CriticalWriteConfirmState) -> Self {
        let action = &state.action;
        Self {
            receipt_ref: format!(
                "authority:{}",
                bytes_to_hex_lower(&state.authority_entry_hash)
            ),
            confirm_id: bytes_to_hex_lower(&action.confirm_id),
            pending_operation: format!("gate:{}", bytes_to_hex_lower(&action.gate_decision_id)),
            claim_ref: action.claim_id.to_hex(),
            nonce: bytes_to_hex_lower(&action.nonce),
            read_frontier_hash: bytes_to_hex_lower(&action.read_frontier_hash),
            effect_digest: bytes_to_hex_lower(&action.effect_digest),
            expires_at: action.expires_at,
            disposition: match action.disposition {
                CriticalWriteConfirmDisposition::Clear => CriticalWriteConfirmAnswer::Clear,
                CriticalWriteConfirmDisposition::Decline => CriticalWriteConfirmAnswer::Decline,
            },
        }
    }
}
