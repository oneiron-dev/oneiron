//! Moved from `crates/oneiron/src/memory/critical_confirm.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

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
