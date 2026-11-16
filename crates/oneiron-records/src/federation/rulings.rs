//! Moved from `crates/oneiron/src/federation/rulings.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminRuling {
    pub id: String,
    pub holder: String,
    pub grant_ref: String,
    pub vault_id: u64,
    pub key: String,
    pub value: Value,
    pub learned_at: u64,
    pub ledger_order: u64,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminRulingReceipt {
    pub ruling: AdminRuling,
    pub previous_ruling: Option<String>,
    pub previous_holder: Option<String>,
    pub previous_value: Option<Value>,
}
