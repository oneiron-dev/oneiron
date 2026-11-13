//! Moved from `crates/oneiron/src/memory/commitment_doors/ledger.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::commitment_doors::*;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;

#[derive(Debug, Clone, Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommitmentLedgerRequest {
    pub contact_ref: String,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct CommitmentLedgerItem {
    pub valid_from: u64,
    pub valid_to: u64,
    pub commitment: CommitmentView,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct CommitmentLedgerView {
    pub contact_ref: String,
    pub identity_ref: String,
    pub counterparty: String,
    pub channel: String,
    pub address_or_handle: String,
    pub owed_by_them: Vec<CommitmentLedgerItem>,
    pub owed_to_them: Vec<CommitmentLedgerItem>,
}
