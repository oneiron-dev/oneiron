//! Moved from `crates/oneiron/src/llm/run_admission/person_billing.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::store::person_billing_account::FiledBillingAccount;
use serde::Deserialize;
use serde::Serialize;

/// `self.billing.account.file`'s input: the caller's own billing account.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BillingAccountFiling {
    /// The account the caller's room-paid calls bill, 1 to 256 bytes with no
    /// control character; empty withdraws the caller's filing.
    pub account: String,
}
