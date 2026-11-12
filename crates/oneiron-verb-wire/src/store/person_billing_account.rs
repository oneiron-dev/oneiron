//! Moved from `crates/oneiron/src/store/person_billing_account.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// One PERSON's own billing account, as filed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FiledBillingAccount {
    /// The account's reference, as the PERSON gave it.
    pub account: String,
    /// When it was filed, in the vault's recorded seconds.
    pub filed_at: u64,
}
