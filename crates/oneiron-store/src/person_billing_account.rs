//! The billing account a PERSON filed (`PERSON_BILLING_ACCOUNT` rows) and
//! the erase that takes it with the PERSON. Run admission
//! (`llm::run_admission::person_billing`) files and reads the row; the row's
//! side-table declaration names its erase hook.
use serde::{Deserialize, Serialize};

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// One PERSON's own billing account, as filed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FiledBillingAccount {
    /// The account's reference, as the PERSON gave it.
    pub account: String,
    /// When it was filed, in the vault's recorded seconds.
    pub filed_at: u64,
}
