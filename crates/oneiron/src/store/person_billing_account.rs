//! The billing account a PERSON filed (`PERSON_BILLING_ACCOUNT` rows) and
//! the erase that takes it with the PERSON. Run admission
//! (`llm::run_admission::person_billing`) files and reads the row; the row's
//! side-table declaration names its erase hook.
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

/// PERSON -> the billing account that PERSON filed. Key: the PERSON.
pub(crate) const PERSON_BILLING_ACCOUNT: SideTable<EntityId, FiledBillingAccount, Named> =
    SideTable::new(&side_table::PERSON_BILLING_ACCOUNT);

/// One PERSON's own billing account, as filed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FiledBillingAccount {
    /// The account's reference, as the PERSON gave it.
    pub account: String,
    /// When it was filed, in the vault's recorded seconds.
    pub filed_at: u64,
}

/// An erase of `entity` takes the billing account it filed with it.
pub(crate) fn erase_billing_account_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    PERSON_BILLING_ACCOUNT.delete(&vault.store, wtxn, entity)?;
    Ok(())
}
