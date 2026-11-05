//! Core half of `store::person_billing_account`: its store-layer items live in `oneiron_store::person_billing_account` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::person_billing_account::*;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use serde::{Deserialize, Serialize};

/// PERSON -> the billing account that PERSON filed. Key: the PERSON.
pub(crate) const PERSON_BILLING_ACCOUNT: SideTable<EntityId, FiledBillingAccount, Named> =
    SideTable::new(&side_table::PERSON_BILLING_ACCOUNT);

/// An erase of `entity` takes the billing account it filed with it.
pub(crate) fn erase_billing_account_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    PERSON_BILLING_ACCOUNT.delete(&vault.store, wtxn, entity)?;
    Ok(())
}
