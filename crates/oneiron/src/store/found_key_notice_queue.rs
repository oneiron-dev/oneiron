//! The found-key notice queue: the custody records whose found-key notice is
//! still due, with when their keys were found. Custody's found-key ledger
//! (`secret_custody::found_keys`) fills and drains it; a write door reads
//! whether any notice is due.

use heed::RoTxn;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::vault::Vault;

/// The records whose notice is still due, with when their keys were found.
pub(crate) const DUE: SideTable<EntityId, u64, Named> =
    SideTable::new(&side_table::SECRET_FOUND_KEY_DUE);

/// Whether a record is due its notice, read through `txn`: what
/// [`raise_found_key_notices_in_txn`] raises at the next write's commit.
pub(crate) fn found_key_notices_due_in_txn(vault: &Vault, txn: &RoTxn<'_>) -> Result<bool> {
    Ok(DUE.iter_from(&vault.store, txn, &[])?.next().is_some())
}
