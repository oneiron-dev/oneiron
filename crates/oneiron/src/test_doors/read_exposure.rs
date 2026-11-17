//! Doors for `tests/actor_read_exposure.rs` (census L8-65): the record rows a reader's read
//! exposure keeps.

use std::collections::BTreeSet;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// The records `reader`'s kept rows name, as the vault's last write left them: one row per
/// record ever served to it that no erase has taken.
pub fn exposed_records(vault: &Vault, reader: &EntityId) -> Result<BTreeSet<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    crate::claim::exposed_records_in(&vault.store, &txn, reader)
}
