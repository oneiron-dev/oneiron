//! Census L8-07 door (review #7814 P1): whether a device kept from one world
//! is kept from a row, as `settings::device_only` judges it.

use std::collections::BTreeSet;

use crate::entity_id::EntityId;
use crate::{Result, Vault};

/// Whether a device for which `world` is the one device-only world is kept
/// from `row` ([`crate::settings::device_only_withholds`]): the row sits in
/// `world`, or carries the words of a row that does.
pub fn kept_from_world(vault: &Vault, world: EntityId, row: EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    crate::settings::device_only_withholds(&vault.store, &txn, &BTreeSet::from([world]), &row)
}
