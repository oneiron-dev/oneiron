//! Test doors for READ-LINEAGE L1: a row's floor, and the policies the
//! source-audience walk meets on a read of it (the oracle a floor holds).

use std::collections::BTreeSet;

use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::{EntityId, Vault};

/// The floor of the stored row `row`: the source it was born in and every
/// source its stored floor names. Empty for a row this vault does not hold.
///
/// # Errors
///
/// Storage failures.
pub fn floor_of(vault: &Vault, row: EntityId) -> Result<BTreeSet<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    let dbs = vault.store.read();
    let Some(raw) = dbs.port_entity_raw(&txn, &row)? else {
        return Ok(BTreeSet::new());
    };
    crate::source_audience::floor::floor_in(vault, &txn, &row, &raw)
}

/// The policies the source-audience walk meets on a read of `row` by
/// `viewers`, along the lineage it walks (`read_audience_in`).
///
/// # Errors
///
/// Storage failures.
pub fn walked_policies_of(
    vault: &Vault,
    row: EntityId,
    viewers: &[EntityId],
) -> Result<BTreeSet<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    let dbs = vault.store.read();
    crate::source_audience::read_audience_in(vault, &dbs, &txn, &[row], viewers)
}

/// Whether the floor of `row` is not known whole here. The head before the
/// floor's state was written keeps none, so every floor reads as whole
/// (the red proof of #9289 review 2's tests).
///
/// # Errors
///
/// None at this head.
pub fn floor_waits(_vault: &Vault, _row: EntityId) -> Result<bool> {
    Ok(false)
}

/// Forgets every floor's state and the floor backfill's. The head before
/// the floor's state was written keeps none, so there is nothing to forget
/// (the red proof of #9289 review 2's tests).
///
/// # Errors
///
/// None at this head.
pub fn forget_floor_state(_vault: &Vault) -> Result<()> {
    Ok(())
}
