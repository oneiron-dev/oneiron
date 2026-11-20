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

/// Whether the floor of `row` is not known whole here (#9289 review 2
/// P1-1, P1-2): it waits on a row or binding that has not landed, or the
/// floor backfill has not raised it yet while it names a birth input or a
/// dependency source.
///
/// # Errors
///
/// Storage failures.
pub fn floor_waits(vault: &Vault, row: EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    crate::source_audience::floor_waits_in(vault, &txn, &row)
}

/// Whether the row passes `withheld_from_replication_in` on
/// `ReplicationScope::Restricted`, a lane that carries no audience (#9289
/// review 3 P1-3).
///
/// # Errors
///
/// Storage and replication-walk failures.
pub fn travels_restricted(vault: &Vault, row: EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(!crate::source_audience::withheld_from_replication_in(
        vault,
        &txn,
        &row,
        crate::source_audience::ReplicationScope::Restricted,
    )?)
}

/// Forgets every floor's state and the floor backfill's, so the vault reads
/// as one whose rows were written before floors were (#9289 review 2 P1-2).
/// The floors already raised stay.
///
/// # Errors
///
/// Storage failures.
pub fn forget_floor_state(vault: &Vault) -> Result<()> {
    let mut txn = vault.store.env.write_txn()?;
    crate::source_audience::forget_floor_state_in_txn(vault, &mut txn)?;
    txn.commit()?;
    Ok(())
}
