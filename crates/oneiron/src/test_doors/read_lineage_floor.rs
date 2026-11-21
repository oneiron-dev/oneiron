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

/// Marks the floor backfill done as a build that ran it before the backfill
/// raised archived rows left it (FLOOR-BACKFILL-SKIPS-ARCHIVED-ROWS): each
/// row keeps the floor it has.
///
/// # Errors
///
/// Storage failures.
pub fn end_backfill_without_archived_rows(vault: &Vault) -> Result<()> {
    let mut txn = vault.store.env.write_txn()?;
    crate::source_audience::end_backfill_without_archived_rows_in_txn(vault, &mut txn)?;
    txn.commit()?;
    Ok(())
}

/// Lands the binding of `row` here as a replicated binding does once its
/// policy resolves (`bind_replicated_in_txn`): the rows waiting on `row` are
/// raised again (#9289 Opus review 3 P1-B).
///
/// # Errors
///
/// Storage failures.
pub fn binding_lands(vault: &Vault, row: EntityId) -> Result<()> {
    let mut txn = vault.store.env.write_txn()?;
    crate::source_audience::binding_landed_in_txn(vault, &mut txn, &row)?;
    txn.commit()?;
    Ok(())
}

/// Lands `made_by` as the stated birth of the live row `id` the way sync
/// lands a replicated row's birth (`stamp_birth_or_warn`): the birth, then
/// the row's floor (#9289 Opus review 3 P2-4).
///
/// # Errors
///
/// Storage failures.
#[cfg(feature = "sync")]
pub fn replicated_birth_lands(
    vault: &Vault,
    id: EntityId,
    made_by: crate::provenance::made_by::MadeBy,
) -> Result<()> {
    let mut txn = vault.store.env.write_txn()?;
    crate::sync::row_birth::stamp_birth_or_warn(
        vault,
        &mut txn,
        &id,
        &crate::store::row_birth::RowBirth::stated(made_by),
    )?;
    txn.commit()?;
    Ok(())
}
