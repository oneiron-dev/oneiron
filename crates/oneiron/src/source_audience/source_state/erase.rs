//! The floor's part of a delete door (Fable design pass 31, section 2).
//!
//! A delete changes the facts of the row it erases and nothing else: a row
//! that still waits on it reads sealed from the delete's first marker on.
//! Before that marker each delete door calls [`before_erase_in_txn`] (or,
//! where its write holds only the store, [`before_erase_in_store_txn`]), so
//! a row whose input was bound and whole takes that floor first; a missed
//! call fails closed. While the migration runs, a row it has not judged that
//! names the erased row by a lineage edge is judged for that link first,
//! because the erase tears the edge (section 5, M3).
//!
//! Three more writes belong to delete doors: a local put over an erased row
//! seals what still waited on it ([`seal_waiters_in_txn`]), a row's own
//! erase drops its open set ([`erase_open_entries_in_txn`]), and an owner's
//! erase of a head records the redirect shells it scrubbed
//! ([`note_shell_erased_in_txn`]).

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use super::judge::{fold_entry_in_txn, judge_row_in_txn, take_floor_in_store_txn};
use super::{
    DeleteLevel, Fresh, OPEN, OPEN_BY, OpenFlags, SHELL_ERASED, close_entry_in_txn, has_open_in,
    migrated_in, open_entry_in_txn,
};
use crate::error::Result;
use crate::source_audience::floor::{
    OwnSource, floor_of_in, floors_possible_of_in, own_source_of_in,
};
use crate::source_audience::floor_migration;
use crate::{EntityId, Vault};

/// Runs, in the write that deletes `erased` at `level`, before its first
/// marker: while the migration runs, judges `erased` itself if it was not
/// judged yet, and judges for their link to it the rows not judged yet that
/// name it by a lineage edge (M3); then folds the rows waiting on it while
/// it still reads whole ([`super::fold_waiters_in_txn`]). A row that reads
/// erased already (a replayed tombstone, a second purge) changes nothing.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn before_erase_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    erased: &EntityId,
    level: DeleteLevel,
) -> Result<()> {
    if !floors_possible_of_in(&vault.store, txn)?
        || crate::ports::erased_in_txn(&vault.store, txn, erased)?
    {
        return Ok(());
    }
    if migrating_in(&vault.store, txn)? {
        if !floor_migration::raised_in(&vault.store, txn, erased)? {
            judge_row_in_txn(vault, txn, erased, &Fresh::None, true)?;
            floor_migration::mark_judged_in_txn(&vault.store, txn, erased)?;
        }
        if vault.get_raw_in(txn, erased)?.is_some() {
            let floor = match super::StateReader::reader(vault, txn)?.state(erased)? {
                super::SourceState::Bound(floor) => Some(floor),
                _ => None,
            };
            judge_edge_rows_in_txn(&vault.store, txn, erased, floor.as_ref(), Some(level))?;
        }
    }
    super::fold_waiters_in_txn(vault, txn, erased)
}

/// [`before_erase_in_txn`] for a write that holds only the store (a purge's
/// deindex, a blob release): one level. The rows waiting on `erased` take
/// its floor when it reads bound and whole with no open entry of its own;
/// a row it cannot judge without the vault (one that waits on inputs of its
/// own, or one the migration has not judged) hands over nothing, and the
/// rows waiting on it read sealed, which fails closed. `level` is `None`
/// for a blob release: a row M3 judges then waits on the ASSET as on any
/// row not here, until the same bytes return.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn before_erase_in_store_txn(
    store: &crate::store::Store,
    txn: &mut RwTxn<'_>,
    erased: &EntityId,
    level: Option<DeleteLevel>,
) -> Result<()> {
    if !floors_possible_of_in(store, txn)? || crate::ports::erased_in_txn(store, txn, erased)? {
        return Ok(());
    }
    let floor = whole_floor_in(store, txn, erased)?;
    if migrating_in(store, txn)?
        && crate::ports::EntityStoreRead::port_entity_raw(store, txn, erased)?.is_some()
    {
        judge_edge_rows_in_txn(store, txn, erased, floor.as_ref(), level)?;
    }
    let Some(floor) = floor else {
        return Ok(());
    };
    for (_, row) in OPEN_BY.scan_keys(store, txn, erased.as_bytes())? {
        fold_entry_in_txn(store, txn, &row, erased, &floor)?;
    }
    Ok(())
}

/// Whether the migration runs and the old backfill had not raised every
/// row: rows not judged yet may stand.
fn migrating_in(store: &crate::store::Store, txn: &RoTxn<'_>) -> Result<bool> {
    Ok(!migrated_in(store, txn)? && !floor_migration::old_backfill_done_in(store, txn)?)
}

/// The floor of `row` when it reads bound and whole here and a read of the
/// store alone can tell: held, not erased, not held back, its binding
/// landed, judged, and no open entry or old mark of its own.
fn whole_floor_in(
    store: &crate::store::Store,
    txn: &RoTxn<'_>,
    row: &EntityId,
) -> Result<Option<BTreeSet<EntityId>>> {
    if crate::ports::erased_in_txn(store, txn, row)? {
        return Ok(None);
    }
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, row)? else {
        return Ok(None);
    };
    let migrated = migrated_in(store, txn)?;
    if crate::source_audience::HELD.contains(store, txn, row)?
        || own_source_of_in(store, txn, row, &raw)? == OwnSource::Unbound
        || has_open_in(store, txn, row)?
        || floor_migration::has_old_marks_in(store, txn, row, migrated)?
        || !(migrated
            || floor_migration::old_backfill_done_in(store, txn)?
            || floor_migration::raised_in(store, txn, row)?)
    {
        return Ok(None);
    }
    Ok(Some(floor_of_in(store, txn, row, &raw)?))
}

/// M3: each row the migration has not judged that names `erased` by a
/// lineage edge (a `PartOf` either way, a `DerivedFrom` to it, a `Supports`
/// from it: the ends whose words the edge adds to) is judged for that link
/// before the erase tears it. It takes `floor`, the floor of `erased` when
/// that reads bound and whole; otherwise it opens an entry on `erased` as
/// an old fact's, at the level of this delete, which waits for good, and a
/// later owner erase of a soft-deleted input seals it (for a blob release,
/// `level` `None`, an ordinary entry). It never seals.
fn judge_edge_rows_in_txn(
    store: &crate::store::Store,
    txn: &mut RwTxn<'_>,
    erased: &EntityId,
    floor: Option<&BTreeSet<EntityId>>,
    level: Option<DeleteLevel>,
) -> Result<()> {
    use crate::EdgeKind;
    use crate::ports::EdgeDirection;
    let mut rows = BTreeSet::new();
    for (direction, kind) in [
        (EdgeDirection::In, EdgeKind::PartOf),
        (EdgeDirection::Out, EdgeKind::PartOf),
        (EdgeDirection::In, EdgeKind::DerivedFrom),
        (EdgeDirection::Out, EdgeKind::Supports),
    ] {
        rows.extend(crate::vault::filtered_edge_peers_in(
            store, txn, direction, erased, kind, None,
        )?);
    }
    rows.remove(erased);
    for row in rows {
        if floor_migration::raised_in(store, txn, &row)?
            || crate::ports::erased_in_txn(store, txn, &row)?
        {
            continue;
        }
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &row)? else {
            continue;
        };
        match floor {
            Some(floor) => {
                take_floor_in_store_txn(store, txn, &row, &raw, floor)?;
            }
            None => {
                let flags = level.map_or(OpenFlags::ORDINARY, OpenFlags::before_floors);
                open_entry_in_txn(store, txn, &row, erased, flags)?;
            }
        }
    }
    Ok(())
}

/// Seals, in the write that puts a new body over the erased row `erased`
/// before its fence goes, each row that waited on it (section 2, limit 6):
/// the row it waited on is gone, and the new body is another row's. Each
/// such row takes [`crate::source_audience::floor::sealed_source`] and its
/// entry goes.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn seal_waiters_in_txn(
    store: &crate::store::Store,
    txn: &mut RwTxn<'_>,
    erased: &EntityId,
) -> Result<()> {
    let sealed = BTreeSet::from([crate::source_audience::floor::sealed_source()]);
    for (_, row) in OPEN_BY.scan_keys(store, txn, erased.as_bytes())? {
        if row != *erased {
            crate::source_audience::add_derived_policies_in_store_txn(store, txn, &row, &sealed)?;
        }
        close_entry_in_txn(store, txn, &row, erased)?;
    }
    Ok(())
}

/// Drops, in `txn`, every open entry of `row` with the row, and its index
/// pairs: the entity erase's, beside its stored floor.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn erase_open_entries_in_txn(
    store: &crate::store::Store,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
) -> Result<()> {
    for (_, input) in OPEN.scan_keys(store, txn, row.as_bytes())? {
        close_entry_in_txn(store, txn, row, &input)?;
    }
    Ok(())
}

/// Records, in the write of an owner's erase of its head, that the redirect
/// shell `shell` was scrubbed (SOURCE-STATE-L2 = A): an old fact that waits
/// for good on it as an input deleted before floors reads sealed from this
/// write on, whether the migration judged that fact before or after.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn note_shell_erased_in_txn(
    store: &crate::store::Store,
    txn: &mut RwTxn<'_>,
    shell: &EntityId,
) -> Result<()> {
    SHELL_ERASED.put(store, txn, shell, &())
}
