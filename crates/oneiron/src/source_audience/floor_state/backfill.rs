//! The floor backfill (READ-LINEAGE L1; #9289 review 2 P1-2), housekeeping's
//! `SourceFloorBackfill` sweep: it raises the floor of every row a vault held
//! before floors were written, clears its marks, repairs once the rows an
//! archive kept out of their floor's raises (#10117 Opus review P1), and in
//! each run raises the waiting rows again (#9289 review 3 P1-4, P1-6). While
//! it runs, a tear carries the torn row's floor onto the rows not raised yet
//! that read it through an edge (#10139 Opus review P2-5).

use std::collections::BTreeSet;
use std::ops::Bound;

use heed::{RoTxn, RwTxn};

use super::marks::take_marks_of_in_txn;
use super::{BACKFILL, PENDING, RAISED, REPAIR, backfill_done_in, floor_holds_in};
use crate::batch::EntityMetadataHeader;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::source_audience::floor::OwnSource;
use crate::{EdgeKind, EntityId, Vault};

/// Entity rows one backfill write reads; each is raised with the not yet
/// raised rows it was written from.
const BACKFILL_PAGE: usize = 64;

/// Raised marks one write clears once the backfill has raised every row.
const CLEAR_PAGE: usize = 1024;

/// A backfill cursor's first byte: raising the rows after the entity key
/// that follows it.
const RAISING: u8 = 0;

/// A backfill cursor's first byte: clearing the raised marks.
const CLEARING: u8 = 1;

/// A backfill cursor's first byte: raising again the waiting rows after the
/// row id that follows it.
const SETTLING: u8 = 2;

/// A backfill cursor's first byte: the floor repair, raising again the rows
/// after the entity key that follows it.
const REPAIRING: u8 = 3;

/// One run of the floor backfill, housekeeping's `SourceFloorBackfill`
/// sweep: from `cursor`, where an unfinished run stopped, it raises the floor
/// of each entity row held here and not erased (an archived row included) in
/// key order, a page per write, each with the not yet raised rows it was
/// written from, and stops between pages once `stop` says so. Once every row
/// is raised it marks the backfill done, then clears the raised marks. A
/// vault whose backfill an earlier build began or ended then runs the floor
/// repair once ([`repair_page_in_txn`]), and clears its raised marks again.
/// Then, and in each later run, it raises every waiting row again, a page
/// per write (#9289 review 3 P1-4, P1-6). In a vault where no row can have a
/// floor yet it does nothing, and runs at the next pass again. The rows it
/// raised, and where an unfinished run goes on (`None` once this run has
/// ended).
///
/// # Errors
///
/// Storage failures.
pub(crate) fn backfill_floors(
    vault: &Vault,
    cursor: Option<&[u8]>,
    stop: impl Fn() -> bool,
) -> Result<(u64, Option<Vec<u8>>)> {
    let mut cursor = cursor.map_or_else(|| vec![RAISING], <[u8]>::to_vec);
    let mut raised = 0_u64;
    loop {
        let (page, next) = vault.with_write_txn(|txn| match cursor.split_first() {
            Some((&CLEARING, _)) => clear_page_in_txn(vault, txn),
            Some((&SETTLING, after)) => settle_page_in_txn(vault, txn, after),
            Some((&REPAIRING, after)) => repair_page_in_txn(vault, txn, after),
            Some((_, after)) => raise_page_in_txn(vault, txn, after),
            None => raise_page_in_txn(vault, txn, &[]),
        })?;
        raised = raised.saturating_add(page);
        let Some(next) = next else {
            return Ok((raised, None));
        };
        cursor = next;
        if stop() {
            return Ok((raised, Some(cursor)));
        }
    }
}

/// The entity rows of one page after the key `after`, and the key a next
/// page starts after, `None` once this page reached the last row.
fn entity_page_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    after: &[u8],
) -> Result<(Vec<EntityId>, Option<Vec<u8>>)> {
    let lower = if after.is_empty() {
        Bound::Unbounded
    } else {
        Bound::Excluded(after)
    };
    let mut rows = Vec::new();
    let mut last = None;
    let mut scanned = 0_usize;
    for entry in vault
        .store
        .entities
        .range(txn, &(lower, Bound::<&[u8]>::Unbounded))?
    {
        let (key, _) = entry?;
        scanned += 1;
        last = Some(key.to_vec());
        // A sentinel key that is no entity id names no row.
        if let Ok(bytes) = <[u8; 16]>::try_from(key.as_ref())
            && let Ok(id) = EntityId::from_bytes(bytes)
        {
            rows.push(id);
        }
        if scanned == BACKFILL_PAGE {
            break;
        }
    }
    Ok((rows, last.filter(|_| scanned == BACKFILL_PAGE)))
}

/// One backfill write: raises the entity rows after the key `after` that are
/// held here and not erased. A backfill this build began raises every row,
/// an archived one included, so it needs no floor repair; one an earlier
/// build began is repaired once it ends, whatever pages that build ran
/// (`decide_repair_in_txn`; #10139 Opus review P2-6).
fn raise_page_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    after: &[u8],
) -> Result<(u64, Option<Vec<u8>>)> {
    if backfill_done_in(vault, txn)? {
        return Ok((0, Some(vec![CLEARING])));
    }
    // No row here can have a floor yet, and no write raises one: the
    // backfill waits for the first source, which may come after rows
    // written from it (a replica's first window).
    if !super::super::floor::floors_possible_in(vault, txn)? {
        return Ok((0, None));
    }
    super::decide_repair_in_txn(vault, txn)?;
    let (rows, next) = entity_page_in(vault, txn, after)?;
    let mut raised = 0_u64;
    for row in &rows {
        if RAISED.contains(&vault.store, txn, row)? || !floor_holds_in(vault, txn, row)? {
            continue;
        }
        super::super::floor::raise_floors_in_txn(vault, txn, [*row])?;
        raised = raised.saturating_add(1);
    }
    if let Some(last) = next {
        let mut next = vec![RAISING];
        next.extend(last);
        return Ok((raised, Some(next)));
    }
    BACKFILL.put(&vault.store, txn, &(), &true)?;
    Ok((raised, Some(vec![CLEARING])))
}

/// One backfill write once every row is raised, or once the floor repair
/// has: clears raised marks; once none is left, the run goes on to the floor
/// repair if it has not run, and then to raising the waiting rows again.
fn clear_page_in_txn(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<(u64, Option<Vec<u8>>)> {
    let keys = RAISED
        .iter_from(&vault.store, txn, &[])?
        .take(CLEAR_PAGE)
        .map(|entry| entry.map(|(row, ())| row))
        .collect::<Result<Vec<_>>>()?;
    for row in &keys {
        RAISED.delete(&vault.store, txn, row)?;
    }
    let next = if keys.len() == CLEAR_PAGE {
        CLEARING
    } else if REPAIR.get(&vault.store, txn, &())?.unwrap_or(false) {
        SETTLING
    } else {
        REPAIRING
    };
    Ok((0, Some(vec![next])))
}

/// One write of the floor repair (#10117 Opus review P1), a raising pass:
/// raises again each entity row after the key `after` that is held here,
/// not erased, not waiting, not raised by this pass yet, and names lineage
/// no read walks (a birth input or a dependency source), each with the rows
/// it was written from that this pass has not raised yet, first (#10139
/// review round 2 P1-3). Until an archive stopped counting as an erase for
/// the floor, an archived row lost its wait marks, so a row restored since
/// came back with no floor from what it waited on; raised again, it takes
/// that floor, as a row raised when its source lands does. Each row's first
/// raise in the pass reads an erased source no read walks as the backfill
/// does: the row waits on it for good (#10139 Opus review P2-6). The rows it
/// raised.
fn repair_page_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    after: &[u8],
) -> Result<(u64, Option<Vec<u8>>)> {
    let (rows, next) = entity_page_in(vault, txn, after)?;
    let mut repair = BTreeSet::new();
    for row in &rows {
        if PENDING.contains(&vault.store, txn, row)?
            || RAISED.contains(&vault.store, txn, row)?
            || !floor_holds_in(vault, txn, row)?
        {
            continue;
        }
        if !crate::store::birth_record::input_rows_in_txn(&vault.store, txn, row)?.is_empty()
            || !crate::ports::dependency_sources_in(&vault.store, txn, row)?.is_empty()
        {
            repair.insert(*row);
        }
    }
    let raised = u64::try_from(repair.len()).unwrap_or(u64::MAX);
    super::super::floor::raise_floors_in_txn(vault, txn, repair)?;
    if let Some(last) = next {
        let mut next = vec![REPAIRING];
        next.extend(last);
        return Ok((raised, Some(next)));
    }
    REPAIR.put(&vault.store, txn, &(), &true)?;
    Ok((raised, Some(vec![CLEARING])))
}

/// One write of a run's last part: raises again the waiting rows after the
/// row id `after`, so a row whose wait resolved in a write that named no row
/// waiting on it (an epoch's head that landed, an erased source, a
/// dependency or a birth taken off it) settles. A waiting row gone from
/// this vault or erased here loses its marks; an archived one keeps them.
fn settle_page_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    after: &[u8],
) -> Result<(u64, Option<Vec<u8>>)> {
    let mut rows = Vec::new();
    for entry in PENDING.iter_from(&vault.store, txn, &[])? {
        let (row, ()) = entry?;
        if row.as_bytes().as_slice() <= after {
            continue;
        }
        rows.push(row);
        if rows.len() == BACKFILL_PAGE {
            break;
        }
    }
    let mut held = BTreeSet::new();
    for row in &rows {
        if floor_holds_in(vault, txn, row)? {
            held.insert(*row);
        } else {
            PENDING.delete(&vault.store, txn, row)?;
            take_marks_of_in_txn(&vault.store, txn, row, &BTreeSet::new())?;
        }
    }
    let raised = u64::try_from(held.len()).unwrap_or(u64::MAX);
    super::super::floor::raise_floors_in_txn(vault, txn, held)?;
    Ok((
        raised,
        match rows.last() {
            Some(last) if rows.len() == BACKFILL_PAGE => {
                let mut next = vec![SETTLING];
                next.extend_from_slice(last.as_bytes());
                Some(next)
            }
            _ => None,
        },
    ))
}

/// While the backfill runs, carries the floor of `erased`, in the write that
/// tears it, onto each row not raised yet that reads it through an edge the
/// tear takes: a row `DerivedFrom` it, a MESSAGE of a TURN, the TURN of a
/// MESSAGE (#10139 Opus review P2-5). That row's raise would no longer meet
/// `erased`, and would settle without what `erased` added. When the floor of
/// `erased` is not known whole here ([`whole_floor_in`]), the row takes
/// [`super::super::floor::sealed_source`] instead, as a row that waits on an
/// erased row does. Lineage the tear keeps (a birth input, a dependency
/// source, a source a body names) is the raise's own to read.
///
/// # Errors
///
/// Storage failures.
pub(super) fn carry_onto_unraised_readers_in_txn(
    store: &crate::store::Store,
    txn: &mut RwTxn<'_>,
    erased: &EntityId,
) -> Result<()> {
    if BACKFILL.get(store, txn, &())?.unwrap_or(false) || !floors_possible_at(store, txn)? {
        return Ok(());
    }
    let Some(raw) = store.port_entity_raw(txn, erased)? else {
        return Ok(());
    };
    let readers = edge_readers_in(store, txn, erased, &raw)?;
    if readers.is_empty() {
        return Ok(());
    }
    let carried = match whole_floor_in(store, txn, erased, &raw)? {
        Some(floor) => floor,
        None => BTreeSet::from([super::super::floor::sealed_source()]),
    };
    if carried.is_empty() {
        return Ok(());
    }
    for row in readers {
        if row == *erased
            || RAISED.contains(store, txn, &row)?
            || super::erased_in(store, txn, &row)?
            || store.port_entity_raw(txn, &row)?.is_none()
        {
            continue;
        }
        let mut floor = super::super::DERIVED
            .get(store, txn, &row)?
            .unwrap_or_default();
        let before = floor.len();
        floor.extend(carried.iter().copied());
        if floor.len() != before {
            super::super::DERIVED.put(store, txn, &row, &floor)?;
        }
    }
    Ok(())
}

/// Whether a write here can give a row a floor, as
/// [`super::super::floor::floors_possible_in`] reads it.
fn floors_possible_at(store: &crate::store::Store, txn: &RoTxn<'_>) -> Result<bool> {
    Ok(super::super::POLICIES
        .iter_from(store, txn, &[])?
        .next()
        .is_some()
        || super::super::DERIVED
            .iter_from(store, txn, &[])?
            .next()
            .is_some()
        || super::super::LANDED.get(store, txn, &())?.unwrap_or(false))
}

/// The rows that read `row` (bytes `raw`) through an edge the source-audience
/// walk follows: each row `DerivedFrom` it, each MESSAGE `PartOf` it when it
/// is a TURN, and each TURN it is `PartOf` when it is a MESSAGE.
fn edge_readers_in(
    store: &crate::store::Store,
    txn: &RoTxn<'_>,
    row: &EntityId,
    raw: &[u8],
) -> Result<Vec<EntityId>> {
    let mut readers =
        crate::conversation_dag::counted_edge_ids(store, txn, row, EdgeKind::DerivedFrom, true)?;
    let (reader_type, incoming) = match EntityMetadataHeader::parse(raw) {
        Some(header) if header.entity_type == ENTITY_TYPE_TURN => (ENTITY_TYPE_MESSAGE, true),
        Some(header) if header.entity_type == ENTITY_TYPE_MESSAGE => (ENTITY_TYPE_TURN, false),
        _ => return Ok(readers),
    };
    for reader in
        crate::conversation_dag::counted_edge_ids(store, txn, row, EdgeKind::PartOf, incoming)?
    {
        let reads = store.port_entity_raw(txn, &reader)?.is_some_and(|bytes| {
            EntityMetadataHeader::parse(&bytes)
                .is_some_and(|header| header.entity_type == reader_type)
        });
        if reads {
            readers.push(reader);
        }
    }
    Ok(readers)
}

/// The floor `row` (bytes `raw`) holds, when it is known whole here: it waits
/// on nothing, its binding is not still to land, and the backfill raised it
/// or it names no birth input or dependency source a raise would read.
/// `None` otherwise. A source its body names, or a row it reads through an
/// edge, of a row the backfill has not raised is not read here.
fn whole_floor_in(
    store: &crate::store::Store,
    txn: &RoTxn<'_>,
    row: &EntityId,
    raw: &[u8],
) -> Result<Option<BTreeSet<EntityId>>> {
    if PENDING.contains(store, txn, row)? {
        return Ok(None);
    }
    if !RAISED.contains(store, txn, row)?
        && (!crate::store::birth_record::input_rows_in_txn(store, txn, row)?.is_empty()
            || !crate::ports::dependency_sources_in(store, txn, row)?.is_empty())
    {
        return Ok(None);
    }
    let mut floor = super::super::DERIVED
        .get(store, txn, row)?
        .unwrap_or_default();
    match super::super::floor::own_source_in(store, txn, row, raw)? {
        OwnSource::Unbound => return Ok(None),
        OwnSource::Source(own) => {
            floor.insert(own);
        }
        OwnSource::None => {}
    }
    Ok(Some(floor))
}
