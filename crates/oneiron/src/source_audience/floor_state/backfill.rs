//! The floor backfill (READ-LINEAGE L1; #9289 review 2 P1-2), housekeeping's
//! `SourceFloorBackfill` sweep: it raises the floor of every row a vault held
//! before floors were written, clears its marks, repairs once the rows an
//! archive kept out of their floor's raises (#10117 Opus review P1), and in
//! each run raises the waiting rows again (#9289 review 3 P1-4, P1-6).

use std::collections::BTreeSet;
use std::ops::Bound;

use heed::{RoTxn, RwTxn};

use super::marks::take_marks_of_in_txn;
use super::{BACKFILL, PENDING, RAISED, REPAIR, backfill_done_in, floor_holds_in};
use crate::error::Result;
use crate::{EntityId, Vault};

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
/// vault whose backfill ended before an archive stopped counting as an erase
/// for the floor then runs the floor repair once ([`repair_page_in_txn`]).
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
/// held here and not erased. Its last page also marks the floor repair done:
/// it raised every row, an archived one included.
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
    REPAIR.put(&vault.store, txn, &(), &true)?;
    Ok((raised, Some(vec![CLEARING])))
}

/// One backfill write once every row is raised: clears raised marks; once
/// none is left, the run goes on to the floor repair if it has not run, and
/// then to raising the waiting rows again.
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

/// One write of the floor repair (#10117 Opus review P1): raises again each
/// entity row after the key `after` that is held here, not erased, not
/// waiting, and names lineage no read walks (a birth input or a dependency
/// source). Until an archive stopped counting as an erase for the floor, an
/// archived row lost its wait marks, so a row restored since came back with
/// no floor from what it waited on; raised again, it takes that floor, as a
/// row raised when its source lands does. The rows it raised.
fn repair_page_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    after: &[u8],
) -> Result<(u64, Option<Vec<u8>>)> {
    let (rows, next) = entity_page_in(vault, txn, after)?;
    let mut repair = BTreeSet::new();
    for row in &rows {
        if PENDING.contains(&vault.store, txn, row)? || !floor_holds_in(vault, txn, row)? {
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
    Ok((raised, Some(vec![SETTLING])))
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
