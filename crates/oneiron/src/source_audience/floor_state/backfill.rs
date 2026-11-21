//! The floor backfill (#9289 review 2 P1-2): housekeeping's
//! `SourceFloorBackfill` sweep raises the floor of each row a vault held
//! before floors were written, a page per write, then clears its marks, and
//! at each run raises every waiting row again ([`super`]).

use std::collections::BTreeSet;
use std::ops::Bound;

use heed::RwTxn;

use super::marks::take_marks_of_in_txn;
use super::{ARCHIVED_RAISED, BACKFILL, Backfill, PENDING, RAISED, backfill_in, raisable_in};
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

/// One run of the floor backfill (#9289 review 2 P1-2), housekeeping's
/// `SourceFloorBackfill` sweep: from `cursor`, where an unfinished run
/// stopped, it raises the floor of each entity row in key order, live or
/// archived (FLOOR-BACKFILL-SKIPS-ARCHIVED-ROWS), a page per write, each
/// with the not yet raised rows it was written from, and stops between
/// pages once `stop` says so. Once every row is raised it marks the
/// backfill done, then clears the raised marks. A vault whose backfill
/// ended before it raised archived rows raises every row once more, the
/// same way ([`Backfill::RaisingAgain`]). Then, and in each
/// later run, it raises every waiting row again, a page per write
/// (#9289 review 3 P1-4, P1-6). In a vault where no row can have a floor yet
/// it does nothing, and runs at the next pass again. The rows it raised, and
/// where an unfinished run goes on (`None` once this run has ended).
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

/// One backfill write: raises the entity rows after the key `after`, live
/// or archived.
fn raise_page_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    after: &[u8],
) -> Result<(u64, Option<Vec<u8>>)> {
    let backfill = backfill_in(vault, txn)?;
    if backfill == Backfill::Done {
        return Ok((0, Some(vec![CLEARING])));
    }
    // No row here can have a floor yet, and no write raises one: the
    // backfill waits for the first source, which may come after rows
    // written from it (a replica's first window).
    if !crate::source_audience::floor::floors_possible_in(vault, txn)? {
        return Ok((0, None));
    }
    // A backfill that begins here raises archived rows from its first page,
    // so it needs no run again. One that a build before it began goes on
    // from its cursor, and runs again once it ends.
    if backfill == Backfill::Raising && after.is_empty() {
        ARCHIVED_RAISED.put(&vault.store, txn, &(), &true)?;
    }
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
    let mut raised = 0_u64;
    for row in &rows {
        if RAISED.contains(&vault.store, txn, row)? || !raisable_in(vault, txn, row)? {
            continue;
        }
        crate::source_audience::floor::raise_floors_in_txn(vault, txn, [*row])?;
        raised = raised.saturating_add(1);
    }
    match last {
        Some(last) if scanned == BACKFILL_PAGE => {
            let mut next = vec![RAISING];
            next.extend(last);
            Ok((raised, Some(next)))
        }
        _ => {
            BACKFILL.put(&vault.store, txn, &(), &true)?;
            if backfill == Backfill::RaisingAgain {
                ARCHIVED_RAISED.put(&vault.store, txn, &(), &true)?;
            }
            Ok((raised, Some(vec![CLEARING])))
        }
    }
}

/// One backfill write once every row is raised: clears raised marks; once
/// none is left, the run goes on raising the waiting rows again.
fn clear_page_in_txn(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<(u64, Option<Vec<u8>>)> {
    let keys = RAISED
        .iter_from(&vault.store, txn, &[])?
        .take(CLEAR_PAGE)
        .map(|entry| entry.map(|(row, ())| row))
        .collect::<Result<Vec<_>>>()?;
    for row in &keys {
        RAISED.delete(&vault.store, txn, row)?;
    }
    Ok((
        0,
        Some(if keys.len() == CLEAR_PAGE {
            vec![CLEARING]
        } else {
            vec![SETTLING]
        }),
    ))
}

/// One write of a run's last part: raises again the waiting rows after the
/// row id `after`, so a row whose wait resolved in a write that named no row
/// waiting on it (an epoch's head that landed, an erased source, a
/// dependency or a birth taken off it) settles. A waiting row gone from
/// this vault loses its marks; an archived one keeps them, and is raised.
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
    let mut live = BTreeSet::new();
    for row in &rows {
        if raisable_in(vault, txn, row)? {
            live.insert(*row);
        } else {
            PENDING.delete(&vault.store, txn, row)?;
            take_marks_of_in_txn(&vault.store, txn, row, &BTreeSet::new())?;
        }
    }
    let raised = u64::try_from(live.len()).unwrap_or(u64::MAX);
    crate::source_audience::floor::raise_floors_in_txn(vault, txn, live)?;
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

/// Marks, in `txn`, the backfill done as a build that ran it before the
/// backfill raised archived rows left it (FLOOR-BACKFILL-SKIPS-ARCHIVED-ROWS).
#[cfg(any(test, feature = "test-support", oneiron_test_support))]
pub(crate) fn end_backfill_without_archived_rows_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
) -> Result<()> {
    BACKFILL.put(&vault.store, txn, &(), &true)?;
    ARCHIVED_RAISED.delete_from(&vault.store, txn, &[])?;
    Ok(())
}

/// Forgets, in `txn`, every floor's state and the backfill's: the vault
/// reads as one whose rows were written before floors were.
#[cfg(any(test, feature = "test-support", oneiron_test_support))]
pub(crate) fn forget_floor_state_in_txn(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    PENDING.delete_from(&vault.store, txn, &[])?;
    super::marks::AWAITED.delete_from(&vault.store, txn, &[])?;
    super::marks::WAITS.delete_from(&vault.store, txn, &[])?;
    RAISED.delete_from(&vault.store, txn, &[])?;
    BACKFILL.delete_from(&vault.store, txn, &[])?;
    ARCHIVED_RAISED.delete_from(&vault.store, txn, &[])?;
    Ok(())
}
