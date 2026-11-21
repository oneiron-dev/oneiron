//! The floor backfill (#9289 review 2 P1-2): housekeeping's
//! `SourceFloorBackfill` sweep raises the floor of each row a vault held
//! before floors were written, a page per write, then clears its marks, and
//! at each run raises every waiting row again ([`super`]).

use std::collections::BTreeSet;
use std::ops::Bound;

use heed::RwTxn;

use super::marks::take_marks_of_in_txn;
use super::{
    ARCHIVED_RAISED, BACKFILL, Backfill, PENDING, RAISED, RAISED_AGAIN, backfill_in, raisable_in,
    raised_in,
};
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

/// A backfill cursor's first byte: raising the rows after the entity key
/// that follows it, in a pass that began in this build with no row raised
/// before its first page, so its end marks archived rows raised (#10265
/// Opus review P2-2). A build before this one reads it as [`RAISING`] and
/// writes [`RAISING`] after its page, so a pass it goes on with runs again.
const RAISING_WHOLE: u8 = 3;

/// A backfill cursor's first byte: raising again, in the run again
/// ([`Backfill::RaisingAgain`]), the rows after the entity key that follows
/// it. Only a cursor of the run again goes on in it: from any other, the
/// run again starts at the first row (#10265 review 2 P1-1).
const RAISING_AGAIN: u8 = 4;

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
/// same way ([`Backfill::RaisingAgain`]); so does a vault whose pass a
/// build before this one began or went on with, or began after rows were
/// raised (#10265 Opus review P2-2). The run again starts at the first row
/// whatever cursor the pass before it left, and keeps its own raised marks,
/// so neither an older pass's cursor nor its marks make it skip a row
/// (#10265 review 2 P1-1, P1-2). Then, and in each later run, it raises
/// every waiting row again, a page per write (#9289 review 3 P1-4, P1-6).
/// In a vault where no row can have a floor yet it does nothing, and runs at
/// the next pass again. The rows it raised, and where an unfinished run goes
/// on (`None` once this run has ended).
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
            Some((&RAISING_WHOLE, after)) => raise_page_in_txn(vault, txn, after, Pass::Whole),
            Some((&RAISING_AGAIN, after)) => raise_page_in_txn(vault, txn, after, Pass::Again),
            Some((_, after)) => raise_page_in_txn(vault, txn, after, Pass::First),
            None => raise_page_in_txn(vault, txn, &[], Pass::First),
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

/// The pass a raising cursor was written in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pass {
    /// A first pass ([`RAISING`]): one a build before this one began or went
    /// on with, or one that began after rows were raised.
    First,
    /// A first pass this build began with no row raised ([`RAISING_WHOLE`]).
    Whole,
    /// The run again ([`RAISING_AGAIN`]).
    Again,
}

/// One backfill write: raises the entity rows after the key `after`, live
/// or archived, in the pass `pass` whose cursor names `after`.
fn raise_page_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    after: &[u8],
    pass: Pass,
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
    // A cursor goes on only in the pass that wrote it. The run again starts
    // at the first row from any cursor but its own: the sweep can hold the
    // cursor an older pass saved before its last page ended it (#10265
    // review 2 P1-1). A first pass never goes on from the run again's.
    let after: &[u8] = match (backfill, pass) {
        (Backfill::RaisingAgain, Pass::Again) | (Backfill::Raising, Pass::First | Pass::Whole) => {
            after
        }
        _ => &[],
    };
    // A pass that begins here with no row raised yet raises archived rows
    // from its first page, so it needs no run again: its cursor says so, and
    // its end marks archived rows raised. A pass a build before this one
    // began or went on with, or one that begins after rows were raised (a
    // write of a build before this one raised them without the archived rows
    // they were written from), runs again once it ends (#10265 Opus review
    // P2-2).
    let whole = backfill == Backfill::Raising
        && ((pass == Pass::Whole && !after.is_empty())
            || (after.is_empty() && RAISED.iter_from(&vault.store, txn, &[])?.next().is_none()));
    let tag = match backfill {
        Backfill::RaisingAgain => RAISING_AGAIN,
        _ if whole => RAISING_WHOLE,
        _ => RAISING,
    };
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
        if raised_in(vault, txn, row, backfill)? || !raisable_in(vault, txn, row)? {
            continue;
        }
        crate::source_audience::floor::raise_floors_in_txn(vault, txn, [*row])?;
        raised = raised.saturating_add(1);
    }
    match last {
        Some(last) if scanned == BACKFILL_PAGE => {
            let mut next = vec![tag];
            next.extend(last);
            Ok((raised, Some(next)))
        }
        _ => {
            BACKFILL.put(&vault.store, txn, &(), &true)?;
            if whole || backfill == Backfill::RaisingAgain {
                ARCHIVED_RAISED.put(&vault.store, txn, &(), &true)?;
            }
            Ok((raised, Some(vec![CLEARING])))
        }
    }
}

/// One backfill write once every row is raised: clears raised marks, the
/// first pass's and the run again's; once none is left, the run goes on
/// raising the waiting rows again.
fn clear_page_in_txn(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<(u64, Option<Vec<u8>>)> {
    let first = RAISED
        .iter_from(&vault.store, txn, &[])?
        .take(CLEAR_PAGE)
        .map(|entry| entry.map(|(row, ())| row))
        .collect::<Result<Vec<_>>>()?;
    for row in &first {
        RAISED.delete(&vault.store, txn, row)?;
    }
    let again = RAISED_AGAIN
        .iter_from(&vault.store, txn, &[])?
        .take(CLEAR_PAGE.saturating_sub(first.len()))
        .map(|entry| entry.map(|(row, ())| row))
        .collect::<Result<Vec<_>>>()?;
    for row in &again {
        RAISED_AGAIN.delete(&vault.store, txn, row)?;
    }
    Ok((
        0,
        Some(if first.len() + again.len() == CLEAR_PAGE {
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

/// Ends, in `txn`, the backfill's pass as a build before the backfill
/// raised archived rows (FLOOR-BACKFILL-SKIPS-ARCHIVED-ROWS) ends it: it
/// marks the backfill done and clears the raised marks, and leaves
/// [`ARCHIVED_RAISED`], which it does not know, as it is.
#[cfg(any(test, feature = "test-support", oneiron_test_support))]
pub(crate) fn end_backfill_without_archived_rows_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
) -> Result<()> {
    BACKFILL.put(&vault.store, txn, &(), &true)?;
    RAISED.delete_from(&vault.store, txn, &[])?;
    Ok(())
}

/// Marks, in `txn`, the backfill done as the last page of a pass of a build
/// before this one commits it, before its clearing pages run: the raised
/// marks stay.
#[cfg(any(test, feature = "test-support", oneiron_test_support))]
pub(crate) fn mark_backfill_done_in_txn(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    BACKFILL.put(&vault.store, txn, &(), &true)
}

/// Runs the floor backfill to the end of its run from the cursor a pass of
/// a build before this one saved after the page that ended at the entity
/// key of `after`, as the sweep does when it holds that cursor.
///
/// # Errors
///
/// Storage failures.
#[cfg(any(test, feature = "test-support", oneiron_test_support))]
pub(crate) fn backfill_floors_from_raising_cursor(vault: &Vault, after: &EntityId) -> Result<()> {
    let mut cursor = vec![RAISING];
    cursor.extend_from_slice(after.as_bytes());
    backfill_floors(vault, Some(&cursor), || false).map(|_| ())
}

/// Marks `row` raised in `txn`, as a write of a build before
/// FLOOR-BACKFILL-SKIPS-ARCHIVED-ROWS marked a row it raised while the
/// backfill ran, without the archived rows it was written from.
#[cfg(any(test, feature = "test-support", oneiron_test_support))]
pub(crate) fn mark_raised_in_txn(vault: &Vault, txn: &mut RwTxn<'_>, row: &EntityId) -> Result<()> {
    RAISED.put(&vault.store, txn, row, &())
}

/// Leaves `row` waiting on `source` in `txn`, with its mark, as the
/// backfill of a build before #10222 left a row learnt from an archived row
/// it read as erased.
#[cfg(any(test, feature = "test-support", oneiron_test_support))]
pub(crate) fn mark_waiting_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
    source: &EntityId,
) -> Result<()> {
    PENDING.put(&vault.store, txn, row, &())?;
    super::marks::mark_wait_in_txn(&vault.store, txn, source, row)
}

/// Forgets, in `txn`, every floor's state and the backfill's: the vault
/// reads as one whose rows were written before floors were.
#[cfg(any(test, feature = "test-support", oneiron_test_support))]
pub(crate) fn forget_floor_state_in_txn(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    PENDING.delete_from(&vault.store, txn, &[])?;
    super::marks::AWAITED.delete_from(&vault.store, txn, &[])?;
    super::marks::WAITS.delete_from(&vault.store, txn, &[])?;
    RAISED.delete_from(&vault.store, txn, &[])?;
    RAISED_AGAIN.delete_from(&vault.store, txn, &[])?;
    BACKFILL.delete_from(&vault.store, txn, &[])?;
    ARCHIVED_RAISED.delete_from(&vault.store, txn, &[])?;
    Ok(())
}
