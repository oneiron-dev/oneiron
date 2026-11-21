//! The migration from the floor's wait marks to the open set (Fable design
//! pass 31, section 5). It goes at the launch reset, with the tables it
//! reads.
//!
//! Builds before pass 31 kept "this row waits" as marks: `PENDING`,
//! `AWAITED` and `WAITS`, and `RAISED` and `BACKFILL` for the backfill of the
//! rows held before floors. The housekeeping sweep `SourceFloorBackfill`
//! keeps its job, cadence and cursor, and until the migration ends it runs
//! these phases, a page per write:
//! - **M1, marks become entries**: each mark becomes an open entry. A mark
//!   on an input erased now was left standing by the old seal, which takes
//!   every mark at a tear, so it is an old fact's (FLOOR-OLD-FACT-ERASED-INPUT
//!   = A): its entry waits for good, at the level of the delete.
//! - **M2, one pass over the held rows**: a row the old backfill had not
//!   raised is judged as an old fact, every link; a row it raised is healed,
//!   its birth inputs and dependency sources read again, which gives back the
//!   marks an archive lost and leaves a released or erased input alone.
//! - **Clearing**: the old tables are emptied, and the migration is marked
//!   ended.
//!
//! Until it ends, a read unions a row's open set with its marks, and judges
//! a row the migration has not reached one level at the read
//! ([`super::source_state`]).

use std::ops::Bound;

use heed::{RoTxn, RwTxn};

use super::source_state::{self, OpenFlags};
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

/// Each row whose floor waited, by an old build.
const PENDING: SideTable<EntityId, (), Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_PENDING);
/// What each row whose floor waited waited on: the awaited id, then the row.
const AWAITED: SideTable<(EntityId, EntityId), (), Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_AWAITED);
/// The marks of [`AWAITED`] by row: the row, then the awaited id.
const WAITS: SideTable<(EntityId, EntityId), (), Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_WAITS);
/// Each row judged since the old backfill began; the migration marks the
/// rows it judges here too.
const RAISED: SideTable<EntityId, (), Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_RAISED);
/// Whether the old backfill raised every row; the migration sets it once
/// its pass has judged every row, so no row reads unjudged while the marks
/// are cleared.
const BACKFILL: SideTable<(), bool, Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_BACKFILL);

/// A sweep cursor's first byte: converting the marks (M1).
const MARKS: u8 = 17;
/// A sweep cursor's first byte: the pass over the held rows after the
/// entity key that follows it (M2).
const JUDGING: u8 = 18;
/// A sweep cursor's first byte: emptying the old tables.
const CLEARING: u8 = 19;

/// Marks one write converts.
const MARKS_PAGE: usize = 512;
/// Entity rows one write of the pass reads.
const JUDGE_PAGE: usize = 64;
/// Rows of each old table one write deletes.
const CLEAR_PAGE: usize = 1024;

/// Whether the old backfill raised every row here, or the migration's pass
/// has judged every row.
///
/// # Errors
///
/// Storage failures.
pub(super) fn old_backfill_done_in(vault: &Vault, txn: &RoTxn<'_>) -> Result<bool> {
    Ok(BACKFILL.get(&vault.store, txn, &())?.unwrap_or(false))
}

/// Whether `row` was judged since the old backfill began.
///
/// # Errors
///
/// Storage failures.
pub(super) fn raised_in(vault: &Vault, txn: &RoTxn<'_>, row: &EntityId) -> Result<bool> {
    RAISED.contains(&vault.store, txn, row)
}

/// Marks `row` judged, in a write while the migration runs.
///
/// # Errors
///
/// Storage failures.
pub(super) fn mark_judged_in_txn(vault: &Vault, txn: &mut RwTxn<'_>, row: &EntityId) -> Result<()> {
    if old_backfill_done_in(vault, txn)? {
        return Ok(());
    }
    RAISED.put(&vault.store, txn, row, &())
}

/// Whether `row` still holds an old build's wait (a mark, or its pending
/// row) the migration has not converted: never once it has ended.
///
/// # Errors
///
/// Storage failures.
pub(super) fn has_old_marks_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    row: &EntityId,
    migrated: bool,
) -> Result<bool> {
    if migrated {
        return Ok(false);
    }
    Ok(PENDING.contains(&vault.store, txn, row)?
        || WAITS
            .iter_from(&vault.store, txn, row.as_bytes())?
            .next()
            .is_some())
}

/// What an old build's wait of `row` reads as: each mark as the entry M1
/// makes of it, and, for a row pending with no mark left (a mark kept only by
/// the awaited id), a wait on itself that no word source resolves.
///
/// # Errors
///
/// Storage failures.
pub(super) fn old_marks_of_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    row: &EntityId,
    migrated: bool,
) -> Result<OldMarks> {
    let mut marks = OldMarks::default();
    if migrated {
        return Ok(marks);
    }
    for (_, awaited) in WAITS.scan_keys(&vault.store, txn, row.as_bytes())? {
        marks
            .entries
            .push((awaited, mark_flags_in(vault, txn, row, &awaited)?));
    }
    marks.pending = marks.entries.is_empty() && PENDING.contains(&vault.store, txn, row)?;
    Ok(marks)
}

/// An old build's wait of one row, as a read meets it.
#[derive(Debug, Default)]
pub(super) struct OldMarks {
    /// Each mark, as the entry M1 makes of it.
    pub(super) entries: Vec<(EntityId, OpenFlags)>,
    /// The row was pending with no mark kept by row: it waits.
    pub(super) pending: bool,
}

/// The flags of the entry a mark of `row` on `awaited` becomes: an old
/// fact's, at the level of the delete, when `awaited` reads erased now.
fn mark_flags_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    row: &EntityId,
    awaited: &EntityId,
) -> Result<OpenFlags> {
    if awaited != row && crate::ports::erased_in_txn(&vault.store, txn, awaited)? {
        return Ok(OpenFlags::before_floors(source_state::delete_level_in(
            vault, txn, awaited,
        )?));
    }
    Ok(OpenFlags::ORDINARY)
}

/// One write of the migration from `cursor` (a cursor of another phase, or
/// an old build's, starts it from M1): what it did, and where it goes on;
/// `None` once it has ended.
///
/// # Errors
///
/// Storage failures.
pub(super) fn step_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    cursor: &[u8],
) -> Result<(u64, Option<Vec<u8>>)> {
    match cursor.split_first() {
        Some((&JUDGING, after)) => {
            let (judged, next) = judge_page_in_txn(vault, txn, after)?;
            Ok((
                judged,
                Some(match next {
                    Some(key) => [JUDGING].into_iter().chain(key).collect(),
                    None => {
                        // Every row is judged: none reads unjudged while the
                        // marks are cleared.
                        BACKFILL.put(&vault.store, txn, &(), &true)?;
                        vec![CLEARING]
                    }
                }),
            ))
        }
        Some((&CLEARING, _)) => Ok((0, (!clear_page_in_txn(vault, txn)?).then(|| vec![CLEARING]))),
        _ => {
            let (converted, more) = marks_page_in_txn(vault, txn)?;
            Ok((
                converted,
                Some(if more { vec![MARKS] } else { vec![JUDGING] }),
            ))
        }
    }
}

/// One write of M1: converts the first marks into open entries, each with
/// its two index rows and its row's pending row. Whether marks are left.
fn marks_page_in_txn(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<(u64, bool)> {
    let mut marks: Vec<(EntityId, EntityId)> = AWAITED
        .iter_from(&vault.store, txn, &[])?
        .take(MARKS_PAGE)
        .map(|entry| entry.map(|((awaited, row), ())| (row, awaited)))
        .collect::<Result<_>>()?;
    if marks.len() < MARKS_PAGE {
        let room = MARKS_PAGE - marks.len();
        marks.extend(
            WAITS
                .iter_from(&vault.store, txn, &[])?
                .take(room)
                .map(|entry| entry.map(|((row, awaited), ())| (row, awaited)))
                .collect::<Result<Vec<_>>>()?,
        );
    }
    let mut converted = 0_u64;
    for (row, awaited) in &marks {
        if vault.get_raw_in(txn, row)?.is_some() {
            let flags = mark_flags_in(vault, txn, row, awaited)?;
            source_state::open_entry_in_txn(vault, txn, row, awaited, flags)?;
            converted = converted.saturating_add(1);
        }
        AWAITED.delete(&vault.store, txn, &(*awaited, *row))?;
        WAITS.delete(&vault.store, txn, &(*row, *awaited))?;
        PENDING.delete(&vault.store, txn, row)?;
    }
    Ok((converted, marks.len() == MARKS_PAGE))
}

/// One write of M2: judges or heals the held rows after the entity key
/// `after`, then folds the rows that waited on each. Where the pass goes
/// on, or `None` once it has read every row.
fn judge_page_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    after: &[u8],
) -> Result<(u64, Option<Vec<u8>>)> {
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
        if let Some(id) = source_state::id_of(&key) {
            rows.push(id);
        }
        if scanned == JUDGE_PAGE {
            break;
        }
    }
    let mut judged = 0_u64;
    let done = old_backfill_done_in(vault, txn)?;
    for row in &rows {
        if vault.get_raw_in(txn, row)?.is_none()
            || crate::ports::erased_in_txn(&vault.store, txn, row)?
        {
            continue;
        }
        if done || raised_in(vault, txn, row)? {
            source_state::heal_row_in_txn(vault, txn, row)?;
        } else {
            source_state::judge_row_in_txn(vault, txn, row, &source_state::Fresh::None, true)?;
            RAISED.put(&vault.store, txn, row, &())?;
        }
        source_state::fold_waiters_in_txn(vault, txn, row)?;
        judged = judged.saturating_add(1);
    }
    Ok((
        judged,
        match last {
            Some(last) if scanned == JUDGE_PAGE => Some(last),
            _ => None,
        },
    ))
}

/// One write of the clearing: deletes a page of each old table; once all
/// are empty, marks the migration ended. Whether it has ended.
fn clear_page_in_txn(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<bool> {
    let pending: Vec<EntityId> = PENDING
        .iter_from(&vault.store, txn, &[])?
        .take(CLEAR_PAGE)
        .map(|entry| entry.map(|(row, ())| row))
        .collect::<Result<_>>()?;
    for row in &pending {
        PENDING.delete(&vault.store, txn, row)?;
    }
    let raised: Vec<EntityId> = RAISED
        .iter_from(&vault.store, txn, &[])?
        .take(CLEAR_PAGE)
        .map(|entry| entry.map(|(row, ())| row))
        .collect::<Result<_>>()?;
    for row in &raised {
        RAISED.delete(&vault.store, txn, row)?;
    }
    if pending.len() == CLEAR_PAGE || raised.len() == CLEAR_PAGE {
        return Ok(false);
    }
    // M1 took every mark; a mark written since by no build stands nowhere.
    AWAITED.delete_from(&vault.store, txn, &[])?;
    WAITS.delete_from(&vault.store, txn, &[])?;
    BACKFILL.delete_from(&vault.store, txn, &[])?;
    source_state::mark_migrated_in_txn(vault, txn)?;
    Ok(true)
}

/// Forgets, in `txn`, every old table: with the open set gone too, the
/// vault reads as one whose rows were written before floors were.
#[cfg(any(test, feature = "test-support", oneiron_test_support))]
pub(super) fn forget_in_txn(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    PENDING.delete_from(&vault.store, txn, &[])?;
    AWAITED.delete_from(&vault.store, txn, &[])?;
    WAITS.delete_from(&vault.store, txn, &[])?;
    RAISED.delete_from(&vault.store, txn, &[])?;
    BACKFILL.delete_from(&vault.store, txn, &[])?;
    Ok(())
}

/// Ends, in `txn`, the old backfill's pass as a build before the backfill
/// raised archived rows (FLOOR-BACKFILL-SKIPS-ARCHIVED-ROWS) ends it: it
/// marks the backfill done and clears the raised marks.
#[cfg(any(test, feature = "test-support", oneiron_test_support))]
pub(crate) fn end_backfill_without_archived_rows_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
) -> Result<()> {
    BACKFILL.put(&vault.store, txn, &(), &true)?;
    RAISED.delete_from(&vault.store, txn, &[])?;
    Ok(())
}

/// Marks, in `txn`, the old backfill done as the last page of an older
/// build's pass commits it, before its clearing pages run: the raised marks
/// stay.
#[cfg(any(test, feature = "test-support", oneiron_test_support))]
pub(crate) fn mark_backfill_done_in_txn(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    BACKFILL.put(&vault.store, txn, &(), &true)
}

/// Marks `row` raised in `txn`, as a write of an older build marked a row
/// it raised while its backfill ran.
#[cfg(any(test, feature = "test-support", oneiron_test_support))]
pub(crate) fn mark_raised_in_txn(vault: &Vault, txn: &mut RwTxn<'_>, row: &EntityId) -> Result<()> {
    RAISED.put(&vault.store, txn, row, &())
}

/// Leaves `row` waiting on `source` in `txn`, with its marks, as an older
/// build's backfill left a row learnt from an archived row it read as
/// erased.
#[cfg(any(test, feature = "test-support", oneiron_test_support))]
pub(crate) fn mark_waiting_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
    source: &EntityId,
) -> Result<()> {
    PENDING.put(&vault.store, txn, row, &())?;
    AWAITED.put(&vault.store, txn, &(*source, *row), &())?;
    WAITS.put(&vault.store, txn, &(*row, *source), &())
}

/// Runs the floor sweep to the end of its run from the cursor an older
/// build's backfill pass saved after the page that ended at the entity key
/// of `after` (its first byte 0), as housekeeping does when it holds that
/// cursor.
///
/// # Errors
///
/// Storage failures.
#[cfg(any(test, feature = "test-support", oneiron_test_support))]
pub(crate) fn sweep_floors_from_raising_cursor(vault: &Vault, after: &EntityId) -> Result<()> {
    let mut cursor = vec![0_u8];
    cursor.extend_from_slice(after.as_bytes());
    source_state::sweep_floors(vault, Some(&cursor), || false).map(|_| ())
}
