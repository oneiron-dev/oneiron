//! The migration from the floor's wait marks to the open set (Fable design
//! pass 31, section 5). It goes at the launch reset, with the tables it
//! reads.
//!
//! Builds before pass 31 kept "this row waits" as marks: `PENDING`,
//! `AWAITED` and `WAITS`, and `RAISED`, `BACKFILL`, and #10265's
//! `RAISED_AGAIN` and `ARCHIVED_RAISED` for the backfill of the rows held
//! before floors. The housekeeping sweep `SourceFloorBackfill` keeps its job,
//! cadence and cursor, and until the migration ends it runs these phases, a
//! page per write:
//! - **M1, marks become entries**: each mark becomes an open entry. A mark
//!   on an input erased now was left standing by the old seal, which takes
//!   every mark at a tear, so it is an old fact's (FLOOR-OLD-FACT-ERASED-INPUT
//!   = A): its entry waits for good, at the level of the delete.
//! - **M2, one pass over the held rows, archived rows too** (case 60): a
//!   row no older build raised is judged as an old fact, every link; a row
//!   an older build raised is healed, its birth inputs and dependency
//!   sources read again, which gives back the marks an archive lost and
//!   leaves a released or erased input alone ([`Visit`]).
//! - **Clearing**: once every row is judged, the old tables and the
//!   migration's own visit marks are emptied, and the migration is marked
//!   ended.
//!
//! The migration keeps its own visit marks ([`VISITED`]): a row this build
//! judged as the migration judges it, by the pass, by a write or before its
//! archive marker moves. A mark an older build left never counts as a visit
//! (cases 64 to 66), and its cursor goes on only in the phase that wrote it
//! (case 65). Until it ends, a read unions a row's open set with its marks,
//! and judges a row the migration has not visited one level at the read, as
//! the migration would ([`super::source_state`]).

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
/// Each row an old build raised while its backfill ran, until the backfill
/// had raised every row.
const RAISED: SideTable<EntityId, (), Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_RAISED);
/// Whether the old backfill raised every row it found to raise.
const BACKFILL: SideTable<(), bool, Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_BACKFILL);
/// Each row #10265's run again of the old backfill raised once more, until
/// that run had raised every row.
const RAISED_AGAIN: SideTable<EntityId, (), Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_RAISED_AGAIN);
/// Whether the old backfill raised archived rows too (#10265): written when
/// a pass ended that raised them from its first page, or its run again
/// ended.
const ARCHIVED_RAISED: SideTable<(), bool, Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_ARCHIVED_RAISED);
/// Each row this build has judged as the migration judges it: [`JUDGED`],
/// or [`OLD_FACT`].
const VISITED: SideTable<EntityId, u8, Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_MIGRATION_VISITED);

/// A visit mark: the row is judged in full.
const JUDGED: u8 = 0;
/// A visit mark: the row is an old fact a delete judged for its link to the
/// row it erased (M3); the migration judges its other links in full.
const OLD_FACT: u8 = 1;

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

/// Where a row stands in the migration (section 5, M2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Visit {
    /// Judged here as the migration judges it, or the migration has judged
    /// every row: its floor and open set say all.
    Visited,
    /// No older build raised it: every link is judged as an old fact's.
    OldFact,
    /// An older build raised it: it is healed, its birth inputs and
    /// dependency sources read again.
    Raised,
}

/// Where `row` stands in the migration. A row is judged as an old fact
/// only on a record that no older build raised it, never on the absence
/// of a stored floor alone (case 63):
/// - while the old backfill has not raised every row, no raised mark of
///   `row`: each raise of that backfill, and of a write while it ran, marked
///   its row; an older pass's marks count as raises, not as visits (case 64);
/// - once it has, and has not raised archived rows (#10265: neither a pass
///   that raised them from its first page nor its run again ended), an
///   archived row with no mark of that run again, no stored floor, no open
///   entry and no old mark, as #10265's run again reads it. The backfill of
///   a build before #10265 skipped archived rows; a row it raised while
///   live and archived since cannot be told from one it skipped when its
///   floor is empty, so such a row is judged as an old fact too (a stated
///   limit, FLOOR-RUN-AGAIN-OVER-SEAL-REACHES-DERIVED-ROWS). The record is
///   read before the marker moves: an archive and a restore visit the row
///   first ([`visit_row_in_txn`]; case 62).
///
/// Every other row not visited was raised by an older build.
///
/// # Errors
///
/// Storage failures.
pub(super) fn visit_in(
    store: &crate::store::Store,
    txn: &RoTxn<'_>,
    row: &EntityId,
) -> Result<Visit> {
    if source_state::judged_all_in(store, txn)? {
        return Ok(Visit::Visited);
    }
    match VISITED.get(store, txn, row)? {
        Some(OLD_FACT) => return Ok(Visit::OldFact),
        Some(_) => return Ok(Visit::Visited),
        None => {}
    }
    if !old_backfill_done_in(store, txn)? {
        return Ok(if RAISED.contains(store, txn, row)? {
            Visit::Raised
        } else {
            Visit::OldFact
        });
    }
    if ARCHIVED_RAISED.get(store, txn, &())?.unwrap_or(false)
        || RAISED_AGAIN.contains(store, txn, row)?
        || !crate::ports::TombstoneStoreRead::port_deletion_state(store, txn, row)?.archived
        || crate::source_audience::DERIVED.contains(store, txn, row)?
        || source_state::has_open_in(store, txn, row)?
        || has_old_marks_in(store, txn, row, false)?
    {
        return Ok(Visit::Raised);
    }
    Ok(Visit::OldFact)
}

/// Whether the old backfill had raised every row it found to raise.
fn old_backfill_done_in(store: &crate::store::Store, txn: &RoTxn<'_>) -> Result<bool> {
    Ok(BACKFILL.get(store, txn, &())?.unwrap_or(false))
}

/// Marks `row` judged in full, in a write before the migration has judged
/// every row.
///
/// # Errors
///
/// Storage failures.
pub(super) fn mark_visited_in_txn(
    store: &crate::store::Store,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
) -> Result<()> {
    if source_state::judged_all_in(store, txn)? {
        return Ok(());
    }
    VISITED.put(store, txn, row, &JUDGED)
}

/// Marks `row`, an old fact a delete judges for one link before its tear
/// (M3), as one: the edge goes with the tear, and the entry or floor that
/// link gives is no older build's raise.
///
/// # Errors
///
/// Storage failures.
pub(super) fn mark_old_fact_in_txn(
    store: &crate::store::Store,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
) -> Result<()> {
    if VISITED.contains(store, txn, row)? {
        return Ok(());
    }
    VISITED.put(store, txn, row, &OLD_FACT)
}

/// Judges `row` as the migration judges it, in a write that puts or clears
/// its archive marker, before the marker moves, if the migration has not
/// visited it yet (case 62): whether an older build raised an archived row
/// reads the marker ([`visit_in`]), so a restore before the pass reaches
/// the row judges it while it is archived, and an archive judges it while
/// it is live. Once the migration has judged every row it does nothing.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn visit_row_in_txn(vault: &Vault, txn: &mut RwTxn<'_>, row: &EntityId) -> Result<()> {
    if source_state::judged_all_in(&vault.store, txn)?
        || !crate::source_audience::floor::floors_possible_in(vault, txn)?
        || vault.get_raw_in(txn, row)?.is_none()
        || crate::ports::erased_in_txn(&vault.store, txn, row)?
    {
        return Ok(());
    }
    let visit = visit_in(&vault.store, txn, row)?;
    visit_held_row_in_txn(vault, txn, row, visit)
}

/// Judges the held row `row`, which stands at `visit`, as the migration
/// judges it, marks it visited, and folds the rows that waited on it.
fn visit_held_row_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
    visit: Visit,
) -> Result<()> {
    match visit {
        Visit::Visited => return Ok(()),
        Visit::OldFact => {
            source_state::judge_row_in_txn(vault, txn, row, &source_state::Fresh::None, true)?;
        }
        Visit::Raised => source_state::heal_row_in_txn(vault, txn, row)?,
    }
    mark_visited_in_txn(&vault.store, txn, row)?;
    source_state::fold_waiters_in_txn(vault, txn, row)
}

/// Whether `row` still holds an old build's wait (a mark, or its pending
/// row) the migration has not converted: never once it has ended.
///
/// # Errors
///
/// Storage failures.
pub(super) fn has_old_marks_in(
    store: &crate::store::Store,
    txn: &RoTxn<'_>,
    row: &EntityId,
    migrated: bool,
) -> Result<bool> {
    if migrated {
        return Ok(false);
    }
    Ok(PENDING.contains(store, txn, row)?
        || WAITS
            .iter_from(store, txn, row.as_bytes())?
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
    store: &crate::store::Store,
    txn: &RoTxn<'_>,
    row: &EntityId,
    migrated: bool,
) -> Result<OldMarks> {
    let mut marks = OldMarks::default();
    if migrated {
        return Ok(marks);
    }
    for (_, awaited) in WAITS.scan_keys(store, txn, row.as_bytes())? {
        marks
            .entries
            .push((awaited, mark_flags_in(store, txn, row, &awaited)?));
    }
    marks.pending = marks.entries.is_empty() && PENDING.contains(store, txn, row)?;
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
    store: &crate::store::Store,
    txn: &RoTxn<'_>,
    row: &EntityId,
    awaited: &EntityId,
) -> Result<OpenFlags> {
    if awaited != row && crate::ports::erased_in_txn(store, txn, awaited)? {
        return Ok(OpenFlags::before_floors(source_state::delete_level_in(
            store, txn, awaited,
        )?));
    }
    Ok(OpenFlags::ORDINARY)
}

/// One write of the migration from `cursor`: what it did, and where it goes
/// on; `None` once it has ended. A cursor goes on only in the phase that
/// wrote it (case 65): a pass cursor goes on with the pass; any other, an
/// older build's included, starts the migration from M1, and M2 then from
/// the first row. Once every row is judged, it only clears.
///
/// # Errors
///
/// Storage failures.
pub(super) fn step_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    cursor: &[u8],
) -> Result<(u64, Option<Vec<u8>>)> {
    if source_state::judged_all_in(&vault.store, txn)? {
        return Ok((0, (!clear_page_in_txn(vault, txn)?).then(|| vec![CLEARING])));
    }
    match cursor.split_first() {
        Some((&JUDGING, after)) => {
            let (judged, next) = judge_page_in_txn(vault, txn, after)?;
            Ok((
                judged,
                Some(match next {
                    Some(key) => [JUDGING].into_iter().chain(key).collect(),
                    None => {
                        // Every row is judged: none reads unjudged while the
                        // old tables and the visit marks are emptied.
                        source_state::mark_judged_all_in_txn(&vault.store, txn)?;
                        vec![CLEARING]
                    }
                }),
            ))
        }
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
/// its two index rows and its row's pending row, a mark on a support into a
/// support's entry ([`source_state::mark_entry_in`]). Whether marks are
/// left.
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
        if let Some(raw) = vault.get_raw_in(txn, row)? {
            let flags = mark_flags_in(&vault.store, txn, row, awaited)?;
            // A mark names no kind of link: one on a support is a support's
            // entry, and none once a support frees the row (case 72).
            if let Some(flags) = source_state::mark_entry_in(vault, txn, row, &raw, awaited, flags)?
            {
                source_state::open_entry_in_txn(&vault.store, txn, row, awaited, flags)?;
            }
            converted = converted.saturating_add(1);
        }
        AWAITED.delete(&vault.store, txn, &(*awaited, *row))?;
        WAITS.delete(&vault.store, txn, &(*row, *awaited))?;
        PENDING.delete(&vault.store, txn, row)?;
    }
    Ok((converted, marks.len() == MARKS_PAGE))
}

/// One write of M2: judges or heals the held rows after the entity key
/// `after`, live or archived (case 60), each as it stood before the page
/// wrote anything (case 61): a floor this page stores, or a fold into a
/// row, is no older build's raise. Then it folds the rows that waited on
/// each. Where the pass goes on, or `None` once it has read every row.
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
    let mut visits = Vec::with_capacity(rows.len());
    for row in rows {
        if vault.get_raw_in(txn, &row)?.is_none()
            || crate::ports::erased_in_txn(&vault.store, txn, &row)?
        {
            continue;
        }
        visits.push((row, visit_in(&vault.store, txn, &row)?));
    }
    let mut judged = 0_u64;
    for (row, visit) in &visits {
        visit_held_row_in_txn(vault, txn, row, *visit)?;
        if *visit != Visit::Visited {
            judged = judged.saturating_add(1);
        }
    }
    Ok((
        judged,
        match last {
            Some(last) if scanned == JUDGE_PAGE => Some(last),
            _ => None,
        },
    ))
}

/// One write of the clearing: deletes a page of each table of row marks;
/// once all are empty, empties the rest and marks the migration ended.
/// Whether it has ended.
fn clear_page_in_txn(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<bool> {
    let mut more = clear_marks_page_in_txn(&vault.store, txn, &PENDING)?;
    more |= clear_marks_page_in_txn(&vault.store, txn, &RAISED)?;
    more |= clear_marks_page_in_txn(&vault.store, txn, &RAISED_AGAIN)?;
    let visited: Vec<EntityId> = VISITED
        .iter_from(&vault.store, txn, &[])?
        .take(CLEAR_PAGE)
        .map(|entry| entry.map(|(row, _)| row))
        .collect::<Result<_>>()?;
    for row in &visited {
        VISITED.delete(&vault.store, txn, row)?;
    }
    if more || visited.len() == CLEAR_PAGE {
        return Ok(false);
    }
    // M1 took every mark; a mark written since by no build stands nowhere.
    AWAITED.delete_from(&vault.store, txn, &[])?;
    WAITS.delete_from(&vault.store, txn, &[])?;
    BACKFILL.delete_from(&vault.store, txn, &[])?;
    ARCHIVED_RAISED.delete_from(&vault.store, txn, &[])?;
    source_state::mark_migrated_in_txn(&vault.store, txn)?;
    Ok(true)
}

/// Deletes a page of the row marks of `table`: whether a whole page went,
/// so more may be left.
fn clear_marks_page_in_txn(
    store: &crate::store::Store,
    txn: &mut RwTxn<'_>,
    table: &SideTable<EntityId, (), Named>,
) -> Result<bool> {
    let rows: Vec<EntityId> = table
        .iter_from(store, txn, &[])?
        .take(CLEAR_PAGE)
        .map(|entry| entry.map(|(row, ())| row))
        .collect::<Result<_>>()?;
    for row in &rows {
        table.delete(store, txn, row)?;
    }
    Ok(rows.len() == CLEAR_PAGE)
}

/// Forgets, in `txn`, every old table and the visit marks: with the open
/// set gone too, the vault reads as one whose rows were written before
/// floors were.
#[cfg(any(test, feature = "test-support", oneiron_test_support))]
pub(super) fn forget_in_txn(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    PENDING.delete_from(&vault.store, txn, &[])?;
    AWAITED.delete_from(&vault.store, txn, &[])?;
    WAITS.delete_from(&vault.store, txn, &[])?;
    RAISED.delete_from(&vault.store, txn, &[])?;
    BACKFILL.delete_from(&vault.store, txn, &[])?;
    RAISED_AGAIN.delete_from(&vault.store, txn, &[])?;
    ARCHIVED_RAISED.delete_from(&vault.store, txn, &[])?;
    VISITED.delete_from(&vault.store, txn, &[])?;
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
