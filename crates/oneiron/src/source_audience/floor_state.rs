//! Whether a row's floor is whole yet (READ-LINEAGE L1; #9289 review 2
//! P1-1 and P1-2), what it waits on, and the backfill that raises the
//! floors of the rows a vault held before floors were written.
//!
//! A floor is written from what this vault holds when its row gets words
//! ([`super::floor`]). A birth input, a dependency source or a named word
//! source that has not landed here yet (lineage no read walks), a source row
//! whose binding has not landed, lineage that does not resolve yet, or a
//! source whose own floor waits leaves it **pending**: the row is marked
//! with what it waits on, and the write that lands that row or binding
//! raises it again, so it reads as its sources say once they are here.
//! Absence never seals a row; only proof of erasure does
//! ([`super::seal_births_from_erased_inputs_in_txn`]). The write that
//! erases a row a floor waits on seals that floor
//! ([`seal_rows_awaiting_in_txn`]): what the erased row would have added to
//! it can no longer be known here, so the floor never settles without it
//! (#9289 Opus review 3 P1-A, P1-B). Every delete door runs it, and so does
//! the first application of a peer's tombstone of a row this vault never
//! held; a soft tombstone replayed over a soft scrub already applied here is
//! no new erase and runs it not (#10108 reviews). Until it runs, a row that
//! reads erased (its delete published, a peer tombstone accepted but not
//! applied yet, a released blob) keeps every row marked as
//! waiting on it waiting: the seal, not a sweep that comes first, ends the
//! wait. A row's marks are its wait set as its last raise found it: a raise
//! takes every mark the row no longer waits on, so an erase of what it once
//! waited on never seals a row that settled without it. An archived row is
//! held, as a waiter and as a source: it keeps its wait and its marks, a
//! landing or a seal reaches it, the backfill raises it, a row written from
//! it reads its floor, and a mark on it is followed (#10222 Opus review 3);
//! its restore raises it again, while its archive marker still stands, so a
//! run again of the backfill counts that raise as the first of a row the
//! backfill that skipped archived rows never raised (#10265 review P1-2).
//!
//! A vault that held rows before floors were written holds them with none.
//! The **backfill** (housekeeping's `SourceFloorBackfill` sweep: at each
//! start, a page per write, from a cursor) raises every row once, archived
//! rows too (FLOOR-BACKFILL-SKIPS-ARCHIVED-ROWS), each with the rows it was
//! written from that it has not raised yet first, so a cycle of rows
//! written from each other settles in one write; then it clears its marks.
//! A vault whose backfill ended before it raised archived rows raises every
//! row once more ([`Backfill::RaisingAgain`]), and so does one whose pass a
//! build before this one began or went on with, or began after rows were
//! raised (#10265 Opus review P2-2). Until it first ends, a row it has not
//! raised waits like a pending row when it names a birth input or a
//! dependency source (lineage no read walks), a word source not held here,
//! or lineage that does not resolve yet; and a write raises the not yet
//! raised rows its row was written from first, so a fact born from an old
//! fact holds that fact's floor at once. A row whose birth input was erased
//! before the backfill raised it waits for good
//! (FLOOR-OLD-FACT-ERASED-INPUT = A, the lead 21 Nov 08:3x): no write that
//! raises it again, follows what waits, or lands a binding frees it.
//!
//! What a row waits on can resolve in a write that names no row waiting on
//! it: an epoch's head lands, a source is erased, a dependency or a birth
//! is taken off the row. So each run of the sweep, once the backfill has
//! ended, raises every waiting row again (#9289 review 3 P1-4, P1-6): a
//! row whose wait has resolved reads as its sources say from that run on.
//!
//! A row whose floor waits reads to no one but a live owner of this vault
//! who reads every source it holds ([`waiting_floor_readable_in`]): the
//! owner of a vault whose sources are all the owner's, never the owner of a
//! vault that holds a member's own mailbox (READ-LINEAGE-L3 as the lead
//! reads it, 21 Nov 06:28). It does not travel on a restricted lane, which
//! carries no audience (#9289 review 3 P1-3).

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};

use self::marks::{AWAITED, mark_wait_in_txn, take_mark_in_txn, take_marks_of_in_txn};
use super::floor::{OwnSource, RowSources};
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

mod backfill;
mod marks;

pub(crate) use self::backfill::backfill_floors;
#[cfg(any(test, feature = "test-support", oneiron_test_support))]
pub(crate) use self::backfill::{
    backfill_floors_from_raising_cursor, end_backfill_without_archived_rows_in_txn,
    forget_floor_state_in_txn, mark_backfill_done_in_txn, mark_raised_in_txn, mark_waiting_in_txn,
};

/// Each row whose floor waits.
const PENDING: SideTable<EntityId, (), Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_PENDING);
/// Each row raised since the backfill began.
const RAISED: SideTable<EntityId, (), Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_RAISED);
/// Whether the backfill has raised every row.
const BACKFILL: SideTable<(), bool, Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_BACKFILL);
/// Whether the backfill has raised archived rows too: set when a pass ends
/// that began in this build with no row raised before its first page, and
/// when the run again ends in a vault whose pass did not begin so
/// (FLOOR-BACKFILL-SKIPS-ARCHIVED-ROWS; #10265 Opus review P2-2).
const ARCHIVED_RAISED: SideTable<(), bool, Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_ARCHIVED_RAISED);

/// How far the backfill has gone in a vault.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Backfill {
    /// It raises every row for the first time: a row it has not raised yet
    /// waits ([`floor_waits_in`]), and its next raise is its first.
    Raising,
    /// It raises every row once more, in a vault whose backfill ended before
    /// it raised archived rows, or whose pass did not run whole in a build
    /// that raises them (#10222 Opus review 3; #10265 Opus review P2-2): a
    /// row it has not raised again yet reads as it did, and only an archived
    /// row with no stored floor, which that backfill never raised, has a
    /// first raise.
    RaisingAgain,
    /// It has raised every row, archived rows too.
    Done,
}

/// Rounds one write raises the rows waiting on what it settled, and then
/// the rows waiting on those. Each round takes the marks it follows, so the
/// rounds end by themselves; past this bound the rows left keep waiting
/// (they read to no one but an owner who reads every source).
const SETTLE_ROUNDS: usize = 1024;

/// Whether the backfill has raised every row this vault holds.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn backfill_done_in(vault: &Vault, txn: &RoTxn<'_>) -> Result<bool> {
    Ok(BACKFILL.get(&vault.store, txn, &())?.unwrap_or(false))
}

/// How far the backfill has gone in this vault.
fn backfill_in(vault: &Vault, txn: &RoTxn<'_>) -> Result<Backfill> {
    if !backfill_done_in(vault, txn)? {
        return Ok(Backfill::Raising);
    }
    let archived_raised = ARCHIVED_RAISED.get(&vault.store, txn, &())?;
    Ok(if archived_raised.unwrap_or(false) {
        Backfill::Done
    } else {
        Backfill::RaisingAgain
    })
}

/// Whether the floor of `row` is not known whole here: it waits on a row or
/// binding that has not landed, or the backfill has not raised it yet while
/// it names a birth input or a dependency source (lineage no read walks), a
/// word source not held here, or lineage that does not resolve yet: what
/// the backfill would leave it waiting on (#9289 review 3 P1-2).
///
/// # Errors
///
/// Storage failures.
pub(crate) fn floor_waits_in(vault: &Vault, txn: &RoTxn<'_>, row: &EntityId) -> Result<bool> {
    if PENDING.contains(&vault.store, txn, row)? {
        return Ok(true);
    }
    if backfill_done_in(vault, txn)?
        || RAISED.contains(&vault.store, txn, row)?
        || !super::floor::floors_possible_in(vault, txn)?
    {
        return Ok(false);
    }
    if !crate::store::birth_record::input_rows_in_txn(&vault.store, txn, row)?.is_empty()
        || !crate::ports::dependency_sources_in(&vault.store, txn, row)?.is_empty()
    {
        return Ok(true);
    }
    let Some(raw) = vault.get_raw_in(txn, row)? else {
        return Ok(false);
    };
    if crate::scope_summary::carried_summary(&raw).is_err() {
        return Ok(true);
    }
    match crate::scope_summary::word_sources_in(vault, txn, row, &raw) {
        Ok(crate::scope_summary::WordSources::Own) => Ok(false),
        Ok(crate::scope_summary::WordSources::From(named)) => {
            for source in &named {
                if matches!(presence_in(vault, txn, source)?, Presence::Absent) {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Ok(crate::scope_summary::WordSources::Unresolved)
        | Err(Error::InvalidClaimBody(_) | Error::Record(_)) => Ok(true),
        Err(error) => Err(error),
    }
}

/// Whether every one of `viewers` reads a row whose floor waits
/// ([`floor_waits_in`]): each is a live owner of this vault and reads every
/// source policy it holds, so no source the floor could name hides the row
/// from them. A policy that does not resolve here reads to no one, so a
/// vault holding one reads such a row to no one.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn waiting_floor_readable_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    viewers: &[EntityId],
) -> Result<bool> {
    if viewers.is_empty() {
        return Ok(false);
    }
    for viewer in viewers {
        if !crate::policy_model::is_live_vault_owner_in_txn(vault, txn, viewer)?
            && super::embedded_owner_person_in(vault, txn, *viewer)?.is_none()
        {
            return Ok(false);
        }
    }
    for entry in super::POLICIES.iter_from(&vault.store, txn, &[])? {
        let (policy, _) = entry?;
        let readers = match super::readers_in(vault, txn, &policy)? {
            None => return Ok(false),
            Some(None) => continue,
            Some(Some(readers)) => readers,
        };
        for viewer in viewers {
            if !super::names_reader_in(vault, txn, &readers, *viewer)? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// Raises again, in `txn`, each row whose floor waits on `row`, a row whose
/// binding just landed here.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn binding_landed_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
) -> Result<()> {
    // An erased row lands nothing: what waits on it waits for good
    // (#9289 Opus review 3 P1-B). An archived one is held: its binding
    // raises it, and what waits on it (#10222 Opus review 3 P2-1).
    if erased_in(&vault.store, txn, row)? {
        return Ok(());
    }
    let awaited = AWAITED
        .iter_from(&vault.store, txn, row.as_bytes())?
        .next()
        .is_some();
    if awaited {
        super::floor::raise_floors_in_txn(vault, txn, [*row])?;
    }
    Ok(())
}

/// Raises the floor of each of `rows` in `txn`, and settles whether each is
/// whole; then raises again the rows waiting on each row it settled, and so
/// on, so a row that lands here clears what waited on it in its own write.
/// While the backfill runs, the not yet raised rows each row was written
/// from are raised with it, first.
///
/// # Errors
///
/// Storage failures.
pub(super) fn raise_and_settle_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    rows: BTreeSet<EntityId>,
) -> Result<()> {
    let backfill = backfill_in(vault, txn)?;
    let mut queue = rows;
    for _ in 0..SETTLE_ROUNDS {
        // The rows waiting on a row raised here, and those waiting on them,
        // are raised with it: rows that wait on each other settle together.
        let waiters = take_waiters_in_txn(vault, txn, &queue)?;
        queue.extend(waiters);
        if queue.is_empty() {
            return Ok(());
        }
        let closure = Closure::gather_in(vault, txn, &queue, backfill)?;
        loop {
            let mut grew = false;
            for (row, sources, _) in &closure.order {
                grew |= super::floor::raise_floor_in_txn(vault, txn, row, sources)?;
            }
            if !grew {
                break;
            }
        }
        let settled = closure.settle_in_txn(vault, txn, backfill)?;
        queue = take_waiters_in_txn(vault, txn, &settled)?;
    }
    if !queue.is_empty() {
        tracing::warn!(
            rows = queue.len(),
            "floors left waiting past the settle bound; they read to no one but the owner"
        );
    }
    Ok(())
}

/// What a write meets of a row a floor was written from.
enum Presence {
    /// Held here: its bytes.
    Held(Vec<u8>),
    /// Erased here: its deletion shell or record stands.
    Erased,
    /// Not held here, and not erased: it has not landed yet.
    Absent,
}

fn presence_in(vault: &Vault, txn: &RoTxn<'_>, row: &EntityId) -> Result<Presence> {
    if erased_in(&vault.store, txn, row)? {
        return Ok(Presence::Erased);
    }
    Ok(match vault.get_raw_in(txn, row)? {
        Some(raw) => Presence::Held(raw),
        None => Presence::Absent,
    })
}

/// Whether `row` is erased here: its own delete stands fenced or torn, or
/// its tombstone is recorded. A cleanup archive is no erase: it tears
/// nothing, and a restore brings the row back whole, so an archived row
/// keeps its wait and its marks (#10117 Opus review P1-1).
fn erased_in(store: &crate::store::Store, txn: &RoTxn<'_>, row: &EntityId) -> Result<bool> {
    crate::ports::removed_in_txn(store, txn, row)
}

/// Whether `row` is archived here and not erased ([`erased_in`]).
fn archived_in(store: &crate::store::Store, txn: &RoTxn<'_>, row: &EntityId) -> Result<bool> {
    Ok(
        crate::ports::TombstoneStoreRead::port_deletion_state(store, txn, row)?.archived
            && !erased_in(store, txn, row)?,
    )
}

/// Whether the backfill raises `row`: it is live here, or archived and not
/// erased (FLOOR-BACKFILL-SKIPS-ARCHIVED-ROWS): a row written from an
/// archived row reads its floor, and a restore brings it back with it.
fn raisable_in(vault: &Vault, txn: &RoTxn<'_>, row: &EntityId) -> Result<bool> {
    Ok(
        crate::vault::live_entity_row_in_txn(&vault.store, txn, row)?.is_live()
            || archived_in(&vault.store, txn, row)?,
    )
}

/// Whether this raise of `row` is its first (`first` of
/// [`source_waits_in`]) while the backfill is where `backfill` says: the
/// backfill has not raised it yet; in its run again, only an archived row
/// with no stored floor, which the backfill that skipped archived rows
/// never raised. A row raised once has no first raise again, so the erase
/// of an input its floor already holds never holds it for good. It is read
/// before the write stores any floor ([`Closure::gather_in`]): the floor
/// this raise stores is no floor of an earlier raise (#10265 review P1-1).
fn first_raise_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    row: &EntityId,
    backfill: Backfill,
) -> Result<bool> {
    Ok(match backfill {
        Backfill::Done => false,
        Backfill::Raising => !RAISED.contains(&vault.store, txn, row)?,
        Backfill::RaisingAgain => {
            !RAISED.contains(&vault.store, txn, row)?
                && archived_in(&vault.store, txn, row)?
                && !super::DERIVED.contains(&vault.store, txn, row)?
        }
    })
}

/// Seals, in the write that erases `erased`, the floor of each row that
/// waits on it (#9289 Opus review 3 P1-A, P1-B): what `erased` would have
/// added to that floor can no longer be known here, so the row reads under
/// [`super::floor::sealed_source`], which admits no one, the vault owner
/// included, as a row born from an erased input does (READ-LINEAGE-L3 = A;
/// doctor counts it, and its re-derive heals it). The marks on `erased` are
/// taken; each such row settles sealed at its next raise, and the rows
/// waiting on it inherit the seal; `erased` itself waits no more. A mark of
/// a row that no longer waits is stale and seals nothing. That includes a
/// fact that waits for good on an input erased before the backfill raised
/// it (FLOOR-OLD-FACT-ERASED-INPUT = A): a later erase of that input through
/// an erase door seals it, as the ruling says. It reads the marks, never the
/// lineage the erase tears: each delete door runs it before the record's
/// body and edges go ([`super::seal_floors_awaiting_in_txn`]).
///
/// # Errors
///
/// Storage failures.
pub(super) fn seal_rows_awaiting_in_txn(
    store: &crate::store::Store,
    txn: &mut RwTxn<'_>,
    erased: &EntityId,
) -> Result<()> {
    PENDING.delete(store, txn, erased)?;
    take_marks_of_in_txn(store, txn, erased, &BTreeSet::new())?;
    let sealed = super::floor::sealed_source();
    for (_, row) in AWAITED.scan_keys(store, txn, erased.as_bytes())? {
        take_mark_in_txn(store, txn, erased, &row)?;
        if row == *erased || erased_in(store, txn, &row)? || !PENDING.contains(store, txn, &row)? {
            continue;
        }
        let mut floor = super::DERIVED.get(store, txn, &row)?.unwrap_or_default();
        if floor.insert(sealed) {
            super::DERIVED.put(store, txn, &row, &floor)?;
        }
    }
    Ok(())
}

/// Whether `row`, written from `source`, waits for it: its binding has not
/// landed, or its own floor waits; or, for a source no read walks
/// (`unwalked`: a birth input, a dependency source, a named word source), it
/// has not landed here. A source that reads erased keeps a row marked as
/// waiting on it waiting, until the erase's seal takes the mark
/// ([`seal_rows_awaiting_in_txn`]; #10108 Opus review P1-1): a sweep that
/// comes before the purge must not settle it. A row the backfill raises for
/// the first time (`first`), whose floor never held an erased unwalked
/// source, waits on it, and for good: it still waits when raised again.
/// Otherwise a read walks the source live, and one gone from the vault
/// carries no words to it.
fn source_waits_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    source: &EntityId,
    row: &EntityId,
    unwalked: bool,
    first: bool,
) -> Result<bool> {
    match presence_in(vault, txn, source)? {
        Presence::Absent => Ok(unwalked),
        Presence::Erased => {
            Ok(AWAITED.contains(&vault.store, txn, &(*source, *row))? || (unwalked && first))
        }
        Presence::Held(raw) => Ok(PENDING.contains(&vault.store, txn, source)?
            || super::floor::own_source_in(vault, txn, source, &raw)? == OwnSource::Unbound),
    }
}

/// Whether `source`, a row this write raises, is a row a source landed
/// whose binding has not landed: a row written from it waits for it.
fn unbound_in(vault: &Vault, txn: &RoTxn<'_>, source: &EntityId) -> Result<bool> {
    Ok(match vault.get_raw_in(txn, source)? {
        Some(raw) => super::floor::own_source_in(vault, txn, source, &raw)? == OwnSource::Unbound,
        None => false,
    })
}

/// The rows one write raises together, each after the rows it was written
/// from that it raises too, with whether a source landed it.
struct Closure {
    order: Vec<(EntityId, RowSources, bool)>,
    members: BTreeSet<EntityId>,
    /// The rows of `order` no source landed whose raise here is their first
    /// ([`first_raise_in`]), read before this write stores any floor.
    firsts: BTreeSet<EntityId>,
}

impl Closure {
    /// `roots`, and while the backfill runs (`backfill` is not
    /// [`Backfill::Done`]) every row they were written from, held here, live
    /// or archived, that it has not raised yet, and so on down: each before
    /// the rows written from it. Whether each raise is its first is read
    /// here, before any floor is raised: a floor stored by this write, which
    /// a run again of the backfill reads, must not hide a first raise
    /// (#10265 review P1-1).
    fn gather_in(
        vault: &Vault,
        txn: &RoTxn<'_>,
        roots: &BTreeSet<EntityId>,
        backfill: Backfill,
    ) -> Result<Self> {
        let backfilling = backfill != Backfill::Done;
        let mut order = Vec::new();
        let mut members = BTreeSet::new();
        let mut firsts = BTreeSet::new();
        let mut seen = BTreeSet::new();
        // A row read already sits above the rows it was written from, so
        // they leave the stack, and join the order, first.
        let mut stack: Vec<(EntityId, Option<(RowSources, bool)>)> =
            roots.iter().rev().map(|row| (*row, None)).collect();
        while let Some((row, read)) = stack.pop() {
            if let Some((sources, landed)) = read {
                if !landed && first_raise_in(vault, txn, &row, backfill)? {
                    firsts.insert(row);
                }
                members.insert(row);
                order.push((row, sources, landed));
                continue;
            }
            if !seen.insert(row) {
                continue;
            }
            // An erased row's shell carries no words and takes no floor; a
            // row written from it reads its erasure as a source
            // (`source_waits_in`; #9289 Opus review 3 P1-B).
            if erased_in(&vault.store, txn, &row)? {
                continue;
            }
            let Some(raw) = vault.get_raw_in(txn, &row)? else {
                continue;
            };
            let sources = super::floor::row_sources_in(vault, txn, &row, &raw)?;
            let mut below = Vec::new();
            if backfilling {
                for source in sources.written_from.iter().chain(&sources.attested_by) {
                    if !seen.contains(source)
                        && !RAISED.contains(&vault.store, txn, source)?
                        && raisable_in(vault, txn, source)?
                    {
                        below.push(*source);
                    }
                }
            }
            let landed = super::obligation::row_obligation(&raw).is_present();
            stack.push((row, Some((sources, landed))));
            stack.extend(below.into_iter().map(|source| (source, None)));
        }
        Ok(Self {
            order,
            members,
            firsts,
        })
    }

    /// Whether a support outside this write frees the row whose sources are
    /// `sources`: a held, whole support with an empty floor.
    fn freed_in(&self, vault: &Vault, txn: &RoTxn<'_>, sources: &RowSources) -> Result<bool> {
        for support in &sources.attested_by {
            if self.members.contains(support) || PENDING.contains(&vault.store, txn, support)? {
                continue;
            }
            if let Presence::Held(raw) = presence_in(vault, txn, support)?
                && super::floor::own_source_in(vault, txn, support, &raw)? != OwnSource::Unbound
                && super::floor::floor_in(vault, txn, support, &raw)?.is_empty()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Marks each row whose floor waits, with what it waits on, and clears
    /// the mark of each row whose floor is whole; a row written from a row
    /// of this write whose floor waits waits on it too. A row a source
    /// landed never waits: its own binding decides its read. A row whose
    /// raise is its first (`firsts`) waits for good on an erased
    /// unwalked source. While the backfill runs (`backfill`), marks every row
    /// raised. The rows whose floor is whole.
    fn settle_in_txn(
        &self,
        vault: &Vault,
        txn: &mut RwTxn<'_>,
        backfill: Backfill,
    ) -> Result<BTreeSet<EntityId>> {
        let mut awaited: BTreeMap<EntityId, BTreeSet<EntityId>> = BTreeMap::new();
        let mut bound: BTreeMap<EntityId, Vec<EntityId>> = BTreeMap::new();
        for (row, sources, landed) in &self.order {
            if *landed {
                continue;
            }
            let first = self.firsts.contains(row);
            let mut waits = BTreeSet::new();
            if sources.unresolved {
                waits.insert(*row);
            }
            for source in &sources.unheld {
                if source_waits_in(vault, txn, source, row, true, first)? {
                    waits.insert(*source);
                }
            }
            let freed = self.freed_in(vault, txn, sources)?;
            let binding: Vec<EntityId> = sources
                .written_from
                .iter()
                .chain(sources.attested_by.iter().filter(|_| !freed))
                .filter(|source| *source != row)
                .copied()
                .collect();
            for source in &binding {
                // Whether a row of this write waits is settled below; its
                // binding is read here.
                let waits_on = if self.members.contains(source) {
                    unbound_in(vault, txn, source)?
                } else {
                    source_waits_in(
                        vault,
                        txn,
                        source,
                        row,
                        sources.unwalked.contains(source),
                        first,
                    )?
                };
                if waits_on {
                    waits.insert(*source);
                }
            }
            awaited.insert(*row, waits);
            bound.insert(*row, binding);
        }
        let mut pending: BTreeSet<EntityId> = awaited
            .iter()
            .filter(|(_, waits)| !waits.is_empty())
            .map(|(row, _)| *row)
            .collect();
        loop {
            let mut grew = false;
            for (row, binding) in &bound {
                for source in binding {
                    if self.members.contains(source) && pending.contains(source) {
                        awaited.entry(*row).or_default().insert(*source);
                        grew |= pending.insert(*row);
                    }
                }
            }
            if !grew {
                break;
            }
        }
        let mut settled = BTreeSet::new();
        let none = BTreeSet::new();
        for (row, sources, _) in &self.order {
            let waits = awaited.get(row).unwrap_or(&none);
            // A mark of what this row no longer waits on goes, so an erase of
            // that row never seals this one (#10108 review P1). A mark written
            // before marks were kept by row is found from the row's sources.
            take_marks_of_in_txn(&vault.store, txn, row, waits)?;
            for source in std::iter::once(row)
                .chain(&sources.unheld)
                .chain(&sources.written_from)
                .chain(&sources.attested_by)
            {
                if !waits.contains(source)
                    && AWAITED.contains(&vault.store, txn, &(*source, *row))?
                {
                    take_mark_in_txn(&vault.store, txn, source, row)?;
                }
            }
            if waits.is_empty() {
                PENDING.delete(&vault.store, txn, row)?;
                settled.insert(*row);
            } else {
                PENDING.put(&vault.store, txn, row, &())?;
                for awaited in waits {
                    mark_wait_in_txn(&vault.store, txn, awaited, row)?;
                }
            }
            if backfill != Backfill::Done {
                RAISED.put(&vault.store, txn, row, &())?;
            }
        }
        Ok(settled)
    }
}

/// The rows waiting on each of `settled`, and those waiting on them, and so
/// on: each mark followed is taken, and a row still waiting once raised
/// again marks what it waits on afresh. An erased row lands nothing, so the
/// marks on it stay (a row waits on it for good); a mark that leads to an
/// erased row is dropped, never followed (#9289 Opus review 3 P1-B). An
/// archived row is held: the marks on it are followed, so a row waiting on
/// it settles when its floor does, and a mark that leads to it is followed,
/// so it keeps its wait (#10222 Opus review 3 P2-1).
fn take_waiters_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    settled: &BTreeSet<EntityId>,
) -> Result<BTreeSet<EntityId>> {
    let mut waiters = BTreeSet::new();
    let mut seen = settled.clone();
    let mut frontier: Vec<EntityId> = settled.iter().copied().collect();
    while let Some(awaited) = frontier.pop() {
        if erased_in(&vault.store, txn, &awaited)? {
            continue;
        }
        for (_, row) in AWAITED.scan_keys(&vault.store, txn, awaited.as_bytes())? {
            take_mark_in_txn(&vault.store, txn, &awaited, &row)?;
            if erased_in(&vault.store, txn, &row)? {
                continue;
            }
            if seen.insert(row) {
                waiters.insert(row);
                frontier.push(row);
            }
        }
    }
    Ok(waiters)
}
