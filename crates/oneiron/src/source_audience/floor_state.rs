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
//! ([`super::seal_births_from_erased_inputs_in_txn`]).
//!
//! A vault that held rows before floors were written holds them with none.
//! The **backfill** (housekeeping's `SourceFloorBackfill` sweep: at each
//! start, a page per write, from a cursor) raises every row once, each with
//! the rows it was written from that it has not raised yet first, so a
//! cycle of rows written from each other settles in one write; then it
//! clears its marks. Until it ends, a row it has not raised that names a
//! birth input or a dependency source (lineage no read walks) waits like a
//! pending row, and a write raises the not yet raised rows its row was
//! written from first, so a fact born from an old fact holds that fact's
//! floor at once.
//!
//! A row whose floor waits reads to no one but a live owner of this vault
//! who reads every source it holds ([`waiting_floor_readable_in`]): the
//! owner of a vault whose sources are all the owner's, never the owner of a
//! vault that holds a member's own mailbox (READ-LINEAGE-L3 as the lead
//! reads it, 21 Nov 06:28).

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;

use heed::{RoTxn, RwTxn};

use super::floor::{OwnSource, RowSources};
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

/// Each row whose floor waits.
const PENDING: SideTable<EntityId, (), Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_PENDING);
/// What each row whose floor waits waits on: the awaited id, then the row.
const AWAITED: SideTable<(EntityId, EntityId), (), Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_AWAITED);
/// Each row raised since the backfill began.
const RAISED: SideTable<EntityId, (), Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_RAISED);
/// Whether the backfill has raised every row.
const BACKFILL: SideTable<(), bool, Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_BACKFILL);

/// Rounds one write raises the rows waiting on what it settled, and then
/// the rows waiting on those. Each round takes the marks it follows, so the
/// rounds end by themselves; past this bound the rows left keep waiting
/// (they read to no one but an owner who reads every source).
const SETTLE_ROUNDS: usize = 1024;

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

/// Whether the backfill has raised every row this vault holds.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn backfill_done_in(vault: &Vault, txn: &RoTxn<'_>) -> Result<bool> {
    Ok(BACKFILL.get(&vault.store, txn, &())?.unwrap_or(false))
}

/// Whether the floor of `row` is not known whole here: it waits on a row or
/// binding that has not landed, or the backfill has not raised it yet while
/// it names a birth input or a dependency source, lineage no read walks.
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
    Ok(
        !crate::store::birth_record::input_rows_in_txn(&vault.store, txn, row)?.is_empty()
            || !crate::ports::dependency_sources_in(&vault.store, txn, row)?.is_empty(),
    )
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
    let backfilling = !backfill_done_in(vault, txn)?;
    let mut queue = rows;
    for _ in 0..SETTLE_ROUNDS {
        // The rows waiting on a row raised here, and those waiting on them,
        // are raised with it: rows that wait on each other settle together.
        let waiters = take_waiters_in_txn(vault, txn, &queue)?;
        queue.extend(waiters);
        if queue.is_empty() {
            return Ok(());
        }
        let closure = Closure::gather_in(vault, txn, &queue, backfilling)?;
        loop {
            let mut grew = false;
            for (row, sources, _) in &closure.order {
                grew |= super::floor::raise_floor_in_txn(vault, txn, row, sources)?;
            }
            if !grew {
                break;
            }
        }
        let settled = closure.settle_in_txn(vault, txn, backfilling)?;
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
    if crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, txn, row)?.deleted {
        return Ok(Presence::Erased);
    }
    Ok(match vault.get_raw_in(txn, row)? {
        Some(raw) => Presence::Held(raw),
        None => Presence::Absent,
    })
}

/// Whether `row`, written from `source`, waits for it: its binding has not
/// landed, or its own floor waits; or, for a source no read walks
/// (`unwalked`: a birth input, a dependency source, a named word source), it
/// has not landed here. An erased source takes its floor with it, so only a
/// row the backfill raises for the first time (`first`), whose floor never
/// held it, waits on it, and for good: it still waits when raised again. A
/// read walks every other source live, and one gone from the vault carries
/// no words to it.
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
            Ok(unwalked && (first || AWAITED.contains(&vault.store, txn, &(*source, *row))?))
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
}

impl Closure {
    /// `roots`, and while the backfill runs (`backfilling`) every row they
    /// were written from, held and live here, that it has not raised yet,
    /// and so on down: each before the rows written from it.
    fn gather_in(
        vault: &Vault,
        txn: &RoTxn<'_>,
        roots: &BTreeSet<EntityId>,
        backfilling: bool,
    ) -> Result<Self> {
        let mut order = Vec::new();
        let mut members = BTreeSet::new();
        let mut seen = BTreeSet::new();
        // A row read already sits above the rows it was written from, so
        // they leave the stack, and join the order, first.
        let mut stack: Vec<(EntityId, Option<(RowSources, bool)>)> =
            roots.iter().rev().map(|row| (*row, None)).collect();
        while let Some((row, read)) = stack.pop() {
            if let Some((sources, landed)) = read {
                members.insert(row);
                order.push((row, sources, landed));
                continue;
            }
            if !seen.insert(row) {
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
                        && crate::vault::live_entity_row_in_txn(&vault.store, txn, source)?
                            .is_live()
                    {
                        below.push(*source);
                    }
                }
            }
            let landed = super::obligation::row_obligation(&raw).is_present();
            stack.push((row, Some((sources, landed))));
            stack.extend(below.into_iter().map(|source| (source, None)));
        }
        Ok(Self { order, members })
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
    /// landed never waits: its own binding decides its read. While the
    /// backfill runs, marks every row raised. The rows whose floor is whole.
    fn settle_in_txn(
        &self,
        vault: &Vault,
        txn: &mut RwTxn<'_>,
        backfilling: bool,
    ) -> Result<BTreeSet<EntityId>> {
        let mut awaited: BTreeMap<EntityId, BTreeSet<EntityId>> = BTreeMap::new();
        let mut bound: BTreeMap<EntityId, Vec<EntityId>> = BTreeMap::new();
        for (row, sources, landed) in &self.order {
            if *landed {
                continue;
            }
            let first = backfilling && !RAISED.contains(&vault.store, txn, row)?;
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
        for (row, _, _) in &self.order {
            match awaited.get(row) {
                Some(waits) if !waits.is_empty() => {
                    PENDING.put(&vault.store, txn, row, &())?;
                    for awaited in waits {
                        AWAITED.put(&vault.store, txn, &(*awaited, *row), &())?;
                    }
                }
                _ => {
                    PENDING.delete(&vault.store, txn, row)?;
                    settled.insert(*row);
                }
            }
            if backfilling {
                RAISED.put(&vault.store, txn, row, &())?;
            }
        }
        Ok(settled)
    }
}

/// The rows waiting on each of `settled`, and those waiting on them, and so
/// on: each mark followed is taken, and a row still waiting once raised
/// again marks what it waits on afresh.
fn take_waiters_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    settled: &BTreeSet<EntityId>,
) -> Result<BTreeSet<EntityId>> {
    let mut waiters = BTreeSet::new();
    let mut seen = settled.clone();
    let mut frontier: Vec<EntityId> = settled.iter().copied().collect();
    while let Some(awaited) = frontier.pop() {
        for key in AWAITED.scan_keys(&vault.store, txn, awaited.as_bytes())? {
            AWAITED.delete(&vault.store, txn, &key)?;
            let (_, row) = key;
            if seen.insert(row) {
                waiters.insert(row);
                frontier.push(row);
            }
        }
    }
    Ok(waiters)
}

/// One run of the floor backfill (#9289 review 2 P1-2), housekeeping's
/// `SourceFloorBackfill` sweep: from `cursor`, where an unfinished run
/// stopped, it raises the floor of each live entity row in key order, a page
/// per write, each with the not yet raised rows it was written from, and
/// stops between pages once `stop` says so. Once every row is raised it
/// marks the backfill done, then clears the raised marks. In a vault where
/// no row can have a floor yet it does nothing, and runs at the next pass
/// again. The rows it raised, and where an unfinished run goes on (`None`
/// once this run has ended).
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

/// One backfill write: raises the live entity rows after the key `after`.
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
    if !super::floor::floors_possible_in(vault, txn)? {
        return Ok((0, None));
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
        if let Ok(bytes) = <[u8; 16]>::try_from(key)
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
        if RAISED.contains(&vault.store, txn, row)?
            || !crate::vault::live_entity_row_in_txn(&vault.store, txn, row)?.is_live()
        {
            continue;
        }
        super::floor::raise_floors_in_txn(vault, txn, [*row])?;
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
            Ok((raised, Some(vec![CLEARING])))
        }
    }
}

/// One backfill write once every row is raised: clears raised marks.
fn clear_page_in_txn(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<(u64, Option<Vec<u8>>)> {
    let keys = RAISED
        .iter_from(&vault.store, txn, &[])?
        .take(CLEAR_PAGE)
        .map(|entry| entry.map(|(row, ())| row))
        .collect::<Result<Vec<_>>>()?;
    for row in &keys {
        RAISED.delete(&vault.store, txn, row)?;
    }
    Ok((0, (keys.len() == CLEAR_PAGE).then(|| vec![CLEARING])))
}

/// Forgets, in `txn`, every floor's state and the backfill's: the vault
/// reads as one whose rows were written before floors were.
#[cfg(any(test, feature = "test-support", oneiron_test_support))]
pub(crate) fn forget_floor_state_in_txn(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    PENDING.delete_from(&vault.store, txn, &[])?;
    AWAITED.delete_from(&vault.store, txn, &[])?;
    RAISED.delete_from(&vault.store, txn, &[])?;
    BACKFILL.delete_from(&vault.store, txn, &[])?;
    Ok(())
}
