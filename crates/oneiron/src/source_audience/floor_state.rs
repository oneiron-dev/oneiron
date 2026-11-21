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
//! applied yet) keeps every row marked as waiting on it waiting: the seal,
//! not a sweep that comes first, ends the wait. An archive and a blob's
//! release fence erase nothing for the floor (#10117 Opus review P1): they
//! tear nothing and lift again, so an archived row keeps its wait and its
//! marks, is raised and sealed as a live one is, and its restore raises it. A row's marks are its wait set as its last raise found it: a raise
//! takes every mark the row no longer waits on, so an erase of what it once
//! waited on never seals a row that settled without it.
//!
//! A vault that held rows before floors were written holds them with none.
//! The **backfill** (housekeeping's `SourceFloorBackfill` sweep: at each
//! start, a page per write, from a cursor) raises every row once, each with
//! the rows it was written from that it has not raised yet first, so a
//! cycle of rows written from each other settles in one write; then it
//! clears its marks. Until it ends, a row it has not raised waits like a
//! pending row when it names a birth input or a dependency source (lineage
//! no read walks), a word source not held here, or lineage that does not
//! resolve yet; and a write raises the not yet raised rows its row was
//! written from first, so a fact born from an old fact holds that fact's
//! floor at once. A row whose birth input was erased before the backfill
//! raised it waits for good (FLOOR-OLD-FACT-ERASED-INPUT = A, the lead 21
//! Nov 08:3x): no write that raises it again, follows what waits, or lands
//! a binding frees it.
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

use self::marks::{AWAITED, WAITS, mark_wait_in_txn, take_mark_in_txn, take_marks_of_in_txn};
use super::floor::{OwnSource, RowSources};
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

mod backfill;
mod marks;

pub(crate) use backfill::backfill_floors;

/// Each row whose floor waits.
const PENDING: SideTable<EntityId, (), Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_PENDING);
/// Each row raised since the backfill began.
const RAISED: SideTable<EntityId, (), Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_RAISED);
/// Whether the backfill has raised every row.
const BACKFILL: SideTable<(), bool, Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_BACKFILL);
/// Whether the floor repair has raised again every held row whose lineage
/// no read walks (#10117 Opus review P1).
const REPAIR: SideTable<(), bool, Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_REPAIR);

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
    // (#9289 Opus review 3 P1-B).
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
    if erased_in(&vault.store, txn, row)? {
        return Ok(Presence::Erased);
    }
    Ok(match vault.get_raw_in(txn, row)? {
        Some(raw) => Presence::Held(raw),
        None => Presence::Absent,
    })
}

/// Whether `row` is erased here for the floor: its delete fence or marker,
/// a tombstone or a pending local delete stands (`ports::removed_in_txn`).
/// A cleanup archive is no erase: it tears nothing, and a restore brings the
/// row back whole (#10117 Opus review P1). Nor is a blob's release fence,
/// which lifts when the same bytes come back.
pub(super) fn erased_in(
    store: &crate::store::Store,
    txn: &RoTxn<'_>,
    row: &EntityId,
) -> Result<bool> {
    if !crate::ports::removed_in_txn(store, txn, row)? {
        return Ok(false);
    }
    #[cfg(feature = "sync")]
    if crate::blob_artifact::release_fenced_only(store, txn, row)? {
        return Ok(false);
    }
    Ok(true)
}

/// Whether `row` is held here and not erased ([`erased_in`]): a live row, or
/// an archived one, whose floor a write raises.
fn floor_holds_in(vault: &Vault, txn: &RoTxn<'_>, row: &EntityId) -> Result<bool> {
    Ok(vault.get_raw_in(txn, row)?.is_some() && !erased_in(&vault.store, txn, row)?)
}

/// Whether the delete of `row` stands fenced here but has not torn it yet:
/// its `df:` fence stands, no `dt:` marker, and its body is not scrubbed (a
/// published delete before its purge, or a peer tombstone that failed to
/// apply and waits for its retry). The purge or the scrub that ends it seals
/// what waits on `row`.
fn delete_unpurged_in(
    store: &crate::store::Store,
    txn: &RoTxn<'_>,
    row: &EntityId,
) -> Result<bool> {
    use crate::ports::{DeletionMarker, EntityStoreRead, TombstoneStoreRead};
    Ok(
        store.port_deletion_marked(txn, DeletionMarker::RowFence, row)?
            && !store.port_deletion_marked(txn, DeletionMarker::HardDelete, row)?
            && store
                .port_entity_raw(txn, row)?
                .is_some_and(|raw| raw.len() > crate::batch::ENTITY_METADATA_HEADER_LEN),
    )
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
/// source, waits on it, and for good: it still waits when raised again. It
/// also waits on a source whose delete stands fenced but not purged
/// ([`delete_unpurged_in`]), so a floor state lost inside that window (a
/// checkpoint restore) is marked again and the purge seals it (#10117 Opus
/// review P2-4); a later raise of a row that settled holding that source's
/// floor does not wait on it. Otherwise a read walks the source live, and
/// one gone from the vault carries no words to it.
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
        Presence::Erased => Ok(AWAITED.contains(&vault.store, txn, &(*source, *row))?
            || (first && (unwalked || delete_unpurged_in(&vault.store, txn, source)?))),
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
            // An erased row's shell carries no words and takes no floor; a
            // row written from it reads its erasure as a source
            // (`source_waits_in`; #9289 Opus review 3 P1-B). An archived row
            // is raised as a live one is.
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
                        && floor_holds_in(vault, txn, source)?
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
            if backfilling {
                RAISED.put(&vault.store, txn, row, &())?;
            }
        }
        Ok(settled)
    }
}

/// The rows waiting on each of `settled`, and those waiting on them, and so
/// on: each mark followed is taken, and a row still waiting once raised
/// again marks what it waits on afresh. An erased row lands nothing, so the
/// marks on it stay (a row waits on it for good), and a mark that leads to
/// an erased row is dropped, never followed (#9289 Opus review 3 P1-B). An
/// archived row is no erased one: it is raised (#10117 Opus review P1).
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

/// Puts `row`, in `txn`, in the state an archive left a waiting row in
/// before an archive stopped counting as an erase for the floor (#10117 Opus
/// review P1): its wait and its marks dropped, as the sweep dropped them,
/// and the floor repair not run yet.
#[cfg(any(test, feature = "test-support", oneiron_test_support))]
pub(crate) fn forget_floor_wait_before_repair_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
) -> Result<()> {
    PENDING.delete(&vault.store, txn, row)?;
    take_marks_of_in_txn(&vault.store, txn, row, &BTreeSet::new())?;
    REPAIR.delete(&vault.store, txn, &())?;
    Ok(())
}

/// Forgets, in `txn`, every floor's state and the backfill's: the vault
/// reads as one whose rows were written before floors were.
#[cfg(any(test, feature = "test-support", oneiron_test_support))]
pub(crate) fn forget_floor_state_in_txn(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    PENDING.delete_from(&vault.store, txn, &[])?;
    AWAITED.delete_from(&vault.store, txn, &[])?;
    WAITS.delete_from(&vault.store, txn, &[])?;
    RAISED.delete_from(&vault.store, txn, &[])?;
    BACKFILL.delete_from(&vault.store, txn, &[])?;
    REPAIR.delete_from(&vault.store, txn, &[])?;
    Ok(())
}
