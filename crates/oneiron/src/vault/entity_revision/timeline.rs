//! The vault's memory timeline (L3-39): one row per move of any row's live
//! revision, numbered in store order, so a memory frontier (a position in
//! that order) names the revision each row held there.
//!
//! The revision ledger keeps every revision until an erase, a redaction or an
//! owner compaction; what it lacked was an order. `put_state` is the one seam
//! every live move passes, so it records each move here, in the transaction
//! that makes it. A move that leaves the live revision where the timeline
//! last saw it (an idle publication, which moves `indexed` only; a document
//! made for a row that had none) writes nothing. A frontier is read from a
//! committed head only, so no reader can name a point between two moves of
//! one transaction.
//!
//! A room is off the record: its moves stay out of the vault's timeline, and
//! its promotion replays them into base, which records them there.
//!
//! An erase drops the row's timeline with its revisions. The head counts
//! moves and names no row, so it stays. A redaction rewrites the revisions it
//! replaces in place, so a frontier keeps naming the row's words as redacted.

use std::ops::Bound;

use heed::{RoTxn, RwTxn};

use super::{MemoryFrontier, RevisionRef};
use crate::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::store::ManifestDbs;

pub(super) const TIMELINE: SideTable<(EntityId, u64), [u8; 16], Raw> =
    SideTable::new(&side_table::ENTITY_REVISION_TIMELINE);
const HEAD: SideTable<(), u64, Raw> = SideTable::new(&side_table::ENTITY_REVISION_TIMELINE_HEAD);

/// Records that `id`'s live revision is now `live`, unless the timeline's
/// newest row for `id` already names it. Base only: a room records nothing.
///
/// # Errors
///
/// Storage errors, and a head at `u64::MAX`.
pub(super) fn record_live_revision_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    live: RevisionRef,
) -> Result<()> {
    if store.is_union() || latest_in_txn(store, txn, id)? == Some(live) {
        return Ok(());
    }
    let sequence = head_in_txn(store, txn)?
        .checked_add(1)
        .ok_or(Error::CorruptedIndex("memory timeline sequence"))?;
    TIMELINE.put(store, txn, &(*id, sequence), &live.0)?;
    HEAD.put(store, txn, &(), &sequence)
}

fn head_in_txn(store: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<u64> {
    Ok(HEAD.get(store, txn, &())?.unwrap_or(0))
}

fn latest_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<RevisionRef>> {
    TIMELINE
        .iter_rev_from(store, txn, id.as_bytes())?
        .next()
        .transpose()
        .map(|row| row.map(|(_, revision)| RevisionRef(revision)))
}

/// The frontier `txn`'s committed head stands at, stamped with the
/// recording-clock instant `recorded_at` its caller hands it out at.
///
/// # Errors
///
/// Storage errors, and a head row that is not eight bytes.
#[cfg_attr(
    not(oneiron_test_support),
    allow(dead_code, reason = "the graph-FS memory fork (L3-39 PR 2) reads it")
)]
pub(crate) fn memory_frontier_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    recorded_at: u64,
) -> Result<MemoryFrontier> {
    Ok(MemoryFrontier {
        sequence: head_in_txn(store, txn)?,
        recorded_at,
    })
}

/// The revision `id` held live at `frontier`: its newest move at or before
/// the frontier's sequence. `None` when its first move came later, or when
/// the timeline holds none of it (an erased row).
///
/// # Errors
///
/// Storage errors, and a timeline row that is not sixteen bytes.
#[cfg_attr(
    not(oneiron_test_support),
    allow(dead_code, reason = "the graph-FS memory fork (L3-39 PR 2) reads it")
)]
pub(crate) fn revision_at_frontier_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    frontier: MemoryFrontier,
) -> Result<Option<RevisionRef>> {
    let first = (*id, 0);
    let last = (*id, frontier.sequence);
    TIMELINE
        .iter_rev_range(store, txn, Bound::Included(&first), Bound::Included(&last))?
        .next()
        .transpose()
        .map(|row| row.map(|(_, revision)| RevisionRef(revision)))
}

/// Rewrites each of `id`'s timeline rows whose revision `replaced` maps to
/// another: a redaction replaced that revision with its redacted one.
///
/// # Errors
///
/// Storage errors, and a timeline row that is not sixteen bytes.
pub(super) fn replace_revisions_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    replaced: impl Fn(RevisionRef) -> Option<RevisionRef>,
) -> Result<()> {
    for (key, revision) in TIMELINE.scan_from(store, txn, id.as_bytes())? {
        if let Some(next) = replaced(RevisionRef(revision))
            && next.0 != revision
        {
            TIMELINE.put(store, txn, &key, &next.0)?;
        }
    }
    Ok(())
}

/// Drops `id`'s timeline, with its revisions (an erase).
///
/// # Errors
///
/// Storage errors.
pub(super) fn remove_timeline_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    TIMELINE.delete_from(store, txn, id.as_bytes())?;
    Ok(())
}
