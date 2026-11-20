//! An erase of a spawn's target over the code-run replay rows (FIX 9180,
//! Engine C2). Each bridge call whose host-resolved seats name an erased id
//! takes its selective erased form ([`erase_spawn_call`]): its ask leaves,
//! it answers `TargetErased`, and the rest of the row stays, its key, order,
//! seq, effects, stamps, frontier and every other call's answer among it.
//!
//! The erase's own pass ([`erase_spawn_targets_in_txn`]) runs in the erase's
//! writer: over every kept step start whose prefix holds a reached call,
//! then over the live rows. Every later write of a row meets the same
//! permanent hard-delete markers in its own writer
//! ([`fence_spawn_targets_in_txn`]), so a copy read before the erase writes
//! its erased form back. A row that does not decode keeps its bytes and is
//! reported; nothing is refused for a target no row proves.

use std::borrow::Cow;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use super::super::replay::CodeRunReplayRecord;
use super::super::spawn_replay::erase_spawn_call;
use super::replay_capsule::erase_spawn_prefixes_in_txn;
use super::replay_rows;
use crate::ports::{DeletionMarker, TombstoneStoreRead};
use crate::side_table::SideKey;
use crate::store::Store;
use crate::{EntityId, Result};

/// The erase of the spawn targets `erased` over the replay rows and the step
/// starts that carry them (FIX 9180), in the erase's own writer: each call
/// whose seats name one of them takes its selective erased form, in every
/// kept step start's prefix and in every live row, and nothing else
/// changes. Erasing an erased call again changes nothing. An id that seats
/// no spawn reaches nothing.
///
/// # Errors
///
/// Storage and custody errors.
pub(crate) fn erase_spawn_targets_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    erased: &BTreeSet<EntityId>,
) -> Result<()> {
    if erased.is_empty() {
        return Ok(());
    }
    let mut reached = Vec::new();
    let mut undecodable = 0_usize;
    for row in replay_rows::iter_canonical_from(store, wtxn, &[])? {
        let (key, bytes) = row?;
        let Some(run) = <EntityId as SideKey>::decode_key(&key) else {
            continue;
        };
        let Ok(mut record) = replay_rows::decode(&bytes) else {
            undecodable += 1;
            continue;
        };
        if !erase_reached_calls(&mut record, erased)?.is_empty() {
            reached.push((run, record));
        }
    }
    if undecodable > 0 {
        tracing::warn!(
            undecodable,
            "replay rows that do not decode keep their bytes; a spawn target erase cannot read their seats"
        );
    }
    // Every kept prefix is read on its own: a live row already in its
    // erased form proves nothing of an older or restored start.
    erase_spawn_prefixes_in_txn(store, wtxn, erased)?;
    for (run, record) in reached {
        replay_rows::put_erased_unchanged(store, wtxn, &run, record)?;
    }
    Ok(())
}

/// Each call of `record` whose seats name one of `erased`, in its selective
/// erased form; the ids of `erased` that seat a call that changed, each one
/// a cause of the change. Empty when no call changed.
///
/// # Errors
///
/// An outcome that does not encode.
pub(super) fn erase_reached_calls(
    record: &mut CodeRunReplayRecord,
    erased: &BTreeSet<EntityId>,
) -> Result<BTreeSet<EntityId>> {
    let mut causes = BTreeSet::new();
    for call in &mut record.bridge_calls {
        if call.spawn_targets.reached_by(erased) && erase_spawn_call(call)? {
            let seats = call.spawn_targets.seats().iter();
            causes.extend(seats.filter(|seat| erased.contains(*seat)).copied());
        }
    }
    Ok(causes)
}

/// `record` as its writer may put it, read in that writer (FIX 9180): each
/// call one of whose seats a permanent hard-delete marker names takes its
/// selective erased form first; any other record goes as given.
///
/// # Errors
///
/// Storage errors reading a marker, and an outcome that does not encode.
pub(super) fn fence_spawn_targets_in_txn<'r>(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    mut record: Cow<'r, CodeRunReplayRecord>,
) -> Result<Cow<'r, CodeRunReplayRecord>> {
    let mut marked = BTreeMap::new();
    for call in &record.bridge_calls {
        for seat in call.spawn_targets.seats() {
            if let Entry::Vacant(entry) = marked.entry(*seat) {
                entry.insert(store.port_deletion_marked(txn, DeletionMarker::HardDelete, seat)?);
            }
        }
    }
    let erased: BTreeSet<EntityId> = marked
        .into_iter()
        .filter_map(|(seat, hard)| hard.then_some(seat))
        .collect();
    if !erased.is_empty() {
        erase_reached_calls(record.to_mut(), &erased)?;
    }
    Ok(record)
}
