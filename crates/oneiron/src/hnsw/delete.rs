//! Node delete with symmetric/legacy backlink scrub.

use heed::RwTxn;

use crate::entity_id::{EntityId, parse_entity_id};
use crate::error::{Error, Result};
use crate::store::ManifestDbs;

use super::discipline::{LinkDiscipline, read_link_discipline};
use super::keys::{
    COUNT_KEY, ENTRY_POINT_KEY, ERR_COUNT_UNDERFLOW, ERR_ENTRY_POINT_MISSING,
    ERR_NEIGHBOR_KEY_BYTES, ERR_REMAINING_NODES_MISSING,
};
use super::one_way::purge_one_way_exceptions_for_target;
use super::storage::{
    collect_backlink_targets, decode_neighbors, read_count, read_entry_point,
    scrub_backlinks_in_place,
};

/// Removes a node from the HNSW graph, scrubbing its ID from surviving
/// neighbor lists and repairing the entry point when needed.
///
/// Search still keeps defensive existence checks because vectors/entities can
/// become partially inconsistent for reasons outside HNSW bookkeeping.
pub(crate) fn hnsw_deindex(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    hnsw_deindex_probed(store, wtxn, id, &mut 0)
}

/// [`hnsw_deindex`] with unit-operation accounting (`ops` increments once
/// per row read/write/delete and once per scanned row on the legacy path),
/// so tests can pin that symmetric-graph deletes never iterate the full
/// `hnsw_neighbors` DB (ONE-325 AC1).
pub(super) fn hnsw_deindex_probed(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    ops: &mut u64,
) -> Result<()> {
    *ops += 1;
    let own_neighbors = match store.hnsw_neighbors().get(&*wtxn, id.as_bytes())? {
        Some(raw) => decode_neighbors(&raw, false)?,
        None => return Ok(()),
    };
    let discipline = read_link_discipline(store, &*wtxn)?;
    let backlink_targets = match discipline {
        // Symmetric invariant: the nodes holding links back to `id` are
        // exactly `id`'s own forward neighbors — no full scan.
        LinkDiscipline::Symmetric => own_neighbors,
        // Pre-migration graphs may hold one-way links into `id` from
        // anywhere; only a full scan finds them all.
        LinkDiscipline::Legacy => collect_backlink_targets(store, &*wtxn, id, ops)?,
    };
    *ops += 1;

    let count = read_count(store, &*wtxn)?;
    *ops += 1;
    let new_count = count
        .checked_sub(1)
        .ok_or(Error::CorruptedIndex(ERR_COUNT_UNDERFLOW))?;
    store.hnsw_neighbors().delete(wtxn, id.as_bytes())?;
    *ops += 1;
    scrub_backlinks_in_place(store, wtxn, id, &backlink_targets, ops)?;
    if discipline == LinkDiscipline::Symmetric {
        // Orphan-protected holders kept a one-way link INTO `id` and are, by
        // definition, absent from `id`'s own forward list — the symmetric
        // backlink set above cannot reach them. Purge them from the tracked
        // exception record so deleting `id` leaves no row pointing at the
        // now-removed node (ONE-325 active-index purge contract).
        purge_one_way_exceptions_for_target(store, wtxn, id, ops)?;
    }

    store
        .hnsw_meta()
        .put(wtxn, COUNT_KEY, &new_count.to_le_bytes())?;

    if new_count == 0 {
        store.hnsw_meta().delete(wtxn, ENTRY_POINT_KEY)?;
        return Ok(());
    }

    let entry_point =
        read_entry_point(store, &*wtxn)?.ok_or(Error::CorruptedIndex(ERR_ENTRY_POINT_MISSING))?;
    if entry_point == *id {
        let (replacement_key, _) = store
            .hnsw_neighbors()
            .first(&*wtxn)?
            .ok_or(Error::CorruptedIndex(ERR_REMAINING_NODES_MISSING))?;
        let replacement =
            parse_entity_id(&replacement_key, ERR_NEIGHBOR_KEY_BYTES).map_err(|e| match e {
                Error::InvalidKey => Error::CorruptedIndex(ERR_NEIGHBOR_KEY_BYTES),
                other => other,
            })?;
        store
            .hnsw_meta()
            .put(wtxn, ENTRY_POINT_KEY, replacement.as_bytes())?;
    }

    Ok(())
}
