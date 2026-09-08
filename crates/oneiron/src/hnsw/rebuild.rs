//! Snapshot graph build, persist, and SLIM rehydrate.

use std::collections::HashMap;

use heed::{RoTxn, RwTxn};

use crate::config::VaultConfig;
use crate::entity_id::{EntityId, parse_entity_id};
use crate::error::{Error, Result};
use crate::store::{ManifestDbs, Store};

use super::discipline::{
    LinkDiscipline, increment_legacy_snapshot_rebuilds, mark_symmetric_links, read_link_discipline,
};
use super::entry_point::select_best_entry_point;
use super::keys::{
    COUNT_KEY, DROPPED_REBUILDABLE_KEY, ENTRY_POINT_KEY, ERR_COUNT_OVERFLOW, ERR_VECTOR_KEY_BYTES,
    SYMMETRIC_LINKS_KEY,
};
use super::one_way::{clear_one_way_exceptions, rebuild_one_way_exception_index};
use super::search::{beam_search_snapshot, score_dims_for};
use super::storage::{detach_reverse_link_in_memory, prune_neighbors_for_node, write_neighbors};
use super::types::RebuiltHnswGraph;

pub(crate) fn build_hnsw_graph_from_snapshot(
    store: &impl ManifestDbs,
    config: &VaultConfig,
    rtxn: &RoTxn<'_>,
    vector_ids: &[EntityId],
    discipline: LinkDiscipline,
) -> Result<RebuiltHnswGraph> {
    let mut neighbors_by_id = HashMap::<EntityId, Vec<EntityId>>::with_capacity(vector_ids.len());
    let mut entry_point = None;
    let mut count = 0_u64;

    for id in vector_ids {
        if count == 0 {
            entry_point = Some(*id);
            neighbors_by_id.insert(*id, Vec::new());
            count = 1;
            continue;
        }

        let graph_entry_point = entry_point.ok_or(Error::InvariantViolation(
            "rebuild entry point missing while validated vector set is non-empty",
        ))?;
        let mut nearest = beam_search_snapshot(
            store,
            rtxn,
            &neighbors_by_id,
            id,
            graph_entry_point,
            config.hnsw.ef_construction,
            score_dims_for(config),
            config.dimensions,
        )?;

        nearest.retain(|entry| entry.id != *id);
        nearest.truncate(config.hnsw.m_max_0);

        let selected: Vec<EntityId> = nearest.into_iter().map(|entry| entry.id).collect();
        neighbors_by_id.insert(*id, selected.clone());

        for neighbor_id in &selected {
            let mut neighbor_neighbors = neighbors_by_id.remove(neighbor_id).unwrap_or_default();
            if !neighbor_neighbors.contains(id) {
                neighbor_neighbors.push(*id);
            }

            if neighbor_neighbors.len() > config.hnsw.m_max_0 {
                let pruned = prune_neighbors_for_node(
                    store,
                    rtxn,
                    neighbor_id,
                    &neighbor_neighbors,
                    config.hnsw.m_max_0,
                    score_dims_for(config),
                    config.dimensions,
                    &mut 0,
                )?;
                if discipline == LinkDiscipline::Symmetric {
                    for victim in neighbor_neighbors
                        .iter()
                        .filter(|candidate| !pruned.contains(candidate))
                    {
                        detach_reverse_link_in_memory(&mut neighbors_by_id, neighbor_id, victim);
                    }
                }
                neighbor_neighbors = pruned;
            }

            neighbors_by_id.insert(*neighbor_id, neighbor_neighbors);
        }

        count = count
            .checked_add(1)
            .ok_or(Error::IndexOverflow(ERR_COUNT_OVERFLOW))?;
    }

    entry_point = select_best_entry_point(&neighbors_by_id, entry_point);

    let neighbors = vector_ids
        .iter()
        .map(|id| (*id, neighbors_by_id.remove(id).unwrap_or_default()))
        .collect();

    Ok(RebuiltHnswGraph {
        entry_point,
        count,
        neighbors,
    })
}

pub(crate) fn write_rebuilt_hnsw(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    rebuilt: &RebuiltHnswGraph,
    discipline: LinkDiscipline,
) -> Result<()> {
    store.hnsw_neighbors().clear(wtxn)?;
    // Rebuild owns only the live graph shape. Preserve unrelated metadata such as
    // graph/version markers, persisted model ids, and schema/config keys.
    store.hnsw_meta().delete(wtxn, COUNT_KEY)?;
    store.hnsw_meta().delete(wtxn, ENTRY_POINT_KEY)?;
    // The old one-way exception records describe the replaced graph; drop them
    // (only the `ow1:` keyspace, never unrelated metadata) and re-derive them
    // from the rebuilt rows for symmetric graphs below.
    clear_one_way_exceptions(store, wtxn)?;

    if let Some(entry_point) = rebuilt.entry_point {
        store
            .hnsw_meta()
            .put(wtxn, ENTRY_POINT_KEY, entry_point.as_bytes())?;
    }
    store
        .hnsw_meta()
        .put(wtxn, COUNT_KEY, &rebuilt.count.to_le_bytes())?;

    for (id, neighbors) in &rebuilt.neighbors {
        write_neighbors(store, wtxn, id, neighbors)?;
    }

    if discipline == LinkDiscipline::Symmetric {
        rebuild_one_way_exception_index(store, wtxn, &rebuilt.neighbors)?;
        mark_symmetric_links(store, wtxn)?;
    } else {
        store.hnsw_meta().delete(wtxn, SYMMETRIC_LINKS_KEY)?;
    }

    // ONE-1933 / OF-447: every PERSISTED complete rebuild — manual
    // maintenance, the marker-aware rehydrate, and the lazy write route —
    // rehydrates the graph shape, so the SLIM dropped marker is cleared here,
    // in the same transaction as the neighbors, count and entry point, and
    // never before the graph write above succeeded.
    store.hnsw_meta().delete(wtxn, DROPPED_REBUILDABLE_KEY)?;

    Ok(())
}

/// Removes the old vector graph while retaining model-independent compatibility metadata.
pub(crate) fn clear_hnsw_graph_in_txn(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
) -> Result<()> {
    store.vectors().clear(wtxn)?;
    store.hnsw_neighbors().clear(wtxn)?;
    store.hnsw_meta().delete(wtxn, COUNT_KEY)?;
    store.hnsw_meta().delete(wtxn, ENTRY_POINT_KEY)?;
    // The source corpus itself is gone, so an inherited SLIM dropped marker
    // would describe nothing: clear it with the shape it referred to.
    store.hnsw_meta().delete(wtxn, DROPPED_REBUILDABLE_KEY)?;
    clear_one_way_exceptions(store, wtxn)
}

/// Deterministic in-memory rehydrate of a dropped graph from `txn`'s vector
/// snapshot under the vault's persisted discipline. Shared by both lazy
/// first-use routes so a search-served graph and a write-persisted graph are
/// byte-for-byte the same rebuild.
pub(super) fn rebuild_dropped_graph_from_snapshot(
    store: &impl ManifestDbs,
    config: &VaultConfig,
    txn: &RoTxn<'_>,
) -> Result<(RebuiltHnswGraph, LinkDiscipline)> {
    // NEVER hardcode `Symmetric`: a Legacy (pre-migration) vault lazily
    // rebuilds as Legacy, matching landed `NeedsLegacyRebuild` behavior. Only
    // explicit maintenance migrates a vault.
    let discipline = read_link_discipline(store, txn)?;
    let vector_ids = collect_vector_ids(store, txn)?;
    let rebuilt = build_hnsw_graph_from_snapshot(store, config, txn, &vector_ids, discipline)?;
    Ok((rebuilt, discipline))
}

/// Legacy refresh contract: rebuild the whole graph from the current
/// `vectors` snapshot with the historical asymmetric link discipline. Does
/// NOT set the symmetric marker — pre-migration vaults keep their legacy
/// shape until `maintain().rebuild_hnsw()` migrates them.
pub(super) fn rebuild_hnsw_from_current_snapshot(
    store: &Store,
    config: &VaultConfig,
    wtxn: &mut RwTxn<'_>,
) -> Result<()> {
    increment_legacy_snapshot_rebuilds(store, wtxn)?;
    let vector_ids = collect_vector_ids(store, &*wtxn)?;
    let rebuilt =
        build_hnsw_graph_from_snapshot(store, config, &*wtxn, &vector_ids, LinkDiscipline::Legacy)?;
    write_rebuilt_hnsw(store, wtxn, &rebuilt, LinkDiscipline::Legacy)
}

pub(super) fn collect_vector_ids(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
) -> Result<Vec<EntityId>> {
    let capacity = usize::try_from(store.vectors().len(txn)?).unwrap_or(0);
    let mut vector_ids = Vec::with_capacity(capacity);
    for entry in store.vectors().iter(txn)? {
        let (key, _) = entry?;
        vector_ids.push(
            parse_entity_id(&key, ERR_VECTOR_KEY_BYTES).map_err(|e| match e {
                Error::InvalidKey => Error::CorruptedIndex(ERR_VECTOR_KEY_BYTES),
                other => other,
            })?,
        );
    }
    Ok(vector_ids)
}
