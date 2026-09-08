//! Insert, localized refresh, and backlink attachment.

use heed::RwTxn;

use crate::config::VaultConfig;
use crate::entity_id::{EntityId, parse_entity_id};
use crate::error::{Error, Result};
use crate::store::{ManifestDbs, Store};

use super::discipline::{
    LinkDiscipline, increment_refresh_fallback_rebuilds, mark_symmetric_links, read_link_discipline,
};
use super::keys::{
    COUNT_KEY, ENTRY_POINT_KEY, ERR_COUNT_OVERFLOW, ERR_ENTRY_POINT_MISSING,
    ERR_EXISTING_NODE_ZERO_COUNT, ERR_NEIGHBOR_KEY_BYTES, ERR_REMAINING_NODES_MISSING,
    ERR_ZERO_COUNT_GRAPH_NOT_EMPTY,
};
use super::one_way::record_one_way_exception;
use super::rebuild::{
    build_hnsw_graph_from_snapshot, collect_vector_ids, rebuild_dropped_graph_from_snapshot,
    rebuild_hnsw_from_current_snapshot, write_rebuilt_hnsw,
};
use super::search::{beam_search, score_dims_for};
use super::slim_drop::hnsw_is_dropped;
use super::storage::{
    decode_neighbors, load_neighbors, load_vector, prune_neighbors_for_node, read_count,
    read_entry_point, write_neighbors,
};
use super::types::{BeamOptions, InsertOutcome};

/// Direct (non-batched) insert/refresh entry point. Production writes go
/// through [`hnsw_insert_batched`]; this wrapper keeps the historical
/// one-shot semantics (a legacy-graph refresh rebuilds inline) for direct
/// callers and tests.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn hnsw_insert(
    store: &Store,
    config: &VaultConfig,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    vector: &[f32],
) -> Result<()> {
    hnsw_insert_probed(store, config, wtxn, id, vector, &mut 0)
}

/// [`hnsw_insert`] with unit-operation accounting: `ops` increments once per
/// row read/write/delete and once per beam-search node/vector access, so
/// tests can pin the localized-update complexity class (ONE-324 AC5).
pub(crate) fn hnsw_insert_probed(
    store: &Store,
    config: &VaultConfig,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    vector: &[f32],
    ops: &mut u64,
) -> Result<()> {
    match hnsw_insert_inner(store, config, wtxn, id, vector, ops)? {
        InsertOutcome::Applied => Ok(()),
        InsertOutcome::NeedsLegacyRebuild => {
            rebuild_hnsw_from_current_snapshot(store, config, wtxn)
        }
    }
}

/// Batched variant: a legacy-graph refresh sets `pending_rebuild` instead of
/// rebuilding inline, and once a rebuild is pending all further graph
/// mutations in the same transaction are skipped — the single
/// end-of-transaction snapshot rebuild re-derives the whole graph from the
/// `vectors` DB, so per-op mutations would be dead writes (ONE-324 AC11).
pub(crate) fn hnsw_insert_batched(
    store: &impl ManifestDbs,
    config: &VaultConfig,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    vector: &[f32],
    pending_rebuild: &mut bool,
) -> Result<()> {
    if *pending_rebuild {
        return Ok(());
    }
    match hnsw_insert_inner(store, config, wtxn, id, vector, &mut 0)? {
        InsertOutcome::Applied => Ok(()),
        InsertOutcome::NeedsLegacyRebuild => {
            *pending_rebuild = true;
            Ok(())
        }
    }
}

/// Runs a pending legacy snapshot rebuild scheduled by
/// [`hnsw_insert_batched`]. Call after the batch op loop.
pub(crate) fn run_pending_legacy_rebuild(
    store: &Store,
    config: &VaultConfig,
    wtxn: &mut RwTxn<'_>,
    pending_rebuild: bool,
) -> Result<()> {
    if pending_rebuild {
        rebuild_hnsw_from_current_snapshot(store, config, wtxn)?;
    }
    Ok(())
}

fn hnsw_insert_inner(
    store: &impl ManifestDbs,
    config: &VaultConfig,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    vector: &[f32],
    ops: &mut u64,
) -> Result<InsertOutcome> {
    let discipline = read_link_discipline(store, &*wtxn)?;
    // SLIM lazy WRITE route (ONE-1933 / OF-447). Production stages the
    // triggering vector row BEFORE this hook (`apply_vector` /
    // `stage_vector_row` in `batch::ops_pipeline`), so the transaction's
    // CURRENT vector snapshot already contains it. The deterministic rebuild
    // IS this mutation's graph application — no separate insertion or refresh
    // runs afterwards — and the shared graph-write helper clears the marker in
    // the same transaction, only after the graph write succeeds.
    if hnsw_is_dropped(store, &*wtxn)? {
        *ops += 1;
        let (rebuilt, rebuilt_discipline) =
            rebuild_dropped_graph_from_snapshot(store, config, &*wtxn)?;
        write_rebuilt_hnsw(store, wtxn, &rebuilt, rebuilt_discipline)?;
        return Ok(InsertOutcome::Applied);
    }
    *ops += 1;
    if store.hnsw_neighbors().get(&*wtxn, id.as_bytes())?.is_some() {
        *ops += 1;
        let count = read_count(store, &*wtxn)?;
        if count == 0 {
            return Err(Error::CorruptedIndex(ERR_EXISTING_NODE_ZERO_COUNT));
        }
        let entry_point = read_entry_point(store, &*wtxn)?
            .ok_or(Error::CorruptedIndex(ERR_ENTRY_POINT_MISSING))?;
        return match discipline {
            LinkDiscipline::Legacy => Ok(InsertOutcome::NeedsLegacyRebuild),
            LinkDiscipline::Symmetric => {
                hnsw_refresh_localized(store, config, wtxn, id, vector, count, entry_point, ops)?;
                Ok(InsertOutcome::Applied)
            }
        };
    }

    let mut count = read_count(store, &*wtxn)?;
    *ops += 1;
    if count == 0 {
        if read_entry_point(store, &*wtxn)?.is_some()
            || store.hnsw_neighbors().first(&*wtxn)?.is_some()
        {
            return Err(Error::CorruptedIndex(ERR_ZERO_COUNT_GRAPH_NOT_EMPTY));
        }
        store
            .hnsw_meta()
            .put(wtxn, ENTRY_POINT_KEY, id.as_bytes())?;
        store
            .hnsw_meta()
            .put(wtxn, COUNT_KEY, &1_u64.to_le_bytes())?;
        store.hnsw_neighbors().put(wtxn, id.as_bytes(), &[])?;
        // A graph created from empty is symmetric by construction and every
        // subsequent write in this module preserves the invariant.
        mark_symmetric_links(store, wtxn)?;
        return Ok(InsertOutcome::Applied);
    }

    let entry_point =
        read_entry_point(store, &*wtxn)?.ok_or(Error::CorruptedIndex(ERR_ENTRY_POINT_MISSING))?;
    let mut nearest = beam_search(
        store,
        &*wtxn,
        vector,
        entry_point,
        BeamOptions {
            ef: config.hnsw.ef_construction,
            lenient_neighbors: false,
            check_existence: false,
            score_dims: score_dims_for(config),
        },
        config.dimensions,
        ops,
    )?;

    nearest.retain(|entry| entry.id != *id);
    nearest.truncate(config.hnsw.m_max_0);

    let selected: Vec<EntityId> = nearest.into_iter().map(|entry| entry.id).collect();
    write_neighbors(store, wtxn, id, &selected)?;
    *ops += 1;

    match discipline {
        LinkDiscipline::Symmetric => {
            attach_backlinks_symmetric(store, config, wtxn, id, &selected, ops)?;
        }
        LinkDiscipline::Legacy => {
            attach_backlinks_legacy(store, config, wtxn, id, &selected, ops)?;
        }
    }

    count = count
        .checked_add(1)
        .ok_or(Error::IndexOverflow(ERR_COUNT_OVERFLOW))?;
    store
        .hnsw_meta()
        .put(wtxn, COUNT_KEY, &count.to_le_bytes())?;

    Ok(InsertOutcome::Applied)
}

/// Legacy (pre-migration) backlink attachment: prune may drop links without
/// removing the reverse direction, leaving one-way edges. Preserved verbatim
/// for vaults that have not run the symmetry migration.
fn attach_backlinks_legacy(
    store: &impl ManifestDbs,
    config: &VaultConfig,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    selected: &[EntityId],
    ops: &mut u64,
) -> Result<()> {
    for neighbor_id in selected {
        let mut neighbors = load_neighbors(store, &*wtxn, neighbor_id)?;
        *ops += 1;
        if !neighbors.contains(id) {
            neighbors.push(*id);
        }

        if neighbors.len() > config.hnsw.m_max_0 {
            neighbors = prune_neighbors_for_node(
                store,
                &*wtxn,
                neighbor_id,
                &neighbors,
                config.hnsw.m_max_0,
                score_dims_for(config),
                config.dimensions,
                ops,
            )?;
        }

        write_neighbors(store, wtxn, neighbor_id, &neighbors)?;
        *ops += 1;
    }
    Ok(())
}

/// Symmetric backlink attachment (ONE-325): every link written here exists
/// in both directions. When adding `id` to a neighbor's list overflows
/// `m_max_0`, the pruned-out victims also lose their reverse link — except a
/// victim whose list would become empty keeps its link one-way (orphan
/// protection), so no prune ever disconnects a node's outgoing side.
fn attach_backlinks_symmetric(
    store: &impl ManifestDbs,
    config: &VaultConfig,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    selected: &[EntityId],
    ops: &mut u64,
) -> Result<()> {
    for neighbor_id in selected {
        let mut neighbors = load_neighbors(store, &*wtxn, neighbor_id)?;
        *ops += 1;
        if !neighbors.contains(id) {
            neighbors.push(*id);
        }

        if neighbors.len() > config.hnsw.m_max_0 {
            let pruned = prune_neighbors_for_node(
                store,
                &*wtxn,
                neighbor_id,
                &neighbors,
                config.hnsw.m_max_0,
                score_dims_for(config),
                config.dimensions,
                ops,
            )?;
            let removed: Vec<EntityId> = neighbors
                .iter()
                .filter(|candidate| !pruned.contains(candidate))
                .copied()
                .collect();
            write_neighbors(store, wtxn, neighbor_id, &pruned)?;
            *ops += 1;
            for victim in &removed {
                detach_reverse_link(store, wtxn, neighbor_id, victim, ops)?;
            }
        } else {
            write_neighbors(store, wtxn, neighbor_id, &neighbors)?;
            *ops += 1;
        }
    }
    Ok(())
}

/// Removes `from` out of `victim`'s neighbor list to mirror a prune of the
/// `from → victim` direction. Orphan protection: when `victim`'s list is
/// exactly `[from]`, the link is kept one-way instead of emptying the list.
fn detach_reverse_link(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    from: &EntityId,
    victim: &EntityId,
    ops: &mut u64,
) -> Result<()> {
    *ops += 1;
    let Some(raw) = store.hnsw_neighbors().get(&*wtxn, victim.as_bytes())? else {
        return Ok(());
    };
    let list = decode_neighbors(&raw, false)?;
    if !list.contains(from) {
        return Ok(());
    }
    if list.len() == 1 {
        // Orphan protection: never empty a node's outgoing links via a
        // cascade removal. The one-way remainder (`victim -> from`) is the
        // documented exception to the symmetric invariant — track it so a
        // later delete of `from` can purge this otherwise-unreachable backlink
        // instead of leaving the deleted id stranded in `victim`'s row.
        record_one_way_exception(store, wtxn, from, victim, ops)?;
        return Ok(());
    }
    let filtered: Vec<EntityId> = list.into_iter().filter(|entry| entry != from).collect();
    write_neighbors(store, wtxn, victim, &filtered)?;
    *ops += 1;
    Ok(())
}

/// Localized refresh of an existing node on a symmetric graph (ONE-324):
/// detach via the node's own neighbor list (≡ backlinks under the
/// invariant), re-insert at the new position with one beam search, then
/// repair any old neighbor the detach orphaned. No full iteration over
/// `vectors` or `hnsw_neighbors` happens on this path.
#[allow(clippy::too_many_arguments)]
fn hnsw_refresh_localized(
    store: &impl ManifestDbs,
    config: &VaultConfig,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    vector: &[f32],
    count: u64,
    mut entry_point: EntityId,
    ops: &mut u64,
) -> Result<()> {
    // 1. Detach: under the symmetric invariant the node's forward neighbors
    //    are exactly the nodes holding links back to it.
    let old_neighbors = load_neighbors(store, &*wtxn, id)?;
    *ops += 1;
    let mut orphaned: Vec<EntityId> = Vec::new();
    for neighbor_id in &old_neighbors {
        *ops += 1;
        let Some(raw) = store.hnsw_neighbors().get(&*wtxn, neighbor_id.as_bytes())? else {
            continue;
        };
        let list = decode_neighbors(&raw, false)?;
        if !list.contains(id) {
            // One-way protected link (id → neighbor without the reverse):
            // nothing to detach on the neighbor's side.
            continue;
        }
        let filtered: Vec<EntityId> = list.into_iter().filter(|entry| entry != id).collect();
        if filtered.is_empty() {
            orphaned.push(*neighbor_id);
        }
        write_neighbors(store, wtxn, neighbor_id, &filtered)?;
        *ops += 1;
    }
    store.hnsw_neighbors().delete(wtxn, id.as_bytes())?;
    *ops += 1;

    if count == 1 {
        // Sole node: trivially re-anchor at the new position.
        write_neighbors(store, wtxn, id, &[])?;
        store
            .hnsw_meta()
            .put(wtxn, ENTRY_POINT_KEY, id.as_bytes())?;
        return Ok(());
    }

    if entry_point == *id {
        let (replacement_key, _) = store
            .hnsw_neighbors()
            .first(&*wtxn)?
            .ok_or(Error::CorruptedIndex(ERR_REMAINING_NODES_MISSING))?;
        entry_point =
            parse_entity_id(&replacement_key, ERR_NEIGHBOR_KEY_BYTES).map_err(|e| match e {
                Error::InvalidKey => Error::CorruptedIndex(ERR_NEIGHBOR_KEY_BYTES),
                other => other,
            })?;
        store
            .hnsw_meta()
            .put(wtxn, ENTRY_POINT_KEY, entry_point.as_bytes())?;
        *ops += 2;
    }

    // 2. Re-insert at the new position.
    let mut nearest = beam_search(
        store,
        &*wtxn,
        vector,
        entry_point,
        BeamOptions {
            ef: config.hnsw.ef_construction,
            lenient_neighbors: false,
            check_existence: false,
            score_dims: score_dims_for(config),
        },
        config.dimensions,
        ops,
    )?;
    nearest.retain(|entry| entry.id != *id);
    nearest.truncate(config.hnsw.m_max_0);
    if nearest.is_empty() {
        // Local repair cannot restore reachability — explicit measured rare
        // path (ONE-324 AC10). With count > 1 the beam always reaches at
        // least the (≠ id) entry point, so this is defensive.
        return hnsw_symmetric_fallback_rebuild(store, config, wtxn);
    }
    let selected: Vec<EntityId> = nearest.into_iter().map(|entry| entry.id).collect();
    write_neighbors(store, wtxn, id, &selected)?;
    *ops += 1;
    attach_backlinks_symmetric(store, config, wtxn, id, &selected, ops)?;

    // 3. Repair: re-link old neighbors that the detach phase orphaned and
    //    that the re-insert did not already reconnect.
    for orphan in orphaned {
        *ops += 1;
        let Some(raw) = store.hnsw_neighbors().get(&*wtxn, orphan.as_bytes())? else {
            continue;
        };
        if !decode_neighbors(&raw, false)?.is_empty() {
            continue;
        }
        let Some(orphan_vector) = load_vector(store, &*wtxn, &orphan, config.dimensions)? else {
            // No stored vector to anchor a repair by; leave the empty row
            // for the next full rebuild to reconcile.
            continue;
        };
        let mut repair_nearest = beam_search(
            store,
            &*wtxn,
            &orphan_vector,
            entry_point,
            BeamOptions {
                ef: config.hnsw.ef_construction,
                lenient_neighbors: false,
                check_existence: false,
                score_dims: score_dims_for(config),
            },
            config.dimensions,
            ops,
        )?;
        repair_nearest.retain(|entry| entry.id != orphan);
        let Some(anchor) = repair_nearest.first().map(|entry| entry.id) else {
            // Local repair cannot restore entry reachability for this
            // orphan — explicit measured rare path (ONE-324 AC10).
            return hnsw_symmetric_fallback_rebuild(store, config, wtxn);
        };
        write_neighbors(store, wtxn, &orphan, &[anchor])?;
        *ops += 1;
        attach_backlinks_symmetric(store, config, wtxn, &orphan, &[anchor], ops)?;
    }

    Ok(())
}

/// Full symmetric snapshot rebuild used when localized refresh repair cannot
/// restore reachability. Increments the persistent fallback counter so the
/// rare path stays measured; the symmetric marker is already set and the
/// rebuilt graph upholds it.
pub(super) fn hnsw_symmetric_fallback_rebuild(
    store: &impl ManifestDbs,
    config: &VaultConfig,
    wtxn: &mut RwTxn<'_>,
) -> Result<()> {
    increment_refresh_fallback_rebuilds(store, wtxn)?;
    let vector_ids = collect_vector_ids(store, &*wtxn)?;
    let rebuilt = build_hnsw_graph_from_snapshot(
        store,
        config,
        &*wtxn,
        &vector_ids,
        LinkDiscipline::Symmetric,
    )?;
    write_rebuilt_hnsw(store, wtxn, &rebuilt, LinkDiscipline::Symmetric)
}
