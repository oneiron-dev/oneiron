//! Search, MRL rescore, and beam traversal.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};

use heed::RoTxn;

use crate::config::VaultConfig;
use crate::distance::PreparedCosine;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::pipeline::ScoredEntity;
use crate::store::ManifestDbs;

use super::keys::{
    ERR_ENTRY_POINT_MISSING, ERR_ENTRY_POINT_VECTOR_MISSING, ERR_VECTOR_ROW_MISSING_AT_RESCORE,
    ERR_VECTOR_ROW_TOO_SHORT, ERR_ZERO_COUNT_GRAPH_NOT_EMPTY,
};
use super::rebuild::rebuild_dropped_graph_from_snapshot;
use super::slim_drop::hnsw_is_dropped;
use super::storage::{
    load_neighbors, load_neighbors_lenient, load_required_vector, load_vector_into, read_count,
    read_entry_point,
};
use super::types::{BeamOptions, GraphSource, HeapEntry};

/// Vector search over the NSW graph.
///
/// EMB-2 MRL funnel: with `fast_dims` configured, traversal scores on the
/// vector prefix and `query_vector` may be either full-length or
/// `fast_dims`-length. Full-length queries get an exact full-dim rescore of
/// the whole beam result set (the funnel's rescore breadth — no extra
/// constant) unless `skip_rescore` opts into the prefix-only hot lane. A
/// `fast_dims`-length query can never be rescored — no full query exists —
/// so the flag is implicit there. With `fast_dims: None` the behavior is
/// identical to the pre-funnel path and `skip_rescore` is inert.
///
/// Recall contract: the rescore restores exact full-dim ORDERING of the
/// retrieved beam only — it is not global exactness. Candidate selection
/// happens in prefix space, so a vector that is distant in the prefix but
/// near in full dimensions may never enter the `ef_search.max(limit)`-wide
/// beam and can never be rescored back in. Recall is beam-bounded and
/// rises with `ef_search`; a beam covering the whole reachable corpus
/// recovers brute-force parity.
pub(crate) fn hnsw_search(
    store: &impl ManifestDbs,
    config: &VaultConfig,
    rtxn: &RoTxn<'_>,
    query_vector: &[f32],
    limit: usize,
    skip_rescore: bool,
) -> Result<Vec<ScoredEntity>> {
    // Defense-in-depth: callers (pipeline vector channel, vault search)
    // validate too.
    if query_vector.len() != config.dimensions
        && config.fast_dims.map(usize::from) != Some(query_vector.len())
    {
        return Err(Error::DimensionMismatch {
            expected: config.dimensions,
            got: query_vector.len(),
        });
    }
    if limit == 0 {
        return Ok(Vec::new());
    }

    // SLIM lazy READ route (ONE-1933 / OF-447). A dropped graph shape is
    // re-derived in memory from THIS snapshot's vectors under the vault's
    // persisted discipline and serves the current call. A pure search never
    // opens a write transaction — LMDB permits none while the caller's read
    // snapshot is live — so it neither commits the rebuild nor clears the
    // marker; the marker may persist across any number of searches.
    let rebuilt = if hnsw_is_dropped(store, rtxn)? {
        Some(rebuild_dropped_graph_from_snapshot(store, config, rtxn)?.0)
    } else {
        None
    };
    let (count, entry_point) = match rebuilt.as_ref() {
        Some(graph) => (graph.count, graph.entry_point),
        None => (read_count(store, rtxn)?, read_entry_point(store, rtxn)?),
    };
    let rebuilt_neighbors: Option<HashMap<EntityId, Vec<EntityId>>> =
        rebuilt.map(|graph| graph.neighbors.into_iter().collect());
    let graph = match rebuilt_neighbors.as_ref() {
        Some(neighbors_by_id) => GraphSource::Rebuilt(neighbors_by_id),
        None => GraphSource::Persisted,
    };
    if count == 0 {
        let graph_rows_exist = match graph {
            GraphSource::Persisted => store.hnsw_neighbors().first(rtxn)?.is_some(),
            GraphSource::Rebuilt(neighbors_by_id) => !neighbors_by_id.is_empty(),
        };
        if entry_point.is_some() || graph_rows_exist {
            return Err(Error::CorruptedIndex(ERR_ZERO_COUNT_GRAPH_NOT_EMPTY));
        }
        return Ok(Vec::new());
    }

    let entry_point = entry_point.ok_or(Error::CorruptedIndex(ERR_ENTRY_POINT_MISSING))?;

    let mut nearest = beam_search_graph(
        store,
        rtxn,
        query_vector,
        entry_point,
        (
            BeamOptions {
                ef: config.hnsw.ef_search.max(limit),
                lenient_neighbors: true,
                check_existence: true,
                score_dims: score_dims_for(config),
            },
            graph,
        ),
        config.dimensions,
        &mut 0,
    )?;

    let rescore_active =
        config.fast_dims.is_some() && query_vector.len() == config.dimensions && !skip_rescore;
    if rescore_active {
        let mut vector_buffer = Vec::with_capacity(query_vector.len());
        // One query, one norm: the rescore sweep re-reads the same query for
        // every beam entry.
        let prepared_query = PreparedCosine::new(query_vector);
        for entry in &mut nearest {
            let Some(row) = load_vector_into(
                store,
                rtxn,
                &entry.id,
                config.dimensions,
                &mut vector_buffer,
            )?
            else {
                // Unreachable under LMDB snapshot isolation: every beam
                // result loaded its row within THIS rtxn to be scored at
                // all. If it fires anyway the index is inconsistent — fail
                // closed rather than leave this entry's PREFIX distance to
                // be ranked against the others' full-dim distances (two
                // incompatible scales in one ordering).
                return Err(Error::CorruptedIndex(ERR_VECTOR_ROW_MISSING_AT_RESCORE));
            };
            // Same fail-closed rule as `score_prefix`: a row shorter than
            // the full query is a truncated/corrupted row and must not
            // rescore on a partial comparison.
            if row.len() < query_vector.len() {
                return Err(Error::CorruptedIndex(ERR_VECTOR_ROW_TOO_SHORT));
            }
            entry.distance = prepared_query.distance(row);
        }
        // HeapEntry orders by (distance asc, id bytes asc) — the pinned
        // rescore tiebreak.
        nearest.sort_unstable();
    }

    // Retain archived nodes for graph traversal, but never return them as
    // active matches. Restore only removes the marker, not graph state.
    let mut visible = Vec::with_capacity(nearest.len());
    for entry in nearest {
        if !crate::vault_cleanup::is_archived_in_txn(store, rtxn, &entry.id)? {
            visible.push(entry);
        }
    }
    visible.truncate(limit);
    Ok(visible
        .into_iter()
        .map(|entry| ScoredEntity {
            id: entry.id,
            score: (1.0 - entry.distance).clamp(-1.0, 1.0),
        })
        .collect())
}

/// The scoring prefix length for one vault: `fast_dims` when the MRL funnel
/// is configured, full `dimensions` otherwise.
pub(super) fn score_dims_for(config: &VaultConfig) -> usize {
    config.fast_dims.map_or(config.dimensions, usize::from)
}

/// Prefix-slices one operand for a funnel distance computation. Prefix
/// cosine is exact for the prefix space — `cosine_distance` computes norms
/// per call, so no renormalization step is needed.
///
/// A vector with FEWER than `score_dims` components fails closed
/// (persisted-data corruption): healthy rows are always full-dimension and
/// both accepted query lengths are >= `score_dims`, so a short vector can
/// only be a truncated/corrupted row — and scoring it on a partial prefix
/// would let it look CLOSER than healthy rows rather than being rejected.
pub(super) fn score_prefix(vector: &[f32], score_dims: usize) -> Result<&[f32]> {
    if vector.len() < score_dims {
        return Err(Error::CorruptedIndex(ERR_VECTOR_ROW_TOO_SHORT));
    }
    Ok(&vector[..score_dims])
}

pub(super) fn beam_search(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    query_vector: &[f32],
    entry_point: EntityId,
    options: BeamOptions,
    dimensions: usize,
    ops: &mut u64,
) -> Result<Vec<HeapEntry>> {
    beam_search_graph(
        store,
        txn,
        query_vector,
        entry_point,
        (options, GraphSource::Persisted),
        dimensions,
        ops,
    )
}

fn beam_search_graph(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    query_vector: &[f32],
    entry_point: EntityId,
    (options, graph): (BeamOptions, GraphSource<'_>),
    dimensions: usize,
    ops: &mut u64,
) -> Result<Vec<HeapEntry>> {
    let BeamOptions {
        ef,
        lenient_neighbors,
        check_existence,
        score_dims,
    } = options;
    let ef = ef.max(1);
    let mut vector_buffer = Vec::with_capacity(query_vector.len());

    *ops += 1;
    let Some(entry_vector) =
        load_vector_into(store, txn, &entry_point, dimensions, &mut vector_buffer)?
    else {
        return Err(Error::CorruptedIndex(ERR_ENTRY_POINT_VECTOR_MISSING));
    };

    // The whole beam scores against ONE query. Preparing it here — after the
    // entry-point load, at the first point the legacy code inspected the
    // query prefix — keeps error ordering identical while the query's norm
    // and the SIMD dispatch are paid for once instead of once per candidate.
    let prepared_query = PreparedCosine::new(score_prefix(query_vector, score_dims)?);

    let entry = HeapEntry {
        id: entry_point,
        distance: prepared_query.distance(score_prefix(entry_vector, score_dims)?),
    };

    let mut candidates: BinaryHeap<Reverse<HeapEntry>> = BinaryHeap::new();
    // Traversal stopping must count archived connectors too. A separate live
    // heap keeps them out of matches without making a sparse live set exhaust
    // the graph. Both heaps are bounded by ef.
    let mut results: BinaryHeap<HeapEntry> = BinaryHeap::new();
    let mut visible: BinaryHeap<HeapEntry> = BinaryHeap::new();
    let graph_nodes = match graph {
        GraphSource::Persisted => usize::try_from(store.hnsw_neighbors().len(txn)?).unwrap_or(0),
        GraphSource::Rebuilt(neighbors_by_id) => neighbors_by_id.len(),
    };
    // Reserve extra headroom so the visited set can absorb frontier growth
    // without immediately rehashing.
    let mut visited: HashSet<EntityId> =
        HashSet::with_capacity(visited_capacity_hint(ef, graph_nodes));

    visited.insert(entry_point);
    candidates.push(Reverse(entry));

    if !check_existence || store.entities().get(txn, entry_point.as_bytes())?.is_some() {
        results.push(entry);
        if check_existence && !crate::vault_cleanup::is_archived_in_txn(store, txn, &entry_point)? {
            visible.push(entry);
        }
    }

    while let Some(Reverse(current)) = candidates.pop() {
        let worst_distance = results.peek().map_or(f32::INFINITY, |entry| entry.distance);

        if results.len() >= ef && current.distance > worst_distance {
            break;
        }

        *ops += 1;
        let neighbors = match graph {
            GraphSource::Persisted if lenient_neighbors => {
                load_neighbors_lenient(store, txn, &current.id)?
            }
            GraphSource::Persisted => load_neighbors(store, txn, &current.id)?,
            // The in-memory rebuild was produced by this module and carries
            // no reserved-sentinel or ragged-length rows, so the lenient and
            // strict decodes coincide.
            GraphSource::Rebuilt(neighbors_by_id) => neighbors_by_id
                .get(&current.id)
                .cloned()
                .unwrap_or_default(),
        };
        for neighbor_id in neighbors {
            if !visited.insert(neighbor_id) {
                continue;
            }

            *ops += 1;
            if check_existence && store.entities().get(txn, neighbor_id.as_bytes())?.is_none() {
                continue;
            }

            let Some(neighbor_vector) =
                load_vector_into(store, txn, &neighbor_id, dimensions, &mut vector_buffer)?
            else {
                continue;
            };

            let distance = prepared_query.distance(score_prefix(neighbor_vector, score_dims)?);
            let candidate = HeapEntry {
                id: neighbor_id,
                distance,
            };
            // A scored live neighbor can be a match even when archived nodes
            // are closer and keep it out of the traversal beam.
            if check_existence
                && (visible.len() < ef
                    || distance < visible.peek().map_or(f32::INFINITY, |entry| entry.distance))
                && !crate::vault_cleanup::is_archived_in_txn(store, txn, &neighbor_id)?
            {
                visible.push(candidate);
                if visible.len() > ef {
                    visible.pop();
                }
            }
            let should_add = results.len() < ef
                || distance < results.peek().map_or(f32::INFINITY, |entry| entry.distance);

            if should_add {
                candidates.push(Reverse(candidate));
                results.push(candidate);
                if results.len() > ef {
                    results.pop();
                }
            }
        }
    }

    let mut found = if check_existence {
        visible.into_vec()
    } else {
        results.into_vec()
    };
    found.sort_unstable();
    Ok(found)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn beam_search_snapshot(
    store: &impl ManifestDbs,
    rtxn: &RoTxn<'_>,
    neighbors_by_id: &HashMap<EntityId, Vec<EntityId>>,
    query_id: &EntityId,
    entry_point: EntityId,
    ef: usize,
    score_dims: usize,
    dimensions: usize,
) -> Result<Vec<HeapEntry>> {
    let ef = ef.max(1);
    let query_vector = load_required_vector(store, rtxn, query_id, dimensions)?;
    let entry_vector = load_required_vector(store, rtxn, &entry_point, dimensions)?;
    let mut vector_buffer = Vec::with_capacity(query_vector.len());

    // Same one-query-many-candidates shape as `beam_search`, prepared at the
    // same point in the sequence.
    let prepared_query = PreparedCosine::new(score_prefix(&query_vector, score_dims)?);

    let entry = HeapEntry {
        id: entry_point,
        distance: prepared_query.distance(score_prefix(&entry_vector, score_dims)?),
    };

    let mut candidates: BinaryHeap<Reverse<HeapEntry>> = BinaryHeap::new();
    let mut results: BinaryHeap<HeapEntry> = BinaryHeap::new();
    let mut visited: HashSet<EntityId> =
        HashSet::with_capacity(visited_capacity_hint(ef, neighbors_by_id.len()));

    visited.insert(entry_point);
    candidates.push(Reverse(entry));
    results.push(entry);

    while let Some(Reverse(current)) = candidates.pop() {
        let worst_distance = results.peek().map_or(f32::INFINITY, |entry| entry.distance);

        if results.len() >= ef && current.distance > worst_distance {
            break;
        }

        for neighbor_id in neighbors_by_id
            .get(&current.id)
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            if !visited.insert(*neighbor_id) {
                continue;
            }

            let Some(neighbor_vector) =
                load_vector_into(store, rtxn, neighbor_id, dimensions, &mut vector_buffer)?
            else {
                continue;
            };

            let distance = prepared_query.distance(score_prefix(neighbor_vector, score_dims)?);
            let should_add = results.len() < ef
                || distance < results.peek().map_or(f32::INFINITY, |entry| entry.distance);

            if should_add {
                let candidate = HeapEntry {
                    id: *neighbor_id,
                    distance,
                };
                candidates.push(Reverse(candidate));
                results.push(candidate);

                if results.len() > ef {
                    results.pop();
                }
            }
        }
    }

    let mut found = results.into_vec();
    found.sort_unstable();
    Ok(found)
}

pub(super) fn visited_capacity_hint(ef: usize, graph_nodes: usize) -> usize {
    ef.saturating_mul(2).min(graph_nodes.max(1))
}
