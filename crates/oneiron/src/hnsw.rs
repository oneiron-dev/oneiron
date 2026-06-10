use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};

use heed::types::Bytes;
use heed::{Database, RoTxn, RwTxn};

use crate::distance::cosine_distance;
use crate::error::{Error, Result};
use crate::store::Store;
use crate::store::VECTOR_VERSION_KEY;
use crate::types::{ENTITY_ID_LEN, EntityId, ScoredEntity, VaultConfig, parse_entity_id};

const ENTRY_POINT_KEY: &[u8] = b"entry_point";
pub(crate) const COUNT_KEY: &[u8] = b"count";
const ERR_ENTRY_POINT_MISSING: &str = "hnsw count > 0 but entry point is missing";
const ERR_ENTRY_POINT_VECTOR_MISSING: &str = "hnsw count > 0 but entry point vector is missing";
const ERR_ENTRY_POINT_BYTES: &str = "hnsw entry point bytes are malformed";
const ERR_COUNT_BYTES: &str = "hnsw count bytes are malformed";
const ERR_NEIGHBOR_KEY_BYTES: &str = "hnsw neighbor key bytes are malformed";
const ERR_NEIGHBOR_VALUE_BYTES: &str = "hnsw neighbor list bytes are malformed";
const ERR_VECTOR_BYTES: &str = "hnsw vector bytes are malformed";
const ERR_VECTOR_KEY_BYTES: &str = "hnsw vector key bytes are malformed";
const ERR_VECTOR_VERSION_BYTES: &str = "hnsw vector version bytes are malformed";
const ERR_COUNT_UNDERFLOW: &str = "hnsw node count underflowed during delete";
const ERR_COUNT_OVERFLOW: &str = "hnsw node count overflowed";
const ERR_REMAINING_NODES_MISSING: &str = "hnsw count > 0 but no nodes remain";
const ERR_EXISTING_NODE_ZERO_COUNT: &str = "hnsw node exists but count is zero";
const ERR_ZERO_COUNT_GRAPH_NOT_EMPTY: &str =
    "hnsw metadata says count is zero but graph rows still exist";

#[derive(Debug)]
pub(crate) struct RebuiltHnswGraph {
    pub entry_point: Option<EntityId>,
    pub count: u64,
    pub neighbors: Vec<(EntityId, Vec<EntityId>)>,
}

#[derive(Clone, Copy, Debug)]
struct HeapEntry {
    id: EntityId,
    distance: f32,
}

impl PartialEq for HeapEntry {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.distance.total_cmp(&other.distance).is_eq()
    }
}

impl Eq for HeapEntry {}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.distance
            .total_cmp(&other.distance)
            .then_with(|| self.id.as_bytes().cmp(other.id.as_bytes()))
    }
}

pub(crate) fn hnsw_insert(
    store: &Store,
    config: &VaultConfig,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    vector: &[f32],
) -> Result<()> {
    if store.hnsw_neighbors.get(&*wtxn, id.as_bytes())?.is_some() {
        return hnsw_refresh(store, config, wtxn, id, vector);
    }

    let mut count = read_count(store, &*wtxn)?;
    if count == 0 {
        if read_entry_point(store, &*wtxn)?.is_some()
            || store.hnsw_neighbors.first(&*wtxn)?.is_some()
        {
            return Err(Error::CorruptedIndex(ERR_ZERO_COUNT_GRAPH_NOT_EMPTY));
        }
        store.hnsw_meta.put(wtxn, ENTRY_POINT_KEY, id.as_bytes())?;
        store.hnsw_meta.put(wtxn, COUNT_KEY, &1_u64.to_le_bytes())?;
        store.hnsw_neighbors.put(wtxn, id.as_bytes(), &[])?;
        return Ok(());
    }

    let entry_point =
        read_entry_point(store, &*wtxn)?.ok_or(Error::CorruptedIndex(ERR_ENTRY_POINT_MISSING))?;
    let mut nearest = beam_search(
        store,
        &*wtxn,
        vector,
        entry_point,
        config.hnsw.ef_construction,
        false,
        false,
    )?;

    nearest.retain(|entry| entry.id != *id);
    nearest.truncate(config.hnsw.m_max_0);

    let selected: Vec<EntityId> = nearest.into_iter().map(|entry| entry.id).collect();
    write_neighbors(store, wtxn, id, &selected)?;

    for neighbor_id in &selected {
        let mut neighbors = load_neighbors(store, &*wtxn, neighbor_id)?;
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
            )?;
        }

        write_neighbors(store, wtxn, neighbor_id, &neighbors)?;
    }

    count = count
        .checked_add(1)
        .ok_or(Error::IndexOverflow(ERR_COUNT_OVERFLOW))?;
    store.hnsw_meta.put(wtxn, COUNT_KEY, &count.to_le_bytes())?;

    Ok(())
}

fn hnsw_refresh(
    store: &Store,
    config: &VaultConfig,
    wtxn: &mut RwTxn<'_>,
    _id: &EntityId,
    _vector: &[f32],
) -> Result<()> {
    let count = read_count(store, &*wtxn)?;
    if count == 0 {
        return Err(Error::CorruptedIndex(ERR_EXISTING_NODE_ZERO_COUNT));
    }
    let _entry_point =
        read_entry_point(store, &*wtxn)?.ok_or(Error::CorruptedIndex(ERR_ENTRY_POINT_MISSING))?;
    rebuild_hnsw_from_current_snapshot(store, config, wtxn)
}

pub(crate) fn build_hnsw_graph_from_snapshot(
    store: &Store,
    config: &VaultConfig,
    rtxn: &RoTxn<'_>,
    vector_ids: &[EntityId],
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
        )?;

        nearest.retain(|entry| entry.id != *id);
        nearest.truncate(config.hnsw.m_max_0);

        let selected: Vec<EntityId> = nearest.into_iter().map(|entry| entry.id).collect();

        for neighbor_id in &selected {
            let mut neighbor_neighbors = neighbors_by_id.remove(neighbor_id).unwrap_or_default();
            if !neighbor_neighbors.contains(id) {
                neighbor_neighbors.push(*id);
            }

            if neighbor_neighbors.len() > config.hnsw.m_max_0 {
                neighbor_neighbors = prune_neighbors_for_node(
                    store,
                    rtxn,
                    neighbor_id,
                    &neighbor_neighbors,
                    config.hnsw.m_max_0,
                )?;
            }

            neighbors_by_id.insert(*neighbor_id, neighbor_neighbors);
        }

        neighbors_by_id.insert(*id, selected);
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
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    rebuilt: &RebuiltHnswGraph,
) -> Result<()> {
    store.hnsw_neighbors.clear(wtxn)?;
    // Rebuild owns only the live graph shape. Preserve unrelated metadata such as
    // graph/version markers, persisted model ids, and schema/config keys.
    store.hnsw_meta.delete(wtxn, COUNT_KEY)?;
    store.hnsw_meta.delete(wtxn, ENTRY_POINT_KEY)?;

    if let Some(entry_point) = rebuilt.entry_point {
        store
            .hnsw_meta
            .put(wtxn, ENTRY_POINT_KEY, entry_point.as_bytes())?;
    }
    store
        .hnsw_meta
        .put(wtxn, COUNT_KEY, &rebuilt.count.to_le_bytes())?;

    for (id, neighbors) in &rebuilt.neighbors {
        write_neighbors(store, wtxn, id, neighbors)?;
    }

    Ok(())
}

pub(crate) fn read_vector_version(store: &Store, txn: &RoTxn<'_>) -> Result<u64> {
    let Some(raw) = store.hnsw_meta.get(txn, VECTOR_VERSION_KEY)? else {
        return Ok(0);
    };

    let bytes: [u8; 8] = raw
        .try_into()
        .map_err(|_| Error::CorruptedIndex(ERR_VECTOR_VERSION_BYTES))?;
    Ok(u64::from_le_bytes(bytes))
}

pub(crate) fn has_population(hnsw_meta: &Database<Bytes, Bytes>, txn: &RoTxn<'_>) -> Result<bool> {
    if let Some(raw) = hnsw_meta.get(txn, COUNT_KEY)? {
        let bytes: [u8; 8] = raw
            .try_into()
            .map_err(|_| Error::CorruptedIndex(ERR_COUNT_BYTES))?;
        if u64::from_le_bytes(bytes) > 0 {
            return Ok(true);
        }
    }

    Ok(hnsw_meta.get(txn, ENTRY_POINT_KEY)?.is_some())
}

pub(crate) fn increment_vector_version(store: &Store, wtxn: &mut RwTxn<'_>) -> Result<u64> {
    let current = read_vector_version(store, &*wtxn)?;
    let next = current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("vector version"))?;
    store
        .hnsw_meta
        .put(wtxn, VECTOR_VERSION_KEY, &next.to_le_bytes())?;
    Ok(next)
}
pub(crate) fn hnsw_search(
    store: &Store,
    config: &VaultConfig,
    rtxn: &RoTxn<'_>,
    query_vector: &[f32],
    limit: usize,
) -> Result<Vec<ScoredEntity>> {
    if limit == 0 {
        return Ok(Vec::new());
    }

    let count = read_count(store, rtxn)?;
    let entry_point = read_entry_point(store, rtxn)?;
    if count == 0 {
        if entry_point.is_some() || store.hnsw_neighbors.first(rtxn)?.is_some() {
            return Err(Error::CorruptedIndex(ERR_ZERO_COUNT_GRAPH_NOT_EMPTY));
        }
        return Ok(Vec::new());
    }

    let entry_point = entry_point.ok_or(Error::CorruptedIndex(ERR_ENTRY_POINT_MISSING))?;

    let mut nearest = beam_search(
        store,
        rtxn,
        query_vector,
        entry_point,
        config.hnsw.ef_search.max(limit),
        true,
        true,
    )?;

    nearest.truncate(limit);
    Ok(nearest
        .into_iter()
        .map(|entry| ScoredEntity {
            id: entry.id,
            score: (1.0 - entry.distance).clamp(-1.0, 1.0),
        })
        .collect())
}

/// Removes a node from the HNSW graph, scrubbing its ID from surviving
/// neighbor lists and repairing the entry point when needed.
///
/// Search still keeps defensive existence checks because vectors/entities can
/// become partially inconsistent for reasons outside HNSW bookkeeping.
pub(crate) fn hnsw_deindex(store: &Store, wtxn: &mut RwTxn<'_>, id: &EntityId) -> Result<()> {
    if store.hnsw_neighbors.get(&*wtxn, id.as_bytes())?.is_none() {
        return Ok(());
    }

    let count = read_count(store, &*wtxn)?;
    let new_count = count
        .checked_sub(1)
        .ok_or(Error::CorruptedIndex(ERR_COUNT_UNDERFLOW))?;
    let backlink_targets = collect_backlink_targets(store, &*wtxn, id)?;
    store.hnsw_neighbors.delete(wtxn, id.as_bytes())?;
    scrub_backlinks_in_place(store, wtxn, id, &backlink_targets)?;

    store
        .hnsw_meta
        .put(wtxn, COUNT_KEY, &new_count.to_le_bytes())?;

    if new_count == 0 {
        store.hnsw_meta.delete(wtxn, ENTRY_POINT_KEY)?;
        return Ok(());
    }

    let entry_point =
        read_entry_point(store, &*wtxn)?.ok_or(Error::CorruptedIndex(ERR_ENTRY_POINT_MISSING))?;
    if entry_point == *id {
        let (replacement_key, _) = store
            .hnsw_neighbors
            .first(&*wtxn)?
            .ok_or(Error::CorruptedIndex(ERR_REMAINING_NODES_MISSING))?;
        let replacement =
            parse_entity_id(replacement_key, ERR_NEIGHBOR_KEY_BYTES).map_err(|e| match e {
                Error::InvalidKey => Error::CorruptedIndex(ERR_NEIGHBOR_KEY_BYTES),
                other => other,
            })?;
        store
            .hnsw_meta
            .put(wtxn, ENTRY_POINT_KEY, replacement.as_bytes())?;
    }

    Ok(())
}

fn beam_search(
    store: &Store,
    txn: &RoTxn<'_>,
    query_vector: &[f32],
    entry_point: EntityId,
    ef: usize,
    lenient_neighbors: bool,
    check_existence: bool,
) -> Result<Vec<HeapEntry>> {
    let ef = ef.max(1);
    let mut vector_buffer = Vec::with_capacity(query_vector.len());

    let Some(entry_vector) = load_vector_into(store, txn, &entry_point, &mut vector_buffer)? else {
        return Err(Error::CorruptedIndex(ERR_ENTRY_POINT_VECTOR_MISSING));
    };

    let entry = HeapEntry {
        id: entry_point,
        distance: cosine_distance(query_vector, entry_vector),
    };

    let mut candidates: BinaryHeap<Reverse<HeapEntry>> = BinaryHeap::new();
    let mut results: BinaryHeap<HeapEntry> = BinaryHeap::new();
    let graph_nodes = usize::try_from(store.hnsw_neighbors.len(txn)?).unwrap_or(0);
    // Reserve extra headroom so the visited set can absorb frontier growth
    // without immediately rehashing.
    let mut visited: HashSet<EntityId> =
        HashSet::with_capacity(visited_capacity_hint(ef, graph_nodes));

    visited.insert(entry_point);
    candidates.push(Reverse(entry));

    if !check_existence || store.entities.get(txn, entry_point.as_bytes())?.is_some() {
        results.push(entry);
    }

    while let Some(Reverse(current)) = candidates.pop() {
        let worst_distance = results
            .peek()
            .map(|entry| entry.distance)
            .unwrap_or(f32::INFINITY);

        if results.len() >= ef && current.distance > worst_distance {
            break;
        }

        let neighbors = if lenient_neighbors {
            load_neighbors_lenient(store, txn, &current.id)?
        } else {
            load_neighbors(store, txn, &current.id)?
        };
        for neighbor_id in neighbors {
            if !visited.insert(neighbor_id) {
                continue;
            }

            if check_existence && store.entities.get(txn, neighbor_id.as_bytes())?.is_none() {
                continue;
            }

            let Some(neighbor_vector) =
                load_vector_into(store, txn, &neighbor_id, &mut vector_buffer)?
            else {
                continue;
            };

            let distance = cosine_distance(query_vector, neighbor_vector);
            let should_add = results.len() < ef
                || distance
                    < results
                        .peek()
                        .map(|entry| entry.distance)
                        .unwrap_or(f32::INFINITY);

            if should_add {
                let candidate = HeapEntry {
                    id: neighbor_id,
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

fn beam_search_snapshot(
    store: &Store,
    rtxn: &RoTxn<'_>,
    neighbors_by_id: &HashMap<EntityId, Vec<EntityId>>,
    query_id: &EntityId,
    entry_point: EntityId,
    ef: usize,
) -> Result<Vec<HeapEntry>> {
    let ef = ef.max(1);
    let query_vector = load_required_vector(store, rtxn, query_id)?;
    let entry_vector = load_required_vector(store, rtxn, &entry_point)?;
    let mut vector_buffer = Vec::with_capacity(query_vector.len());

    let entry = HeapEntry {
        id: entry_point,
        distance: cosine_distance(&query_vector, &entry_vector),
    };

    let mut candidates: BinaryHeap<Reverse<HeapEntry>> = BinaryHeap::new();
    let mut results: BinaryHeap<HeapEntry> = BinaryHeap::new();
    let mut visited: HashSet<EntityId> =
        HashSet::with_capacity(visited_capacity_hint(ef, neighbors_by_id.len()));

    visited.insert(entry_point);
    candidates.push(Reverse(entry));
    results.push(entry);

    while let Some(Reverse(current)) = candidates.pop() {
        let worst_distance = results
            .peek()
            .map(|entry| entry.distance)
            .unwrap_or(f32::INFINITY);

        if results.len() >= ef && current.distance > worst_distance {
            break;
        }

        for neighbor_id in neighbors_by_id
            .get(&current.id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            if !visited.insert(*neighbor_id) {
                continue;
            }

            let Some(neighbor_vector) =
                load_vector_into(store, rtxn, neighbor_id, &mut vector_buffer)?
            else {
                continue;
            };

            let distance = cosine_distance(&query_vector, neighbor_vector);
            let should_add = results.len() < ef
                || distance
                    < results
                        .peek()
                        .map(|entry| entry.distance)
                        .unwrap_or(f32::INFINITY);

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

fn visited_capacity_hint(ef: usize, graph_nodes: usize) -> usize {
    ef.saturating_mul(2).min(graph_nodes.max(1))
}

fn rebuild_hnsw_from_current_snapshot(
    store: &Store,
    config: &VaultConfig,
    wtxn: &mut RwTxn<'_>,
) -> Result<()> {
    let vector_ids = collect_vector_ids(store, &*wtxn)?;
    let rebuilt = build_hnsw_graph_from_snapshot(store, config, &*wtxn, &vector_ids)?;
    write_rebuilt_hnsw(store, wtxn, &rebuilt)
}

fn collect_vector_ids(store: &Store, txn: &RoTxn<'_>) -> Result<Vec<EntityId>> {
    let capacity = usize::try_from(store.vectors.len(txn)?).unwrap_or(0);
    let mut vector_ids = Vec::with_capacity(capacity);
    for entry in store.vectors.iter(txn)? {
        let (key, _) = entry?;
        vector_ids.push(
            parse_entity_id(key, ERR_VECTOR_KEY_BYTES).map_err(|e| match e {
                Error::InvalidKey => Error::CorruptedIndex(ERR_VECTOR_KEY_BYTES),
                other => other,
            })?,
        );
    }
    Ok(vector_ids)
}

fn select_best_entry_point(
    neighbors_by_id: &HashMap<EntityId, Vec<EntityId>>,
    suggested: Option<EntityId>,
) -> Option<EntityId> {
    select_best_entry_point_probed(neighbors_by_id, suggested, &mut 0)
}

/// Selects the rebuild entry point, counting unit operations into `ops`.
///
/// Reachability here is DIRECTED: `m_max_0` pruning makes neighbor lists
/// asymmetric, so undirected components are not equivalent. The previous
/// implementation ran one full BFS per candidate node (`O(V·(V+E))`); this
/// version is linear-class:
///
/// 1. Fast path: a single BFS from `suggested`. Fully reachable graphs (the
///    common case after a healthy rebuild) keep the cheap early-exit and the
///    suggested entry point.
/// 2. Otherwise: condense the graph into strongly connected components
///    (iterative Tarjan, `O(V+E)`) and pick from the source SCCs
///    (condensation in-degree zero). Every maximal-reach node lives in a
///    source SCC — a non-source SCC is reached from some predecessor SCC
///    whose forward closure is strictly larger (the condensation is acyclic,
///    so the predecessor's own nodes are not in the successor's closure) —
///    therefore comparing source closures suffices. Winner: the source SCC
///    whose forward closure covers the most nodes; ties break to the lowest
///    entity id among the tied sources' member nodes, preserving the
///    previous per-candidate scan's deterministic tie-break.
///
/// `ops` increments once per node visit and once per edge scan in every
/// phase, so tests can pin the complexity class.
fn select_best_entry_point_probed(
    neighbors_by_id: &HashMap<EntityId, Vec<EntityId>>,
    suggested: Option<EntityId>,
    ops: &mut u64,
) -> Option<EntityId> {
    let initial = suggested.or_else(|| neighbors_by_id.keys().copied().next())?;
    if reachable_from_entry_probed(neighbors_by_id, initial, ops).len() == neighbors_by_id.len() {
        return Some(initial);
    }

    let condensation = condense_sccs(neighbors_by_id, ops);
    best_source_scc_member(&condensation, ops)
}

/// Strongly-connected-component condensation of an in-memory rebuild graph.
struct SccCondensation {
    /// Member-node count per SCC.
    sizes: Vec<usize>,
    /// Lowest member entity id per SCC (deterministic tie-break key).
    min_ids: Vec<EntityId>,
    /// Outgoing condensation edges per SCC. May contain duplicates;
    /// consumers deduplicate via visited marks.
    adjacency: Vec<Vec<usize>>,
    /// True when the SCC has at least one incoming condensation edge,
    /// i.e. it is not a source.
    has_incoming: Vec<bool>,
}

const TARJAN_UNVISITED: usize = usize::MAX;

/// Iterative Tarjan SCC condensation, `O(V+E)`. Explicit DFS frames keep the
/// recursion depth off the thread stack (chain-shaped graphs are `O(V)`
/// deep). Neighbor ids absent from `neighbors_by_id` are skipped: rebuild
/// adjacency only references inserted nodes.
fn condense_sccs(
    neighbors_by_id: &HashMap<EntityId, Vec<EntityId>>,
    ops: &mut u64,
) -> SccCondensation {
    let node_count = neighbors_by_id.len();
    let mut ids = Vec::with_capacity(node_count);
    let mut index_of = HashMap::with_capacity(node_count);
    for id in neighbors_by_id.keys() {
        index_of.insert(*id, ids.len());
        ids.push(*id);
    }

    let mut discovery = vec![TARJAN_UNVISITED; node_count];
    let mut lowlink = vec![0_usize; node_count];
    let mut on_stack = vec![false; node_count];
    let mut scc_of = vec![TARJAN_UNVISITED; node_count];
    let mut member_stack: Vec<usize> = Vec::new();
    let mut next_discovery = 0_usize;

    let mut sizes: Vec<usize> = Vec::new();
    let mut min_ids: Vec<EntityId> = Vec::new();

    // DFS frames: (node, offset of the next unexamined edge).
    let mut frames: Vec<(usize, usize)> = Vec::new();
    for root in 0..node_count {
        if discovery[root] != TARJAN_UNVISITED {
            continue;
        }
        frames.push((root, 0));
        while let Some(&mut (node, ref mut edge_pos)) = frames.last_mut() {
            if *edge_pos == 0 {
                *ops += 1;
                discovery[node] = next_discovery;
                lowlink[node] = next_discovery;
                next_discovery += 1;
                on_stack[node] = true;
                member_stack.push(node);
            }

            let neighbors = neighbors_by_id[&ids[node]].as_slice();
            let mut descend_into = None;
            while *edge_pos < neighbors.len() {
                let neighbor = &neighbors[*edge_pos];
                *edge_pos += 1;
                *ops += 1;
                let Some(&target) = index_of.get(neighbor) else {
                    continue;
                };
                if discovery[target] == TARJAN_UNVISITED {
                    descend_into = Some(target);
                    break;
                }
                if on_stack[target] {
                    lowlink[node] = lowlink[node].min(discovery[target]);
                }
            }
            if let Some(child) = descend_into {
                frames.push((child, 0));
                continue;
            }

            if lowlink[node] == discovery[node] {
                let scc = sizes.len();
                let mut size = 0_usize;
                let mut min_id = ids[node];
                loop {
                    let member = member_stack
                        .pop()
                        .expect("Tarjan member stack holds every open node until its root pops");
                    on_stack[member] = false;
                    scc_of[member] = scc;
                    size += 1;
                    if ids[member].as_bytes() < min_id.as_bytes() {
                        min_id = ids[member];
                    }
                    if member == node {
                        break;
                    }
                }
                sizes.push(size);
                min_ids.push(min_id);
            }

            frames.pop();
            if let Some(&mut (parent, _)) = frames.last_mut() {
                lowlink[parent] = lowlink[parent].min(lowlink[node]);
            }
        }
    }

    let scc_count = sizes.len();
    let mut adjacency: Vec<Vec<usize>> = vec![Vec::new(); scc_count];
    let mut has_incoming = vec![false; scc_count];
    for (node, id) in ids.iter().enumerate() {
        *ops += 1;
        let from = scc_of[node];
        for neighbor in &neighbors_by_id[id] {
            *ops += 1;
            let Some(&target) = index_of.get(neighbor) else {
                continue;
            };
            let to = scc_of[target];
            if from != to {
                adjacency[from].push(to);
                has_incoming[to] = true;
            }
        }
    }

    SccCondensation {
        sizes,
        min_ids,
        adjacency,
        has_incoming,
    }
}

/// Picks the entry point from the condensation: the lowest member entity id
/// among the source SCCs whose forward closure covers the most nodes.
///
/// Closure traversals run over the condensation only (never the original
/// graph) and visit each source's reachable SCCs once, marked per-source via
/// an epoch array — no per-candidate full BFS. On disconnected rebuild
/// graphs the traversals cover disjoint SCC sets, keeping the total
/// `O(V+E)`-class.
fn best_source_scc_member(condensation: &SccCondensation, ops: &mut u64) -> Option<EntityId> {
    let scc_count = condensation.sizes.len();
    let mut visited_mark = vec![usize::MAX; scc_count];
    let mut frontier: Vec<usize> = Vec::new();
    let mut best: Option<(usize, EntityId)> = None;

    for source in 0..scc_count {
        *ops += 1;
        if condensation.has_incoming[source] {
            continue;
        }

        let mut closure_nodes = 0_usize;
        visited_mark[source] = source;
        frontier.push(source);
        while let Some(scc) = frontier.pop() {
            *ops += 1;
            closure_nodes += condensation.sizes[scc];
            for &next in &condensation.adjacency[scc] {
                *ops += 1;
                if visited_mark[next] != source {
                    visited_mark[next] = source;
                    frontier.push(next);
                }
            }
        }

        let candidate_id = condensation.min_ids[source];
        let replace = match &best {
            None => true,
            Some((best_closure, best_id)) => {
                closure_nodes > *best_closure
                    || (closure_nodes == *best_closure
                        && candidate_id.as_bytes() < best_id.as_bytes())
            }
        };
        if replace {
            best = Some((closure_nodes, candidate_id));
        }
    }

    best.map(|(_, id)| id)
}

/// Test-facing wrapper: production code paths use
/// [`reachable_from_entry_probed`] so op counts cover the BFS fast path.
#[cfg(test)]
fn reachable_from_entry(
    neighbors_by_id: &HashMap<EntityId, Vec<EntityId>>,
    entry_point: EntityId,
) -> HashSet<EntityId> {
    reachable_from_entry_probed(neighbors_by_id, entry_point, &mut 0)
}

fn reachable_from_entry_probed(
    neighbors_by_id: &HashMap<EntityId, Vec<EntityId>>,
    entry_point: EntityId,
    ops: &mut u64,
) -> HashSet<EntityId> {
    let mut visited = HashSet::with_capacity(neighbors_by_id.len().max(1));
    let mut frontier = vec![entry_point];

    while let Some(current) = frontier.pop() {
        if !visited.insert(current) {
            continue;
        }
        *ops += 1;
        if let Some(neighbors) = neighbors_by_id.get(&current) {
            for neighbor in neighbors {
                *ops += 1;
                frontier.push(*neighbor);
            }
        }
    }

    visited
}

fn read_count(store: &Store, txn: &RoTxn<'_>) -> Result<u64> {
    let Some(raw) = store.hnsw_meta.get(txn, COUNT_KEY)? else {
        return Ok(0);
    };

    let bytes: [u8; 8] = raw
        .try_into()
        .map_err(|_| Error::CorruptedIndex(ERR_COUNT_BYTES))?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_entry_point(store: &Store, txn: &RoTxn<'_>) -> Result<Option<EntityId>> {
    let Some(raw) = store.hnsw_meta.get(txn, ENTRY_POINT_KEY)? else {
        return Ok(None);
    };

    parse_entity_id(raw, ERR_ENTRY_POINT_BYTES)
        .map_err(|e| match e {
            Error::InvalidKey => Error::CorruptedIndex(ERR_ENTRY_POINT_BYTES),
            other => other,
        })
        .map(Some)
}

fn decode_neighbors(raw: &[u8], lenient: bool) -> Result<Vec<EntityId>> {
    if !raw.len().is_multiple_of(ENTITY_ID_LEN) {
        return Err(Error::CorruptedIndex(ERR_NEIGHBOR_VALUE_BYTES));
    }

    let mut neighbors = Vec::with_capacity(raw.len() / ENTITY_ID_LEN);
    for chunk in raw.chunks_exact(ENTITY_ID_LEN) {
        let bytes: [u8; ENTITY_ID_LEN] = chunk.try_into().expect("chunk length is exact");
        match EntityId::from_bytes(bytes) {
            Ok(neighbor) => neighbors.push(neighbor),
            // Reserved sentinel keys are the only `from_bytes` failure mode possible
            // after `chunks_exact(EID_LEN)` — length is fixed by the iterator. So
            // `lenient` mode never silently swallows length corruption; only the
            // sentinel-rejection branch is skipped.
            Err(_) if lenient => continue,
            Err(_) => return Err(Error::CorruptedIndex(ERR_NEIGHBOR_VALUE_BYTES)),
        }
    }

    Ok(neighbors)
}

fn load_neighbors(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<Vec<EntityId>> {
    let Some(raw) = store.hnsw_neighbors.get(txn, id.as_bytes())? else {
        return Ok(Vec::new());
    };

    decode_neighbors(raw, false)
}

fn load_neighbors_lenient(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<Vec<EntityId>> {
    let Some(raw) = store.hnsw_neighbors.get(txn, id.as_bytes())? else {
        return Ok(Vec::new());
    };

    decode_neighbors(raw, true)
}

fn write_neighbors(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    neighbors: &[EntityId],
) -> Result<()> {
    let mut bytes = Vec::with_capacity(neighbors.len() * ENTITY_ID_LEN);
    for neighbor in neighbors {
        bytes.extend_from_slice(neighbor.as_bytes());
    }

    store.hnsw_neighbors.put(wtxn, id.as_bytes(), &bytes)?;
    Ok(())
}

fn load_vector(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<Option<Vec<f32>>> {
    let Some(raw) = store.vectors.get(txn, id.as_bytes())? else {
        return Ok(None);
    };

    let mut vector = Vec::new();
    decode_vector_into(raw, &mut vector)?;
    Ok(Some(vector))
}

fn load_vector_into<'a>(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    scratch: &'a mut Vec<f32>,
) -> Result<Option<&'a [f32]>> {
    let Some(raw) = store.vectors.get(txn, id.as_bytes())? else {
        return Ok(None);
    };

    decode_vector_into(raw, scratch).map(Some)
}

fn load_required_vector(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<Vec<f32>> {
    load_vector(store, txn, id)?.ok_or(Error::InvariantViolation(
        "validated rebuild vector disappeared within the same read snapshot",
    ))
}

fn prune_neighbors_for_node(
    store: &Store,
    txn: &RoTxn<'_>,
    node_id: &EntityId,
    neighbors: &[EntityId],
    max_neighbors: usize,
) -> Result<Vec<EntityId>> {
    let mut node_buffer = Vec::new();
    let Some(node_vector) = load_vector_into(store, txn, node_id, &mut node_buffer)? else {
        return Ok(neighbors.iter().copied().take(max_neighbors).collect());
    };
    let mut neighbor_buffer = Vec::with_capacity(node_vector.len());

    let mut seen = HashSet::with_capacity(neighbors.len());
    let mut scored = Vec::with_capacity(neighbors.len());

    for neighbor_id in neighbors {
        if *neighbor_id == *node_id || !seen.insert(*neighbor_id) {
            continue;
        }

        let Some(neighbor_vector) =
            load_vector_into(store, txn, neighbor_id, &mut neighbor_buffer)?
        else {
            continue;
        };

        scored.push(HeapEntry {
            id: *neighbor_id,
            distance: cosine_distance(node_vector, neighbor_vector),
        });
    }

    scored.sort_unstable();
    scored.truncate(max_neighbors);

    Ok(scored.into_iter().map(|entry| entry.id).collect())
}

fn collect_backlink_targets(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Vec<EntityId>> {
    let mut targets = Vec::new();
    // TODO: Replace this delete-time full scan with a reverse-adjacency index
    // once we need sublinear delete performance at larger graph sizes.
    for entry in store.hnsw_neighbors.iter(txn)? {
        let (key, raw) = entry?;
        let node_id = parse_entity_id(key, ERR_NEIGHBOR_KEY_BYTES).map_err(|e| match e {
            Error::InvalidKey => Error::CorruptedIndex(ERR_NEIGHBOR_KEY_BYTES),
            other => other,
        })?;
        if node_id == *id {
            continue;
        }

        if !neighbor_bytes_contain(raw, id)? {
            continue;
        }
        targets.push(node_id);
    }
    Ok(targets)
}

fn scrub_backlinks_in_place(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    targets: &[EntityId],
) -> Result<()> {
    for node_id in targets {
        let Some(raw) = store.hnsw_neighbors.get(&*wtxn, node_id.as_bytes())? else {
            continue;
        };
        let Some(scrubbed) = scrub_neighbor_bytes(raw, id)? else {
            continue;
        };
        store
            .hnsw_neighbors
            .put(wtxn, node_id.as_bytes(), &scrubbed)?;
    }
    Ok(())
}

fn neighbor_bytes_contain(raw: &[u8], target: &EntityId) -> Result<bool> {
    let mut chunks = raw.chunks_exact(ENTITY_ID_LEN);
    if !chunks.remainder().is_empty() {
        return Err(Error::CorruptedIndex(ERR_NEIGHBOR_VALUE_BYTES));
    }

    Ok(chunks.any(|chunk| chunk == target.as_bytes()))
}

fn scrub_neighbor_bytes(raw: &[u8], target: &EntityId) -> Result<Option<Vec<u8>>> {
    let mut chunks = raw.chunks_exact(ENTITY_ID_LEN);
    if !chunks.remainder().is_empty() {
        return Err(Error::CorruptedIndex(ERR_NEIGHBOR_VALUE_BYTES));
    }

    let mut changed = false;
    let mut scrubbed = Vec::with_capacity(raw.len());
    for chunk in &mut chunks {
        if chunk == target.as_bytes() {
            changed = true;
            continue;
        }
        scrubbed.extend_from_slice(chunk);
    }

    Ok(changed.then_some(scrubbed))
}

fn decode_vector_into<'a>(raw: &[u8], scratch: &'a mut Vec<f32>) -> Result<&'a [f32]> {
    let mut chunks = raw.chunks_exact(4);
    if !chunks.remainder().is_empty() {
        return Err(Error::CorruptedIndex(ERR_VECTOR_BYTES));
    }

    let len = raw.len() / 4;
    scratch.resize(len, 0.0);
    for (slot, chunk) in scratch.iter_mut().zip(&mut chunks) {
        *slot = f32::from_le_bytes(
            chunk
                .try_into()
                .expect("chunks_exact(4) yields only 4-byte chunks"),
        );
    }

    Ok(scratch.as_slice())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::Vault;
    use crate::store::Store;
    use crate::types::{TimeRange, VaultConfig};

    fn test_config() -> VaultConfig {
        let mut config = VaultConfig::device();
        config.dimensions = 4;
        config.embedding_model = Some("test-model-v1".to_owned());
        config.map_size = 64 * 1024 * 1024;
        config.hnsw.m_max_0 = 1;
        config.hnsw.ef_construction = 8;
        config.hnsw.ef_search = 8;
        config
    }

    fn point(start: u64, end: u64) -> TimeRange {
        TimeRange { start, end }
    }

    fn vector_bytes(vector: &[f32]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(vector.len() * 4);
        for value in vector {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn visited_capacity_hint_caps_by_graph_size() {
        assert_eq!(visited_capacity_hint(8, 3), 3);
        assert_eq!(visited_capacity_hint(2, 16), 4);
        assert_eq!(visited_capacity_hint(1, 0), 1);
    }

    fn put_vector_raw(
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
        vector: &[f32],
    ) -> Result<()> {
        let bytes = vector_bytes(vector);
        store.vectors.put(wtxn, id.as_bytes(), &bytes)?;
        Ok(())
    }

    #[test]
    fn hnsw_deindex_scrubs_backlinks() -> Result<()> {
        let temp_dir = tempdir()?;
        let store = Store::open(temp_dir.path(), &test_config())?;
        let mut wtxn = store.env.write_txn()?;
        let a = EntityId::now();
        let b = EntityId::now();
        let c = EntityId::now();

        write_neighbors(&store, &mut wtxn, &a, &[b, c])?;
        write_neighbors(&store, &mut wtxn, &b, &[a])?;
        write_neighbors(&store, &mut wtxn, &c, &[a])?;
        store
            .hnsw_meta
            .put(&mut wtxn, ENTRY_POINT_KEY, a.as_bytes())?;
        store
            .hnsw_meta
            .put(&mut wtxn, COUNT_KEY, &3_u64.to_le_bytes())?;

        hnsw_deindex(&store, &mut wtxn, &a)?;

        assert!(store.hnsw_neighbors.get(&wtxn, a.as_bytes())?.is_none());
        assert_eq!(load_neighbors(&store, &wtxn, &b)?, Vec::<EntityId>::new());
        assert_eq!(load_neighbors(&store, &wtxn, &c)?, Vec::<EntityId>::new());
        assert_eq!(read_count(&store, &wtxn)?, 2);
        assert_eq!(
            read_entry_point(&store, &wtxn)?.expect("replacement entry point"),
            b
        );
        Ok(())
    }

    #[test]
    fn hnsw_deindex_non_entry_preserves_entry_point() -> Result<()> {
        let temp_dir = tempdir()?;
        let store = Store::open(temp_dir.path(), &test_config())?;
        let mut wtxn = store.env.write_txn()?;
        let a = EntityId::now();
        let b = EntityId::now();
        let c = EntityId::now();

        write_neighbors(&store, &mut wtxn, &a, &[b, c])?;
        write_neighbors(&store, &mut wtxn, &b, &[a, c])?;
        write_neighbors(&store, &mut wtxn, &c, &[a, b])?;
        store
            .hnsw_meta
            .put(&mut wtxn, ENTRY_POINT_KEY, a.as_bytes())?;
        store
            .hnsw_meta
            .put(&mut wtxn, COUNT_KEY, &3_u64.to_le_bytes())?;

        hnsw_deindex(&store, &mut wtxn, &c)?;

        assert!(store.hnsw_neighbors.get(&wtxn, c.as_bytes())?.is_none());
        assert_eq!(load_neighbors(&store, &wtxn, &a)?, vec![b]);
        assert_eq!(load_neighbors(&store, &wtxn, &b)?, vec![a]);
        assert_eq!(read_count(&store, &wtxn)?, 2);
        assert_eq!(read_entry_point(&store, &wtxn)?.expect("entry point"), a);
        Ok(())
    }

    #[test]
    fn hnsw_insert_existing_node_updates_neighbors_and_count() -> Result<()> {
        let temp_dir = tempdir()?;
        let store = Store::open(temp_dir.path(), &test_config())?;
        let mut wtxn = store.env.write_txn()?;
        let a = EntityId::now();
        let b = EntityId::now();
        let c = EntityId::now();

        put_vector_raw(&store, &mut wtxn, &a, &[1.0, 0.0, 0.0, 0.0])?;
        put_vector_raw(&store, &mut wtxn, &b, &[0.8, 0.6, 0.0, 0.0])?;
        put_vector_raw(&store, &mut wtxn, &c, &[0.0, 1.0, 0.0, 0.0])?;

        write_neighbors(&store, &mut wtxn, &a, &[b])?;
        write_neighbors(&store, &mut wtxn, &b, &[a, c])?;
        write_neighbors(&store, &mut wtxn, &c, &[b])?;
        store
            .hnsw_meta
            .put(&mut wtxn, ENTRY_POINT_KEY, b.as_bytes())?;
        store
            .hnsw_meta
            .put(&mut wtxn, COUNT_KEY, &3_u64.to_le_bytes())?;

        put_vector_raw(&store, &mut wtxn, &a, &[0.0, 1.0, 0.0, 0.0])?;
        hnsw_insert(&store, &test_config(), &mut wtxn, &a, &[0.0, 1.0, 0.0, 0.0])?;

        assert_eq!(read_count(&store, &wtxn)?, 3);
        assert_eq!(load_neighbors(&store, &wtxn, &a)?, vec![c]);
        assert_eq!(load_neighbors(&store, &wtxn, &b)?, vec![a]);
        assert_eq!(load_neighbors(&store, &wtxn, &c)?, vec![a]);
        Ok(())
    }

    #[test]
    fn hnsw_refresh_prunes_stale_neighbors_without_new_ids() -> Result<()> {
        let temp_dir = tempdir()?;
        let store = Store::open(temp_dir.path(), &test_config())?;
        let mut wtxn = store.env.write_txn()?;
        let a = EntityId::now();
        let b = EntityId::now();
        let c = EntityId::now();

        put_vector_raw(&store, &mut wtxn, &a, &[0.0, 1.0, 0.0, 0.0])?;
        put_vector_raw(&store, &mut wtxn, &b, &[1.0, 0.0, 0.0, 0.0])?;
        put_vector_raw(&store, &mut wtxn, &c, &[0.0, 1.0, 0.0, 0.0])?;

        write_neighbors(&store, &mut wtxn, &a, &[b, c])?;
        write_neighbors(&store, &mut wtxn, &b, &[a])?;
        write_neighbors(&store, &mut wtxn, &c, &[a])?;
        store
            .hnsw_meta
            .put(&mut wtxn, ENTRY_POINT_KEY, b.as_bytes())?;
        store
            .hnsw_meta
            .put(&mut wtxn, COUNT_KEY, &3_u64.to_le_bytes())?;

        hnsw_insert(&store, &test_config(), &mut wtxn, &a, &[0.0, 1.0, 0.0, 0.0])?;

        assert_eq!(load_neighbors(&store, &wtxn, &a)?, vec![c]);
        assert_eq!(load_neighbors(&store, &wtxn, &b)?, vec![a]);
        assert_eq!(load_neighbors(&store, &wtxn, &c)?, vec![a]);
        assert_eq!(
            read_entry_point(&store, &wtxn)?.expect("rebuilt entry point"),
            b
        );
        Ok(())
    }

    #[test]
    fn put_vector_refresh_preserves_search_connectivity() -> Result<()> {
        let temp_dir = tempdir()?;
        let mut config = test_config();
        config.hnsw.m_max_0 = 2;
        let vault = Vault::open(temp_dir.path(), config)?;
        let a = EntityId::now();
        let b = EntityId::now();
        let c = EntityId::now();

        for id in [a, b, c] {
            vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
        }

        let mut wtxn = vault.store.env.write_txn()?;
        put_vector_raw(&vault.store, &mut wtxn, &a, &[0.8, 0.2, 0.0, 0.0])?;
        put_vector_raw(&vault.store, &mut wtxn, &b, &[1.0, 0.0, 0.0, 0.0])?;
        put_vector_raw(&vault.store, &mut wtxn, &c, &[0.0, 1.0, 0.0, 0.0])?;
        write_neighbors(&vault.store, &mut wtxn, &c, &[a])?;
        write_neighbors(&vault.store, &mut wtxn, &a, &[b])?;
        write_neighbors(&vault.store, &mut wtxn, &b, &[a])?;
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, ENTRY_POINT_KEY, c.as_bytes())?;
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, COUNT_KEY, &3_u64.to_le_bytes())?;
        wtxn.commit()?;

        let query = [1.0_f32, 0.0, 0.0, 0.0];
        let before = vault.search_vector(&query, 3)?;
        assert!(
            before.iter().any(|entry| entry.id == b),
            "expected B to be reachable before refresh, got {before:?}"
        );

        vault.put_vector(&a, &[0.0, 1.0, 0.0, 0.0])?;

        let after = vault.search_vector(&query, 3)?;
        assert!(
            after.iter().any(|entry| entry.id == b),
            "expected B to remain reachable after refresh, got {after:?}"
        );
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            load_neighbors(&vault.store, &rtxn, &a)?.contains(&c),
            "expected refreshed node to pick up a new outgoing link toward its new region"
        );
        Ok(())
    }

    #[test]
    fn put_vector_refresh_repairs_entry_point_reachability() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = EntityId::now();
        let b = EntityId::now();
        let c = EntityId::now();

        for id in [a, b, c] {
            vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
        }

        let mut wtxn = vault.store.env.write_txn()?;
        put_vector_raw(&vault.store, &mut wtxn, &a, &[1.0, 0.0, 0.0, 0.0])?;
        put_vector_raw(&vault.store, &mut wtxn, &b, &[0.9, 0.1, 0.0, 0.0])?;
        put_vector_raw(&vault.store, &mut wtxn, &c, &[0.0, 1.0, 0.0, 0.0])?;
        write_neighbors(&vault.store, &mut wtxn, &a, &[b])?;
        write_neighbors(&vault.store, &mut wtxn, &b, &[a])?;
        write_neighbors(&vault.store, &mut wtxn, &c, &[a])?;
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, ENTRY_POINT_KEY, a.as_bytes())?;
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, COUNT_KEY, &3_u64.to_le_bytes())?;
        wtxn.commit()?;

        vault.put_vector(&a, &[0.0, 1.0, 0.0, 0.0])?;

        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            read_entry_point(&vault.store, &rtxn)?.expect("reachable entry point"),
            b
        );
        assert_eq!(load_neighbors(&vault.store, &rtxn, &a)?, vec![c]);
        assert!(
            load_neighbors(&vault.store, &rtxn, &b)?.contains(&a),
            "expected the rebuilt graph to stay searchable from the refreshed entry region"
        );
        drop(rtxn);

        let results = vault.search_vector(&[1.0, 0.0, 0.0, 0.0], 3)?;
        assert!(
            results.iter().any(|entry| entry.id == b),
            "expected old-region node to remain reachable after entry-point refresh, got {results:?}"
        );
        Ok(())
    }

    #[test]
    fn put_vector_refresh_rewrites_stale_incoming_only_links() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = EntityId::now();
        let b = EntityId::now();
        let c = EntityId::now();

        for id in [a, b, c] {
            vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
        }

        let mut wtxn = vault.store.env.write_txn()?;
        put_vector_raw(&vault.store, &mut wtxn, &a, &[1.0, 0.0, 0.0, 0.0])?;
        put_vector_raw(&vault.store, &mut wtxn, &b, &[1.0, 0.0, 0.0, 0.0])?;
        put_vector_raw(&vault.store, &mut wtxn, &c, &[1.0, 0.0, 0.0, 0.0])?;
        write_neighbors(&vault.store, &mut wtxn, &a, &[c])?;
        write_neighbors(&vault.store, &mut wtxn, &b, &[a])?;
        write_neighbors(&vault.store, &mut wtxn, &c, &[a])?;
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, ENTRY_POINT_KEY, a.as_bytes())?;
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, COUNT_KEY, &3_u64.to_le_bytes())?;
        wtxn.commit()?;

        vault.put_vector(&a, &[0.0, 1.0, 0.0, 0.0])?;

        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(load_neighbors(&vault.store, &rtxn, &a)?, vec![b]);
        assert_eq!(load_neighbors(&vault.store, &rtxn, &b)?, vec![c]);
        assert_eq!(load_neighbors(&vault.store, &rtxn, &c)?, vec![b]);
        Ok(())
    }

    /// Each variant corrupts HNSW state in a different way then asserts the
    /// targeted API path propagates the expected `CorruptedIndex` message
    /// rather than silently returning bad neighbors or vectors.
    ///
    /// Search-side variants (use `vault.search_vector`):
    /// - `search/corrupted_neighbor_bytes`: neighbor row with a non-multiple
    ///   of `ENTITY_ID_LEN` payload.
    /// - `search/corrupted_vector_bytes`: vector row truncated to 3 bytes.
    /// - `search/corrupted_entry_point_bytes`: `ENTRY_POINT_KEY` rewritten
    ///   to 3 bytes instead of `ENTITY_ID_LEN`.
    /// - `search/missing_entry_point_when_count_is_nonzero`:
    ///   `ENTRY_POINT_KEY` deleted while count > 0.
    /// - `search/missing_entry_point_vector_when_count_is_nonzero`: vector
    ///   row for the entry point deleted.
    /// - `search/non_empty_graph_when_count_is_zero`: count forced to 0 while
    ///   the graph still has nodes.
    ///
    /// Insert-side variants (call `hnsw_insert` directly):
    /// - `insert/corrupted_count_bytes`: `COUNT_KEY` rewritten to 3 bytes.
    /// - `insert/non_empty_graph_when_count_is_zero`: graph already has
    ///   neighbors/entry-point but `COUNT_KEY` is missing (read as 0).
    /// - `insert/missing_entry_point_vector`: entry point row present but
    ///   its vector row is missing.
    ///
    /// Version-side variant:
    /// - `read_vector_version/corrupted_bytes`: `VECTOR_VERSION_KEY`
    ///   rewritten to 3 bytes.
    #[test]
    fn hnsw_corruption_variants_fail_closed() -> Result<()> {
        // Each variant runs in its own temp vault/store and reports the
        // observed error and the API path's expected message.
        type Variant = fn() -> Result<(Error, &'static str)>;

        fn search_corrupted_neighbor_bytes() -> Result<(Error, &'static str)> {
            let temp_dir = tempdir()?;
            let vault = Vault::open(temp_dir.path(), test_config())?;
            let id = EntityId::now();
            vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
            vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;

            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .hnsw_neighbors
                .put(&mut wtxn, id.as_bytes(), &[1, 2, 3])?;
            wtxn.commit()?;

            let err = vault
                .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
                .expect_err("expected corrupted neighbor list");
            Ok((err, ERR_NEIGHBOR_VALUE_BYTES))
        }

        fn search_corrupted_vector_bytes() -> Result<(Error, &'static str)> {
            let temp_dir = tempdir()?;
            let vault = Vault::open(temp_dir.path(), test_config())?;
            let id = EntityId::now();
            vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
            vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;

            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .vectors
                .put(&mut wtxn, id.as_bytes(), &[1, 2, 3])?;
            wtxn.commit()?;

            let err = vault
                .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
                .expect_err("expected corrupted vector bytes");
            Ok((err, ERR_VECTOR_BYTES))
        }

        fn search_corrupted_entry_point_bytes() -> Result<(Error, &'static str)> {
            let temp_dir = tempdir()?;
            let vault = Vault::open(temp_dir.path(), test_config())?;
            let id = EntityId::now();
            vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
            vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;

            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .hnsw_meta
                .put(&mut wtxn, ENTRY_POINT_KEY, &[1, 2, 3])?;
            wtxn.commit()?;

            let err = vault
                .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
                .expect_err("expected corrupted entry point bytes");
            Ok((err, ERR_ENTRY_POINT_BYTES))
        }

        fn search_missing_entry_point_when_count_is_nonzero() -> Result<(Error, &'static str)> {
            let temp_dir = tempdir()?;
            let vault = Vault::open(temp_dir.path(), test_config())?;
            let id = EntityId::now();
            vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
            vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;

            let mut wtxn = vault.store.env.write_txn()?;
            vault.store.hnsw_meta.delete(&mut wtxn, ENTRY_POINT_KEY)?;
            wtxn.commit()?;

            let err = vault
                .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
                .expect_err("expected missing entry point corruption");
            Ok((err, ERR_ENTRY_POINT_MISSING))
        }

        fn search_missing_entry_point_vector_when_count_is_nonzero() -> Result<(Error, &'static str)>
        {
            let temp_dir = tempdir()?;
            let vault = Vault::open(temp_dir.path(), test_config())?;
            let id = EntityId::now();
            vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
            vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;

            let mut wtxn = vault.store.env.write_txn()?;
            vault.store.vectors.delete(&mut wtxn, id.as_bytes())?;
            wtxn.commit()?;

            let err = vault
                .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
                .expect_err("expected missing entry point vector corruption");
            Ok((err, ERR_ENTRY_POINT_VECTOR_MISSING))
        }

        fn search_non_empty_graph_when_count_is_zero() -> Result<(Error, &'static str)> {
            let temp_dir = tempdir()?;
            let vault = Vault::open(temp_dir.path(), test_config())?;
            let id = EntityId::now();
            vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
            vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;

            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .hnsw_meta
                .put(&mut wtxn, COUNT_KEY, &0_u64.to_le_bytes())?;
            wtxn.commit()?;

            let err = vault
                .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
                .expect_err("expected zero-count graph corruption");
            Ok((err, ERR_ZERO_COUNT_GRAPH_NOT_EMPTY))
        }

        fn insert_corrupted_count_bytes() -> Result<(Error, &'static str)> {
            let temp_dir = tempdir()?;
            let store = Store::open(temp_dir.path(), &test_config())?;
            let mut wtxn = store.env.write_txn()?;
            let existing = EntityId::now();
            let new_id = EntityId::now();

            put_vector_raw(&store, &mut wtxn, &existing, &[1.0, 0.0, 0.0, 0.0])?;
            put_vector_raw(&store, &mut wtxn, &new_id, &[0.0, 1.0, 0.0, 0.0])?;
            write_neighbors(&store, &mut wtxn, &existing, &[])?;
            store
                .hnsw_meta
                .put(&mut wtxn, ENTRY_POINT_KEY, existing.as_bytes())?;
            store.hnsw_meta.put(&mut wtxn, COUNT_KEY, &[1, 2, 3])?;

            let err = hnsw_insert(
                &store,
                &test_config(),
                &mut wtxn,
                &new_id,
                &[0.0, 1.0, 0.0, 0.0],
            )
            .expect_err("expected corrupted count bytes");
            Ok((err, ERR_COUNT_BYTES))
        }

        fn insert_non_empty_graph_when_count_is_zero() -> Result<(Error, &'static str)> {
            let temp_dir = tempdir()?;
            let store = Store::open(temp_dir.path(), &test_config())?;
            let mut wtxn = store.env.write_txn()?;
            let existing = EntityId::now();
            let new_id = EntityId::now();

            write_neighbors(&store, &mut wtxn, &existing, &[])?;
            store
                .hnsw_meta
                .put(&mut wtxn, ENTRY_POINT_KEY, existing.as_bytes())?;
            put_vector_raw(&store, &mut wtxn, &new_id, &[0.0, 1.0, 0.0, 0.0])?;

            let err = hnsw_insert(
                &store,
                &test_config(),
                &mut wtxn,
                &new_id,
                &[0.0, 1.0, 0.0, 0.0],
            )
            .expect_err("expected non-empty graph corruption");
            Ok((err, ERR_ZERO_COUNT_GRAPH_NOT_EMPTY))
        }

        fn insert_missing_entry_point_vector() -> Result<(Error, &'static str)> {
            let temp_dir = tempdir()?;
            let store = Store::open(temp_dir.path(), &test_config())?;
            let mut wtxn = store.env.write_txn()?;
            let existing = EntityId::now();
            let new_id = EntityId::now();

            write_neighbors(&store, &mut wtxn, &existing, &[])?;
            store
                .hnsw_meta
                .put(&mut wtxn, ENTRY_POINT_KEY, existing.as_bytes())?;
            store
                .hnsw_meta
                .put(&mut wtxn, COUNT_KEY, &1_u64.to_le_bytes())?;
            put_vector_raw(&store, &mut wtxn, &new_id, &[0.0, 1.0, 0.0, 0.0])?;

            let err = hnsw_insert(
                &store,
                &test_config(),
                &mut wtxn,
                &new_id,
                &[0.0, 1.0, 0.0, 0.0],
            )
            .expect_err("expected missing entry point vector corruption");
            Ok((err, ERR_ENTRY_POINT_VECTOR_MISSING))
        }

        fn read_vector_version_corrupted_bytes() -> Result<(Error, &'static str)> {
            let temp_dir = tempdir()?;
            let store = Store::open(temp_dir.path(), &test_config())?;
            let mut wtxn = store.env.write_txn()?;
            store
                .hnsw_meta
                .put(&mut wtxn, VECTOR_VERSION_KEY, &[1, 2, 3])?;

            let err =
                read_vector_version(&store, &wtxn).expect_err("expected corrupted version bytes");
            Ok((err, ERR_VECTOR_VERSION_BYTES))
        }

        let variants: Vec<(&str, Variant)> = vec![
            (
                "search/corrupted_neighbor_bytes",
                search_corrupted_neighbor_bytes,
            ),
            (
                "search/corrupted_vector_bytes",
                search_corrupted_vector_bytes,
            ),
            (
                "search/corrupted_entry_point_bytes",
                search_corrupted_entry_point_bytes,
            ),
            (
                "search/missing_entry_point_when_count_is_nonzero",
                search_missing_entry_point_when_count_is_nonzero,
            ),
            (
                "search/missing_entry_point_vector_when_count_is_nonzero",
                search_missing_entry_point_vector_when_count_is_nonzero,
            ),
            (
                "search/non_empty_graph_when_count_is_zero",
                search_non_empty_graph_when_count_is_zero,
            ),
            ("insert/corrupted_count_bytes", insert_corrupted_count_bytes),
            (
                "insert/non_empty_graph_when_count_is_zero",
                insert_non_empty_graph_when_count_is_zero,
            ),
            (
                "insert/missing_entry_point_vector",
                insert_missing_entry_point_vector,
            ),
            (
                "read_vector_version/corrupted_bytes",
                read_vector_version_corrupted_bytes,
            ),
        ];

        for (case_name, variant) in variants {
            let (err, expected_msg) = variant()?;
            assert!(
                matches!(&err, Error::CorruptedIndex(message) if *message == expected_msg),
                "case {case_name}: expected CorruptedIndex({expected_msg:?}), got {err:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn hnsw_insert_rejects_corrupted_neighbor_lists() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = EntityId::now();
        let b = EntityId::now();

        vault.put_entity(&a, 1, point(1, 1), 1, b"a")?;
        vault.put_entity(&b, 1, point(1, 1), 1, b"b")?;
        vault.put_vector(&a, &[1.0, 0.0, 0.0, 0.0])?;

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .hnsw_neighbors
            .put(&mut wtxn, a.as_bytes(), &[0; ENTITY_ID_LEN])?;
        wtxn.commit()?;

        let err = vault
            .put_vector(&b, &[0.9, 0.1, 0.0, 0.0])
            .expect_err("expected corrupted write-side neighbors to fail");
        assert!(matches!(
            err,
            Error::CorruptedIndex(message) if message == ERR_NEIGHBOR_VALUE_BYTES
        ));
        Ok(())
    }

    #[test]
    fn beam_search_strict_rejects_corrupted_neighbor_rows() -> Result<()> {
        let temp_dir = tempdir()?;
        let store = Store::open(temp_dir.path(), &test_config())?;
        let a = EntityId::now();
        let b = EntityId::now();

        let mut wtxn = store.env.write_txn()?;
        store
            .entities
            .put(&mut wtxn, a.as_bytes(), &[0, 0, 0, 0, 0, 0, 0, 0])?;
        store
            .entities
            .put(&mut wtxn, b.as_bytes(), &[0, 0, 0, 0, 0, 0, 0, 0])?;
        store.vectors.put(
            &mut wtxn,
            a.as_bytes(),
            &vector_bytes(&[1.0, 0.0, 0.0, 0.0]),
        )?;
        store.vectors.put(
            &mut wtxn,
            b.as_bytes(),
            &vector_bytes(&[0.9, 0.1, 0.0, 0.0]),
        )?;
        store
            .hnsw_neighbors
            .put(&mut wtxn, a.as_bytes(), b.as_bytes())?;
        store
            .hnsw_neighbors
            .put(&mut wtxn, b.as_bytes(), &[0; ENTITY_ID_LEN])?;
        wtxn.commit()?;

        let rtxn = store.env.read_txn()?;
        let err = beam_search(&store, &rtxn, &[1.0, 0.0, 0.0, 0.0], a, 2, false, false)
            .expect_err("strict beam search should reject corrupted neighbors");
        assert!(matches!(
            err,
            Error::CorruptedIndex(message) if message == ERR_NEIGHBOR_VALUE_BYTES
        ));
        Ok(())
    }

    // Original 9 corruption tests folded into `hnsw_corruption_variants_fail_closed` above.

    #[test]
    fn select_best_entry_point_prefers_full_reachability() {
        let a = EntityId::now();
        let b = EntityId::now();
        let c = EntityId::now();
        let neighbors = HashMap::from([(a, vec![c]), (b, vec![a]), (c, vec![a])]);

        assert_eq!(select_best_entry_point(&neighbors, Some(a)), Some(b));
        assert_eq!(reachable_from_entry(&neighbors, b).len(), neighbors.len());
    }

    #[test]
    fn select_best_entry_point_tie_breaks_by_entity_id() {
        let low = EntityId::from_bytes([0x10; ENTITY_ID_LEN]).expect("test id should be valid");
        let mid = EntityId::from_bytes([0x20; ENTITY_ID_LEN]).expect("test id should be valid");
        let high = EntityId::from_bytes([0x30; ENTITY_ID_LEN]).expect("test id should be valid");
        let neighbors = HashMap::from([
            (high, Vec::<EntityId>::new()),
            (mid, Vec::<EntityId>::new()),
            (low, Vec::<EntityId>::new()),
        ]);

        assert_eq!(reachable_from_entry(&neighbors, low).len(), 1);
        assert_eq!(reachable_from_entry(&neighbors, mid).len(), 1);
        assert_eq!(reachable_from_entry(&neighbors, high).len(), 1);
        assert!(reachable_from_entry(&neighbors, low).len() < neighbors.len());
        assert_eq!(select_best_entry_point(&neighbors, Some(high)), Some(low));
    }

    /// Builds a distinct, lexicographically ordered test id: `value` (>= 1,
    /// big-endian) in the first 8 bytes, zero padding after. Ordering by
    /// `as_bytes()` equals numeric ordering of `value`.
    fn id_from_u64(value: u64) -> EntityId {
        assert!(value >= 1, "zero would collide with the reserved zero id");
        let mut bytes = [0_u8; ENTITY_ID_LEN];
        bytes[..8].copy_from_slice(&value.to_be_bytes());
        EntityId::from_bytes(bytes).expect("nonzero counter ids avoid reserved sentinels")
    }

    /// SplitMix64 — deterministic test PRNG, no external dependency.
    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// The pre-SCC selector — one full directed BFS per candidate node,
    /// `O(V·(V+E))` — kept verbatim as the exhaustive reference that the
    /// linear implementation must match: maximal directed reach, ties broken
    /// by lowest entity id.
    fn reference_select_best_entry_point(
        neighbors_by_id: &HashMap<EntityId, Vec<EntityId>>,
        suggested: Option<EntityId>,
    ) -> Option<EntityId> {
        let mut best = suggested.or_else(|| neighbors_by_id.keys().copied().next())?;
        let mut best_reach = reachable_from_entry(neighbors_by_id, best).len();
        if best_reach == neighbors_by_id.len() {
            return Some(best);
        }

        for candidate in neighbors_by_id.keys().copied() {
            if candidate == best {
                continue;
            }
            let reach = reachable_from_entry(neighbors_by_id, candidate).len();
            if reach > best_reach || (reach == best_reach && candidate.as_bytes() < best.as_bytes())
            {
                best = candidate;
                best_reach = reach;
                if best_reach == neighbors_by_id.len() {
                    break;
                }
            }
        }

        Some(best)
    }

    /// Directed reach decides the entry point, not SCC size and not weak
    /// (undirected) components: a 6-node chain's head (forward closure 6)
    /// beats a 5-node cycle (the largest SCC, closure 5). The chain head is
    /// deliberately NOT the lowest id of its own component, so a
    /// "lowest id in the biggest component" implementation also fails here.
    #[test]
    fn select_best_entry_point_prefers_long_chain_over_larger_scc() {
        let cycle: Vec<EntityId> = (1..=5_u64).map(id_from_u64).collect();
        let chain_head = id_from_u64(60);
        let chain_rest: Vec<EntityId> = (10..=14_u64).map(id_from_u64).collect();

        let mut neighbors = HashMap::new();
        for (i, id) in cycle.iter().enumerate() {
            neighbors.insert(*id, vec![cycle[(i + 1) % cycle.len()]]);
        }
        neighbors.insert(chain_head, vec![chain_rest[0]]);
        for window in chain_rest.windows(2) {
            neighbors.insert(window[0], vec![window[1]]);
        }
        neighbors.insert(chain_rest[4], Vec::new());

        assert_eq!(
            select_best_entry_point(&neighbors, Some(cycle[0])),
            Some(chain_head)
        );
    }

    /// On closure ties the winner is the lowest entity id over ALL member
    /// nodes of the tied source SCCs — not the suggested node and not an
    /// SCC-root artifact. Two disconnected 2-cycles tie at closure 2; the
    /// 0x10 member of the {0x10, 0x40} cycle must win.
    #[test]
    fn select_best_entry_point_tie_breaks_by_lowest_member_id_across_sccs() {
        let m1 = EntityId::from_bytes([0x10; ENTITY_ID_LEN]).expect("test id should be valid");
        let m2 = EntityId::from_bytes([0x40; ENTITY_ID_LEN]).expect("test id should be valid");
        let n1 = EntityId::from_bytes([0x20; ENTITY_ID_LEN]).expect("test id should be valid");
        let n2 = EntityId::from_bytes([0x30; ENTITY_ID_LEN]).expect("test id should be valid");
        let neighbors = HashMap::from([
            (m1, vec![m2]),
            (m2, vec![m1]),
            (n1, vec![n2]),
            (n2, vec![n1]),
        ]);

        assert_eq!(select_best_entry_point(&neighbors, Some(n1)), Some(m1));
    }

    /// AC: on randomized disconnected fixtures the SCC-based entry reaches at
    /// least as many nodes as the per-candidate-BFS reference's choice. The
    /// fixtures are disconnected (>= 2 disjoint components), so no node is
    /// fully reaching, the reference is deterministic (max reach, lowest-id
    /// tie-break), and the result must match it exactly.
    #[test]
    fn select_best_entry_point_matches_exhaustive_reference_on_disconnected_fixtures() {
        for seed in 0..60_u64 {
            let mut state = seed;
            let component_count = 2 + (splitmix64(&mut state) % 4) as usize;
            let mut neighbors = HashMap::new();
            let mut all_ids = Vec::new();
            let mut next_id = 1_u64;

            for _ in 0..component_count {
                let size = 2 + (splitmix64(&mut state) % 9) as usize;
                let ids: Vec<EntityId> = (0..size)
                    .map(|_| {
                        let id = id_from_u64(next_id);
                        next_id += 1;
                        id
                    })
                    .collect();
                for (i, id) in ids.iter().enumerate() {
                    let out_degree = (splitmix64(&mut state) % 4) as usize;
                    let mut outs: Vec<EntityId> = Vec::new();
                    for _ in 0..out_degree {
                        let target = (splitmix64(&mut state) % size as u64) as usize;
                        if target != i && !outs.contains(&ids[target]) {
                            outs.push(ids[target]);
                        }
                    }
                    neighbors.insert(*id, outs);
                }
                all_ids.extend(ids);
            }

            let suggested = all_ids[(splitmix64(&mut state) as usize) % all_ids.len()];
            let expected = reference_select_best_entry_point(&neighbors, Some(suggested))
                .expect("non-empty fixture");
            let actual =
                select_best_entry_point(&neighbors, Some(suggested)).expect("non-empty fixture");

            let expected_reach = reachable_from_entry(&neighbors, expected).len();
            let actual_reach = reachable_from_entry(&neighbors, actual).len();
            assert!(
                actual_reach >= expected_reach,
                "seed {seed}: SCC entry reaches {actual_reach} < reference {expected_reach}"
            );
            assert!(
                expected_reach < neighbors.len(),
                "seed {seed}: disconnected fixture must not be fully reachable"
            );
            assert_eq!(
                actual, expected,
                "seed {seed}: deterministic (max reach, lowest id) winner must match"
            );
        }
    }

    /// AC: complexity stays `O(V+E)`-class on a multi-component fixture —
    /// verified by op-count probe. 10 disjoint 100-node chains: V = 1000,
    /// E = 990. The SCC path touches each node and edge a small constant
    /// number of times (measured ~3.6·(V+E)); budget 8·(V+E). A
    /// per-candidate full-BFS selector pays Σ reach(v) =
    /// 10 · (100·101/2) ≈ 50,500 node visits alone and cannot fit the
    /// budget.
    #[test]
    fn select_best_entry_point_op_count_is_linear_on_multi_component_fixture() {
        const CHAINS: usize = 10;
        const CHAIN_LEN: usize = 100;

        let mut neighbors = HashMap::new();
        let mut heads = Vec::new();
        let mut next_id = 1_u64;
        for _ in 0..CHAINS {
            let ids: Vec<EntityId> = (0..CHAIN_LEN)
                .map(|_| {
                    let id = id_from_u64(next_id);
                    next_id += 1;
                    id
                })
                .collect();
            heads.push(ids[0]);
            for (i, id) in ids.iter().enumerate() {
                let outs = if i + 1 < CHAIN_LEN {
                    vec![ids[i + 1]]
                } else {
                    Vec::new()
                };
                neighbors.insert(*id, outs);
            }
        }

        let v = CHAINS * CHAIN_LEN;
        let e = CHAINS * (CHAIN_LEN - 1);
        let mut ops = 0_u64;
        // Suggested is NOT the winning head: every chain head reaches
        // CHAIN_LEN nodes, ties break to the lowest id (heads[0]).
        let entry = select_best_entry_point_probed(&neighbors, Some(heads[3]), &mut ops)
            .expect("non-empty fixture");

        assert_eq!(entry, heads[0]);
        let budget = 8 * (v + e) as u64;
        assert!(
            ops <= budget,
            "ops {ops} exceeded linear budget {budget} (V={v}, E={e})"
        );
    }

    /// AC: fully reachable graphs keep the cheap early-exit — a single BFS,
    /// no SCC pass (which alone would at least double the op count), and the
    /// suggested entry point is kept verbatim even though it is not the
    /// lowest id.
    #[test]
    fn select_best_entry_point_keeps_suggested_on_fully_reachable_graph_with_single_bfs() {
        const N: usize = 200;
        let ids: Vec<EntityId> = (1..=N as u64).map(id_from_u64).collect();
        let mut neighbors = HashMap::new();
        for (i, id) in ids.iter().enumerate() {
            neighbors.insert(*id, vec![ids[(i + 1) % N]]);
        }
        let suggested = ids[N / 2];

        let mut ops = 0_u64;
        let entry = select_best_entry_point_probed(&neighbors, Some(suggested), &mut ops)
            .expect("non-empty fixture");

        assert_eq!(entry, suggested);
        // Single BFS budget: one op per node + one per edge, nothing else.
        let single_bfs_budget = (N + N) as u64;
        assert!(
            ops <= single_bfs_budget,
            "expected single-BFS early-exit, got {ops} ops > {single_bfs_budget}"
        );
    }
}
