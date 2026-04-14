use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};

use heed::{RoTxn, RwTxn};

use crate::distance::cosine_distance;
use crate::error::{Error, Result};
use crate::store::Store;
use crate::store::VECTOR_VERSION_KEY;
use crate::types::{EntityId, ScoredEntity, VaultConfig, ENTITY_ID_LEN};

const ENTRY_POINT_KEY: &[u8] = b"entry_point";
pub(crate) const COUNT_KEY: &[u8] = b"count";
const ERR_ENTRY_POINT_MISSING: &str = "hnsw count > 0 but entry point is missing";
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

    let Some(entry_point) = read_entry_point(store, rtxn)? else {
        return Ok(Vec::new());
    };

    let mut nearest = beam_search(
        store,
        rtxn,
        query_vector,
        entry_point,
        config.hnsw.ef_search.max(limit),
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

    let backlink_targets = collect_backlink_targets(store, &*wtxn, id)?;
    store.hnsw_neighbors.delete(wtxn, id.as_bytes())?;
    scrub_backlinks_in_place(store, wtxn, id, &backlink_targets)?;

    let count = read_count(store, &*wtxn)?;
    let new_count = count
        .checked_sub(1)
        .ok_or(Error::CorruptedIndex(ERR_COUNT_UNDERFLOW))?;
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
        let replacement = parse_entity_id(replacement_key, ERR_NEIGHBOR_KEY_BYTES)?;
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
    check_existence: bool,
) -> Result<Vec<HeapEntry>> {
    let ef = ef.max(1);
    let mut vector_buffer = Vec::with_capacity(query_vector.len());

    let Some(entry_vector) = load_vector_into(store, txn, &entry_point, &mut vector_buffer)? else {
        return Ok(Vec::new());
    };

    let entry = HeapEntry {
        id: entry_point,
        distance: cosine_distance(query_vector, entry_vector),
    };

    let mut candidates: BinaryHeap<Reverse<HeapEntry>> = BinaryHeap::new();
    let mut results: BinaryHeap<HeapEntry> = BinaryHeap::new();
    let graph_nodes = usize::try_from(store.hnsw_neighbors.len(txn)?).unwrap_or(usize::MAX);
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

        let neighbors = load_neighbors(store, txn, &current.id)?;
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
    let capacity = usize::try_from(store.vectors.len(txn)?).unwrap_or(usize::MAX);
    let mut vector_ids = Vec::with_capacity(capacity);
    for entry in store.vectors.iter(txn)? {
        let (key, _) = entry?;
        vector_ids.push(parse_entity_id(key, ERR_VECTOR_KEY_BYTES)?);
    }
    Ok(vector_ids)
}

fn select_best_entry_point(
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
        if reach > best_reach || (reach == best_reach && candidate.as_bytes() < best.as_bytes()) {
            best = candidate;
            best_reach = reach;
            if best_reach == neighbors_by_id.len() {
                break;
            }
        }
    }

    Some(best)
}

fn reachable_from_entry(
    neighbors_by_id: &HashMap<EntityId, Vec<EntityId>>,
    entry_point: EntityId,
) -> HashSet<EntityId> {
    let mut visited = HashSet::with_capacity(neighbors_by_id.len().max(1));
    let mut frontier = vec![entry_point];

    while let Some(current) = frontier.pop() {
        if !visited.insert(current) {
            continue;
        }
        if let Some(neighbors) = neighbors_by_id.get(&current) {
            frontier.extend(neighbors.iter().copied());
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

    parse_entity_id(raw, ERR_ENTRY_POINT_BYTES).map(Some)
}

fn parse_entity_id(bytes: &[u8], err: &'static str) -> Result<EntityId> {
    let raw: [u8; ENTITY_ID_LEN] = bytes.try_into().map_err(|_| Error::CorruptedIndex(err))?;
    Ok(EntityId::from_bytes(raw))
}

fn load_neighbors(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<Vec<EntityId>> {
    let Some(raw) = store.hnsw_neighbors.get(txn, id.as_bytes())? else {
        return Ok(Vec::new());
    };

    if raw.len() % ENTITY_ID_LEN != 0 {
        return Err(Error::CorruptedIndex(ERR_NEIGHBOR_VALUE_BYTES));
    }

    raw.chunks_exact(ENTITY_ID_LEN)
        .map(|chunk| parse_entity_id(chunk, ERR_NEIGHBOR_VALUE_BYTES))
        .collect()
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
        let node_id = parse_entity_id(key, ERR_NEIGHBOR_KEY_BYTES)?;
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
    use crate::store::Store;
    use crate::types::{TimeRange, VaultConfig};
    use crate::Vault;

    fn test_config() -> VaultConfig {
        let mut config = VaultConfig::device();
        config.dimensions = 4;
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
        let vault = Vault::open(temp_dir.path(), config.clone())?;
        let a = EntityId::now();
        let b = EntityId::now();
        let c = EntityId::now();

        for id in [a, b, c] {
            vault.put_entity(&id, 0, point(1, 1), 1, b"node")?;
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
            vault.put_entity(&id, 0, point(1, 1), 1, b"node")?;
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
            vault.put_entity(&id, 0, point(1, 1), 1, b"node")?;
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

    #[test]
    fn hnsw_search_reports_corrupted_neighbor_bytes() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        vault.put_entity(&id, 0, point(1, 1), 1, b"node")?;
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
        assert!(matches!(
            err,
            Error::CorruptedIndex(message) if message == ERR_NEIGHBOR_VALUE_BYTES
        ));
        Ok(())
    }

    #[test]
    fn hnsw_search_reports_corrupted_vector_bytes() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        vault.put_entity(&id, 0, point(1, 1), 1, b"node")?;
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
        assert!(matches!(
            err,
            Error::CorruptedIndex(message) if message == ERR_VECTOR_BYTES
        ));
        Ok(())
    }

    #[test]
    fn hnsw_search_reports_corrupted_entry_point_bytes() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        vault.put_entity(&id, 0, point(1, 1), 1, b"node")?;
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
        assert!(matches!(
            err,
            Error::CorruptedIndex(message) if message == ERR_ENTRY_POINT_BYTES
        ));
        Ok(())
    }

    #[test]
    fn hnsw_insert_reports_corrupted_count_bytes() -> Result<()> {
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
        assert!(matches!(
            err,
            Error::CorruptedIndex(message) if message == ERR_COUNT_BYTES
        ));
        Ok(())
    }

    #[test]
    fn hnsw_insert_reports_non_empty_graph_when_count_is_zero() -> Result<()> {
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
        assert!(matches!(
            err,
            Error::CorruptedIndex(message) if message == ERR_ZERO_COUNT_GRAPH_NOT_EMPTY
        ));
        Ok(())
    }

    #[test]
    fn read_vector_version_reports_corrupted_bytes() -> Result<()> {
        let temp_dir = tempdir()?;
        let store = Store::open(temp_dir.path(), &test_config())?;
        let mut wtxn = store.env.write_txn()?;
        store
            .hnsw_meta
            .put(&mut wtxn, VECTOR_VERSION_KEY, &[1, 2, 3])?;

        let err = read_vector_version(&store, &wtxn).expect_err("expected corrupted version bytes");
        assert!(matches!(
            err,
            Error::CorruptedIndex(message) if message == ERR_VECTOR_VERSION_BYTES
        ));
        Ok(())
    }

    #[test]
    fn select_best_entry_point_prefers_full_reachability() {
        let a = EntityId::now();
        let b = EntityId::now();
        let c = EntityId::now();
        let neighbors = HashMap::from([(a, vec![c]), (b, vec![a]), (c, vec![a])]);

        assert_eq!(select_best_entry_point(&neighbors, Some(a)), Some(b));
        assert_eq!(reachable_from_entry(&neighbors, b).len(), neighbors.len());
    }
}
