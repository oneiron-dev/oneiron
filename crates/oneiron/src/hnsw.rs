use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};

use heed::{RoTxn, RwTxn};

use crate::distance::cosine_distance;
use crate::error::{Error, Result};
use crate::le_bytes_to_f32_vec;
use crate::store::Store;
use crate::types::{EntityId, ScoredEntity, VaultConfig, ENTITY_ID_LEN};

const ENTRY_POINT_KEY: &[u8] = b"entry_point";
const COUNT_KEY: &[u8] = b"count";

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
    // Idempotent upsert behavior for repeated vector writes.
    if store.hnsw_neighbors.get(&*wtxn, id.as_bytes())?.is_some() {
        return Ok(());
    }

    let mut count = read_count(store, &*wtxn)?;
    if count == 0 {
        store.hnsw_meta.put(wtxn, ENTRY_POINT_KEY, id.as_bytes())?;
        store.hnsw_meta.put(wtxn, COUNT_KEY, &1_u64.to_le_bytes())?;
        store.hnsw_neighbors.put(wtxn, id.as_bytes(), &[])?;
        return Ok(());
    }

    let entry_point = read_entry_point(store, &*wtxn)?.ok_or(Error::InvalidKey)?;
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

    count = count.checked_add(1).ok_or(Error::InvalidKey)?;
    store.hnsw_meta.put(wtxn, COUNT_KEY, &count.to_le_bytes())?;

    Ok(())
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
        config.hnsw.ef_search,
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

pub(crate) fn hnsw_deindex(store: &Store, wtxn: &mut RwTxn<'_>, id: &EntityId) -> Result<()> {
    let had_entry = store.hnsw_neighbors.delete(wtxn, id.as_bytes())?;
    if !had_entry {
        return Ok(());
    }

    let count = read_count(store, &*wtxn)?;
    let new_count = count.saturating_sub(1);
    store
        .hnsw_meta
        .put(wtxn, COUNT_KEY, &new_count.to_le_bytes())?;

    let is_entry_point = store
        .hnsw_meta
        .get(&*wtxn, ENTRY_POINT_KEY)?
        .is_some_and(|raw| raw == id.as_bytes());
    if is_entry_point {
        let replacement = store
            .hnsw_neighbors
            .first(&*wtxn)?
            .map(|(key, _)| key.to_vec());

        if let Some(key) = replacement {
            store.hnsw_meta.put(wtxn, ENTRY_POINT_KEY, &key)?;
        } else {
            store.hnsw_meta.delete(wtxn, ENTRY_POINT_KEY)?;
            store.hnsw_meta.put(wtxn, COUNT_KEY, &0_u64.to_le_bytes())?;
        }
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

    let Some(entry_vector) = load_vector(store, txn, &entry_point)? else {
        return Ok(Vec::new());
    };

    let entry = HeapEntry {
        id: entry_point,
        distance: cosine_distance(query_vector, &entry_vector),
    };

    let mut candidates: BinaryHeap<Reverse<HeapEntry>> = BinaryHeap::new();
    let mut results: BinaryHeap<HeapEntry> = BinaryHeap::new();
    let mut visited: HashSet<EntityId> = HashSet::new();

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

            let Some(neighbor_vector) = load_vector(store, txn, &neighbor_id)? else {
                continue;
            };

            let distance = cosine_distance(query_vector, &neighbor_vector);
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

fn read_count(store: &Store, txn: &RoTxn<'_>) -> Result<u64> {
    let Some(raw) = store.hnsw_meta.get(txn, COUNT_KEY)? else {
        return Ok(0);
    };

    let bytes: [u8; 8] = raw.try_into().map_err(|_| Error::InvalidKey)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_entry_point(store: &Store, txn: &RoTxn<'_>) -> Result<Option<EntityId>> {
    let Some(raw) = store.hnsw_meta.get(txn, ENTRY_POINT_KEY)? else {
        return Ok(None);
    };

    parse_entity_id(raw).map(Some)
}

fn parse_entity_id(bytes: &[u8]) -> Result<EntityId> {
    let raw: [u8; ENTITY_ID_LEN] = bytes.try_into().map_err(|_| Error::InvalidKey)?;
    Ok(EntityId::from_bytes(raw))
}

fn load_neighbors(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<Vec<EntityId>> {
    let Some(raw) = store.hnsw_neighbors.get(txn, id.as_bytes())? else {
        return Ok(Vec::new());
    };

    if !raw.len().is_multiple_of(ENTITY_ID_LEN) {
        return Err(Error::InvalidKey);
    }

    raw.chunks_exact(ENTITY_ID_LEN)
        .map(parse_entity_id)
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

    le_bytes_to_f32_vec(raw).map(Some)
}

fn prune_neighbors_for_node(
    store: &Store,
    txn: &RoTxn<'_>,
    node_id: &EntityId,
    neighbors: &[EntityId],
    max_neighbors: usize,
) -> Result<Vec<EntityId>> {
    let Some(node_vector) = load_vector(store, txn, node_id)? else {
        return Ok(neighbors.iter().copied().take(max_neighbors).collect());
    };

    let mut seen = HashSet::with_capacity(neighbors.len());
    let mut scored = Vec::with_capacity(neighbors.len());

    for neighbor_id in neighbors {
        if *neighbor_id == *node_id || !seen.insert(*neighbor_id) {
            continue;
        }

        let Some(neighbor_vector) = load_vector(store, txn, neighbor_id)? else {
            continue;
        };

        scored.push(HeapEntry {
            id: *neighbor_id,
            distance: cosine_distance(&node_vector, &neighbor_vector),
        });
    }

    scored.sort_unstable();
    scored.truncate(max_neighbors);

    Ok(scored.into_iter().map(|entry| entry.id).collect())
}
