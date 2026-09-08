//! Metadata/counter reads and neighbor/vector codec.

use std::collections::{HashMap, HashSet};

use heed::{RoTxn, RwTxn};

use crate::distance::{PreparedCosine, cosine_distance};
use crate::entity_id::{ENTITY_ID_LEN, EntityId, parse_entity_id};
use crate::error::{Error, Result};
use crate::overlay_db::OverlayDb;
use crate::store::{EMBEDDING_MODEL_EPOCH_KEY, ManifestDbs, VECTOR_VERSION_KEY};

use super::keys::{
    COUNT_KEY, ENTRY_POINT_KEY, ERR_COUNT_BYTES, ERR_EMBEDDING_MODEL_EPOCH_BYTES,
    ERR_ENTRY_POINT_BYTES, ERR_NEIGHBOR_KEY_BYTES, ERR_NEIGHBOR_VALUE_BYTES, ERR_VECTOR_BYTES,
    ERR_VECTOR_VERSION_BYTES,
};
use super::search::score_prefix;
use super::slim_drop::hnsw_is_dropped;
use super::types::HeapEntry;

pub(crate) fn read_vector_version(store: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<u64> {
    let Some(raw) = store.hnsw_meta().get(txn, VECTOR_VERSION_KEY)? else {
        return Ok(0);
    };

    let bytes: [u8; 8] = raw
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex(ERR_VECTOR_VERSION_BYTES))?;
    Ok(u64::from_le_bytes(bytes))
}

pub(crate) fn read_embedding_model_epoch(store: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<u64> {
    let Some(raw) = store.hnsw_meta().get(txn, EMBEDDING_MODEL_EPOCH_KEY)? else {
        return Ok(0);
    };

    let bytes: [u8; 8] = raw
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex(ERR_EMBEDDING_MODEL_EPOCH_BYTES))?;
    Ok(u64::from_le_bytes(bytes))
}

pub(crate) fn has_population(hnsw_meta: &OverlayDb, txn: &RoTxn<'_>) -> Result<bool> {
    if let Some(raw) = hnsw_meta.get(txn, COUNT_KEY)? {
        let bytes: [u8; 8] = raw
            .as_ref()
            .try_into()
            .map_err(|_| Error::CorruptedIndex(ERR_COUNT_BYTES))?;
        if u64::from_le_bytes(bytes) > 0 {
            return Ok(true);
        }
    }

    Ok(hnsw_meta.get(txn, ENTRY_POINT_KEY)?.is_some())
}

pub(crate) fn increment_vector_version(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
) -> Result<u64> {
    let current = read_vector_version(store, &*wtxn)?;
    let next = current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("vector version"))?;
    store
        .hnsw_meta()
        .put(wtxn, VECTOR_VERSION_KEY, &next.to_le_bytes())?;
    Ok(next)
}

pub(crate) fn increment_embedding_model_epoch(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
) -> Result<u64> {
    let current = read_embedding_model_epoch(store, &*wtxn)?;
    let next = current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("embedding model epoch"))?;
    store
        .hnsw_meta()
        .put(wtxn, EMBEDDING_MODEL_EPOCH_KEY, &next.to_le_bytes())?;
    Ok(next)
}

pub(super) fn read_count(store: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<u64> {
    let Some(raw) = store.hnsw_meta().get(txn, COUNT_KEY)? else {
        return Ok(0);
    };

    let bytes: [u8; 8] = raw
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex(ERR_COUNT_BYTES))?;
    Ok(u64::from_le_bytes(bytes))
}

/// Live indexed-entity count.
///
/// While the SLIM dropped marker is set (ONE-1933 / OF-447) the graph shape is
/// absent but the source corpus is intact, so this reports the SOURCE-VECTOR
/// count rather than the absent graph-node count. Dropped means "graph shape
/// absent", not "empty corpus" — which is what keeps `PipelineBuilder`'s
/// fence-widening loop correct without editing `pipeline.rs`.
pub(crate) fn hnsw_entity_count(store: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<usize> {
    if hnsw_is_dropped(store, txn)? {
        return usize::try_from(store.vectors().len(txn)?)
            .map_err(|_| Error::IndexOverflow("hnsw entity count"));
    }
    usize::try_from(read_count(store, txn)?).map_err(|_| Error::IndexOverflow("hnsw entity count"))
}

pub(super) fn read_entry_point(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
) -> Result<Option<EntityId>> {
    let Some(raw) = store.hnsw_meta().get(txn, ENTRY_POINT_KEY)? else {
        return Ok(None);
    };

    parse_entity_id(&raw, ERR_ENTRY_POINT_BYTES)
        .map_err(|e| match e {
            Error::InvalidKey => Error::CorruptedIndex(ERR_ENTRY_POINT_BYTES),
            other => other,
        })
        .map(Some)
}

pub(super) fn decode_neighbors(raw: &[u8], lenient: bool) -> Result<Vec<EntityId>> {
    let (chunks, rem) = raw.as_chunks::<ENTITY_ID_LEN>();
    if !rem.is_empty() {
        return Err(Error::CorruptedIndex(ERR_NEIGHBOR_VALUE_BYTES));
    }

    let mut neighbors = Vec::with_capacity(chunks.len());
    for bytes in chunks {
        match EntityId::from_bytes(*bytes) {
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

pub(super) fn load_neighbors(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Vec<EntityId>> {
    let Some(raw) = store.hnsw_neighbors().get(txn, id.as_bytes())? else {
        return Ok(Vec::new());
    };

    decode_neighbors(&raw, false)
}

pub(super) fn load_neighbors_lenient(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Vec<EntityId>> {
    let Some(raw) = store.hnsw_neighbors().get(txn, id.as_bytes())? else {
        return Ok(Vec::new());
    };

    decode_neighbors(&raw, true)
}

pub(super) fn write_neighbors(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    neighbors: &[EntityId],
) -> Result<()> {
    let mut bytes = Vec::with_capacity(neighbors.len() * ENTITY_ID_LEN);
    for neighbor in neighbors {
        bytes.extend_from_slice(neighbor.as_bytes());
    }

    store.hnsw_neighbors().put(wtxn, id.as_bytes(), &bytes)?;
    Ok(())
}

pub(super) fn load_vector(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    dimensions: usize,
) -> Result<Option<Vec<f32>>> {
    let Some(raw) = store.vectors().get(txn, id.as_bytes())? else {
        return Ok(None);
    };

    let mut vector = Vec::new();
    decode_vector_into(&raw, dimensions, &mut vector)?;
    Ok(Some(vector))
}

pub(super) fn load_vector_into<'a>(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    dimensions: usize,
    scratch: &'a mut Vec<f32>,
) -> Result<Option<&'a [f32]>> {
    let Some(raw) = store.vectors().get(txn, id.as_bytes())? else {
        return Ok(None);
    };

    decode_vector_into(&raw, dimensions, scratch).map(Some)
}

pub(super) fn load_required_vector(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    dimensions: usize,
) -> Result<Vec<f32>> {
    load_vector(store, txn, id, dimensions)?.ok_or(Error::InvariantViolation(
        "validated rebuild vector disappeared within the same read snapshot",
    ))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn prune_neighbors_for_node(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    node_id: &EntityId,
    neighbors: &[EntityId],
    max_neighbors: usize,
    score_dims: usize,
    dimensions: usize,
    ops: &mut u64,
) -> Result<Vec<EntityId>> {
    let mut node_buffer = Vec::new();
    *ops += 1;
    let Some(node_vector) = load_vector_into(store, txn, node_id, dimensions, &mut node_buffer)?
    else {
        return Ok(neighbors.iter().copied().take(max_neighbors).collect());
    };
    let mut neighbor_buffer = Vec::with_capacity(node_vector.len());

    // The pruned node is the query for every neighbor comparison, so its norm
    // is prepared once for the whole pass. A row too short to prefix is
    // corruption; leave that error on the per-neighbor path below so a node
    // whose neighbor rows have all vanished still returns `Ok` exactly as
    // before, instead of failing earlier.
    let prepared_node = score_prefix(node_vector, score_dims)
        .ok()
        .map(PreparedCosine::new);

    let mut seen = HashSet::with_capacity(neighbors.len());
    let mut scored = Vec::with_capacity(neighbors.len());

    for neighbor_id in neighbors {
        if *neighbor_id == *node_id || !seen.insert(*neighbor_id) {
            continue;
        }

        *ops += 1;
        let Some(neighbor_vector) =
            load_vector_into(store, txn, neighbor_id, dimensions, &mut neighbor_buffer)?
        else {
            continue;
        };

        let distance = match prepared_node.as_ref() {
            Some(prepared) => prepared.distance(score_prefix(neighbor_vector, score_dims)?),
            None => cosine_distance(
                score_prefix(node_vector, score_dims)?,
                score_prefix(neighbor_vector, score_dims)?,
            ),
        };

        scored.push(HeapEntry {
            id: *neighbor_id,
            distance,
        });
    }

    scored.sort_unstable();
    scored.truncate(max_neighbors);

    Ok(scored.into_iter().map(|entry| entry.id).collect())
}

/// Legacy-only delete-time full scan. Symmetric-marker vaults never call
/// this: their backlinks are exactly the node's own forward neighbor list.
pub(super) fn collect_backlink_targets(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    ops: &mut u64,
) -> Result<Vec<EntityId>> {
    let mut targets = Vec::new();
    for entry in store.hnsw_neighbors().iter(txn)? {
        *ops += 1;
        let (key, raw) = entry?;
        let node_id = parse_entity_id(&key, ERR_NEIGHBOR_KEY_BYTES).map_err(|e| match e {
            Error::InvalidKey => Error::CorruptedIndex(ERR_NEIGHBOR_KEY_BYTES),
            other => other,
        })?;
        if node_id == *id {
            continue;
        }

        if !neighbor_bytes_contain(&raw, id)? {
            continue;
        }
        targets.push(node_id);
    }
    Ok(targets)
}

pub(super) fn scrub_backlinks_in_place(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    targets: &[EntityId],
    ops: &mut u64,
) -> Result<()> {
    for node_id in targets {
        *ops += 1;
        let Some(raw) = store.hnsw_neighbors().get(&*wtxn, node_id.as_bytes())? else {
            continue;
        };
        let Some(scrubbed) = scrub_neighbor_bytes(&raw, id)? else {
            continue;
        };
        store
            .hnsw_neighbors()
            .put(wtxn, node_id.as_bytes(), &scrubbed)?;
        *ops += 1;
    }
    Ok(())
}

/// In-memory mirror of [`detach_reverse_link`] for the snapshot rebuilder:
/// removes `from` out of `victim`'s list, keeping the link one-way when the
/// victim would otherwise be orphaned.
pub(super) fn detach_reverse_link_in_memory(
    neighbors_by_id: &mut HashMap<EntityId, Vec<EntityId>>,
    from: &EntityId,
    victim: &EntityId,
) {
    let Some(list) = neighbors_by_id.get_mut(victim) else {
        return;
    };
    if !list.contains(from) || list.len() == 1 {
        return;
    }
    list.retain(|entry| entry != from);
}

pub(super) fn neighbor_bytes_contain(raw: &[u8], target: &EntityId) -> Result<bool> {
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

fn decode_vector_into<'a>(
    raw: &[u8],
    dimensions: usize,
    scratch: &'a mut Vec<f32>,
) -> Result<&'a [f32]> {
    crate::store::decode_vector_row_into(raw, dimensions, scratch)
        .map_err(|_| Error::CorruptedIndex(ERR_VECTOR_BYTES))
}
