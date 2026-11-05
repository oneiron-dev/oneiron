//! Persisted vector-index metadata and admission vocabulary: the `hnsw_meta`
//! keys and counters, read and bumped through a store's `hnsw_meta` table.

use heed::{RoTxn, RwTxn};
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::error::{Error, Result};

use crate::overlay_db::OverlayDb;

pub mod keys;
use keys::{
    COUNT_KEY, EMBEDDING_MODEL_EPOCH_KEY, ENTRY_POINT_KEY, ERR_COUNT_BYTES,
    ERR_EMBEDDING_MODEL_EPOCH_BYTES, ERR_VECTOR_VERSION_BYTES, VECTOR_VERSION_KEY,
};

/// The vector version counter in `hnsw_meta`; zero when unset.
pub fn read_vector_version(hnsw_meta: &OverlayDb, txn: &RoTxn<'_>) -> Result<u64> {
    let Some(raw) = hnsw_meta.get(txn, VECTOR_VERSION_KEY)? else {
        return Ok(0);
    };

    let bytes: [u8; 8] = raw
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex(ERR_VECTOR_VERSION_BYTES))?;
    Ok(u64::from_le_bytes(bytes))
}

/// The embedding model epoch counter in `hnsw_meta`; zero when unset.
pub fn read_embedding_model_epoch(hnsw_meta: &OverlayDb, txn: &RoTxn<'_>) -> Result<u64> {
    let Some(raw) = hnsw_meta.get(txn, EMBEDDING_MODEL_EPOCH_KEY)? else {
        return Ok(0);
    };

    let bytes: [u8; 8] = raw
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex(ERR_EMBEDDING_MODEL_EPOCH_BYTES))?;
    Ok(u64::from_le_bytes(bytes))
}

/// Whether the graph holds any node: a positive count or an entry point.
pub fn has_population(hnsw_meta: &OverlayDb, txn: &RoTxn<'_>) -> Result<bool> {
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

/// Bumps the vector version counter in `wtxn` and returns the new value.
pub fn increment_vector_version(hnsw_meta: &OverlayDb, wtxn: &mut RwTxn<'_>) -> Result<u64> {
    let current = read_vector_version(hnsw_meta, &*wtxn)?;
    let next = current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("vector version"))?;
    hnsw_meta.put(wtxn, VECTOR_VERSION_KEY, &next.to_le_bytes())?;
    Ok(next)
}

/// Bumps the embedding model epoch counter in `wtxn` and returns the new
/// value.
pub fn increment_embedding_model_epoch(hnsw_meta: &OverlayDb, wtxn: &mut RwTxn<'_>) -> Result<u64> {
    let current = read_embedding_model_epoch(hnsw_meta, &*wtxn)?;
    let next = current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("embedding model epoch"))?;
    hnsw_meta.put(wtxn, EMBEDDING_MODEL_EPOCH_KEY, &next.to_le_bytes())?;
    Ok(next)
}

/// Whether a read admits one node a walk scored as a match, judged in the
/// walk's own transaction. A node it refuses still connects the walk.
pub type Admission<'a> = dyn Fn(&RoTxn<'_>, &EntityId) -> Result<bool> + 'a;

/// What the vector index reads and writes through a store handle: its three
/// tables, whether reads see an overlay over base, and the engine checks a
/// walk and a graph clear run. The engine implements it for each of its
/// store handles; each check is the engine function of the same purpose,
/// run on that handle.
pub trait VectorIndexDbs {
    /// The stored vector rows.
    fn index_vectors(&self) -> &OverlayDb;
    /// The HNSW neighbor lists.
    fn index_neighbors(&self) -> &OverlayDb;
    /// The HNSW metadata: entry point, count, markers and counters.
    fn index_meta(&self) -> &OverlayDb;
    /// Whether reads see an overlay over base rather than base alone.
    fn index_reads_union(&self) -> bool;
    /// Whether the entity row `id` is present in `txn`.
    fn index_entity_present(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool>;
    /// Whether any dependent walk is pending in `txn`.
    fn index_any_pending_walk(&self, txn: &RoTxn<'_>) -> Result<bool>;
    /// Whether `id` is archived in `txn`.
    fn index_is_archived(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool>;
    /// Whether `id` is stale behind a pending dependent walk in `txn`.
    fn index_is_stale(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool>;
    /// Clears every source vector's embedding-device row in `wtxn`.
    fn index_clear_embedding_devices(&self, wtxn: &mut RwTxn<'_>) -> Result<()>;
}
