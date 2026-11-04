//! Persisted vector-index metadata and admission vocabulary.

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::overlay_db::OverlayDb;
use crate::store::{EMBEDDING_MODEL_EPOCH_KEY, ManifestDbs, VECTOR_VERSION_KEY};
use heed::{RoTxn, RwTxn};

pub(crate) mod keys;
pub(crate) mod rebuild;
pub(crate) use keys::COUNT_KEY;
use keys::{
    ENTRY_POINT_KEY, ERR_COUNT_BYTES, ERR_EMBEDDING_MODEL_EPOCH_BYTES, ERR_VECTOR_VERSION_BYTES,
};

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

/// Whether a read admits one node a walk scored as a match, judged in the
/// walk's own transaction. A node it refuses still connects the walk.
pub(crate) type Admission<'a> = dyn Fn(&RoTxn<'_>, &EntityId) -> Result<bool> + 'a;
