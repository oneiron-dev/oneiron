//! Persisted vector-index metadata and admission vocabulary, defined in
//! `oneiron_store::vector_index`: each counter is read and bumped through the
//! store's own `hnsw_meta` table.

use crate::error::Result;
use crate::store::ManifestDbs;
use heed::{RoTxn, RwTxn};

pub(crate) mod rebuild;
pub(crate) use oneiron_store::vector_index::keys;
pub(crate) use oneiron_store::vector_index::keys::COUNT_KEY;
pub(crate) use oneiron_store::vector_index::{Admission, has_population};

pub(crate) fn read_vector_version(store: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<u64> {
    oneiron_store::vector_index::read_vector_version(store.hnsw_meta(), txn)
}

pub(crate) fn read_embedding_model_epoch(store: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<u64> {
    oneiron_store::vector_index::read_embedding_model_epoch(store.hnsw_meta(), txn)
}

pub(crate) fn increment_vector_version(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
) -> Result<u64> {
    oneiron_store::vector_index::increment_vector_version(store.hnsw_meta(), wtxn)
}

pub(crate) fn increment_embedding_model_epoch(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
) -> Result<u64> {
    oneiron_store::vector_index::increment_embedding_model_epoch(store.hnsw_meta(), wtxn)
}
