//! `Store::open` / `Store::open_existing` and the fail-closed open-time gate
//! sequence: vault-root preflight, DB-manifest create/validate, storage
//! ABI/schema gates, HNSW config and embedding-model gates, and open-time
//! migrations. The exact gate order is documented on [`crate::store`].

mod hnsw_model_gates;
mod manifest_storage_gates;
mod open_create_door;
mod open_existing_door;
mod open_version_keys;
mod vault_root_bind;

pub(crate) use self::hnsw_model_gates::{
    ensure_model_id_for_vector_write, format_hnsw_distance_metric, format_hnsw_index_structure,
    parse_utf8_bytes, read_hnsw_compatibility, read_vault_meta_u16, validate_embedding_model_id,
};
pub(in crate::store) use self::manifest_storage_gates::RegisteredPath;
pub(crate) use self::manifest_storage_gates::{
    OwnedEnv, lmdb_database_open_guard, materialized_database_names,
};
pub use self::open_version_keys::{
    DB_MANIFEST, DB_MANIFEST_VERSION, DbManifestEntry, MAX_DBS, STORAGE_ABI_VERSION,
    STORAGE_SCHEMA_VERSION, StorageMigrationPlan,
};
pub(crate) use self::open_version_keys::{
    DefaultPolicySeedMode, EMBEDDING_MODEL_EPOCH_KEY, GRAPH_VERSION_KEY, HnswCompatibilityState,
    MODEL_ID_KEY, STORAGE_ABI_VERSION_KEY, STORAGE_SCHEMA_VERSION_KEY,
    TEXT_ANALYZER_MANIFEST_HASH_KEY, TEXT_ANALYZER_MANIFEST_KEY, TEXT_BM25_FIELD_SCHEMA_HASH_KEY,
    TEXT_INDEX_SCHEMA_VERSION, TEXT_INDEX_SCHEMA_VERSION_KEY, VECTOR_VERSION_KEY,
};
// Test-only seam (gate/mod.rs precedent): the store test suite names these
// bare through `use super::*`, but no non-test code outside `open_gates/`
// reaches them through the seam, so the re-exports live under `cfg(test)`.
#[cfg(test)]
pub(crate) use self::manifest_storage_gates::StorageAbiGate;
#[cfg(test)]
pub(in crate::store) use self::manifest_storage_gates::gate_storage_abi_value;
#[cfg(test)]
pub(in crate::store) use self::open_version_keys::{
    HNSW_COMPATIBILITY_LEN, HNSW_COMPATIBILITY_V2_LEN, HNSW_COMPATIBILITY_V2_VERSION,
    HNSW_COMPATIBILITY_VERSION, HNSW_DISTANCE_METRIC_COSINE, HNSW_INDEX_STRUCTURE_FLAT_NSW,
    RECEIPT_FAMILY_INDEX_VERSION, RECEIPT_FAMILY_INDEX_VERSION_KEY,
};
#[cfg(test)]
pub(crate) use self::open_version_keys::{
    HNSW_CONFIG_KEY, STORAGE_ABI_VERSION_V3_REKEY_PREDECESSOR,
    TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY,
};
