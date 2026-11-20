//! Version stamps, vault-meta key consts, HNSW layout consts, error strings, process locks, DB manifest, and migration-plan/compat types.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex};

use crate::config::VaultConfig;

use super::vault_root_bind::VaultRootIdentity;

#[doc(hidden)]
pub use oneiron_records::store::open_gates::open_version_keys::{
    DB_MANIFEST, DB_MANIFEST_VERSION, DbManifestEntry, MAX_DBS, STORAGE_ABI_VERSION,
    STORAGE_SCHEMA_VERSION,
};

pub(crate) const STORAGE_ABI_VERSION_KEY: &[u8] = b"storage_abi_version";

pub(crate) const STORAGE_SCHEMA_VERSION_KEY: &[u8] = b"schema_version";

pub(crate) const MODEL_ID_KEY: &[u8] = b"model_id";

pub(crate) use oneiron_store::graph_version::GRAPH_VERSION_KEY;

pub(crate) const HNSW_CONFIG_KEY: &[u8] = b"hnsw_config";

pub(crate) const TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY: &[u8] =
    b"temporal_long_intervals_schema_version";

pub(super) const TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION: u8 = 2;

pub(crate) use oneiron_store::vector_index::keys::{EMBEDDING_MODEL_EPOCH_KEY, VECTOR_VERSION_KEY};

pub(in crate::store) const HNSW_COMPATIBILITY_VERSION: u8 = 3;

pub(super) const HNSW_COMPATIBILITY_V0_LEN: usize = 24;

pub(super) const HNSW_COMPATIBILITY_V1_LEN: usize = 25;

pub(in crate::store) const HNSW_COMPATIBILITY_V2_LEN: usize = 27;

/// v3 layout = v2 layout (version u8, dimensions u64le, m_max_0 u64le,
/// ef_construction u64le, distance_metric u8, index_structure u8) +
/// `fast_dims` u16le at bytes 27..29 (wire `0` = None).
pub(in crate::store) const HNSW_COMPATIBILITY_LEN: usize = 29;

pub(in crate::store) const HNSW_COMPATIBILITY_V2_VERSION: u8 = 2;

pub(super) const HNSW_DISTANCE_METRIC_MISSING: u8 = 0;

pub(in crate::store) const HNSW_DISTANCE_METRIC_COSINE: u8 = 1;

pub(super) const HNSW_INDEX_STRUCTURE_MISSING: u8 = 0;

pub(in crate::store) const HNSW_INDEX_STRUCTURE_FLAT_NSW: u8 = 1;

#[cfg(any(unix, windows))]
pub(super) const VAULT_ROOT_IDENTITY_CHECKS_AVAILABLE: bool = true;

#[cfg(not(any(unix, windows)))]
pub(super) const VAULT_ROOT_IDENTITY_CHECKS_AVAILABLE: bool = false;

pub(super) const ERR_POPULATED_MISSING_MODEL_ID: &str =
    "populated vault is missing embedding model identity; rebuild or migrate it before reopening";

pub(super) const ERR_POPULATED_REQUIRES_EMBEDDING_MODEL: &str =
    "embedding model is required to open a populated vector vault";

pub(super) const ERR_VECTOR_WRITE_REQUIRES_EMBEDDING_MODEL: &str =
    "embedding model is required before writing vectors";

/// `Store::open` writes a missing HNSW compatibility record on an unpopulated
/// vault. `Store::open_existing` refuses instead: a vault whose persisted
/// graph shape was never recorded has no identity to be reopened against, and
/// that door writes nothing before every comparison has passed.
pub(super) const ERR_EXISTING_MISSING_HNSW_CONFIG: &str =
    "existing vault has no persisted vector/hnsw compatibility record to reopen against";

/// The analyzer bypass exists so `MaintenanceBuilder::clear_text_index` can
/// run through the create-capable door. The existing-only door compares the
/// stored analyzer identity exactly, so a bypass request is refused rather
/// than silently ignored.
pub(super) const ERR_EXISTING_NO_ANALYZER_BYPASS: &str =
    "skip_text_index_manifest_check is not available on an existing-only open";

/// How an absent nullable embedding-model identity renders inside the exact
/// existing-only comparison. It cannot collide with a real id: the grammar is
/// `org/name@revision`, which always carries a `/` and an `@`.
pub(super) const MODEL_ID_NONE: &str = "none";

pub(super) static LMDB_DATABASE_OPEN_LOCK: Mutex<()> = Mutex::new(());

pub(super) static VAULT_ROOT_OPEN_LOCK: Mutex<()> = Mutex::new(());

/// One open store's place in [`OPEN_STORE_PATHS`]: the root identity it
/// holds, and the vault handles its leader holds (FIX 12316).
pub(super) struct OpenStorePath {
    pub(super) identity: Option<VaultRootIdentity>,
    pub(super) holds: crate::store::LeaderHolds,
}

pub(super) static OPEN_STORE_PATHS: LazyLock<Mutex<HashMap<PathBuf, OpenStorePath>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(in crate::store) const RECEIPT_FAMILY_INDEX_VERSION_KEY: &[u8] =
    b"receipt_family_index:v1:version";

/// Receipt-family ABI-pin rule: changing this requires a
/// [`STORAGE_ABI_VERSION`] bump.
pub(in crate::store) const RECEIPT_FAMILY_INDEX_VERSION: u8 = 1;

/// Production reads/writes of these rows now go through the typed
/// `side_table::{TEXT_INDEX_SCHEMA_VERSION, TEXT_ANALYZER_MANIFEST,
/// TEXT_BM25_FIELD_SCHEMA_HASH}` tables bound in `vault::doctor_manifest`.
/// The raw index-version and analyzer-body keys stay `#[cfg(test)]`; the two
/// hash keys below are production reads for replay identity.
#[cfg(test)]
pub(crate) const TEXT_INDEX_SCHEMA_VERSION_KEY: &[u8] = b"text_index_schema_version";

#[cfg(test)]
pub(crate) const TEXT_ANALYZER_MANIFEST_KEY: &[u8] = b"text_analyzer_manifest";

pub(crate) const TEXT_ANALYZER_MANIFEST_HASH_KEY: &[u8] = b"text_analyzer_manifest_hash";

pub(crate) const TEXT_BM25_FIELD_SCHEMA_HASH_KEY: &[u8] = b"text_bm25_field_schema_hash";

/// Current text-index schema version written on new vaults.
/// * v1 = pre-ONE-317 hand-rolled tokenizer (never written — greenfield).
/// * v2 = ONE-317 analyzer + BM25F (this release).
pub(crate) const TEXT_INDEX_SCHEMA_VERSION: u16 = 2;

/// Scaffold for a future storage-schema migration runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageMigrationPlan {
    Initialize,
    Current,
    Required { from: Option<u16>, to: u16 },
}

impl StorageMigrationPlan {
    #[must_use]
    pub fn for_stored_schema_version(stored: Option<u16>, new_vault: bool) -> Self {
        match stored {
            Some(STORAGE_SCHEMA_VERSION) => Self::Current,
            Some(from) => Self::Required {
                from: Some(from),
                to: STORAGE_SCHEMA_VERSION,
            },
            None if new_vault => Self::Initialize,
            None => Self::Required {
                from: None,
                to: STORAGE_SCHEMA_VERSION,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PersistedHnswCompatibility {
    pub(crate) dimensions: usize,
    pub(crate) m_max_0: usize,
    pub(crate) ef_construction: usize,
    pub(crate) distance_metric: u8,
    pub(crate) index_structure: u8,
    /// MRL fast-lane prefix (EMB-2). Part of persisted graph shape: the NSW
    /// graph is built over this prefix, so changing it on a populated vault
    /// fails `HnswConfigChanged` like any other shape field.
    pub(crate) fast_dims: Option<u16>,
}

impl PersistedHnswCompatibility {
    pub(super) fn from_config(config: &VaultConfig) -> Self {
        Self {
            dimensions: config.dimensions,
            m_max_0: config.hnsw.m_max_0,
            ef_construction: config.hnsw.ef_construction,
            // `ef_search` is intentionally excluded: it is a search-time beam
            // width and can be retuned without changing persisted graph shape
            // or vector scoring semantics.
            distance_metric: HNSW_DISTANCE_METRIC_COSINE,
            index_structure: HNSW_INDEX_STRUCTURE_FLAT_NSW,
            fast_dims: config.fast_dims,
        }
    }
}

pub(crate) enum HnswCompatibilityState {
    Missing,
    Current(PersistedHnswCompatibility),
}

/// Raw LMDB database handles for the 28 named databases (ARCH-0019 manifest).
///
/// These are the base handles a per-handle [`OverlayDb`] view wraps. They are
/// reserved for open-time machinery and for constructing accessor views —
/// runtime readers and writers MUST go through the [`OverlayDb`] accessors on
/// [`Store`] so a session write-overlay (ARCH-0052) composes at one seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DefaultPolicySeedMode {
    Required,
    #[cfg(feature = "test-support")]
    TestUnseeded,
}
