//! LMDB store: one environment per vault plus the 25 named databases pinned
//! by the ARCH-0019 manifest, and the fail-closed open-time gates.
//!
//! # Canonical open-gate sequence (`Store::open` → `Vault::open`)
//!
//! Gates run in this exact order. The FIRST failing gate aborts the open with
//! its typed error and **no usable `Store`/`Vault` handle is returned**. Every
//! error path also releases the process-local path registration, so a retry
//! observes the same gate failure again rather than a phantom
//! "vault path is already open" error.
//!
//! `Store::open` — steps 1–4 run inside a single write transaction while
//! holding [`lmdb_database_open_guard`] (`mdb_dbi_open` is transaction-scoped:
//! the txn that opens a DBI must finish before another txn opens one):
//!
//! 1. **`vault_meta` (manifest DB #5) is created/opened FIRST.** Rationale:
//!    the storage-version gate (step 2) reads its versions FROM `vault_meta`,
//!    so an existing vault with a missing/blank `vault_meta` is caught by the
//!    ABI gate as [`StorageAbiVersionChanged`]`{ stored: None, .. }` — not by
//!    the manifest gate. Creating it first cannot mask a genuinely missing
//!    database: the manifest-set gate (step 3) runs BEFORE the other 24
//!    manifest DBs are (re)created in this transaction, so any of those
//!    missing is still detected.
//! 2. **`gate_storage_versions`** — storage ABI gate, then schema gate.
//!    * `vault_meta["storage_abi_version"]` (u16 LE) ≠
//!      [`STORAGE_ABI_VERSION`], or absent on an existing vault →
//!      [`StorageAbiVersionChanged`].
//!    * `vault_meta["schema_version"]` (u16 LE) ≠ [`STORAGE_SCHEMA_VERSION`],
//!      or absent on an existing vault → [`StorageSchemaVersionChanged`].
//!    * New vaults stamp both current versions instead of gating.
//! 3. **`validate_db_manifest_set`** (existing vaults) — the named-database
//!    set in the environment must equal the 25-entry [`DB_MANIFEST`] exactly;
//!    any missing or unexpected name → [`DbManifestMismatch`]. New vaults run
//!    this validation after step 4 instead (nothing pre-exists to validate).
//! 4. The remaining 24 manifest DBs are created/opened, the transaction
//!    commits, and the DBI-open guard is released.
//! 5. **`preflight_hnsw_config`** — `hnsw_meta["hnsw_config"]` (27-byte v2
//!    record: dimensions, m_max_0, ef_construction, distance_metric,
//!    index_structure; `ef_search` is a search-time knob and deliberately
//!    excluded). A mismatch, or a legacy-shape record on a vault with
//!    persisted vector/HNSW data → [`HnswConfigChanged`]; a missing record on
//!    a populated vault → [`InvalidConfig`].
//! 6. **`preflight_embedding_model`** — `hnsw_meta["model_id"]` (UTF-8).
//!    Stored ≠ requested → [`EmbeddingModelChanged`]; a populated vault whose
//!    stored id is missing, or a populated vault opened without a requested
//!    model → [`InvalidConfig`].
//! 7. `migrate_temporal_long_intervals_if_needed`
//!    (`hnsw_meta["temporal_long_intervals_schema_version"]`), then the
//!    persist-if-missing writes for the HNSW config / model id validated
//!    above (each re-checks under its own write transaction).
//!
//! `Vault::open` — after `Store::open` returns:
//!
//! 8. **Analyzer / BM25F handshake** (`handshake_text_index_manifest`) — keys
//!    `vault_meta["text_index_schema_version"]`,
//!    `vault_meta["text_analyzer_manifest"]` /
//!    `vault_meta["text_analyzer_manifest_hash"]`, and
//!    `vault_meta["text_bm25_field_schema_hash"]`. On a populated text index:
//!    a per-language analyzer mode flip (or a pre-ONE-317 / corrupt manifest)
//!    → [`IncompatibleAnalyzer`]; a diverged BM25F field schema →
//!    [`Bm25FieldSchemaChanged`]. The
//!    [`VaultConfig::skip_text_index_manifest_check`] escape hatch sits HERE
//!    and only here: it bypasses this final gate so
//!    `MaintenanceBuilder::clear_text_index` can run; on a populated index it
//!    marks the text index untrusted so text reads/writes fail closed with
//!    `Error::CorruptedIndex` until the clear commits.
//!
//! # Compat-key homes (ONE-1097 owner decision: documented, not consolidated)
//!
//! `vault_meta` (#5) owns the storage/schema and text-index identity keys,
//! plus the per-type short-id counters (`b"sid_counter:" ‖ type_byte` → u64
//! LE, see [`SHORT_ID_COUNTER_KEY_PREFIX`]); `hnsw_meta` (#8) owns the
//! vector-side compatibility keys (`model_id`, `hnsw_config`) alongside HNSW
//! runtime metadata (`entry_point`, `count`, graph/vector version counters).
//! Consolidating the vector compat keys into `vault_meta` would be a storage
//! migration with no behavioral win, so the split is intentional and
//! documented here instead.
//!
//! [`StorageAbiVersionChanged`]: crate::error::Error::StorageAbiVersionChanged
//! [`StorageSchemaVersionChanged`]: crate::error::Error::StorageSchemaVersionChanged
//! [`DbManifestMismatch`]: crate::error::Error::DbManifestMismatch
//! [`HnswConfigChanged`]: crate::error::Error::HnswConfigChanged
//! [`EmbeddingModelChanged`]: crate::error::Error::EmbeddingModelChanged
//! [`InvalidConfig`]: crate::error::Error::InvalidConfig
//! [`IncompatibleAnalyzer`]: crate::error::Error::IncompatibleAnalyzer
//! [`Bm25FieldSchemaChanged`]: crate::error::Error::Bm25FieldSchemaChanged
//! [`VaultConfig::skip_text_index_manifest_check`]: crate::types::VaultConfig::skip_text_index_manifest_check

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::str;
use std::sync::{LazyLock, Mutex, MutexGuard};

use heed::types::{Bytes, Str};
use heed::{Database, DatabaseFlags, Env, EnvOpenOptions, RwTxn};

use crate::error::{Error, Result};
use crate::types::{EdgeKind, EntityId, VaultConfig};

// Contract-pinned at 32 by ARCH-0019/ARCH-0031: 25 named DBs plus headroom.
pub const MAX_DBS: u32 = 32;
/// v4 (ONE-299): `text_postings` became a DUP_SORT database holding one
/// posting entry per (term, entity) duplicate item, and `text_forward`
/// records dropped the dead `tf` u32. v3 vaults fail closed at the ABI
/// gate — there is no silent migration; rebuild the vault.
pub const STORAGE_ABI_VERSION: u16 = 4;
pub(crate) const STORAGE_ABI_VERSION_KEY: &[u8] = b"storage_abi_version";
pub const STORAGE_SCHEMA_VERSION: u16 = 1;
pub(crate) const STORAGE_SCHEMA_VERSION_KEY: &[u8] = b"schema_version";
pub(crate) const MODEL_ID_KEY: &[u8] = b"model_id";
pub(crate) const GRAPH_VERSION_KEY: &[u8] = b"graph_version";
pub(crate) const HNSW_CONFIG_KEY: &[u8] = b"hnsw_config";
pub(crate) const TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY: &[u8] =
    b"temporal_long_intervals_schema_version";
const TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION: u8 = 2;
pub(crate) const VECTOR_VERSION_KEY: &[u8] = b"vector_version";
const HNSW_COMPATIBILITY_VERSION: u8 = 2;
const HNSW_COMPATIBILITY_V0_LEN: usize = 24;
const HNSW_COMPATIBILITY_V1_LEN: usize = 25;
const HNSW_COMPATIBILITY_LEN: usize = 27;
const HNSW_DISTANCE_METRIC_MISSING: u8 = 0;
const HNSW_DISTANCE_METRIC_COSINE: u8 = 1;
const HNSW_INDEX_STRUCTURE_MISSING: u8 = 0;
// ARCH-0019 fixes the graph as flat single-layer NSW; the upper-layer M value
// stays compile-time-only because this structure has no upper layers.
const HNSW_INDEX_STRUCTURE_FLAT_NSW: u8 = 1;
const ERR_POPULATED_MISSING_MODEL_ID: &str =
    "populated vault is missing embedding model identity; rebuild or migrate it before reopening";
const ERR_POPULATED_REQUIRES_EMBEDDING_MODEL: &str =
    "embedding model is required to open a populated vector vault";
const ERR_VECTOR_WRITE_REQUIRES_EMBEDDING_MODEL: &str =
    "embedding model is required before writing vectors";
static LMDB_DATABASE_OPEN_LOCK: Mutex<()> = Mutex::new(());
static OPEN_STORE_PATHS: LazyLock<Mutex<HashSet<PathBuf>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// `vault_meta` key prefix for the per-type short-id counters (M2-5 /
/// ONE-1102, storage ABI v3). The full key is the 12-byte ASCII prefix
/// `b"sid_counter:"` followed by the raw entity type byte (13 bytes total);
/// the value is the last issued counter as u64 LE. These counters previously
/// lived as `[type_byte, 0xFF x15]` sentinel rows inside `short_ids`; they
/// were relocated so `short_ids` holds only the contract's manifest rows
/// (ARCH-0019 row n3: `(short_id, content_hash)` -> `entity_id`).
pub(crate) const SHORT_ID_COUNTER_KEY_PREFIX: &[u8] = b"sid_counter:";
pub(crate) const SHORT_ID_COUNTER_KEY_LEN: usize = 13;
const _: () = assert!(SHORT_ID_COUNTER_KEY_PREFIX.len() + 1 == SHORT_ID_COUNTER_KEY_LEN);

/// Encodes the `vault_meta` key for the short-id counter of `entity_type`.
/// See [`SHORT_ID_COUNTER_KEY_PREFIX`] for the documented key scheme.
pub(crate) fn short_id_counter_key(entity_type: u8) -> [u8; SHORT_ID_COUNTER_KEY_LEN] {
    let mut key = [0u8; SHORT_ID_COUNTER_KEY_LEN];
    key[..SHORT_ID_COUNTER_KEY_PREFIX.len()].copy_from_slice(SHORT_ID_COUNTER_KEY_PREFIX);
    key[SHORT_ID_COUNTER_KEY_PREFIX.len()] = entity_type;
    key
}

// BM25F / analyzer schema v2 keys. All live in the new `vault_meta` DB.
pub(crate) const TEXT_INDEX_SCHEMA_VERSION_KEY: &[u8] = b"text_index_schema_version";
pub(crate) const TEXT_ANALYZER_MANIFEST_KEY: &[u8] = b"text_analyzer_manifest";
pub(crate) const TEXT_ANALYZER_MANIFEST_HASH_KEY: &[u8] = b"text_analyzer_manifest_hash";
pub(crate) const TEXT_BM25_FIELD_SCHEMA_HASH_KEY: &[u8] = b"text_bm25_field_schema_hash";
/// Current text-index schema version written on new vaults.
/// * v1 = pre-ONE-317 hand-rolled tokenizer (never written — greenfield).
/// * v2 = ONE-317 analyzer + BM25F (this release).
pub(crate) const TEXT_INDEX_SCHEMA_VERSION: u16 = 2;

/// Oneiron DB manifest derived from the ARCH-0019 contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DbManifestEntry {
    pub n: u8,
    pub name: &'static str,
    pub group: &'static str,
}

pub const DB_MANIFEST: [DbManifestEntry; 25] = [
    DbManifestEntry {
        n: 1,
        name: "entities",
        group: "Core",
    },
    DbManifestEntry {
        n: 2,
        name: "type_index",
        group: "Core",
    },
    DbManifestEntry {
        n: 3,
        name: "short_ids",
        group: "Core",
    },
    DbManifestEntry {
        n: 4,
        name: "short_ids_reverse",
        group: "Core",
    },
    DbManifestEntry {
        n: 5,
        name: "vault_meta",
        group: "Core",
    },
    DbManifestEntry {
        n: 6,
        name: "vectors",
        group: "Vector",
    },
    DbManifestEntry {
        n: 7,
        name: "hnsw_neighbors",
        group: "Vector",
    },
    DbManifestEntry {
        n: 8,
        name: "hnsw_meta",
        group: "Vector",
    },
    DbManifestEntry {
        n: 9,
        name: "text_postings",
        group: "Text",
    },
    DbManifestEntry {
        n: 10,
        name: "text_meta",
        group: "Text",
    },
    DbManifestEntry {
        n: 11,
        name: "text_forward",
        group: "Text",
    },
    DbManifestEntry {
        n: 12,
        name: "text_bm25_field_stats",
        group: "Text",
    },
    DbManifestEntry {
        n: 13,
        name: "text_doc_field_lengths",
        group: "Text",
    },
    DbManifestEntry {
        n: 14,
        name: "edges_out",
        group: "Graph",
    },
    DbManifestEntry {
        n: 15,
        name: "edges_in",
        group: "Graph",
    },
    DbManifestEntry {
        n: 16,
        name: "ppr_cache",
        group: "Graph",
    },
    DbManifestEntry {
        n: 17,
        name: "ppr_cache_deps",
        group: "Graph",
    },
    DbManifestEntry {
        n: 18,
        name: "temporal_occurred_start",
        group: "Temporal",
    },
    DbManifestEntry {
        n: 19,
        name: "temporal_occurred_end",
        group: "Temporal",
    },
    DbManifestEntry {
        n: 20,
        name: "temporal_learned",
        group: "Temporal",
    },
    DbManifestEntry {
        n: 21,
        name: "temporal_long_intervals",
        group: "Temporal",
    },
    DbManifestEntry {
        n: 22,
        name: "phonetic_index",
        group: "Phonetic",
    },
    DbManifestEntry {
        n: 23,
        name: "phonetic_forward",
        group: "Phonetic",
    },
    DbManifestEntry {
        n: 24,
        name: "sync_state",
        group: "Sync",
    },
    DbManifestEntry {
        n: 25,
        name: "sync_queue",
        group: "Sync",
    },
];

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

/// Future migrations plug in here; v1 only classifies and rejects.
pub trait StorageMigrationRunner {
    fn run(&mut self, plan: StorageMigrationPlan) -> Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PersistedHnswCompatibility {
    pub(crate) dimensions: usize,
    pub(crate) m_max_0: usize,
    pub(crate) ef_construction: usize,
    pub(crate) distance_metric: u8,
    pub(crate) index_structure: u8,
}

impl PersistedHnswCompatibility {
    fn from_config(config: &VaultConfig) -> Self {
        Self {
            dimensions: config.dimensions,
            m_max_0: config.hnsw.m_max_0,
            ef_construction: config.hnsw.ef_construction,
            // `ef_search` is intentionally excluded: it is a search-time beam
            // width and can be retuned without changing persisted graph shape
            // or vector scoring semantics.
            distance_metric: HNSW_DISTANCE_METRIC_COSINE,
            index_structure: HNSW_INDEX_STRUCTURE_FLAT_NSW,
        }
    }
}

pub(crate) enum HnswCompatibilityState {
    Missing,
    Legacy(PersistedHnswCompatibility),
    Current(PersistedHnswCompatibility),
}

/// LMDB environment and database handles for a vault.
///
/// Dropping the last handle to a `Store` (normally via the owning
/// [`crate::Vault`]) CLOSES the LMDB environment — see [`OwnedEnv`] for the
/// close-path rationale (ONE-1142).
pub struct Store {
    pub(crate) env: OwnedEnv,
    pub(crate) entities: Database<Bytes, Bytes>,
    pub(crate) edges_out: Database<Bytes, Bytes>,
    pub(crate) edges_in: Database<Bytes, Bytes>,
    pub(crate) vectors: Database<Bytes, Bytes>,
    pub(crate) hnsw_neighbors: Database<Bytes, Bytes>,
    pub(crate) hnsw_meta: Database<Bytes, Bytes>,
    /// Fielded inverted index, opened with `DUP_SORT` (storage ABI v4 /
    /// ONE-299). Key: term bytes. Each duplicate data item is ONE posting
    /// entry `entity_id(16) | field_count(u8) | (field_id_u16_be |
    /// tf_u32_le)*`; LMDB keeps duplicates bytewise sorted, so items order
    /// by entity-id prefix and an index append never reads the list.
    pub(crate) text_postings: Database<Bytes, Bytes>,
    pub(crate) text_meta: Database<Bytes, Bytes>,
    pub(crate) text_forward: Database<Bytes, Bytes>,
    /// BM25F per-field corpus stats.
    /// Key: `field_id` big-endian u16.
    /// Value: `[doc_count_u32_le | total_length_u64_le]`.
    pub(crate) text_bm25_field_stats: Database<Bytes, Bytes>,
    /// Per-doc, per-field surface-token lengths used by the BM25F length
    /// normalization term. Key: entity_id (16B). Value: a flat
    /// `[(field_id_u16_be | length_u32_le)*]` list over present fields.
    pub(crate) text_doc_field_lengths: Database<Bytes, Bytes>,
    /// Vault-level metadata (analyzer manifest, schema version, field
    /// schema hash). Read on `Vault::open` to gate index compatibility.
    pub(crate) vault_meta: Database<Bytes, Bytes>,
    pub(crate) ppr_cache: Database<Bytes, Bytes>,
    pub(crate) ppr_cache_deps: Database<Bytes, Bytes>,
    pub(crate) type_index: Database<Bytes, Bytes>,
    pub(crate) temporal_occurred_start: Database<Bytes, Bytes>,
    pub(crate) temporal_occurred_end: Database<Bytes, Bytes>,
    pub(crate) temporal_learned: Database<Bytes, Bytes>,
    pub(crate) temporal_long_intervals: Database<Bytes, Bytes>,
    pub(crate) phonetic_index: Database<Bytes, Bytes>,
    pub(crate) phonetic_forward: Database<Bytes, Bytes>,
    pub(crate) short_ids: Database<Bytes, Bytes>,
    pub(crate) short_ids_reverse: Database<Bytes, Bytes>,
    /// CRDT Doc states, state vectors, pending updates, metadata. Present in
    /// EVERY build (ONE-1132): the delete path writes its CRDT-independent
    /// `pt:` pending-tombstone marker here unconditionally, so deletion
    /// durability never depends on the `sync` cargo feature.
    pub(crate) sync_state: Database<Str, Bytes>,
    /// Offline update queue, embed job queue, and hard-delete sweep queue.
    pub(crate) sync_queue: Database<Bytes, Bytes>,
    // DROP-ORDER: keep this field after `env`. Fields drop in declaration
    // order, so the path registry releases the path only after [`OwnedEnv`]
    // has closed the LMDB environment — a reopen racing this drop can never
    // observe the path as free while the old environment is still live.
    _registered_path: RegisteredPath,
}

impl Store {
    /// Opens or creates a store at `path` and initializes all named databases.
    pub fn open(path: impl AsRef<Path>, config: &VaultConfig) -> Result<Self> {
        std::fs::create_dir_all(path.as_ref())?;
        let canonical_path = path.as_ref().canonicalize()?;
        let is_new_vault = !canonical_path.join("data.mdb").exists();
        let registered_path = RegisteredPath::reserve(canonical_path.clone())?;

        // SAFETY: heed/LMDB require a single Env per filesystem path, the path
        // must not be on NFS or another unsupported network filesystem, and
        // map_size must not be changed concurrently while the environment is
        // open elsewhere. The path existence/writability precondition is
        // established by create_dir_all above. The caller must not retarget the
        // canonicalized filesystem path while it is being opened, and the
        // process-local registry above rejects a second live Env for the same
        // canonical path.
        let env = unsafe {
            EnvOpenOptions::new()
                .map_size(config.map_size)
                .max_readers(config.max_readers)
                .max_dbs(MAX_DBS)
                .open(&canonical_path)?
        };
        // Wrap IMMEDIATELY so every `?` early-return below (failed open
        // gates) also releases the environment instead of leaking it into
        // heed's process-global registry (ONE-1142).
        let env = OwnedEnv { env };

        let db_open_guard = lmdb_database_open_guard()?;
        let mut wtxn = env.write_txn()?;
        let vault_meta = create_manifest_db(&env, &mut wtxn, 4)?;
        gate_storage_versions(&vault_meta, &mut wtxn, is_new_vault)?;
        if !is_new_vault {
            validate_db_manifest_set(&env, &wtxn)?;
        }

        let entities = create_manifest_db(&env, &mut wtxn, 0)?;
        let type_index = create_manifest_db(&env, &mut wtxn, 1)?;
        let short_ids = create_manifest_db(&env, &mut wtxn, 2)?;
        let short_ids_reverse = create_manifest_db(&env, &mut wtxn, 3)?;
        let vectors = create_manifest_db(&env, &mut wtxn, 5)?;
        let hnsw_neighbors = create_manifest_db(&env, &mut wtxn, 6)?;
        let hnsw_meta = create_manifest_db(&env, &mut wtxn, 7)?;
        let text_postings = create_manifest_dupsort_db(&env, &mut wtxn, 8)?;
        let text_meta = create_manifest_db(&env, &mut wtxn, 9)?;
        let text_forward = create_manifest_db(&env, &mut wtxn, 10)?;
        let text_bm25_field_stats = create_manifest_db(&env, &mut wtxn, 11)?;
        let text_doc_field_lengths = create_manifest_db(&env, &mut wtxn, 12)?;
        let edges_out = create_manifest_db(&env, &mut wtxn, 13)?;
        let edges_in = create_manifest_db(&env, &mut wtxn, 14)?;
        let ppr_cache = create_manifest_db(&env, &mut wtxn, 15)?;
        let ppr_cache_deps = create_manifest_db(&env, &mut wtxn, 16)?;
        let temporal_occurred_start = create_manifest_db(&env, &mut wtxn, 17)?;
        let temporal_occurred_end = create_manifest_db(&env, &mut wtxn, 18)?;
        let temporal_learned = create_manifest_db(&env, &mut wtxn, 19)?;
        let temporal_long_intervals = create_manifest_db(&env, &mut wtxn, 20)?;
        let phonetic_index = create_manifest_db(&env, &mut wtxn, 21)?;
        let phonetic_forward = create_manifest_db(&env, &mut wtxn, 22)?;
        let sync_state = create_manifest_str_db(&env, &mut wtxn, 23)?;
        let sync_queue = create_manifest_db(&env, &mut wtxn, 24)?;
        if is_new_vault {
            validate_db_manifest_set(&env, &wtxn)?;
        }
        wtxn.commit()?;
        drop(db_open_guard);

        let should_persist_hnsw_config =
            preflight_hnsw_config(&env, &hnsw_meta, &vectors, &hnsw_neighbors, config)?;
        let should_persist_model_id = preflight_embedding_model(
            &env,
            &hnsw_meta,
            &vectors,
            &hnsw_neighbors,
            config.embedding_model.as_deref(),
        )?;
        migrate_temporal_long_intervals_if_needed(&env, &hnsw_meta, &temporal_long_intervals)?;

        if should_persist_hnsw_config {
            persist_hnsw_config_if_missing(&env, &hnsw_meta, &vectors, &hnsw_neighbors, config)?;
        }

        if should_persist_model_id {
            let requested = config
                .embedding_model
                .as_deref()
                .ok_or_else(|| Error::InvalidConfig("missing embedding model".to_owned()))?;
            persist_model_id_if_missing(&env, &hnsw_meta, &vectors, &hnsw_neighbors, requested)?;
        }

        Ok(Self {
            env,
            entities,
            edges_out,
            edges_in,
            vectors,
            hnsw_neighbors,
            hnsw_meta,
            text_postings,
            text_meta,
            text_forward,
            text_bm25_field_stats,
            text_doc_field_lengths,
            vault_meta,
            ppr_cache,
            ppr_cache_deps,
            type_index,
            temporal_occurred_start,
            temporal_occurred_end,
            temporal_learned,
            temporal_long_intervals,
            phonetic_index,
            phonetic_forward,
            short_ids,
            short_ids_reverse,
            sync_state,
            sync_queue,
            _registered_path: registered_path,
        })
    }

    /// Encodes an edge key as `[src(16) | kind(1) | tgt(16)]`.
    pub fn encode_edge_key(src: &EntityId, kind: EdgeKind, tgt: &EntityId) -> [u8; 33] {
        let mut key = [0_u8; 33];
        key[..16].copy_from_slice(src.as_bytes());
        key[16] = kind as u8;
        key[17..].copy_from_slice(tgt.as_bytes());
        key
    }

    /// Encodes a temporal key as `[timestamp_be(8) | id(16)]`.
    pub fn encode_temporal_key(ts: u64, id: &EntityId) -> [u8; 24] {
        let mut key = [0_u8; 24];
        key[..8].copy_from_slice(&ts.to_be_bytes());
        key[8..].copy_from_slice(id.as_bytes());
        key
    }

    /// Encodes a type key as `[entity_type(1) | id(16)]`.
    pub fn encode_type_key(entity_type: u8, id: &EntityId) -> [u8; 17] {
        let mut key = [0_u8; 17];
        key[0] = entity_type;
        key[1..].copy_from_slice(id.as_bytes());
        key
    }
}

struct RegisteredPath {
    path: PathBuf,
}

impl RegisteredPath {
    fn reserve(path: PathBuf) -> Result<Self> {
        let mut open_paths = OPEN_STORE_PATHS
            .lock()
            .map_err(|_| Error::InvariantViolation("store path registry mutex poisoned"))?;

        if !open_paths.insert(path.clone()) {
            return Err(Error::InvalidConfig(format!(
                "vault path is already open in this process: {}",
                path.display()
            )));
        }

        Ok(Self { path })
    }
}

impl Drop for RegisteredPath {
    fn drop(&mut self) {
        let mut open_paths = match OPEN_STORE_PATHS.lock() {
            Ok(open_paths) => open_paths,
            Err(poisoned) => poisoned.into_inner(),
        };
        open_paths.remove(&self.path);
    }
}

/// Sole owner of the vault's LMDB environment; restores close-on-last-drop
/// semantics (ONE-1142).
///
/// heed 0.20 keeps a clone of every opened [`Env`] in a process-global
/// registry, so dropping all user-held clones never runs `mdb_env_close`:
/// the mmap, the `data.mdb`/`lock.mdb` descriptors, and — the binding
/// constraint — the per-environment pthread TLS key LMDB allocates in
/// `mdb_env_setup_locks` all leak for the life of the process. macOS caps
/// pthread keys at `PTHREAD_KEYS_MAX = 512`, so a process that opens vaults
/// dynamically (a long-lived sync server, the test suite) hits a
/// deterministic `Vault::open` EAGAIN cliff around the ~509th cumulative
/// open. Closing requires an explicit [`Env::prepare_for_closing`], which
/// this crate previously never called.
///
/// Dropping this wrapper calls `prepare_for_closing`, which removes the
/// registry's clone; the environment then actually closes (`mdb_env_close`)
/// when the last remaining `Env` clone drops — normally the wrapped `env`
/// itself, immediately after the `Drop` body returns: transactions only
/// borrow the env, and this crate never stores `Env` clones outside
/// [`Store`].
///
/// The close path is deliberately RAII rather than an explicit
/// `Vault::close()`: a forgotten explicit close would silently reintroduce
/// the leak, while drop-based closing cannot be skipped and composes with
/// the existing `Arc<Vault>` holders (sync manager, observers, the server's
/// `SyncServer.vault`) — the last clone to drop closes the environment.
pub(crate) struct OwnedEnv {
    env: Env,
}

impl std::ops::Deref for OwnedEnv {
    type Target = Env;

    fn deref(&self) -> &Env {
        &self.env
    }
}

impl Drop for OwnedEnv {
    fn drop(&mut self) {
        // Deliberately NOT waiting on the returned `EnvClosingEvent`: this
        // thread still holds an `Env` clone (`self.env`), so waiting here
        // would deadlock. `mdb_env_close` runs when `self.env` drops, right
        // after this body returns.
        let _closing_event = self.env.clone().prepare_for_closing();
    }
}

fn create_db(env: &Env, wtxn: &mut RwTxn<'_>, name: &str) -> Result<Database<Bytes, Bytes>> {
    Ok(env.create_database::<Bytes, Bytes>(wtxn, Some(name))?)
}

pub(crate) fn lmdb_database_open_guard() -> Result<MutexGuard<'static, ()>> {
    LMDB_DATABASE_OPEN_LOCK
        .lock()
        .map_err(|_| Error::InvariantViolation("lmdb database-open mutex poisoned"))
}

fn create_manifest_db(
    env: &Env,
    wtxn: &mut RwTxn<'_>,
    manifest_index: usize,
) -> Result<Database<Bytes, Bytes>> {
    create_db(env, wtxn, DB_MANIFEST[manifest_index].name)
}

fn create_manifest_str_db(
    env: &Env,
    wtxn: &mut RwTxn<'_>,
    manifest_index: usize,
) -> Result<Database<Str, Bytes>> {
    Ok(env.create_database::<Str, Bytes>(wtxn, Some(DB_MANIFEST[manifest_index].name))?)
}

/// Creates/opens a manifest database with `MDB_DUPSORT` (storage ABI v4:
/// only `text_postings`). LMDB persists database flags, so reopening an
/// existing database created without `DUP_SORT` fails closed with
/// `MDB_INCOMPATIBLE` — but a pre-v4 vault is already rejected earlier by
/// the storage-ABI gate.
fn create_manifest_dupsort_db(
    env: &Env,
    wtxn: &mut RwTxn<'_>,
    manifest_index: usize,
) -> Result<Database<Bytes, Bytes>> {
    Ok(env
        .database_options()
        .types::<Bytes, Bytes>()
        .name(DB_MANIFEST[manifest_index].name)
        .flags(DatabaseFlags::DUP_SORT)
        .create(wtxn)?)
}

fn validate_db_manifest_set(env: &Env, wtxn: &RwTxn<'_>) -> Result<()> {
    let env_names = materialized_database_names(env, wtxn)?;
    let expected: HashSet<&str> = DB_MANIFEST.iter().map(|entry| entry.name).collect();
    let present: HashSet<&str> = env_names.iter().map(String::as_str).collect();

    let mut missing: Vec<String> = DB_MANIFEST
        .iter()
        .map(|entry| entry.name)
        .filter(|name| !present.contains(name))
        .map(str::to_owned)
        .collect();
    let mut unexpected: Vec<String> = env_names
        .into_iter()
        .filter(|name| !expected.contains(name.as_str()))
        .collect();

    missing.sort();
    unexpected.sort();
    if missing.is_empty() && unexpected.is_empty() {
        Ok(())
    } else {
        Err(Error::DbManifestMismatch {
            missing,
            unexpected,
        })
    }
}

pub(crate) fn materialized_database_names(env: &Env, txn: &heed::RoTxn<'_>) -> Result<Vec<String>> {
    let main = env
        .open_database::<Bytes, Bytes>(txn, None)?
        .ok_or(Error::InvariantViolation("missing unnamed lmdb database"))?;

    let mut names = Vec::new();
    for row in main.iter(txn)? {
        let (key, _) = row?;
        if key.contains(&0) {
            continue;
        }
        names.push(
            str::from_utf8(key)
                .map_err(|_| Error::InvalidKey)?
                .to_owned(),
        );
    }
    names.sort();
    Ok(names)
}

fn gate_storage_versions(
    vault_meta: &Database<Bytes, Bytes>,
    wtxn: &mut RwTxn<'_>,
    new_vault: bool,
) -> Result<()> {
    let stored_abi = read_vault_meta_u16(
        vault_meta,
        &*wtxn,
        STORAGE_ABI_VERSION_KEY,
        "storage ABI version",
    )?;
    match stored_abi {
        Some(STORAGE_ABI_VERSION) => {}
        Some(stored) => {
            return Err(Error::StorageAbiVersionChanged {
                stored: Some(stored),
                current: STORAGE_ABI_VERSION,
            });
        }
        None if new_vault => {
            vault_meta.put(
                wtxn,
                STORAGE_ABI_VERSION_KEY,
                &STORAGE_ABI_VERSION.to_le_bytes(),
            )?;
        }
        None => {
            return Err(Error::StorageAbiVersionChanged {
                stored: None,
                current: STORAGE_ABI_VERSION,
            });
        }
    }

    let stored_schema = read_vault_meta_u16(
        vault_meta,
        &*wtxn,
        STORAGE_SCHEMA_VERSION_KEY,
        "storage schema version",
    )?;
    match StorageMigrationPlan::for_stored_schema_version(stored_schema, new_vault) {
        StorageMigrationPlan::Initialize => {
            vault_meta.put(
                wtxn,
                STORAGE_SCHEMA_VERSION_KEY,
                &STORAGE_SCHEMA_VERSION.to_le_bytes(),
            )?;
        }
        StorageMigrationPlan::Current => {}
        StorageMigrationPlan::Required { from, to } => {
            return Err(Error::StorageSchemaVersionChanged {
                stored: from,
                current: to,
            });
        }
    }

    Ok(())
}

pub(crate) fn read_vault_meta_u16(
    vault_meta: &Database<Bytes, Bytes>,
    txn: &heed::RoTxn<'_>,
    key: &[u8],
    context: &'static str,
) -> Result<Option<u16>> {
    let Some(raw) = vault_meta.get(txn, key)? else {
        return Ok(None);
    };
    let bytes: [u8; 2] = raw.try_into().map_err(|_| Error::CorruptedIndex(context))?;
    Ok(Some(u16::from_le_bytes(bytes)))
}

fn preflight_embedding_model(
    env: &Env,
    hnsw_meta: &Database<Bytes, Bytes>,
    vectors: &Database<Bytes, Bytes>,
    hnsw_neighbors: &Database<Bytes, Bytes>,
    requested: Option<&str>,
) -> Result<bool> {
    let rtxn = env.read_txn()?;
    match hnsw_meta.get(&rtxn, MODEL_ID_KEY)? {
        Some(raw) => {
            let stored = parse_utf8_bytes(raw)?;
            match requested {
                Some(requested) if stored != requested => Err(Error::EmbeddingModelChanged {
                    stored,
                    requested: requested.to_owned(),
                }),
                Some(_) => Ok(false),
                None if has_persisted_vector_or_hnsw_data(
                    hnsw_meta,
                    vectors,
                    hnsw_neighbors,
                    &rtxn,
                )? =>
                {
                    Err(Error::InvalidConfig(
                        ERR_POPULATED_REQUIRES_EMBEDDING_MODEL.to_owned(),
                    ))
                }
                None => Ok(false),
            }
        }
        None if has_persisted_vector_or_hnsw_data(hnsw_meta, vectors, hnsw_neighbors, &rtxn)? => {
            Err(Error::InvalidConfig(
                ERR_POPULATED_MISSING_MODEL_ID.to_owned(),
            ))
        }
        None => Ok(requested.is_some()),
    }
}

fn preflight_hnsw_config(
    env: &Env,
    hnsw_meta: &Database<Bytes, Bytes>,
    vectors: &Database<Bytes, Bytes>,
    hnsw_neighbors: &Database<Bytes, Bytes>,
    requested: &VaultConfig,
) -> Result<bool> {
    let rtxn = env.read_txn()?;
    match read_hnsw_compatibility(hnsw_meta, &rtxn)? {
        HnswCompatibilityState::Current(stored) => {
            let requested = PersistedHnswCompatibility::from_config(requested);
            if stored != requested {
                return Err(Error::HnswConfigChanged {
                    stored: format_hnsw_compatibility(&stored),
                    requested: format_hnsw_compatibility(&requested),
                });
            }
            Ok(false)
        }
        HnswCompatibilityState::Missing => {
            if has_persisted_vector_or_hnsw_data(hnsw_meta, vectors, hnsw_neighbors, &rtxn)? {
                return Err(Error::InvalidConfig(
                    "populated vault is missing complete vector/hnsw compatibility metadata; rebuild or migrate it before reopening".to_owned(),
                ));
            }
            Ok(true)
        }
        HnswCompatibilityState::Legacy(stored) => {
            let requested = PersistedHnswCompatibility::from_config(requested);
            if has_persisted_vector_or_hnsw_data(hnsw_meta, vectors, hnsw_neighbors, &rtxn)? {
                return Err(Error::HnswConfigChanged {
                    stored: format_hnsw_compatibility(&stored),
                    requested: format_hnsw_compatibility(&requested),
                });
            }
            Ok(true)
        }
    }
}

fn persist_hnsw_config_if_missing(
    env: &Env,
    hnsw_meta: &Database<Bytes, Bytes>,
    vectors: &Database<Bytes, Bytes>,
    hnsw_neighbors: &Database<Bytes, Bytes>,
    requested: &VaultConfig,
) -> Result<()> {
    let requested = PersistedHnswCompatibility::from_config(requested);
    let encoded = encode_hnsw_config(&requested)?;
    let mut wtxn = env.write_txn()?;
    match read_hnsw_compatibility(hnsw_meta, &wtxn)? {
        HnswCompatibilityState::Current(stored) => {
            if stored != requested {
                return Err(Error::HnswConfigChanged {
                    stored: format_hnsw_compatibility(&stored),
                    requested: format_hnsw_compatibility(&requested),
                });
            }
        }
        HnswCompatibilityState::Missing => {
            if has_persisted_vector_or_hnsw_data(hnsw_meta, vectors, hnsw_neighbors, &wtxn)? {
                return Err(Error::InvalidConfig(
                    "populated vault is missing complete vector/hnsw compatibility metadata; rebuild or migrate it before reopening".to_owned(),
                ));
            }
            hnsw_meta.put(&mut wtxn, HNSW_CONFIG_KEY, &encoded)?;
            wtxn.commit()?;
        }
        HnswCompatibilityState::Legacy(stored) => {
            if has_persisted_vector_or_hnsw_data(hnsw_meta, vectors, hnsw_neighbors, &wtxn)? {
                return Err(Error::HnswConfigChanged {
                    stored: format_hnsw_compatibility(&stored),
                    requested: format_hnsw_compatibility(&requested),
                });
            }
            hnsw_meta.put(&mut wtxn, HNSW_CONFIG_KEY, &encoded)?;
            wtxn.commit()?;
        }
    }
    Ok(())
}

fn persist_model_id_if_missing(
    env: &Env,
    hnsw_meta: &Database<Bytes, Bytes>,
    vectors: &Database<Bytes, Bytes>,
    hnsw_neighbors: &Database<Bytes, Bytes>,
    requested: &str,
) -> Result<()> {
    let mut wtxn = env.write_txn()?;
    match hnsw_meta.get(&wtxn, MODEL_ID_KEY)? {
        Some(raw) => {
            let stored = parse_utf8_bytes(raw)?;
            if stored != requested {
                return Err(Error::EmbeddingModelChanged {
                    stored,
                    requested: requested.to_owned(),
                });
            }
        }
        None => {
            if has_persisted_vector_or_hnsw_data(hnsw_meta, vectors, hnsw_neighbors, &wtxn)? {
                return Err(Error::InvalidConfig(
                    ERR_POPULATED_MISSING_MODEL_ID.to_owned(),
                ));
            }
            hnsw_meta.put(&mut wtxn, MODEL_ID_KEY, requested.as_bytes())?;
            wtxn.commit()?;
        }
    }
    Ok(())
}

pub(crate) fn ensure_model_id_for_vector_write(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    requested: Option<&str>,
) -> Result<()> {
    let requested = requested.ok_or_else(|| {
        Error::InvalidConfig(ERR_VECTOR_WRITE_REQUIRES_EMBEDDING_MODEL.to_owned())
    })?;
    match store.hnsw_meta.get(&*wtxn, MODEL_ID_KEY)? {
        Some(raw) => {
            let stored = parse_utf8_bytes(raw)?;
            if stored != requested {
                return Err(Error::EmbeddingModelChanged {
                    stored,
                    requested: requested.to_owned(),
                });
            }
        }
        None => {
            if has_persisted_vector_or_hnsw_data(
                &store.hnsw_meta,
                &store.vectors,
                &store.hnsw_neighbors,
                &*wtxn,
            )? {
                return Err(Error::InvalidConfig(
                    ERR_POPULATED_MISSING_MODEL_ID.to_owned(),
                ));
            }
            store
                .hnsw_meta
                .put(wtxn, MODEL_ID_KEY, requested.as_bytes())?;
        }
    }
    Ok(())
}

fn encode_hnsw_config(config: &PersistedHnswCompatibility) -> Result<[u8; HNSW_COMPATIBILITY_LEN]> {
    let dimensions = u64::try_from(config.dimensions)
        .map_err(|_| Error::InvalidConfig("dimensions too large".to_owned()))?;
    let m_max_0 = u64::try_from(config.m_max_0)
        .map_err(|_| Error::InvalidConfig("hnsw m_max_0 too large".to_owned()))?;
    let ef_construction = u64::try_from(config.ef_construction)
        .map_err(|_| Error::InvalidConfig("hnsw ef_construction too large".to_owned()))?;

    let mut encoded = [0_u8; HNSW_COMPATIBILITY_LEN];
    encoded[0] = HNSW_COMPATIBILITY_VERSION;
    encoded[1..9].copy_from_slice(&dimensions.to_le_bytes());
    encoded[9..17].copy_from_slice(&m_max_0.to_le_bytes());
    encoded[17..25].copy_from_slice(&ef_construction.to_le_bytes());
    encoded[25] = config.distance_metric;
    encoded[26] = config.index_structure;
    Ok(encoded)
}

pub(crate) fn read_hnsw_compatibility(
    hnsw_meta: &Database<Bytes, Bytes>,
    txn: &heed::RoTxn<'_>,
) -> Result<HnswCompatibilityState> {
    let Some(raw) = hnsw_meta.get(txn, HNSW_CONFIG_KEY)? else {
        return Ok(HnswCompatibilityState::Missing);
    };

    match raw.len() {
        HNSW_COMPATIBILITY_LEN => {
            decode_hnsw_compatibility(raw).map(HnswCompatibilityState::Current)
        }
        HNSW_COMPATIBILITY_V1_LEN | HNSW_COMPATIBILITY_V0_LEN => {
            decode_legacy_hnsw_compatibility(raw).map(HnswCompatibilityState::Legacy)
        }
        _ => Err(Error::InvalidKey),
    }
}

fn decode_hnsw_compatibility(raw: &[u8]) -> Result<PersistedHnswCompatibility> {
    if raw.len() != HNSW_COMPATIBILITY_LEN || raw[0] != HNSW_COMPATIBILITY_VERSION {
        return Err(Error::InvalidKey);
    }

    let dimensions = usize::try_from(u64::from_le_bytes(
        raw[1..9].try_into().map_err(|_| Error::InvalidKey)?,
    ))
    .map_err(|_| Error::InvalidKey)?;
    let m_max_0 = usize::try_from(u64::from_le_bytes(
        raw[9..17].try_into().map_err(|_| Error::InvalidKey)?,
    ))
    .map_err(|_| Error::InvalidKey)?;
    let ef_construction = usize::try_from(u64::from_le_bytes(
        raw[17..25].try_into().map_err(|_| Error::InvalidKey)?,
    ))
    .map_err(|_| Error::InvalidKey)?;
    let distance_metric = raw[25];
    let index_structure = raw[26];

    Ok(PersistedHnswCompatibility {
        dimensions,
        m_max_0,
        ef_construction,
        distance_metric,
        index_structure,
    })
}

fn decode_legacy_hnsw_compatibility(raw: &[u8]) -> Result<PersistedHnswCompatibility> {
    let field_offset = match raw.len() {
        HNSW_COMPATIBILITY_V1_LEN => {
            if raw[0] != 1 {
                return Err(Error::InvalidKey);
            }
            1
        }
        HNSW_COMPATIBILITY_V0_LEN => 0,
        _ => return Err(Error::InvalidKey),
    };

    let dimensions = usize::try_from(u64::from_le_bytes(
        raw[field_offset..field_offset + 8]
            .try_into()
            .map_err(|_| Error::InvalidKey)?,
    ))
    .map_err(|_| Error::InvalidKey)?;
    let m_max_0 = usize::try_from(u64::from_le_bytes(
        raw[field_offset + 8..field_offset + 16]
            .try_into()
            .map_err(|_| Error::InvalidKey)?,
    ))
    .map_err(|_| Error::InvalidKey)?;
    let ef_construction = usize::try_from(u64::from_le_bytes(
        raw[field_offset + 16..field_offset + 24]
            .try_into()
            .map_err(|_| Error::InvalidKey)?,
    ))
    .map_err(|_| Error::InvalidKey)?;

    Ok(PersistedHnswCompatibility {
        dimensions,
        m_max_0,
        ef_construction,
        distance_metric: HNSW_DISTANCE_METRIC_MISSING,
        index_structure: HNSW_INDEX_STRUCTURE_MISSING,
    })
}

fn format_hnsw_compatibility(config: &PersistedHnswCompatibility) -> String {
    format!(
        "dimensions={},m_max_0={},ef_construction={},distance_metric={},index_structure={}",
        config.dimensions,
        config.m_max_0,
        config.ef_construction,
        format_hnsw_distance_metric(config.distance_metric),
        format_hnsw_index_structure(config.index_structure)
    )
}

pub(crate) fn format_hnsw_distance_metric(code: u8) -> String {
    match code {
        HNSW_DISTANCE_METRIC_MISSING => "missing".to_owned(),
        HNSW_DISTANCE_METRIC_COSINE => "cosine".to_owned(),
        unknown => format!("unknown({unknown})"),
    }
}

pub(crate) fn format_hnsw_index_structure(code: u8) -> String {
    match code {
        HNSW_INDEX_STRUCTURE_MISSING => "missing".to_owned(),
        HNSW_INDEX_STRUCTURE_FLAT_NSW => "flat_nsw".to_owned(),
        unknown => format!("unknown({unknown})"),
    }
}

fn has_persisted_vector_or_hnsw_data(
    hnsw_meta: &Database<Bytes, Bytes>,
    vectors: &Database<Bytes, Bytes>,
    hnsw_neighbors: &Database<Bytes, Bytes>,
    txn: &heed::RoTxn<'_>,
) -> Result<bool> {
    Ok(database_has_entries(vectors, txn)?
        || database_has_entries(hnsw_neighbors, txn)?
        || crate::hnsw::has_population(hnsw_meta, txn)?)
}

fn database_has_entries(db: &Database<Bytes, Bytes>, txn: &heed::RoTxn<'_>) -> Result<bool> {
    Ok(db.iter(txn)?.next().transpose()?.is_some())
}

fn migrate_temporal_long_intervals_if_needed(
    env: &Env,
    hnsw_meta: &Database<Bytes, Bytes>,
    temporal_long_intervals: &Database<Bytes, Bytes>,
) -> Result<()> {
    let rtxn = env.read_txn()?;
    let stored_version = match hnsw_meta.get(&rtxn, TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY)? {
        Some(raw) if raw.len() == 1 => raw[0],
        Some(_) => return Err(Error::InvalidKey),
        None => 0,
    };
    drop(rtxn);

    if stored_version > TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION {
        return Err(Error::InvalidKey);
    }
    if stored_version == TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION {
        return Ok(());
    }

    let mut wtxn = env.write_txn()?;
    let mut legacy_rows = Vec::<([u8; 16], [u8; 16])>::new();
    for entry in temporal_long_intervals.iter(&wtxn)? {
        let (key, value) = entry?;
        match (key.len(), value.len()) {
            (24, 8) => {}
            (16, 16) => {
                let old_key = key.try_into().map_err(|_| Error::InvalidKey)?;
                let old_value = value.try_into().map_err(|_| Error::InvalidKey)?;
                legacy_rows.push((old_key, old_value));
            }
            _ => return Err(Error::InvalidKey),
        }
    }

    for (legacy_key, legacy_value) in legacy_rows {
        let occurred_start = u64::from_be_bytes(
            legacy_value[..8]
                .try_into()
                .map_err(|_| Error::InvalidKey)?,
        );
        let occurred_end = u64::from_be_bytes(
            legacy_value[8..]
                .try_into()
                .map_err(|_| Error::InvalidKey)?,
        );
        let new_key = {
            let mut key = [0_u8; 24];
            key[..8].copy_from_slice(&occurred_end.to_be_bytes());
            key[8..].copy_from_slice(&legacy_key);
            key
        };

        temporal_long_intervals.delete(&mut wtxn, &legacy_key)?;
        temporal_long_intervals.put(&mut wtxn, &new_key, &occurred_start.to_be_bytes())?;
    }

    hnsw_meta.put(
        &mut wtxn,
        TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY,
        &[TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION],
    )?;
    wtxn.commit()?;
    Ok(())
}

pub(crate) fn parse_utf8_bytes(bytes: &[u8]) -> Result<String> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| Error::InvalidKey)
}
