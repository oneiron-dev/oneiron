//! LMDB store: one environment per vault plus the 28 named databases pinned
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
//! holding `lmdb_database_open_guard` (`mdb_dbi_open` is transaction-scoped:
//! the txn that opens a DBI must finish before another txn opens one):
//!
//! 0. **`preflight_vault_root`** — before the unsafe LMDB open, the root must
//!    contain either no LMDB files (new vault) or exactly one regular,
//!    non-symlink, single-link `data.mdb` plus one matching `lock.mdb`
//!    (existing vault). Partial, aliased, hard-linked, or already-live roots
//!    fail with [`VaultRootPreflight`].
//! 1. **`vault_meta` (manifest DB #5) is created/opened FIRST.** Rationale:
//!    the storage-version gate (step 2) reads its versions FROM `vault_meta`,
//!    so an existing vault with a missing/blank `vault_meta` is caught by the
//!    ABI gate as [`StorageAbiVersionChanged`]`{ stored: None, .. }` — not by
//!    the manifest gate. Creating it first cannot mask a genuinely missing
//!    database: the manifest-set gate (step 3) runs BEFORE the other 27
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
//!    set in the environment must equal the 28-entry [`DB_MANIFEST`] exactly;
//!    any missing or unexpected name → [`DbManifestMismatch`]. New vaults run
//!    this validation after step 4 instead (nothing pre-exists to validate).
//! 4. The remaining 27 manifest DBs are created/opened, the transaction
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
//! LE, see `SHORT_ID_COUNTER_KEY_PREFIX`); `hnsw_meta` (#8) owns the
//! vector-side compatibility keys (`model_id`, `hnsw_config`) alongside HNSW
//! runtime metadata (`entry_point`, `count`, graph/vector version counters).
//! Consolidating the vector compat keys into `vault_meta` would be a storage
//! migration with no behavioral win, so the split is intentional and
//! documented here instead.
//!
//! [`StorageAbiVersionChanged`]: crate::error::Error::StorageAbiVersionChanged
//! [`StorageSchemaVersionChanged`]: crate::error::Error::StorageSchemaVersionChanged
//! [`DbManifestMismatch`]: crate::error::Error::DbManifestMismatch
//! [`VaultRootPreflight`]: crate::error::Error::VaultRootPreflight
//! [`HnswConfigChanged`]: crate::error::Error::HnswConfigChanged
//! [`EmbeddingModelChanged`]: crate::error::Error::EmbeddingModelChanged
//! [`InvalidConfig`]: crate::error::Error::InvalidConfig
//! [`IncompatibleAnalyzer`]: crate::error::Error::IncompatibleAnalyzer
//! [`Bm25FieldSchemaChanged`]: crate::error::Error::Bm25FieldSchemaChanged
//! [`VaultConfig::skip_text_index_manifest_check`]: crate::types::VaultConfig::skip_text_index_manifest_check

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap, HashSet};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::str;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{LazyLock, Mutex, MutexGuard, RwLock};

use heed::types::{Bytes, Str};
use heed::{Database, DatabaseFlags, Env, EnvOpenOptions, RoTxn, RwTxn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::batch::secret_scan;
use crate::error::{Error, Result, VaultRootEntry, VaultRootProblem};
use crate::types::{
    COMPANION_REGISTER_PACK_ID, COMPANION_REGISTER_SHORT_ID_PREFIX, ENTITY_TYPE_CLAIM,
    ENTITY_TYPE_COMPANION_REGISTER, EdgeKind, EntityId, Signal, StructuralKindRegistration,
    TypeByteBand, VaultConfig, band_of, bytes_to_hex_lower, entity_type_registry_entry,
    short_id_prefix, static_short_id_prefix_collision,
    validate_entity_type as validate_static_entity_type,
    validate_public_entity_type as validate_static_public_entity_type,
};

// Contract-pinned at 32 by ARCH-0019/ARCH-0031: 28 named DBs plus headroom.
pub const MAX_DBS: u32 = 32;
/// v8 (ONE-1213): job queue rows gained durable terminal states (`Completed`
/// and `Failed`) plus retry backoff metadata. v7 queue readers only understand
/// `Queued`/`Leased`, so v7 vaults fail closed at the ABI gate — there is no
/// silent migration; rebuild the vault.
///
/// v7 (ONE-1206): generic LMDB-backed job queue landed as three named DBs:
/// `job_records`, `job_ready`, and `job_dedupe`. v6 vaults fail closed at
/// the ABI gate — there is no silent migration; rebuild the vault.
///
/// v6 (ONE-1204): PSYCH_PROFILE was registered as persistent maintenance
/// entity type byte 129. v5 vaults fail closed at the ABI gate — there is no
/// silent migration; rebuild the vault.
///
/// v5 (ONE-1293): maintenance-band bytes were realigned so byte 122 is
/// reserved for AUTHORITY_LOG, POLICY_MANIFEST is 123, and FEDERATION_GRANT is
/// 124. v4 vaults fail closed at the ABI gate — there is no silent migration;
/// rebuild the vault.
///
/// v4 (ONE-299): `text_postings` became a DUP_SORT database holding one
/// posting entry per (term, entity) duplicate item, and `text_forward`
/// records dropped the dead `tf` u32.
pub const STORAGE_ABI_VERSION: u16 = 8;
pub(crate) const STORAGE_ABI_VERSION_KEY: &[u8] = b"storage_abi_version";
pub const STORAGE_SCHEMA_VERSION: u16 = 1;
pub(crate) const STORAGE_SCHEMA_VERSION_KEY: &[u8] = b"schema_version";
/// Version of the pinned DB-manifest shape surfaced in whole-vault exports.
pub const DB_MANIFEST_VERSION: u16 = 2;
pub(crate) const MODEL_ID_KEY: &[u8] = b"model_id";
pub(crate) const GRAPH_VERSION_KEY: &[u8] = b"graph_version";
pub(crate) const HNSW_CONFIG_KEY: &[u8] = b"hnsw_config";
pub(crate) const TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY: &[u8] =
    b"temporal_long_intervals_schema_version";
const TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION: u8 = 2;
pub(crate) const VECTOR_VERSION_KEY: &[u8] = b"vector_version";
const PENDING_EMBEDDING_MARKER_PREFIX: &str = "pe:";
const PENDING_EMBEDDING_MARKER_VERSION: u8 = 1;
const PENDING_EMBEDDING_MARKER_TOKEN_LEN: usize = 1 + 32;
const ENTITY_BODY_OFFSET: usize = 25;
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

fn current_claim_embedding_token_from_record(
    record: &[u8],
) -> Option<[u8; PENDING_EMBEDDING_MARKER_TOKEN_LEN]> {
    if record.len() <= ENTITY_BODY_OFFSET || record[0] != ENTITY_TYPE_CLAIM {
        return None;
    }
    let body = &record[ENTITY_BODY_OFFSET..];
    if body.is_empty() {
        return None;
    }
    Some(Store::pending_embedding_marker_token(body))
}

#[cfg(any(unix, windows))]
const VAULT_ROOT_IDENTITY_CHECKS_AVAILABLE: bool = true;
#[cfg(not(any(unix, windows)))]
const VAULT_ROOT_IDENTITY_CHECKS_AVAILABLE: bool = false;
const ERR_POPULATED_MISSING_MODEL_ID: &str =
    "populated vault is missing embedding model identity; rebuild or migrate it before reopening";
const ERR_POPULATED_REQUIRES_EMBEDDING_MODEL: &str =
    "embedding model is required to open a populated vector vault";
const ERR_VECTOR_WRITE_REQUIRES_EMBEDDING_MODEL: &str =
    "embedding model is required before writing vectors";
static LMDB_DATABASE_OPEN_LOCK: Mutex<()> = Mutex::new(());
static VAULT_ROOT_OPEN_LOCK: Mutex<()> = Mutex::new(());
static OPEN_STORE_PATHS: LazyLock<Mutex<HashMap<PathBuf, Option<VaultRootIdentity>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

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

/// `vault_meta` key prefix for vault-scoped dynamic StructuralKind
/// registrations. The full key is `b"kind_reg:"` followed by the raw type
/// byte; the value is a versioned record carrying `(type_byte,
/// short_id_prefix, band, pack)`.
pub(crate) const STRUCTURAL_KIND_REGISTRY_KEY_PREFIX: &[u8] = b"kind_reg:";
pub(crate) const STRUCTURAL_KIND_REGISTRY_KEY_LEN: usize = 10;
const _: () =
    assert!(STRUCTURAL_KIND_REGISTRY_KEY_PREFIX.len() + 1 == STRUCTURAL_KIND_REGISTRY_KEY_LEN);
const STRUCTURAL_KIND_REGISTRY_RECORD_VERSION: u8 = 1;
const STRUCTURAL_KIND_REGISTRY_RECORD_HEADER_LEN: usize = 6;
const RETRIEVAL_TELEMETRY_VERSION: u8 = 0;
const RETRIEVAL_RUN_KEY_PREFIX: &[u8] = b"retr_run:v0:";
const RETRIEVAL_RUN_PROVISIONAL_KEY_PREFIX: &[u8] = b"retr_run_prov:v0:";
const RETRIEVAL_TRACE_FORK_KEY_PREFIX: &[u8] = b"retr_trace_fork:v0:";
const RETRIEVAL_OUTCOME_KEY_PREFIX: &[u8] = b"retr_out:v0:";
const RETRIEVAL_BLEND_WEIGHT_TABLE_KEY: &[u8] = b"retr_blend_weights:v0:active";
const RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT: usize = 1024;
const RETRIEVAL_OUTCOME_KEY_MAX_LEN: usize = 128;
const RETRIEVAL_BLEND_WEIGHT_TABLE_VERSION: u8 = 1;
const RETRIEVAL_BLEND_TUNER_ALGORITHM: &str = "ret010d.reward_weighted_bandit.v1";
const RETRIEVAL_BLEND_BOOTSTRAP_SOURCE: &str = "ret010b.bootstrap";
const GATE_DECISION_LEDGER_VERSION: u8 = 0;
const GATE_DECISION_KEY_PREFIX: &[u8] = b"gate_decision:v0:";
const PENDING_GATE_CONSENT_KEY_PREFIX: &[u8] = b"gate_pending:v0:";
const GATE_DIFF_HANDLE_MAX_LEN: usize = 128;
const PENDING_GATE_CONSENT_DREAMER_RUN_ID_MAX_LEN: usize = 128;

thread_local! {
    static ACTIVE_WRITE_TXN_DEPTH: Cell<usize> = const { Cell::new(0) };
}

pub(crate) struct ActiveWriteTxnGuard;

impl Drop for ActiveWriteTxnGuard {
    fn drop(&mut self) {
        ACTIVE_WRITE_TXN_DEPTH.with(|depth| {
            depth.set(depth.get().saturating_sub(1));
        });
    }
}

pub(crate) fn active_write_txn_guard() -> ActiveWriteTxnGuard {
    ACTIVE_WRITE_TXN_DEPTH.with(|depth| {
        depth.set(depth.get().saturating_add(1));
    });
    ActiveWriteTxnGuard
}

fn active_write_txn_depth() -> usize {
    ACTIVE_WRITE_TXN_DEPTH.with(Cell::get)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RetrievalRunId {
    bytes: [u8; 16],
}

impl RetrievalRunId {
    #[must_use]
    pub fn now() -> Self {
        Self {
            bytes: Uuid::now_v7().into_bytes(),
        }
    }

    #[must_use]
    pub fn as_bytes(self) -> [u8; 16] {
        self.bytes
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        bytes_to_hex_lower(&self.bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalAction {
    Pipeline,
    ContextPack,
    VaultSearch,
    GraphFsCoreutils,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalSignal {
    Vector,
    Text,
    Phonetic,
    Temporal,
    Ppr,
    Recency,
    Salience,
    Confidence,
    Gravity,
}

impl RetrievalSignal {
    #[must_use]
    pub fn as_blend_signal(self) -> Option<RetrievalBlendSignal> {
        match self {
            Self::Recency => Some(RetrievalBlendSignal::Recency),
            Self::Salience => Some(RetrievalBlendSignal::Salience),
            Self::Confidence => Some(RetrievalBlendSignal::Confidence),
            Self::Gravity => Some(RetrievalBlendSignal::Gravity),
            Self::Vector | Self::Text | Self::Phonetic | Self::Temporal | Self::Ppr => None,
        }
    }
}

impl From<Signal> for RetrievalSignal {
    fn from(signal: Signal) -> Self {
        match signal {
            Signal::Vector => Self::Vector,
            Signal::Text => Self::Text,
            Signal::Phonetic => Self::Phonetic,
            Signal::Temporal => Self::Temporal,
            Signal::Ppr => Self::Ppr,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalBlendSignal {
    Recency,
    Salience,
    Confidence,
    Gravity,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RetrievalBlendWeights {
    pub recency: f32,
    pub salience: f32,
    pub confidence: f32,
    pub gravity: f32,
}

impl RetrievalBlendWeights {
    #[must_use]
    pub const fn bootstrap() -> Self {
        Self {
            recency: 0.35,
            salience: 0.30,
            confidence: 0.20,
            gravity: 0.15,
        }
    }

    #[must_use]
    pub const fn new(recency: f32, salience: f32, confidence: f32, gravity: f32) -> Self {
        Self {
            recency,
            salience,
            confidence,
            gravity,
        }
    }

    #[must_use]
    pub fn weight(self, signal: RetrievalBlendSignal) -> f32 {
        match signal {
            RetrievalBlendSignal::Recency => self.recency,
            RetrievalBlendSignal::Salience => self.salience,
            RetrievalBlendSignal::Confidence => self.confidence,
            RetrievalBlendSignal::Gravity => self.gravity,
        }
    }

    pub(crate) fn normalized(self) -> Result<Self> {
        validate_retrieval_blend_weights(self).map_err(Error::InvalidConfig)?;
        let sum = self.sum();
        Ok(Self {
            recency: self.recency / sum,
            salience: self.salience / sum,
            confidence: self.confidence / sum,
            gravity: self.gravity / sum,
        })
    }

    fn sum(self) -> f32 {
        self.recency + self.salience + self.confidence + self.gravity
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RetrievalBlendWeightDataWindow {
    pub run_count: u32,
    pub outcome_count: u32,
    pub candidate_count: u32,
    pub started_at_min: Option<u64>,
    pub started_at_max: Option<u64>,
    pub outcome_updated_at_min: Option<u64>,
    pub outcome_updated_at_max: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalBlendWeightTableEntry {
    pub version: u8,
    pub weights: RetrievalBlendWeights,
    pub tuned_at: u64,
    pub provenance: BTreeMap<String, String>,
    pub data_window: RetrievalBlendWeightDataWindow,
}

impl RetrievalBlendWeightTableEntry {
    #[must_use]
    pub fn bootstrap() -> Self {
        let mut provenance = BTreeMap::new();
        provenance.insert(
            "source".to_owned(),
            RETRIEVAL_BLEND_BOOTSTRAP_SOURCE.to_owned(),
        );
        provenance.insert("algorithm".to_owned(), "ret010b.bootstrap.v1".to_owned());
        Self {
            version: RETRIEVAL_BLEND_WEIGHT_TABLE_VERSION,
            weights: RetrievalBlendWeights::bootstrap(),
            tuned_at: 0,
            provenance,
            data_window: RetrievalBlendWeightDataWindow::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RetrievalBlendTuningConfig {
    pub max_runs: usize,
    pub learning_rate: f32,
    pub min_reward_count: usize,
}

impl Default for RetrievalBlendTuningConfig {
    fn default() -> Self {
        Self {
            max_runs: RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT,
            learning_rate: 0.05,
            min_reward_count: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalScoreComponent {
    pub signal: RetrievalSignal,
    pub rank: u32,
    pub score: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalScoreBreakdown {
    pub result_id: [u8; 16],
    pub final_rank: u32,
    pub final_score: f32,
    pub components: Vec<RetrievalScoreComponent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalTraceStage {
    PerChannel,
    Fused,
    Blended,
    Reranked,
    Final,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalTraceChannelRecord {
    pub stage: RetrievalTraceStage,
    pub signal: RetrievalSignal,
    pub candidates: Vec<RetrievalScoreBreakdown>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalTraceStageRecord {
    pub stage: RetrievalTraceStage,
    pub candidates: Vec<RetrievalScoreBreakdown>,
}

/// SHA-256 replay key for a content-addressed [`RetrievalTrace`].
///
/// The hash is stored as the raw 32-byte digest, not hex. It is computed by
/// the retrieval pipeline with the same domain-separated SHA-256 style as the
/// gate policy frontier hash: length-prefixed UTF-8 strings/bytes, little-endian
/// integers, one-byte booleans, and IEEE-754 `to_bits()` bytes for floats.
pub type RetrievalTraceForkHash = [u8; 32];

/// Opt-in per-stage retrieval trace.
///
/// `fork_hash` is the content-addressed replay key for fork-and-diff eval. Its
/// canonical input snapshot is: query inputs for all enabled retrieval channels,
/// normalized retrieval config and flags, the BM25 rank-profile snapshot, the
/// pinned recency half-life table, the active retrieval-blend weight table,
/// an explicitly supplied replay clock when present for time-dependent scoring,
/// and the candidate set canonicalized as sorted, deduplicated `EntityId`
/// bytes. Implicit wall-clock seconds are not hashed. Legacy traces missing
/// the field decode to the all-zero sentinel, which is treated as unknown and
/// is not indexed. The trace remains typed msgpack-native; JSONL/parquet export
/// belongs outside the engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalTrace {
    #[serde(default)]
    pub fork_hash: RetrievalTraceForkHash,
    pub per_channel: Vec<RetrievalTraceChannelRecord>,
    pub fused: RetrievalTraceStageRecord,
    pub blended: RetrievalTraceStageRecord,
    pub reranked: RetrievalTraceStageRecord,
    #[serde(rename = "final")]
    pub final_stage: RetrievalTraceStageRecord,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalRunRecord {
    pub version: u8,
    pub run_id: RetrievalRunId,
    pub action: RetrievalAction,
    pub started_at: u64,
    pub elapsed_us: u64,
    pub signals: Vec<RetrievalSignal>,
    pub result_ids: Vec<[u8; 16]>,
    pub score_breakdown: Vec<RetrievalScoreBreakdown>,
    pub total_in_scope: usize,
    pub claims_suppressed: usize,
    pub empty_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<RetrievalTrace>,
}

impl RetrievalRunRecord {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        run_id: RetrievalRunId,
        action: RetrievalAction,
        started_at: u64,
        elapsed_us: u64,
        signals: Vec<RetrievalSignal>,
        score_breakdown: Vec<RetrievalScoreBreakdown>,
        total_in_scope: usize,
        claims_suppressed: usize,
        empty_reason: Option<String>,
    ) -> Self {
        let result_ids = score_breakdown
            .iter()
            .map(|entry| entry.result_id)
            .collect();
        Self {
            version: RETRIEVAL_TELEMETRY_VERSION,
            run_id,
            action,
            started_at,
            elapsed_us,
            signals,
            result_ids,
            score_breakdown,
            total_in_scope,
            claims_suppressed,
            empty_reason,
            trace: None,
        }
    }

    pub(crate) fn with_trace(mut self, trace: Option<RetrievalTrace>) -> Self {
        self.trace = trace;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalOutcome {
    pub run_id: RetrievalRunId,
    pub key: String,
    pub reward: Option<f32>,
    pub accepted: Option<bool>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalOutcomeRecord {
    pub version: u8,
    pub run_id: RetrievalRunId,
    pub key: String,
    pub reward: Option<f32>,
    pub accepted: Option<bool>,
    pub metadata: BTreeMap<String, String>,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GateDecisionId {
    bytes: [u8; 16],
}

impl GateDecisionId {
    #[must_use]
    pub fn now() -> Self {
        Self {
            bytes: Uuid::now_v7().into_bytes(),
        }
    }

    #[must_use]
    pub fn as_bytes(self) -> [u8; 16] {
        self.bytes
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        bytes_to_hex_lower(&self.bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateDecisionRecord {
    pub version: u8,
    pub decision_id: GateDecisionId,
    pub created_at: u64,
    pub outcome: String,
    pub reason_codes: Vec<String>,
    pub actor_class: String,
    pub actor_ref: Option<String>,
    pub content_kind: String,
    pub policy_manifest_version: String,
    pub claim_id: Option<[u8; 16]>,
    pub diff_handle: Vec<u8>,
    pub read_frontier_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingGateConsentRecord {
    pub version: u8,
    pub claim_id: [u8; 16],
    pub decision_id: GateDecisionId,
    pub created_at: u64,
    pub diff_handle: Vec<u8>,
    pub read_frontier_hash: [u8; 32],
    pub reason_codes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dreamer_run_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingGateConsentGroup {
    pub dreamer_run_id: Option<String>,
    pub records: Vec<PendingGateConsentRecord>,
}

/// Encodes the `vault_meta` key for the short-id counter of `entity_type`.
/// See [`SHORT_ID_COUNTER_KEY_PREFIX`] for the documented key scheme.
pub(crate) fn short_id_counter_key(entity_type: u8) -> [u8; SHORT_ID_COUNTER_KEY_LEN] {
    let mut key = [0u8; SHORT_ID_COUNTER_KEY_LEN];
    key[..SHORT_ID_COUNTER_KEY_PREFIX.len()].copy_from_slice(SHORT_ID_COUNTER_KEY_PREFIX);
    key[SHORT_ID_COUNTER_KEY_PREFIX.len()] = entity_type;
    key
}

pub(crate) fn structural_kind_registry_key(
    type_byte: u8,
) -> [u8; STRUCTURAL_KIND_REGISTRY_KEY_LEN] {
    let mut key = [0u8; STRUCTURAL_KIND_REGISTRY_KEY_LEN];
    key[..STRUCTURAL_KIND_REGISTRY_KEY_PREFIX.len()]
        .copy_from_slice(STRUCTURAL_KIND_REGISTRY_KEY_PREFIX);
    key[STRUCTURAL_KIND_REGISTRY_KEY_PREFIX.len()] = type_byte;
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

pub const DB_MANIFEST: [DbManifestEntry; 28] = [
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
    DbManifestEntry {
        n: 26,
        name: "job_records",
        group: "Jobs",
    },
    DbManifestEntry {
        n: 27,
        name: "job_ready",
        group: "Jobs",
    },
    DbManifestEntry {
        n: 28,
        name: "job_dedupe",
        group: "Jobs",
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
/// [`crate::Vault`]) CLOSES the LMDB environment — see `OwnedEnv` for the
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
    /// Vault-scoped dynamic StructuralKind registry loaded from `vault_meta`.
    pub(crate) kind_registry: RwLock<HashMap<u8, StructuralKindRegistration>>,
    /// Serializes reward-to-weight tuning so concurrent callers cannot lose
    /// a gradient step between read, compute, and persist.
    retrieval_blend_tuning_lock: Mutex<()>,
    /// PPR cache rows. Values carry the final scores and, for current rows,
    /// the residual/frontier state needed to resume a deeper Forward-Push run.
    pub(crate) ppr_cache: Database<Bytes, Bytes>,
    /// Reverse dependency index for PPR cache invalidation:
    /// `[entity_id | cache_key]`.
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
    /// Generic background job records keyed by job id.
    pub(crate) job_records: Database<Bytes, Bytes>,
    /// Ready-job ordering index keyed by ready-at time then job id.
    pub(crate) job_ready: Database<Bytes, Bytes>,
    /// Advisory dedupe index keys mapped to job ids.
    pub(crate) job_dedupe: Database<Bytes, Bytes>,
    /// Process-local clock domain for monotonic authority first-seen windows.
    pub(crate) authority_clock_domain: usize,
    /// True only for the open call that created a previously absent LMDB root.
    created_new_vault: bool,
    // DROP-ORDER: keep this field after `env`. Fields drop in declaration
    // order, so the path registry releases the path only after [`OwnedEnv`]
    // has closed the LMDB environment — a reopen racing this drop can never
    // observe the path as free while the old environment is still live.
    _registered_path: RegisteredPath,
}

static NEXT_AUTHORITY_CLOCK_DOMAIN: AtomicUsize = AtomicUsize::new(1);

impl Drop for Store {
    fn drop(&mut self) {
        crate::authority::release_authority_clock_domain(self.authority_clock_domain);
    }
}

impl Store {
    /// Opens or creates a store at `path` and initializes all named databases.
    pub fn open(path: impl AsRef<Path>, config: &VaultConfig) -> Result<Self> {
        let (env, registered_path, is_new_vault) = {
            let _vault_root_open_guard = vault_root_open_guard()?;

            std::fs::create_dir_all(path.as_ref())?;
            let canonical_path = path.as_ref().canonicalize()?;
            let root_preflight = preflight_vault_root(&canonical_path)?;
            let is_new_vault = root_preflight.is_new_vault;
            let mut registered_path =
                RegisteredPath::reserve(canonical_path.clone(), root_preflight.identity)?;

            // SAFETY: heed/LMDB require a single Env per filesystem path, the
            // path must not be on NFS or another unsupported network
            // filesystem, and map_size must not be changed concurrently while
            // the environment is open elsewhere. The path
            // existence/writability precondition is established by
            // create_dir_all plus the root preflight above. The caller must
            // not retarget the canonicalized filesystem path while it is being
            // opened. The process-local root-open guard keeps the initial
            // preflight, path reservation, unsafe LMDB open, and post-create
            // identity refresh indivisible against other openers; the
            // path/identity registry then rejects later duplicate live Env
            // opens for the same canonical path or known LMDB file identity.
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
            #[cfg(test)]
            test_hooks::run_after_lmdb_open(&canonical_path);
            if VAULT_ROOT_IDENTITY_CHECKS_AVAILABLE {
                registered_path
                    .refresh_identity(preflight_vault_root(&canonical_path)?.identity)?;
            }

            (env, registered_path, is_new_vault)
        };

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
        let job_records = create_manifest_db(&env, &mut wtxn, 25)?;
        let job_ready = create_manifest_db(&env, &mut wtxn, 26)?;
        let job_dedupe = create_manifest_db(&env, &mut wtxn, 27)?;
        if is_new_vault {
            validate_db_manifest_set(&env, &wtxn)?;
        }
        wtxn.commit()?;
        drop(db_open_guard);

        let kind_registry = RwLock::new(load_structural_kind_registry(&env, &vault_meta)?);

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
            kind_registry,
            retrieval_blend_tuning_lock: Mutex::new(()),
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
            job_records,
            job_ready,
            job_dedupe,
            authority_clock_domain: NEXT_AUTHORITY_CLOCK_DOMAIN
                .fetch_add(1, AtomicOrdering::Relaxed),
            created_new_vault: is_new_vault,
            _registered_path: registered_path,
        })
    }

    pub(crate) fn created_new_vault(&self) -> bool {
        self.created_new_vault
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

    pub(crate) fn pending_embedding_marker_key(id: &EntityId) -> String {
        format!("{PENDING_EMBEDDING_MARKER_PREFIX}{}", id.to_hex())
    }

    pub(crate) fn pending_embedding_marker_token(
        claim_body: &[u8],
    ) -> [u8; PENDING_EMBEDDING_MARKER_TOKEN_LEN] {
        let digest = Sha256::digest(claim_body);
        let mut token = [0_u8; PENDING_EMBEDDING_MARKER_TOKEN_LEN];
        token[0] = PENDING_EMBEDDING_MARKER_VERSION;
        token[1..].copy_from_slice(&digest);
        token
    }

    pub(crate) fn mark_pending_embedding(
        &self,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
        claim_body: &[u8],
    ) -> Result<Vec<u8>> {
        let key = Self::pending_embedding_marker_key(id);
        let token = Self::pending_embedding_marker_token(claim_body);
        self.sync_state.put(wtxn, key.as_str(), token.as_slice())?;
        Ok(token.to_vec())
    }

    pub(crate) fn clear_pending_embedding(
        &self,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        let key = Self::pending_embedding_marker_key(id);
        Ok(self.sync_state.delete(wtxn, key.as_str())?)
    }

    pub(crate) fn clear_pending_embedding_if_token_matches(
        &self,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
        token: &[u8],
    ) -> Result<bool> {
        if !self.pending_embedding_matches_in_txn(wtxn, id, token)? {
            return Ok(false);
        }
        self.clear_pending_embedding(wtxn, id)
    }

    pub(crate) fn pending_embedding_token(
        &self,
        rtxn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<Vec<u8>>> {
        let key = Self::pending_embedding_marker_key(id);
        let Some(marker) = self.sync_state.get(rtxn, key.as_str())? else {
            return Ok(None);
        };
        let Some(current) = self.current_claim_embedding_token(rtxn, id)? else {
            return Ok(None);
        };
        Ok((marker == current).then_some(marker.to_vec()))
    }

    #[cfg(feature = "sync")]
    pub(crate) fn pending_embedding_token_in_txn(
        &self,
        wtxn: &RwTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<Vec<u8>>> {
        let key = Self::pending_embedding_marker_key(id);
        let Some(marker) = self.sync_state.get(wtxn, key.as_str())? else {
            return Ok(None);
        };
        let Some(current) = self.current_claim_embedding_token_in_txn(wtxn, id)? else {
            return Ok(None);
        };
        Ok((marker == current).then_some(marker.to_vec()))
    }

    pub(crate) fn has_current_pending_embedding_in_txn(
        &self,
        wtxn: &RwTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        let key = Self::pending_embedding_marker_key(id);
        let Some(marker) = self.sync_state.get(wtxn, key.as_str())? else {
            return Ok(false);
        };
        let Some(current) = self.current_claim_embedding_token_in_txn(wtxn, id)? else {
            return Ok(false);
        };
        Ok(marker == current)
    }

    pub(crate) fn pending_embedding_matches_in_txn(
        &self,
        wtxn: &RwTxn<'_>,
        id: &EntityId,
        token: &[u8],
    ) -> Result<bool> {
        let key = Self::pending_embedding_marker_key(id);
        let Some(marker) = self.sync_state.get(wtxn, key.as_str())? else {
            return Ok(false);
        };
        if marker != token {
            return Ok(false);
        }
        Ok(self
            .current_claim_embedding_token_in_txn(wtxn, id)?
            .is_some_and(|current| current == token))
    }

    fn current_claim_embedding_token(
        &self,
        rtxn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<[u8; PENDING_EMBEDDING_MARKER_TOKEN_LEN]>> {
        let Some(record) = self.entities.get(rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        Ok(current_claim_embedding_token_from_record(record))
    }

    fn current_claim_embedding_token_in_txn(
        &self,
        wtxn: &RwTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<[u8; PENDING_EMBEDDING_MARKER_TOKEN_LEN]>> {
        let Some(record) = self.entities.get(wtxn, id.as_bytes())? else {
            return Ok(None);
        };
        Ok(current_claim_embedding_token_from_record(record))
    }

    pub(crate) fn structural_kind_registration(
        &self,
        type_byte: u8,
    ) -> Option<StructuralKindRegistration> {
        let registry = self
            .kind_registry
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        registry.get(&type_byte).cloned()
    }

    pub(crate) fn structural_kind_registrations(&self) -> Vec<StructuralKindRegistration> {
        let registry = self
            .kind_registry
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut entries: Vec<StructuralKindRegistration> = registry.values().cloned().collect();
        entries.sort_by_key(|entry| entry.type_byte);
        entries
    }

    pub(crate) fn validate_entity_type(&self, entity_type: u8) -> Result<()> {
        if validate_static_entity_type(entity_type).is_ok() {
            return Ok(());
        }
        if self.structural_kind_registration(entity_type).is_some() {
            return Ok(());
        }
        Err(Error::InvalidEntityType(entity_type))
    }

    pub(crate) fn validate_public_entity_type(&self, entity_type: u8) -> Result<()> {
        if entity_type_registry_entry(entity_type).is_some() {
            return validate_static_public_entity_type(entity_type);
        }
        self.validate_entity_type(entity_type)
    }

    pub(crate) fn short_id_prefix(&self, entity_type: u8) -> Result<String> {
        if let Ok(prefix) = short_id_prefix(entity_type) {
            return Ok(prefix.to_owned());
        }
        self.structural_kind_registration(entity_type)
            .map(|entry| entry.short_id_prefix)
            .ok_or(Error::InvalidEntityType(entity_type))
    }

    pub(crate) fn register_structural_kind(
        &self,
        type_byte: u8,
        short_id_prefix: impl Into<String>,
        band: TypeByteBand,
        pack: impl Into<String>,
    ) -> Result<StructuralKindRegistration> {
        let registration = StructuralKindRegistration {
            type_byte,
            short_id_prefix: short_id_prefix.into(),
            band,
            pack: pack.into(),
        };
        vet_structural_kind_registration_shape(&registration)?;
        vet_structural_kind_registration_band(&registration)?;
        secret_scan::scan_metadata_field(&registration.pack)?;
        if entity_type_registry_entry(type_byte).is_some() {
            return Err(Error::StructuralKindTypeByteCollision(type_byte));
        }
        if static_short_id_prefix_collision(&registration.short_id_prefix) {
            return Err(Error::StructuralKindPrefixCollision(
                registration.short_id_prefix,
            ));
        }

        let key = structural_kind_registry_key(type_byte);
        let encoded = encode_structural_kind_registration(&registration)?;
        let mut wtxn = self.env.write_txn()?;
        let mut registry = self
            .kind_registry
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if registry.contains_key(&type_byte) || self.vault_meta.get(&wtxn, &key)?.is_some() {
            return Err(Error::StructuralKindTypeByteCollision(type_byte));
        }
        if registry
            .values()
            .any(|entry| entry.short_id_prefix == registration.short_id_prefix)
            || vault_meta_has_structural_kind_prefix(
                &self.vault_meta,
                &wtxn,
                &registration.short_id_prefix,
            )?
        {
            return Err(Error::StructuralKindPrefixCollision(
                registration.short_id_prefix,
            ));
        }

        self.vault_meta.put(&mut wtxn, &key, &encoded)?;
        wtxn.commit()?;
        registry.insert(type_byte, registration.clone());
        Ok(registration)
    }

    pub(crate) fn record_retrieval_run(&self, record: &RetrievalRunRecord) -> Result<()> {
        self.record_retrieval_run_with_visibility(record, true)
    }

    pub(crate) fn append_gate_decision_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &GateDecisionRecord,
    ) -> Result<()> {
        vet_gate_decision_record(record)?;
        let key = gate_decision_key(record.decision_id);
        if self.vault_meta.get(wtxn, &key)?.is_some() {
            return Err(Error::InvariantViolation("gate decision id collision"));
        }
        let value = encode_gate_decision(record)?;
        self.vault_meta.put(wtxn, &key, &value)?;
        Ok(())
    }

    pub(crate) fn gate_decision_in_txn(
        &self,
        txn: &RoTxn<'_>,
        decision_id: GateDecisionId,
    ) -> Result<Option<GateDecisionRecord>> {
        let Some(value) = self.vault_meta.get(txn, &gate_decision_key(decision_id))? else {
            return Ok(None);
        };
        let record = decode_gate_decision(value)?;
        if record.decision_id != decision_id {
            return Err(Error::CorruptedIndex("gate decision ledger"));
        }
        Ok(Some(record))
    }

    pub(crate) fn put_pending_gate_consent_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &PendingGateConsentRecord,
    ) -> Result<()> {
        vet_pending_gate_consent_record(record)?;
        let key = pending_gate_consent_key(&record.claim_id);
        let value = encode_pending_gate_consent(record)?;
        self.vault_meta.put(wtxn, &key, &value)?;
        Ok(())
    }

    pub(crate) fn pending_gate_consent_in_txn(
        &self,
        txn: &RoTxn<'_>,
        claim_id: &EntityId,
    ) -> Result<Option<PendingGateConsentRecord>> {
        let Some(value) = self
            .vault_meta
            .get(txn, &pending_gate_consent_key(claim_id.as_bytes()))?
        else {
            return Ok(None);
        };
        let record = decode_pending_gate_consent(value)?;
        if record.claim_id != *claim_id.as_bytes() {
            return Err(Error::CorruptedIndex("pending gate consent"));
        }
        Ok(Some(record))
    }

    pub(crate) fn delete_pending_gate_consent_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        claim_id: &EntityId,
    ) -> Result<()> {
        self.vault_meta
            .delete(wtxn, &pending_gate_consent_key(claim_id.as_bytes()))?;
        Ok(())
    }

    pub(crate) fn let_go_pending_gate_consent_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        claim_id: &EntityId,
        created_at: u64,
    ) -> Result<Option<GateDecisionRecord>> {
        let Some(pending) = self.pending_gate_consent_in_txn(wtxn, claim_id)? else {
            return Ok(None);
        };
        let Some(value) = self
            .vault_meta
            .get(wtxn, &gate_decision_key(pending.decision_id))?
        else {
            return Err(Error::CorruptedIndex("pending gate consent"));
        };
        let original = decode_gate_decision(value)?;
        if original.decision_id != pending.decision_id {
            return Err(Error::CorruptedIndex("pending gate consent"));
        }
        let record = GateDecisionRecord {
            version: GATE_DECISION_LEDGER_VERSION,
            decision_id: GateDecisionId::now(),
            created_at,
            outcome: "let_go".to_owned(),
            reason_codes: vec!["gate.pending.gap_decayed".to_owned()],
            actor_class: original.actor_class,
            actor_ref: original.actor_ref,
            content_kind: original.content_kind,
            policy_manifest_version: original.policy_manifest_version,
            claim_id: Some(pending.claim_id),
            diff_handle: pending.diff_handle,
            read_frontier_hash: pending.read_frontier_hash,
        };
        self.append_gate_decision_in_txn(wtxn, &record)?;
        self.delete_pending_gate_consent_in_txn(wtxn, claim_id)?;
        Ok(Some(record))
    }

    pub fn pending_gate_consents(&self, limit: usize) -> Result<Vec<PendingGateConsentRecord>> {
        let rtxn = self.env.read_txn()?;
        self.pending_gate_consents_in_txn(&rtxn, limit)
    }

    pub(crate) fn pending_gate_consents_in_txn(
        &self,
        txn: &RoTxn<'_>,
        limit: usize,
    ) -> Result<Vec<PendingGateConsentRecord>> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let upper = pending_gate_consent_upper_bound();
        let mut records = Vec::with_capacity(limit.min(RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT));
        for row in self.vault_meta.range(
            txn,
            &(
                std::ops::Bound::Included(PENDING_GATE_CONSENT_KEY_PREFIX),
                std::ops::Bound::Excluded(upper.as_slice()),
            ),
        )? {
            let (key, value) = row?;
            if !key.starts_with(PENDING_GATE_CONSENT_KEY_PREFIX) {
                return Err(Error::CorruptedIndex("pending gate consent"));
            }
            let claim_id = pending_gate_consent_claim_id_from_key(key)?;
            let record = decode_pending_gate_consent(value)?;
            if record.claim_id != claim_id {
                return Err(Error::CorruptedIndex("pending gate consent"));
            }
            records.push(record);
        }

        records.sort_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then_with(|| {
                    left.decision_id
                        .as_bytes()
                        .cmp(&right.decision_id.as_bytes())
                })
                .then_with(|| left.claim_id.cmp(&right.claim_id))
        });
        records.truncate(limit);
        Ok(records)
    }

    pub fn pending_gate_consent_groups(
        &self,
        limit: usize,
    ) -> Result<Vec<PendingGateConsentGroup>> {
        let mut groups: Vec<PendingGateConsentGroup> = Vec::new();
        for record in self.pending_gate_consents(limit)? {
            let dreamer_run_id = record.dreamer_run_id.clone();
            if let Some(group) = groups
                .iter_mut()
                .find(|group| group.dreamer_run_id == dreamer_run_id)
            {
                group.records.push(record);
            } else {
                groups.push(PendingGateConsentGroup {
                    dreamer_run_id,
                    records: vec![record],
                });
            }
        }
        Ok(groups)
    }

    pub fn gate_decisions(&self, limit: usize) -> Result<Vec<GateDecisionRecord>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let rtxn = self.env.read_txn()?;
        let upper = gate_decision_upper_bound();
        let mut records = Vec::with_capacity(limit.min(RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT));
        for row in self.vault_meta.rev_range(
            &rtxn,
            &(
                std::ops::Bound::Included(GATE_DECISION_KEY_PREFIX),
                std::ops::Bound::Excluded(upper.as_slice()),
            ),
        )? {
            let (key, value) = row?;
            if !key.starts_with(GATE_DECISION_KEY_PREFIX) {
                break;
            }
            let decision_id = gate_decision_id_from_key(key)?;
            let record = decode_gate_decision(value)?;
            if record.decision_id != decision_id {
                return Err(Error::CorruptedIndex("gate decision ledger"));
            }
            records.push(record);
            if records.len() == limit {
                break;
            }
        }
        Ok(records)
    }

    pub(crate) fn record_context_pack_provisional_retrieval_run(
        &self,
        record: &RetrievalRunRecord,
    ) -> Result<()> {
        self.record_retrieval_run_with_visibility(record, false)
    }

    fn record_retrieval_run_with_visibility(
        &self,
        record: &RetrievalRunRecord,
        published: bool,
    ) -> Result<()> {
        #[cfg(test)]
        if test_hooks::take_fail_next_retrieval_run_write(&self._registered_path.path) {
            return Err(Error::InvariantViolation(
                "forced retrieval telemetry write failure",
            ));
        }
        if active_write_txn_depth() > 0 {
            return Err(Error::ConcurrentWrite(
                "retrieval telemetry skipped inside active write transaction",
            ));
        }

        let key = retrieval_run_key(record.run_id);
        let value = encode_retrieval_run(record)?;
        let provisional_key = retrieval_run_provisional_key(record.run_id);
        let mut wtxn = self.env.write_txn()?;
        self.vault_meta.put(&mut wtxn, &key, &value)?;
        if published {
            self.vault_meta.delete(&mut wtxn, &provisional_key)?;
            if let Some(trace) = &record.trace {
                put_retrieval_trace_fork_index(
                    &self.vault_meta,
                    &mut wtxn,
                    &trace.fork_hash,
                    record.run_id,
                )?;
            }
        } else {
            self.vault_meta.put(&mut wtxn, &provisional_key, b"1")?;
        }
        wtxn.commit()?;
        Ok(())
    }

    pub(crate) fn delete_retrieval_run(&self, run_id: RetrievalRunId) -> Result<()> {
        if active_write_txn_depth() > 0 {
            return Err(Error::ConcurrentWrite(
                "retrieval telemetry delete skipped inside active write transaction",
            ));
        }

        let key = retrieval_run_key(run_id);
        let provisional_key = retrieval_run_provisional_key(run_id);
        let outcome_prefix = retrieval_outcome_run_prefix(run_id);
        let mut wtxn = self.env.write_txn()?;
        delete_retrieval_trace_fork_indexes_for_run(&self.vault_meta, &mut wtxn, &key, run_id)?;
        let mut outcome_keys = Vec::new();
        for row in self.vault_meta.prefix_iter(&wtxn, &outcome_prefix)? {
            let (key, _) = row?;
            outcome_keys.push(key.to_vec());
        }
        for key in outcome_keys {
            self.vault_meta.delete(&mut wtxn, &key)?;
        }
        self.vault_meta.delete(&mut wtxn, &provisional_key)?;
        self.vault_meta.delete(&mut wtxn, &key)?;
        wtxn.commit()?;
        Ok(())
    }

    pub(crate) fn finalize_context_pack_retrieval_run(
        &self,
        run_id: RetrievalRunId,
        elapsed_us: u64,
        claims_suppressed: usize,
        surfaced_result_ids: &[[u8; 16]],
        empty_reason: Option<String>,
    ) -> Result<()> {
        if active_write_txn_depth() > 0 {
            return Err(Error::ConcurrentWrite(
                "context-pack retrieval telemetry skipped inside active write transaction",
            ));
        }

        let key = retrieval_run_key(run_id);
        let provisional_key = retrieval_run_provisional_key(run_id);
        let mut wtxn = self.env.write_txn()?;
        let Some(raw) = self.vault_meta.get(&wtxn, &key)? else {
            self.vault_meta.delete(&mut wtxn, &provisional_key)?;
            wtxn.commit()?;
            return Ok(());
        };
        let mut record = decode_retrieval_run(raw)?;
        record.elapsed_us = elapsed_us;
        record.claims_suppressed = claims_suppressed;
        record.result_ids = surfaced_result_ids.to_vec();
        let mut surfaced_breakdown = Vec::with_capacity(surfaced_result_ids.len());
        for (index, result_id) in surfaced_result_ids.iter().enumerate() {
            if let Some(entry) = record
                .score_breakdown
                .iter()
                .find(|entry| entry.result_id == *result_id)
            {
                let mut entry = entry.clone();
                entry.final_rank = u32::try_from(index.saturating_add(1)).unwrap_or(u32::MAX);
                surfaced_breakdown.push(entry);
            }
        }
        record.score_breakdown = surfaced_breakdown;
        if let Some(trace) = record.trace.as_mut() {
            trace.final_stage.candidates = record.score_breakdown.clone();
        }
        record.empty_reason = empty_reason;
        let value = encode_retrieval_run(&record)?;
        self.vault_meta.put(&mut wtxn, &key, &value)?;
        if let Some(trace) = &record.trace {
            put_retrieval_trace_fork_index(
                &self.vault_meta,
                &mut wtxn,
                &trace.fork_hash,
                record.run_id,
            )?;
        }
        self.vault_meta.delete(&mut wtxn, &provisional_key)?;
        wtxn.commit()?;
        Ok(())
    }

    pub(crate) fn record_retrieval_outcome(&self, outcome: RetrievalOutcome) -> Result<()> {
        if active_write_txn_depth() > 0 {
            return Err(Error::ConcurrentWrite(
                "retrieval outcome telemetry skipped inside active write transaction",
            ));
        }

        vet_retrieval_outcome(&outcome)?;
        secret_scan::scan_metadata_field(&outcome.key)?;
        for (key, value) in &outcome.metadata {
            secret_scan::scan_metadata_field(key)?;
            secret_scan::scan_metadata_field(value)?;
        }
        let record = RetrievalOutcomeRecord {
            version: RETRIEVAL_TELEMETRY_VERSION,
            run_id: outcome.run_id,
            key: outcome.key,
            reward: outcome.reward,
            accepted: outcome.accepted,
            metadata: outcome.metadata,
            updated_at: crate::unix_seconds_now(),
        };
        let key = retrieval_outcome_key(record.run_id, &record.key);
        let value = encode_retrieval_outcome(&record)?;
        let mut wtxn = self.env.write_txn()?;
        let run_key = retrieval_run_key(record.run_id);
        if self.vault_meta.get(&wtxn, &run_key)?.is_none() {
            return Err(Error::InvalidConfig(
                "retrieval outcome references unknown run id".to_owned(),
            ));
        }
        let provisional_key = retrieval_run_provisional_key(record.run_id);
        if self.vault_meta.get(&wtxn, &provisional_key)?.is_some() {
            return Err(Error::InvalidConfig(
                "retrieval outcome references unpublished context-pack run id".to_owned(),
            ));
        }
        self.vault_meta.put(&mut wtxn, &key, &value)?;
        wtxn.commit()?;
        Ok(())
    }

    pub fn retrieval_runs(&self, limit: usize) -> Result<Vec<RetrievalRunRecord>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let rtxn = self.env.read_txn()?;
        let mut records = Vec::with_capacity(limit.min(RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT));
        let upper = retrieval_run_upper_bound();
        for row in self.vault_meta.rev_range(
            &rtxn,
            &(
                std::ops::Bound::Included(RETRIEVAL_RUN_KEY_PREFIX),
                std::ops::Bound::Excluded(upper.as_slice()),
            ),
        )? {
            let (key, value) = row?;
            if !key.starts_with(RETRIEVAL_RUN_KEY_PREFIX) {
                break;
            }
            let run_id = retrieval_run_id_from_key(key)?;
            if self
                .vault_meta
                .get(&rtxn, &retrieval_run_provisional_key(run_id))?
                .is_some()
            {
                continue;
            }
            let record = decode_retrieval_run(value)?;
            if record.run_id != run_id {
                return Err(Error::CorruptedIndex("retrieval run telemetry"));
            }
            records.push(record);
            if records.len() == limit {
                break;
            }
        }
        Ok(records)
    }

    pub(crate) fn retrieval_run(
        &self,
        run_id: RetrievalRunId,
    ) -> Result<Option<RetrievalRunRecord>> {
        let rtxn = self.env.read_txn()?;
        if self
            .vault_meta
            .get(&rtxn, &retrieval_run_provisional_key(run_id))?
            .is_some()
        {
            return Ok(None);
        }
        let Some(value) = self.vault_meta.get(&rtxn, &retrieval_run_key(run_id))? else {
            return Ok(None);
        };
        let record = decode_retrieval_run(value)?;
        if record.run_id != run_id {
            return Err(Error::CorruptedIndex("retrieval run telemetry"));
        }
        Ok(Some(record))
    }

    pub(crate) fn retrieval_trace_by_fork_hash(
        &self,
        fork_hash: RetrievalTraceForkHash,
    ) -> Result<Option<RetrievalTrace>> {
        if is_unknown_retrieval_trace_fork_hash(&fork_hash) {
            return Ok(None);
        }
        let rtxn = self.env.read_txn()?;
        let prefix = retrieval_trace_fork_prefix(&fork_hash);
        let mut latest = None::<RetrievalRunRecord>;
        for row in self.vault_meta.prefix_iter(&rtxn, &prefix)? {
            let (key, _) = row?;
            let run_id = retrieval_run_id_from_fork_key(key)?;
            if self
                .vault_meta
                .get(&rtxn, &retrieval_run_provisional_key(run_id))?
                .is_some()
            {
                continue;
            }
            let Some(value) = self.vault_meta.get(&rtxn, &retrieval_run_key(run_id))? else {
                return Err(Error::CorruptedIndex("retrieval trace fork index"));
            };
            let record = decode_retrieval_run(value)?;
            let Some(trace) = &record.trace else {
                return Err(Error::CorruptedIndex("retrieval trace fork index"));
            };
            if record.run_id != run_id || trace.fork_hash != fork_hash {
                return Err(Error::CorruptedIndex("retrieval trace fork index"));
            }
            let replace = latest.as_ref().is_none_or(|current| {
                (record.started_at, record.run_id.as_bytes())
                    > (current.started_at, current.run_id.as_bytes())
            });
            if replace {
                latest = Some(record);
            }
        }
        Ok(latest.and_then(|record| record.trace))
    }

    pub(crate) fn retrieval_blend_weight_table_in_txn(
        &self,
        rtxn: &RoTxn<'_>,
    ) -> Result<RetrievalBlendWeightTableEntry> {
        let Some(value) = self
            .vault_meta
            .get(rtxn, RETRIEVAL_BLEND_WEIGHT_TABLE_KEY)?
        else {
            return Ok(RetrievalBlendWeightTableEntry::bootstrap());
        };
        decode_retrieval_blend_weight_table(value)
    }

    pub fn retrieval_blend_weight_table(&self) -> Result<RetrievalBlendWeightTableEntry> {
        let rtxn = self.env.read_txn()?;
        self.retrieval_blend_weight_table_in_txn(&rtxn)
    }

    pub fn tune_retrieval_blend_weights(
        &self,
        config: RetrievalBlendTuningConfig,
    ) -> Result<RetrievalBlendWeightTableEntry> {
        validate_retrieval_blend_tuning_config(config)?;
        if active_write_txn_depth() > 0 {
            return Err(Error::ConcurrentWrite(
                "retrieval blend weight tuning skipped inside active write transaction",
            ));
        }
        let _tuning_guard = self
            .retrieval_blend_tuning_lock
            .lock()
            .map_err(|_| Error::InvariantViolation("retrieval blend tuning mutex poisoned"))?;

        let rtxn = self.env.read_txn()?;
        let previous = self.retrieval_blend_weight_table_in_txn(&rtxn)?;
        let upper = retrieval_run_upper_bound();
        let mut gradient = [0.0_f64; 4];
        let mut reward_count = 0_usize;
        let mut component_count = 0_usize;
        let mut data_window = RetrievalBlendWeightDataWindow::default();

        let mut accepted_runs = 0_usize;
        for row in self.vault_meta.rev_range(
            &rtxn,
            &(
                std::ops::Bound::Included(RETRIEVAL_RUN_KEY_PREFIX),
                std::ops::Bound::Excluded(upper.as_slice()),
            ),
        )? {
            let (key, value) = row?;
            if !key.starts_with(RETRIEVAL_RUN_KEY_PREFIX) {
                break;
            }
            let run_id = retrieval_run_id_from_key(key)?;
            if self
                .vault_meta
                .get(&rtxn, &retrieval_run_provisional_key(run_id))?
                .is_some()
            {
                continue;
            }
            let record = decode_retrieval_run(value)?;
            if record.run_id != run_id {
                return Err(Error::CorruptedIndex("retrieval run telemetry"));
            }
            if accepted_runs == config.max_runs {
                break;
            }
            accepted_runs += 1;

            let outcomes = retrieval_outcomes_for_run_in_txn(&self.vault_meta, &rtxn, run_id)?;
            let run_reward_count_before = reward_count;
            let run_candidate_count_before = data_window.candidate_count;
            for outcome in outcomes.iter().filter(|outcome| outcome.reward.is_some()) {
                let reward = f64::from(outcome.reward.expect("filtered reward"));
                let mut outcome_gradient = [0.0_f64; 4];
                let mut outcome_component_count = 0_usize;
                let mut outcome_candidate_count = 0_u32;
                for candidate in &record.score_breakdown {
                    let rank_credit = 1.0 / f64::from(candidate.final_rank.max(1));
                    let mut candidate_has_blend_component = false;
                    for component in &candidate.components {
                        let Some(index) = retrieval_blend_component_index(component.signal) else {
                            continue;
                        };
                        if !component.score.is_finite() {
                            return Err(Error::CorruptedIndex("retrieval blend tuning"));
                        }
                        outcome_gradient[index] +=
                            reward * rank_credit * f64::from(component.score);
                        outcome_component_count += 1;
                        candidate_has_blend_component = true;
                    }
                    if candidate_has_blend_component {
                        outcome_candidate_count = outcome_candidate_count.saturating_add(1);
                    }
                }
                if outcome_component_count == 0 {
                    continue;
                }
                for (total, outcome) in gradient.iter_mut().zip(outcome_gradient) {
                    *total += outcome;
                }
                component_count += outcome_component_count;
                reward_count += 1;
                observe_retrieval_blend_outcome(&mut data_window, outcome);
                data_window.candidate_count = data_window
                    .candidate_count
                    .saturating_add(outcome_candidate_count);
            }
            if reward_count > run_reward_count_before
                && data_window.candidate_count > run_candidate_count_before
            {
                observe_retrieval_blend_run(&mut data_window, &record);
            }
        }
        drop(rtxn);

        if reward_count < config.min_reward_count {
            return Err(Error::InvalidConfig(format!(
                "retrieval blend tuning requires at least {} reward outcome(s), found {reward_count}",
                config.min_reward_count
            )));
        }
        if component_count == 0 {
            return Err(Error::InvalidConfig(
                "retrieval blend tuning requires blend-signal score components".to_owned(),
            ));
        }

        let weights = apply_retrieval_blend_weight_update(
            previous.weights,
            gradient,
            config.learning_rate,
            reward_count,
        )?;
        let mut provenance = BTreeMap::new();
        provenance.insert("source".to_owned(), "RetrievalOutcomeRecord".to_owned());
        provenance.insert(
            "algorithm".to_owned(),
            RETRIEVAL_BLEND_TUNER_ALGORITHM.to_owned(),
        );
        provenance.insert("max_runs".to_owned(), config.max_runs.to_string());
        provenance.insert("learning_rate".to_owned(), config.learning_rate.to_string());
        provenance.insert(
            "previous_tuned_at".to_owned(),
            previous.tuned_at.to_string(),
        );
        let entry = RetrievalBlendWeightTableEntry {
            version: RETRIEVAL_BLEND_WEIGHT_TABLE_VERSION,
            weights,
            tuned_at: crate::unix_seconds_now(),
            provenance,
            data_window,
        };
        self.put_retrieval_blend_weight_table_entry(&entry)?;
        Ok(entry)
    }

    fn put_retrieval_blend_weight_table_entry(
        &self,
        entry: &RetrievalBlendWeightTableEntry,
    ) -> Result<()> {
        vet_retrieval_blend_weight_table_entry(entry)
            .map_err(|_| Error::InvalidConfig("invalid retrieval blend weight table".to_owned()))?;
        let value = encode_retrieval_blend_weight_table(entry)?;
        let mut wtxn = self.env.write_txn()?;
        self.vault_meta
            .put(&mut wtxn, RETRIEVAL_BLEND_WEIGHT_TABLE_KEY, &value)?;
        wtxn.commit()?;
        Ok(())
    }

    pub fn retrieval_outcomes(
        &self,
        run_id: RetrievalRunId,
    ) -> Result<Vec<RetrievalOutcomeRecord>> {
        let rtxn = self.env.read_txn()?;
        if self
            .vault_meta
            .get(&rtxn, &retrieval_run_key(run_id))?
            .is_none()
            || self
                .vault_meta
                .get(&rtxn, &retrieval_run_provisional_key(run_id))?
                .is_some()
        {
            return Ok(Vec::new());
        }
        retrieval_outcomes_for_run_in_txn(&self.vault_meta, &rtxn, run_id)
    }
}

fn retrieval_run_key(run_id: RetrievalRunId) -> Vec<u8> {
    let mut key = Vec::with_capacity(RETRIEVAL_RUN_KEY_PREFIX.len() + 16);
    key.extend_from_slice(RETRIEVAL_RUN_KEY_PREFIX);
    key.extend_from_slice(&run_id.as_bytes());
    key
}

fn retrieval_run_id_from_key(key: &[u8]) -> Result<RetrievalRunId> {
    let bytes = key
        .strip_prefix(RETRIEVAL_RUN_KEY_PREFIX)
        .ok_or(Error::CorruptedIndex("retrieval run telemetry"))?;
    retrieval_run_id_from_value(bytes)
}

fn retrieval_run_id_from_value(bytes: &[u8]) -> Result<RetrievalRunId> {
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| Error::CorruptedIndex("retrieval run telemetry"))?;
    Ok(RetrievalRunId { bytes })
}

fn retrieval_trace_fork_prefix(fork_hash: &RetrievalTraceForkHash) -> Vec<u8> {
    let mut key = Vec::with_capacity(RETRIEVAL_TRACE_FORK_KEY_PREFIX.len() + 32);
    key.extend_from_slice(RETRIEVAL_TRACE_FORK_KEY_PREFIX);
    key.extend_from_slice(fork_hash);
    key
}

fn retrieval_trace_fork_key(fork_hash: &RetrievalTraceForkHash, run_id: RetrievalRunId) -> Vec<u8> {
    let mut key = Vec::with_capacity(RETRIEVAL_TRACE_FORK_KEY_PREFIX.len() + 32 + 16);
    key.extend_from_slice(&retrieval_trace_fork_prefix(fork_hash));
    key.extend_from_slice(&run_id.as_bytes());
    key
}

fn is_unknown_retrieval_trace_fork_hash(fork_hash: &RetrievalTraceForkHash) -> bool {
    fork_hash.iter().all(|byte| *byte == 0)
}

fn put_retrieval_trace_fork_index(
    vault_meta: &Database<Bytes, Bytes>,
    wtxn: &mut RwTxn<'_>,
    fork_hash: &RetrievalTraceForkHash,
    run_id: RetrievalRunId,
) -> Result<()> {
    if !is_unknown_retrieval_trace_fork_hash(fork_hash) {
        vault_meta.put(wtxn, &retrieval_trace_fork_key(fork_hash, run_id), b"1")?;
    }
    Ok(())
}

fn delete_retrieval_trace_fork_indexes_for_run(
    vault_meta: &Database<Bytes, Bytes>,
    wtxn: &mut RwTxn<'_>,
    run_key: &[u8],
    run_id: RetrievalRunId,
) -> Result<()> {
    if let Some(raw) = vault_meta.get(wtxn, run_key)?
        && let Ok(record) = decode_retrieval_run(raw)
        && record.run_id == run_id
        && let Some(trace) = record.trace
        && !is_unknown_retrieval_trace_fork_hash(&trace.fork_hash)
    {
        vault_meta.delete(wtxn, &retrieval_trace_fork_key(&trace.fork_hash, run_id))?;
        return Ok(());
    }

    let run_id_bytes = run_id.as_bytes();
    let expected_len = RETRIEVAL_TRACE_FORK_KEY_PREFIX.len() + 32 + 16;
    let mut keys = Vec::new();
    for row in vault_meta.prefix_iter(wtxn, RETRIEVAL_TRACE_FORK_KEY_PREFIX)? {
        let (key, _) = row?;
        if key.len() == expected_len && key.ends_with(&run_id_bytes) {
            keys.push(key.to_vec());
        }
    }
    for key in keys {
        vault_meta.delete(wtxn, &key)?;
    }
    Ok(())
}

fn retrieval_run_id_from_fork_key(key: &[u8]) -> Result<RetrievalRunId> {
    let suffix = key
        .strip_prefix(RETRIEVAL_TRACE_FORK_KEY_PREFIX)
        .and_then(|bytes| bytes.get(32..))
        .ok_or(Error::CorruptedIndex("retrieval trace fork index"))?;
    retrieval_run_id_from_value(suffix)
}

fn retrieval_run_provisional_key(run_id: RetrievalRunId) -> Vec<u8> {
    let mut key = Vec::with_capacity(RETRIEVAL_RUN_PROVISIONAL_KEY_PREFIX.len() + 16);
    key.extend_from_slice(RETRIEVAL_RUN_PROVISIONAL_KEY_PREFIX);
    key.extend_from_slice(&run_id.as_bytes());
    key
}

fn retrieval_run_upper_bound() -> Vec<u8> {
    let mut key = Vec::with_capacity(RETRIEVAL_RUN_KEY_PREFIX.len());
    key.extend_from_slice(RETRIEVAL_RUN_KEY_PREFIX);
    *key.last_mut()
        .expect("retrieval run key prefix must be non-empty") += 1;
    key
}

fn retrieval_outcome_run_prefix(run_id: RetrievalRunId) -> Vec<u8> {
    let mut key = Vec::with_capacity(RETRIEVAL_OUTCOME_KEY_PREFIX.len() + 17);
    key.extend_from_slice(RETRIEVAL_OUTCOME_KEY_PREFIX);
    key.extend_from_slice(&run_id.as_bytes());
    key.push(b':');
    key
}

fn retrieval_outcome_key(run_id: RetrievalRunId, outcome_key: &str) -> Vec<u8> {
    let mut key = retrieval_outcome_run_prefix(run_id);
    key.extend_from_slice(outcome_key.as_bytes());
    key
}

fn retrieval_outcome_parts_from_key(key: &[u8]) -> Result<(RetrievalRunId, String)> {
    let suffix = key
        .strip_prefix(RETRIEVAL_OUTCOME_KEY_PREFIX)
        .ok_or(Error::CorruptedIndex("retrieval outcome telemetry"))?;
    if suffix.len() < 17 || suffix[16] != b':' {
        return Err(Error::CorruptedIndex("retrieval outcome telemetry"));
    }
    let run_id_bytes: [u8; 16] = suffix[..16]
        .try_into()
        .map_err(|_| Error::CorruptedIndex("retrieval outcome telemetry"))?;
    let outcome_key_bytes = &suffix[17..];
    let outcome_key = std::str::from_utf8(outcome_key_bytes)
        .map_err(|_| Error::CorruptedIndex("retrieval outcome telemetry"))?;
    if outcome_key.is_empty()
        || outcome_key.len() > RETRIEVAL_OUTCOME_KEY_MAX_LEN
        || !outcome_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err(Error::CorruptedIndex("retrieval outcome telemetry"));
    }
    Ok((
        RetrievalRunId {
            bytes: run_id_bytes,
        },
        outcome_key.to_owned(),
    ))
}

fn encode_retrieval_run(record: &RetrievalRunRecord) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvariantViolation("retrieval run telemetry encode failed"))
}

fn decode_retrieval_run(raw: &[u8]) -> Result<RetrievalRunRecord> {
    let record: RetrievalRunRecord =
        rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("retrieval run telemetry"))?;
    if record.version != RETRIEVAL_TELEMETRY_VERSION {
        return Err(Error::CorruptedIndex("retrieval run telemetry"));
    }
    Ok(record)
}

fn encode_retrieval_outcome(record: &RetrievalOutcomeRecord) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvariantViolation("retrieval outcome telemetry encode failed"))
}

fn decode_retrieval_outcome(raw: &[u8]) -> Result<RetrievalOutcomeRecord> {
    let record: RetrievalOutcomeRecord = rmp_serde::from_slice(raw)
        .map_err(|_| Error::CorruptedIndex("retrieval outcome telemetry"))?;
    if record.version != RETRIEVAL_TELEMETRY_VERSION {
        return Err(Error::CorruptedIndex("retrieval outcome telemetry"));
    }
    Ok(record)
}

fn retrieval_outcomes_for_run_in_txn(
    vault_meta: &Database<Bytes, Bytes>,
    rtxn: &RoTxn<'_>,
    run_id: RetrievalRunId,
) -> Result<Vec<RetrievalOutcomeRecord>> {
    let prefix = retrieval_outcome_run_prefix(run_id);
    let mut records = Vec::new();
    for row in vault_meta.prefix_iter(rtxn, &prefix)? {
        let (key, value) = row?;
        let (key_run_id, key_outcome_key) = retrieval_outcome_parts_from_key(key)?;
        if key_run_id != run_id {
            return Err(Error::CorruptedIndex("retrieval outcome telemetry"));
        }
        let record = decode_retrieval_outcome(value)?;
        if record.run_id != key_run_id || record.key != key_outcome_key {
            return Err(Error::CorruptedIndex("retrieval outcome telemetry"));
        }
        records.push(record);
    }
    records.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(records)
}

fn encode_retrieval_blend_weight_table(entry: &RetrievalBlendWeightTableEntry) -> Result<Vec<u8>> {
    vet_retrieval_blend_weight_table_entry(entry)?;
    rmp_serde::to_vec_named(entry)
        .map_err(|_| Error::InvariantViolation("retrieval blend weight table encode failed"))
}

fn decode_retrieval_blend_weight_table(raw: &[u8]) -> Result<RetrievalBlendWeightTableEntry> {
    let mut entry: RetrievalBlendWeightTableEntry = rmp_serde::from_slice(raw)
        .map_err(|_| Error::CorruptedIndex("retrieval blend weight table"))?;
    vet_retrieval_blend_weight_table_entry(&entry)?;
    entry.weights = entry
        .weights
        .normalized()
        .map_err(|_| Error::CorruptedIndex("retrieval blend weight table"))?;
    Ok(entry)
}

fn vet_retrieval_blend_weight_table_entry(entry: &RetrievalBlendWeightTableEntry) -> Result<()> {
    if entry.version != RETRIEVAL_BLEND_WEIGHT_TABLE_VERSION
        || entry.provenance.is_empty()
        || !entry.provenance.contains_key("source")
        || !entry.provenance.contains_key("algorithm")
    {
        return Err(Error::CorruptedIndex("retrieval blend weight table"));
    }
    validate_retrieval_blend_weights(entry.weights)
        .map_err(|_| Error::CorruptedIndex("retrieval blend weight table"))?;
    if entry.data_window.outcome_count > 0
        && (entry.data_window.outcome_updated_at_min.is_none()
            || entry.data_window.outcome_updated_at_max.is_none())
    {
        return Err(Error::CorruptedIndex("retrieval blend weight table"));
    }
    if entry.data_window.run_count > 0
        && (entry.data_window.started_at_min.is_none()
            || entry.data_window.started_at_max.is_none())
    {
        return Err(Error::CorruptedIndex("retrieval blend weight table"));
    }
    Ok(())
}

fn validate_retrieval_blend_weights(
    weights: RetrievalBlendWeights,
) -> std::result::Result<(), String> {
    let values = [
        ("recency", weights.recency),
        ("salience", weights.salience),
        ("confidence", weights.confidence),
        ("gravity", weights.gravity),
    ];
    for (name, value) in values {
        if !value.is_finite() || value < 0.0 {
            return Err(format!(
                "retrieval blend {name} weight must be finite and non-negative"
            ));
        }
    }
    if weights.sum() <= 0.0 {
        return Err("retrieval blend weights must have positive total mass".to_owned());
    }
    Ok(())
}

fn validate_retrieval_blend_tuning_config(config: RetrievalBlendTuningConfig) -> Result<()> {
    if config.max_runs == 0 {
        return Err(Error::InvalidConfig(
            "retrieval blend tuning max_runs must be positive".to_owned(),
        ));
    }
    if config.min_reward_count == 0 {
        return Err(Error::InvalidConfig(
            "retrieval blend tuning min_reward_count must be positive".to_owned(),
        ));
    }
    if !config.learning_rate.is_finite() || config.learning_rate <= 0.0 {
        return Err(Error::InvalidConfig(
            "retrieval blend tuning learning_rate must be finite and positive".to_owned(),
        ));
    }
    Ok(())
}

fn retrieval_blend_component_index(signal: RetrievalSignal) -> Option<usize> {
    match signal.as_blend_signal()? {
        RetrievalBlendSignal::Recency => Some(0),
        RetrievalBlendSignal::Salience => Some(1),
        RetrievalBlendSignal::Confidence => Some(2),
        RetrievalBlendSignal::Gravity => Some(3),
    }
}

fn observe_retrieval_blend_run(
    data_window: &mut RetrievalBlendWeightDataWindow,
    record: &RetrievalRunRecord,
) {
    data_window.run_count = data_window.run_count.saturating_add(1);
    data_window.started_at_min = Some(
        data_window
            .started_at_min
            .map_or(record.started_at, |current| current.min(record.started_at)),
    );
    data_window.started_at_max = Some(
        data_window
            .started_at_max
            .map_or(record.started_at, |current| current.max(record.started_at)),
    );
}

fn observe_retrieval_blend_outcome(
    data_window: &mut RetrievalBlendWeightDataWindow,
    record: &RetrievalOutcomeRecord,
) {
    data_window.outcome_count = data_window.outcome_count.saturating_add(1);
    data_window.outcome_updated_at_min = Some(
        data_window
            .outcome_updated_at_min
            .map_or(record.updated_at, |current| current.min(record.updated_at)),
    );
    data_window.outcome_updated_at_max = Some(
        data_window
            .outcome_updated_at_max
            .map_or(record.updated_at, |current| current.max(record.updated_at)),
    );
}

fn apply_retrieval_blend_weight_update(
    previous: RetrievalBlendWeights,
    gradient: [f64; 4],
    learning_rate: f32,
    reward_count: usize,
) -> Result<RetrievalBlendWeights> {
    let reward_scale = reward_count.max(1) as f64;
    let learning_rate = f64::from(learning_rate);
    let mut next = [
        f64::from(previous.recency) + learning_rate * gradient[0] / reward_scale,
        f64::from(previous.salience) + learning_rate * gradient[1] / reward_scale,
        f64::from(previous.confidence) + learning_rate * gradient[2] / reward_scale,
        f64::from(previous.gravity) + learning_rate * gradient[3] / reward_scale,
    ];
    for value in &mut next {
        if !value.is_finite() {
            return Err(Error::InvalidConfig(
                "retrieval blend tuning produced non-finite weight".to_owned(),
            ));
        }
        *value = value.max(0.0);
    }
    let sum = next.iter().sum::<f64>();
    if sum <= f64::EPSILON {
        return previous.normalized();
    }
    RetrievalBlendWeights::new(
        (next[0] / sum) as f32,
        (next[1] / sum) as f32,
        (next[2] / sum) as f32,
        (next[3] / sum) as f32,
    )
    .normalized()
}

fn gate_decision_key(decision_id: GateDecisionId) -> Vec<u8> {
    let mut key = Vec::with_capacity(GATE_DECISION_KEY_PREFIX.len() + 16);
    key.extend_from_slice(GATE_DECISION_KEY_PREFIX);
    key.extend_from_slice(&decision_id.as_bytes());
    key
}

fn gate_decision_id_from_key(key: &[u8]) -> Result<GateDecisionId> {
    let bytes = key
        .strip_prefix(GATE_DECISION_KEY_PREFIX)
        .ok_or(Error::CorruptedIndex("gate decision ledger"))?;
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| Error::CorruptedIndex("gate decision ledger"))?;
    Ok(GateDecisionId { bytes })
}

fn gate_decision_upper_bound() -> Vec<u8> {
    let mut key = Vec::from(GATE_DECISION_KEY_PREFIX);
    let last = key
        .last_mut()
        .expect("gate decision key prefix must be non-empty");
    *last = last
        .checked_add(1)
        .expect("gate decision key prefix upper bound must not overflow");
    key
}

fn pending_gate_consent_key(claim_id: &[u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(PENDING_GATE_CONSENT_KEY_PREFIX.len() + 16);
    key.extend_from_slice(PENDING_GATE_CONSENT_KEY_PREFIX);
    key.extend_from_slice(claim_id);
    key
}

fn pending_gate_consent_claim_id_from_key(key: &[u8]) -> Result<[u8; 16]> {
    let bytes = key
        .strip_prefix(PENDING_GATE_CONSENT_KEY_PREFIX)
        .ok_or(Error::CorruptedIndex("pending gate consent"))?;
    bytes
        .try_into()
        .map_err(|_| Error::CorruptedIndex("pending gate consent"))
}

fn pending_gate_consent_upper_bound() -> Vec<u8> {
    let mut key = Vec::from(PENDING_GATE_CONSENT_KEY_PREFIX);
    let last = key
        .last_mut()
        .expect("pending gate consent key prefix must be non-empty");
    *last = last
        .checked_add(1)
        .expect("pending gate consent key prefix upper bound must not overflow");
    key
}

fn encode_gate_decision(record: &GateDecisionRecord) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvariantViolation("gate decision ledger encode failed"))
}

fn decode_gate_decision(raw: &[u8]) -> Result<GateDecisionRecord> {
    let record: GateDecisionRecord =
        rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("gate decision ledger"))?;
    vet_gate_decision_record(&record)?;
    Ok(record)
}

fn encode_pending_gate_consent(record: &PendingGateConsentRecord) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvariantViolation("pending gate consent encode failed"))
}

fn decode_pending_gate_consent(raw: &[u8]) -> Result<PendingGateConsentRecord> {
    let record: PendingGateConsentRecord =
        rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("pending gate consent"))?;
    vet_pending_gate_consent_record(&record)?;
    Ok(record)
}

fn vet_gate_decision_record(record: &GateDecisionRecord) -> Result<()> {
    if record.version != GATE_DECISION_LEDGER_VERSION
        || record.outcome.is_empty()
        || record.reason_codes.is_empty()
        || record.content_kind.is_empty()
        || record.policy_manifest_version.is_empty()
        || record.diff_handle.is_empty()
        || record.diff_handle.len() > GATE_DIFF_HANDLE_MAX_LEN
        || !record
            .reason_codes
            .iter()
            .all(|reason| reason.starts_with("gate."))
    {
        return Err(Error::CorruptedIndex("gate decision ledger"));
    }
    Ok(())
}

fn vet_pending_gate_consent_record(record: &PendingGateConsentRecord) -> Result<()> {
    if record.version != GATE_DECISION_LEDGER_VERSION
        || record.diff_handle.is_empty()
        || record.diff_handle.len() > GATE_DIFF_HANDLE_MAX_LEN
        || record.reason_codes.is_empty()
        || !record
            .reason_codes
            .iter()
            .all(|reason| reason.starts_with("gate.pending."))
    {
        return Err(Error::CorruptedIndex("pending gate consent"));
    }
    if let Some(dreamer_run_id) = record.dreamer_run_id.as_deref()
        && (dreamer_run_id.trim().is_empty()
            || dreamer_run_id.len() > PENDING_GATE_CONSENT_DREAMER_RUN_ID_MAX_LEN)
    {
        return Err(Error::CorruptedIndex("pending gate consent"));
    }
    Ok(())
}

fn vet_retrieval_outcome(outcome: &RetrievalOutcome) -> Result<()> {
    if outcome.key.is_empty()
        || outcome.key.len() > RETRIEVAL_OUTCOME_KEY_MAX_LEN
        || !outcome
            .key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err(Error::InvalidConfig(
            "retrieval outcome key must be 1-128 chars of ASCII alnum, '.', '_', '-', or ':'"
                .to_owned(),
        ));
    }
    if let Some(reward) = outcome.reward
        && !reward.is_finite()
    {
        return Err(Error::InvalidConfig(
            "retrieval outcome reward must be finite".to_owned(),
        ));
    }
    Ok(())
}

fn load_structural_kind_registry(
    env: &Env,
    vault_meta: &Database<Bytes, Bytes>,
) -> Result<HashMap<u8, StructuralKindRegistration>> {
    let rtxn = env.read_txn()?;
    let mut registry = HashMap::new();
    let mut prefixes = HashSet::new();
    for row in vault_meta.prefix_iter(&rtxn, STRUCTURAL_KIND_REGISTRY_KEY_PREFIX)? {
        let (key, value) = row?;
        let registration = decode_structural_kind_registration(key, value)?;
        vet_structural_kind_registration_shape(&registration)
            .map_err(|_| Error::CorruptedIndex("structural kind registry"))?;
        vet_structural_kind_registration_band(&registration)
            .map_err(|_| Error::CorruptedIndex("structural kind registry"))?;
        if entity_type_registry_entry(registration.type_byte).is_some() {
            if is_compatible_legacy_companion_register_row(&registration) {
                continue;
            }
            return Err(Error::CorruptedIndex("structural kind registry"));
        }
        if static_short_id_prefix_collision(&registration.short_id_prefix)
            || !prefixes.insert(registration.short_id_prefix.clone())
            || registry
                .insert(registration.type_byte, registration)
                .is_some()
        {
            return Err(Error::CorruptedIndex("structural kind registry"));
        }
    }
    Ok(registry)
}

fn is_compatible_legacy_companion_register_row(registration: &StructuralKindRegistration) -> bool {
    registration.type_byte == ENTITY_TYPE_COMPANION_REGISTER
        && registration.short_id_prefix == COMPANION_REGISTER_SHORT_ID_PREFIX
        && registration.band == TypeByteBand::Companion
        && registration.pack == COMPANION_REGISTER_PACK_ID
}

fn vault_meta_has_structural_kind_prefix(
    vault_meta: &Database<Bytes, Bytes>,
    txn: &RwTxn<'_>,
    short_id_prefix: &str,
) -> Result<bool> {
    for row in vault_meta.prefix_iter(txn, STRUCTURAL_KIND_REGISTRY_KEY_PREFIX)? {
        let (key, value) = row?;
        let registration = decode_structural_kind_registration(key, value)?;
        if registration.short_id_prefix == short_id_prefix {
            return Ok(true);
        }
    }
    Ok(false)
}

fn vet_structural_kind_registration_shape(registration: &StructuralKindRegistration) -> Result<()> {
    let prefix = registration.short_id_prefix.as_bytes();
    if prefix.len() != 2 || !prefix.iter().all(u8::is_ascii_lowercase) {
        return Err(Error::InvalidStructuralKindRegistration(
            "short_id_prefix must be exactly two lowercase ASCII letters",
        ));
    }
    if registration.pack.is_empty() {
        return Err(Error::InvalidStructuralKindRegistration(
            "pack must not be empty",
        ));
    }
    if registration.pack.len() > u16::MAX as usize {
        return Err(Error::InvalidStructuralKindRegistration(
            "pack must fit in u16 bytes",
        ));
    }
    Ok(())
}

fn vet_structural_kind_registration_band(registration: &StructuralKindRegistration) -> Result<()> {
    let actual_band = band_of(registration.type_byte);
    if actual_band != registration.band {
        return Err(Error::StructuralKindBandViolation {
            type_byte: registration.type_byte,
            declared_band: registration.band,
            actual_band,
            reason: "type byte is outside the declared band",
        });
    }
    match actual_band {
        TypeByteBand::Companion | TypeByteBand::Productivity | TypeByteBand::Crm => Ok(()),
        TypeByteBand::Semantic | TypeByteBand::Core => Err(Error::StructuralKindBandViolation {
            type_byte: registration.type_byte,
            declared_band: registration.band,
            actual_band,
            reason: "semantic and CORE bytes are reserved",
        }),
        TypeByteBand::InducedDynamicMaintenance => Err(Error::StructuralKindBandViolation {
            type_byte: registration.type_byte,
            declared_band: registration.band,
            actual_band,
            reason: "maintenance-band dynamic registration is out of scope",
        }),
    }
}

fn encode_structural_kind_registration(
    registration: &StructuralKindRegistration,
) -> Result<Vec<u8>> {
    let prefix = registration.short_id_prefix.as_bytes();
    let pack = registration.pack.as_bytes();
    let pack_len = u16::try_from(pack.len())
        .map_err(|_| Error::InvalidStructuralKindRegistration("pack must fit in u16 bytes"))?;

    let mut encoded =
        Vec::with_capacity(STRUCTURAL_KIND_REGISTRY_RECORD_HEADER_LEN + prefix.len() + pack.len());
    encoded.push(STRUCTURAL_KIND_REGISTRY_RECORD_VERSION);
    encoded.push(registration.type_byte);
    encoded.push(type_byte_band_code(registration.band));
    encoded.push(u8::try_from(prefix.len()).expect("prefix length vetted as two bytes"));
    encoded.extend_from_slice(&pack_len.to_le_bytes());
    encoded.extend_from_slice(prefix);
    encoded.extend_from_slice(pack);
    Ok(encoded)
}

fn decode_structural_kind_registration(
    key: &[u8],
    raw: &[u8],
) -> Result<StructuralKindRegistration> {
    if key.len() != STRUCTURAL_KIND_REGISTRY_KEY_LEN
        || !key.starts_with(STRUCTURAL_KIND_REGISTRY_KEY_PREFIX)
        || raw.len() < STRUCTURAL_KIND_REGISTRY_RECORD_HEADER_LEN
        || raw[0] != STRUCTURAL_KIND_REGISTRY_RECORD_VERSION
    {
        return Err(Error::CorruptedIndex("structural kind registry"));
    }

    let type_byte = raw[1];
    if key[STRUCTURAL_KIND_REGISTRY_KEY_PREFIX.len()] != type_byte {
        return Err(Error::CorruptedIndex("structural kind registry"));
    }
    let band = type_byte_band_from_code(raw[2])
        .ok_or(Error::CorruptedIndex("structural kind registry"))?;
    let prefix_len = raw[3] as usize;
    let pack_len = u16::from_le_bytes(
        raw[4..6]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("structural kind registry"))?,
    ) as usize;
    let expected_len = STRUCTURAL_KIND_REGISTRY_RECORD_HEADER_LEN + prefix_len + pack_len;
    if raw.len() != expected_len {
        return Err(Error::CorruptedIndex("structural kind registry"));
    }
    let prefix_start = STRUCTURAL_KIND_REGISTRY_RECORD_HEADER_LEN;
    let pack_start = prefix_start + prefix_len;
    let short_id_prefix = str::from_utf8(&raw[prefix_start..pack_start])
        .map_err(|_| Error::CorruptedIndex("structural kind registry"))?
        .to_owned();
    let pack = str::from_utf8(&raw[pack_start..])
        .map_err(|_| Error::CorruptedIndex("structural kind registry"))?
        .to_owned();

    Ok(StructuralKindRegistration {
        type_byte,
        short_id_prefix,
        band,
        pack,
    })
}

fn type_byte_band_code(band: TypeByteBand) -> u8 {
    match band {
        TypeByteBand::Semantic => 0,
        TypeByteBand::Core => 1,
        TypeByteBand::Companion => 2,
        TypeByteBand::Productivity => 3,
        TypeByteBand::Crm => 4,
        TypeByteBand::InducedDynamicMaintenance => 5,
    }
}

fn type_byte_band_from_code(code: u8) -> Option<TypeByteBand> {
    match code {
        0 => Some(TypeByteBand::Semantic),
        1 => Some(TypeByteBand::Core),
        2 => Some(TypeByteBand::Companion),
        3 => Some(TypeByteBand::Productivity),
        4 => Some(TypeByteBand::Crm),
        5 => Some(TypeByteBand::InducedDynamicMaintenance),
        _ => None,
    }
}

#[derive(Clone, Debug)]
struct VaultRootPreflight {
    is_new_vault: bool,
    identity: Option<VaultRootIdentity>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VaultRootIdentity {
    data: FileIdentity,
    lock: FileIdentity,
}

impl VaultRootIdentity {
    fn overlaps(&self, other: &Self) -> bool {
        self.data == other.data
            || self.data == other.lock
            || self.lock == other.data
            || self.lock == other.lock
    }
}

#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
}

#[cfg(windows)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct FileIdentity {
    volume_serial_number: u32,
    file_index: u64,
}

#[cfg(not(any(unix, windows)))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct FileIdentity {
    unsupported: (),
}

#[derive(Clone, Debug)]
struct VaultRootFile {
    identity: FileIdentity,
    link_count: u64,
}

fn preflight_vault_root(root: &Path) -> Result<VaultRootPreflight> {
    let data = inspect_vault_root_entry(root, VaultRootEntry::Data)?;
    let lock = inspect_vault_root_entry(root, VaultRootEntry::Lock)?;

    match (data, lock) {
        (None, None) => Ok(VaultRootPreflight {
            is_new_vault: true,
            identity: None,
        }),
        (Some(_), None) => Err(vault_root_preflight_error(
            root,
            VaultRootProblem::IncompleteLmdbPair {
                present: VaultRootEntry::Data,
                missing: VaultRootEntry::Lock,
            },
        )),
        (None, Some(_)) => Err(vault_root_preflight_error(
            root,
            VaultRootProblem::IncompleteLmdbPair {
                present: VaultRootEntry::Lock,
                missing: VaultRootEntry::Data,
            },
        )),
        (Some(data), Some(lock)) => {
            if data.identity == lock.identity {
                return Err(vault_root_preflight_error(
                    root,
                    VaultRootProblem::AliasedLmdbFiles {
                        first: VaultRootEntry::Data,
                        second: VaultRootEntry::Lock,
                    },
                ));
            }
            if data.link_count > 1 {
                return Err(vault_root_preflight_error(
                    root,
                    VaultRootProblem::MultipleHardLinks {
                        entry: VaultRootEntry::Data,
                        link_count: data.link_count,
                    },
                ));
            }
            if lock.link_count > 1 {
                return Err(vault_root_preflight_error(
                    root,
                    VaultRootProblem::MultipleHardLinks {
                        entry: VaultRootEntry::Lock,
                        link_count: lock.link_count,
                    },
                ));
            }

            Ok(VaultRootPreflight {
                is_new_vault: false,
                identity: Some(VaultRootIdentity {
                    data: data.identity,
                    lock: lock.identity,
                }),
            })
        }
    }
}

fn inspect_vault_root_entry(root: &Path, entry: VaultRootEntry) -> Result<Option<VaultRootFile>> {
    let path = root.join(entry.file_name());
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(vault_root_preflight_error(
            root,
            VaultRootProblem::SymlinkEntry { entry },
        ));
    }
    if !file_type.is_file() {
        return Err(vault_root_preflight_error(
            root,
            VaultRootProblem::NonRegularEntry { entry },
        ));
    }

    #[cfg(unix)]
    {
        Ok(Some(VaultRootFile {
            identity: file_identity(&metadata),
            link_count: hard_link_count(&metadata),
        }))
    }
    #[cfg(windows)]
    {
        file_info(&path).map(Some)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(vault_root_preflight_error(
            root,
            VaultRootProblem::UnsupportedPlatform { entry },
        ))
    }
}

#[cfg(unix)]
fn file_identity(metadata: &std::fs::Metadata) -> FileIdentity {
    FileIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    }
}

#[cfg(unix)]
fn hard_link_count(metadata: &std::fs::Metadata) -> u64 {
    metadata.nlink()
}

#[cfg(windows)]
fn file_info(path: &Path) -> Result<VaultRootFile> {
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let file = std::fs::File::open(path)?;
    let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: `file.as_raw_handle()` is a live file handle for the duration of
    // the call, and `info` points to writable, properly aligned storage for the
    // Win32 API to initialize.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: `GetFileInformationByHandle` returned non-zero, which means it
    // initialized the BY_HANDLE_FILE_INFORMATION buffer.
    let info = unsafe { info.assume_init() };

    Ok(VaultRootFile {
        identity: FileIdentity {
            volume_serial_number: info.dwVolumeSerialNumber,
            file_index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        },
        link_count: u64::from(info.nNumberOfLinks),
    })
}

fn vault_root_preflight_error(root: &Path, problem: VaultRootProblem) -> Error {
    Error::VaultRootPreflight {
        path: root.to_path_buf(),
        problem,
    }
}

fn duplicate_open_root(
    open_paths: &HashMap<PathBuf, Option<VaultRootIdentity>>,
    path: &Path,
    identity: &VaultRootIdentity,
) -> Option<PathBuf> {
    open_paths.iter().find_map(|(open_path, open_identity)| {
        (open_path != path
            && open_identity
                .as_ref()
                .is_some_and(|open| open.overlaps(identity)))
        .then(|| open_path.clone())
    })
}

struct RegisteredPath {
    path: PathBuf,
}

impl RegisteredPath {
    fn reserve(path: PathBuf, identity: Option<VaultRootIdentity>) -> Result<Self> {
        let mut open_paths = OPEN_STORE_PATHS
            .lock()
            .map_err(|_| Error::InvariantViolation("store path registry mutex poisoned"))?;

        if open_paths.contains_key(&path) {
            return Err(vault_root_preflight_error(
                &path,
                VaultRootProblem::DuplicateOpenRoot {
                    open_path: path.clone(),
                },
            ));
        }
        if let Some(identity) = &identity
            && let Some(open_path) = duplicate_open_root(&open_paths, &path, identity)
        {
            return Err(vault_root_preflight_error(
                &path,
                VaultRootProblem::DuplicateOpenRoot { open_path },
            ));
        }

        open_paths.insert(path.clone(), identity);
        Ok(Self { path })
    }

    fn refresh_identity(&mut self, identity: Option<VaultRootIdentity>) -> Result<()> {
        let mut open_paths = OPEN_STORE_PATHS
            .lock()
            .map_err(|_| Error::InvariantViolation("store path registry mutex poisoned"))?;

        if let Some(identity) = &identity
            && let Some(open_path) = duplicate_open_root(&open_paths, &self.path, identity)
        {
            return Err(vault_root_preflight_error(
                &self.path,
                VaultRootProblem::DuplicateOpenRoot { open_path },
            ));
        }

        let slot = open_paths
            .get_mut(&self.path)
            .ok_or(Error::InvariantViolation("missing reserved store path"))?;
        *slot = identity;
        Ok(())
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

fn vault_root_open_guard() -> Result<MutexGuard<'static, ()>> {
    VAULT_ROOT_OPEN_LOCK
        .lock()
        .map_err(|_| Error::InvariantViolation("vault root open mutex poisoned"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Vault;
    use crate::types::{EntityId, TimeRange};
    use std::collections::BTreeMap;
    use std::sync::{Arc, Barrier};

    fn open_test_vault() -> (tempfile::TempDir, Vault) {
        crate::test_util::open_test_vault_with(VaultConfig::device())
    }

    fn entity_id(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; 16]).expect("test ids should be valid")
    }

    fn put_text(vault: &Vault, id: EntityId, text: &str) -> Result<()> {
        vault
            .batch()
            .put(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"payload")
            .text(&id, &[("body", text)])
            .commit()
    }

    fn raw_retrieval_run_row(vault: &Vault, run_id: RetrievalRunId) -> Result<Vec<u8>> {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .vault_meta
            .get(&rtxn, &retrieval_run_key(run_id))?
            .map(<[u8]>::to_vec)
            .ok_or(Error::CorruptedIndex("retrieval run telemetry"))
    }

    fn raw_retrieval_outcome_row(
        vault: &Vault,
        run_id: RetrievalRunId,
        outcome_key: &str,
    ) -> Result<Vec<u8>> {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .vault_meta
            .get(&rtxn, &retrieval_outcome_key(run_id, outcome_key))?
            .map(<[u8]>::to_vec)
            .ok_or(Error::CorruptedIndex("retrieval outcome telemetry"))
    }

    fn record_click_outcome(vault: &Vault, run_id: RetrievalRunId) -> Result<()> {
        vault.record_retrieval_outcome(RetrievalOutcome {
            run_id,
            key: "click".to_owned(),
            reward: Some(1.0),
            accepted: Some(true),
            metadata: BTreeMap::new(),
        })
    }

    fn assert_secret_scan_rejected(error: Error, expected_reason: &'static str) {
        match error {
            Error::GateWriteRejected {
                outcome,
                reason_codes,
            } => {
                assert_eq!(outcome, "deny");
                assert_eq!(
                    reason_codes.as_slice(),
                    &["gate.secret_scan.detected", expected_reason]
                );
            }
            other => panic!("expected GateWriteRejected, got {other:?}"),
        }
    }

    #[test]
    fn retrieval_run_without_trace_omits_trace_field_from_msgpack() -> Result<()> {
        let record = RetrievalRunRecord::new(
            RetrievalRunId::now(),
            RetrievalAction::Pipeline,
            1,
            2,
            vec![RetrievalSignal::Text],
            Vec::new(),
            0,
            0,
            None,
        );

        assert!(record.trace.is_none());
        let encoded = encode_retrieval_run(&record)?;
        let encoded_value =
            rmpv::decode::read_value(&mut &encoded[..]).expect("encoded retrieval run msgpack");
        let rmpv::Value::Map(fields) = encoded_value else {
            panic!("encoded retrieval run must be a msgpack map");
        };
        assert!(
            fields.iter().all(|(key, _)| key.as_str() != Some("trace")),
            "flag-off trace extension must omit the top-level trace key"
        );
        let decoded = decode_retrieval_run(&encoded)?;
        assert_eq!(decoded.trace, None);
        Ok(())
    }

    #[test]
    fn context_pack_finalization_preserves_reranked_trace_stage() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let run_id = RetrievalRunId::now();
        let kept = entity_id(0xD1);
        let dropped = entity_id(0xD2);
        let score_breakdown = vec![
            RetrievalScoreBreakdown {
                result_id: *kept.as_bytes(),
                final_rank: 1,
                final_score: 2.0,
                components: vec![RetrievalScoreComponent {
                    signal: RetrievalSignal::Text,
                    rank: 1,
                    score: 2.0,
                }],
            },
            RetrievalScoreBreakdown {
                result_id: *dropped.as_bytes(),
                final_rank: 2,
                final_score: 1.0,
                components: vec![RetrievalScoreComponent {
                    signal: RetrievalSignal::Text,
                    rank: 2,
                    score: 1.0,
                }],
            },
        ];
        let record = RetrievalRunRecord::new(
            run_id,
            RetrievalAction::ContextPack,
            1,
            2,
            vec![RetrievalSignal::Text],
            score_breakdown.clone(),
            0,
            0,
            None,
        )
        .with_trace(Some(RetrievalTrace {
            fork_hash: [0xD0; 32],
            per_channel: Vec::new(),
            fused: RetrievalTraceStageRecord {
                stage: RetrievalTraceStage::Fused,
                candidates: score_breakdown.clone(),
            },
            blended: RetrievalTraceStageRecord {
                stage: RetrievalTraceStage::Blended,
                candidates: score_breakdown.clone(),
            },
            reranked: RetrievalTraceStageRecord {
                stage: RetrievalTraceStage::Reranked,
                candidates: score_breakdown.clone(),
            },
            final_stage: RetrievalTraceStageRecord {
                stage: RetrievalTraceStage::Final,
                candidates: score_breakdown,
            },
        }));
        vault.store.record_retrieval_run(&record)?;

        vault.store.finalize_context_pack_retrieval_run(
            run_id,
            10,
            0,
            &[*kept.as_bytes()],
            None,
        )?;

        let finalized = vault
            .retrieval_run(run_id)?
            .expect("finalized context-pack run");
        let trace = finalized.trace.expect("trace remains present");
        assert_eq!(trace.reranked.candidates.len(), 2);
        assert_eq!(trace.final_stage.candidates.len(), 1);
        assert_eq!(trace.reranked.candidates[1].result_id, *dropped.as_bytes());
        assert_eq!(trace.final_stage.candidates[0].result_id, *kept.as_bytes());
        Ok(())
    }

    #[test]
    fn provisional_context_pack_trace_is_hidden_until_finalized() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let run_id = RetrievalRunId::now();
        let kept = entity_id(0xD3);
        let score_breakdown = vec![RetrievalScoreBreakdown {
            result_id: *kept.as_bytes(),
            final_rank: 1,
            final_score: 2.0,
            components: vec![RetrievalScoreComponent {
                signal: RetrievalSignal::Text,
                rank: 1,
                score: 2.0,
            }],
        }];
        let fork_hash = [0xD3; 32];
        let record = RetrievalRunRecord::new(
            run_id,
            RetrievalAction::ContextPack,
            1,
            2,
            vec![RetrievalSignal::Text],
            score_breakdown.clone(),
            0,
            0,
            None,
        )
        .with_trace(Some(RetrievalTrace {
            fork_hash,
            per_channel: Vec::new(),
            fused: RetrievalTraceStageRecord {
                stage: RetrievalTraceStage::Fused,
                candidates: score_breakdown.clone(),
            },
            blended: RetrievalTraceStageRecord {
                stage: RetrievalTraceStage::Blended,
                candidates: score_breakdown.clone(),
            },
            reranked: RetrievalTraceStageRecord {
                stage: RetrievalTraceStage::Reranked,
                candidates: score_breakdown.clone(),
            },
            final_stage: RetrievalTraceStageRecord {
                stage: RetrievalTraceStage::Final,
                candidates: score_breakdown,
            },
        }));

        vault
            .store
            .record_context_pack_provisional_retrieval_run(&record)?;
        assert!(
            vault.retrieval_trace_by_fork_hash(fork_hash)?.is_none(),
            "provisional context-pack traces must not be fork-hash visible"
        );

        vault.store.finalize_context_pack_retrieval_run(
            run_id,
            10,
            0,
            &[*kept.as_bytes()],
            None,
        )?;

        assert_eq!(
            vault
                .retrieval_trace_by_fork_hash(fork_hash)?
                .expect("finalized trace should be fork-hash visible")
                .fork_hash,
            fork_hash
        );
        Ok(())
    }

    #[test]
    fn unknown_zero_retrieval_trace_fork_hash_is_not_indexed() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let run_id = RetrievalRunId::now();
        let id = entity_id(0xD4);
        let score_breakdown = vec![RetrievalScoreBreakdown {
            result_id: *id.as_bytes(),
            final_rank: 1,
            final_score: 1.0,
            components: vec![RetrievalScoreComponent {
                signal: RetrievalSignal::Text,
                rank: 1,
                score: 1.0,
            }],
        }];
        let record = RetrievalRunRecord::new(
            run_id,
            RetrievalAction::Pipeline,
            1,
            2,
            vec![RetrievalSignal::Text],
            score_breakdown.clone(),
            0,
            0,
            None,
        )
        .with_trace(Some(RetrievalTrace {
            fork_hash: [0; 32],
            per_channel: Vec::new(),
            fused: RetrievalTraceStageRecord {
                stage: RetrievalTraceStage::Fused,
                candidates: score_breakdown.clone(),
            },
            blended: RetrievalTraceStageRecord {
                stage: RetrievalTraceStage::Blended,
                candidates: score_breakdown.clone(),
            },
            reranked: RetrievalTraceStageRecord {
                stage: RetrievalTraceStage::Reranked,
                candidates: score_breakdown.clone(),
            },
            final_stage: RetrievalTraceStageRecord {
                stage: RetrievalTraceStage::Final,
                candidates: score_breakdown,
            },
        }));

        vault.store.record_retrieval_run(&record)?;

        assert!(
            vault.retrieval_trace_by_fork_hash([0; 32])?.is_none(),
            "all-zero fork hash is the legacy unknown sentinel, not an index key"
        );
        Ok(())
    }

    #[test]
    fn delete_retrieval_run_removes_fork_index_when_run_row_is_corrupt() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let run_id = RetrievalRunId::now();
        let id = entity_id(0xD5);
        let score_breakdown = vec![RetrievalScoreBreakdown {
            result_id: *id.as_bytes(),
            final_rank: 1,
            final_score: 1.0,
            components: vec![RetrievalScoreComponent {
                signal: RetrievalSignal::Text,
                rank: 1,
                score: 1.0,
            }],
        }];
        let fork_hash = [0xD5; 32];
        let record = RetrievalRunRecord::new(
            run_id,
            RetrievalAction::Pipeline,
            1,
            2,
            vec![RetrievalSignal::Text],
            score_breakdown.clone(),
            0,
            0,
            None,
        )
        .with_trace(Some(RetrievalTrace {
            fork_hash,
            per_channel: Vec::new(),
            fused: RetrievalTraceStageRecord {
                stage: RetrievalTraceStage::Fused,
                candidates: score_breakdown.clone(),
            },
            blended: RetrievalTraceStageRecord {
                stage: RetrievalTraceStage::Blended,
                candidates: score_breakdown.clone(),
            },
            reranked: RetrievalTraceStageRecord {
                stage: RetrievalTraceStage::Reranked,
                candidates: score_breakdown.clone(),
            },
            final_stage: RetrievalTraceStageRecord {
                stage: RetrievalTraceStage::Final,
                candidates: score_breakdown,
            },
        }));

        vault.store.record_retrieval_run(&record)?;
        assert!(vault.retrieval_trace_by_fork_hash(fork_hash)?.is_some());

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .vault_meta
            .put(&mut wtxn, &retrieval_run_key(run_id), b"not-msgpack")?;
        wtxn.commit()?;

        vault.store.delete_retrieval_run(run_id)?;
        assert!(
            vault.retrieval_trace_by_fork_hash(fork_hash)?.is_none(),
            "delete must self-heal stale fork-index rows even when the run row is undecodable"
        );
        Ok(())
    }

    #[test]
    fn delete_retrieval_run_removes_fork_index_when_run_has_no_trace() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let run_id = RetrievalRunId::now();
        let fork_hash = [0xD6; 32];
        let record = RetrievalRunRecord::new(
            run_id,
            RetrievalAction::Pipeline,
            1,
            2,
            vec![RetrievalSignal::Text],
            Vec::new(),
            0,
            0,
            None,
        );

        vault.store.record_retrieval_run(&record)?;
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vault_meta.put(
            &mut wtxn,
            &retrieval_trace_fork_key(&fork_hash, run_id),
            b"1",
        )?;
        wtxn.commit()?;

        vault.store.delete_retrieval_run(run_id)?;
        assert!(
            vault.retrieval_trace_by_fork_hash(fork_hash)?.is_none(),
            "delete must self-heal stale fork-index rows when the run row has no trace"
        );
        Ok(())
    }

    #[test]
    fn register_structural_kind_rejects_secret_pack_before_vault_meta_write() {
        let (_dir, vault) = open_test_vault();

        let error = vault
            .register_structural_kind(
                65,
                "zz",
                TypeByteBand::Companion,
                "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
            )
            .expect_err("secret-shaped structural pack must reject");

        assert_secret_scan_rejected(error, "gate.secret_scan.github_token");
        assert!(vault.structural_kind_registration(65).is_none());
        assert!(vault.store.structural_kind_registrations().is_empty());
    }

    #[test]
    fn store_metadata_allows_secret_prefix_embedded_in_larger_identifier() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let registration = vault.register_structural_kind(
            65,
            "zz",
            TypeByteBand::Companion,
            "myghp_0123456789abcdefghijklmnopqrstuvwxyz_label",
        )?;
        assert_eq!(
            registration.pack,
            "myghp_0123456789abcdefghijklmnopqrstuvwxyz_label"
        );

        let id = entity_id(0x47);
        put_text(&vault, id, "retrieval outcome embedded prefix")?;
        let result = vault
            .query()
            .search_text("retrieval outcome embedded prefix", 10)
            .run_with_telemetry()?;
        let run_id = result.run_id.expect("telemetry run id");
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "source".to_owned(),
            "myghp_0123456789abcdefghijklmnopqrstuvwxyz_label".to_owned(),
        );
        vault.record_retrieval_outcome(RetrievalOutcome {
            run_id,
            key: "click".to_owned(),
            reward: Some(1.0),
            accepted: Some(true),
            metadata,
        })?;

        let outcomes = vault.retrieval_outcomes(run_id)?;
        assert_eq!(outcomes.len(), 1);
        assert_eq!(
            outcomes[0].metadata.get("source").map(String::as_str),
            Some("myghp_0123456789abcdefghijklmnopqrstuvwxyz_label")
        );

        Ok(())
    }

    #[test]
    fn record_retrieval_outcome_rejects_secret_key_and_metadata_before_vault_meta_write()
    -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = entity_id(0x46);
        put_text(&vault, id, "retrieval outcome secret scan")?;
        let result = vault
            .query()
            .search_text("retrieval outcome secret scan", 10)
            .run_with_telemetry()?;
        let run_id = result.run_id.expect("telemetry run id");

        let secret_key_error = vault
            .record_retrieval_outcome(RetrievalOutcome {
                run_id,
                key: "ghp_0123456789abcdefghijklmnopqrstuvwxyz_suffix".to_owned(),
                reward: Some(1.0),
                accepted: Some(true),
                metadata: BTreeMap::new(),
            })
            .expect_err("secret-shaped retrieval outcome key must reject");
        assert_secret_scan_rejected(secret_key_error, "gate.secret_scan.github_token");
        assert!(vault.retrieval_outcomes(run_id)?.is_empty());

        let mut metadata = BTreeMap::new();
        metadata.insert(
            "source".to_owned(),
            "ghp_0123456789abcdefghijklmnopqrstuvwxyz".to_owned(),
        );
        let metadata_error = vault
            .record_retrieval_outcome(RetrievalOutcome {
                run_id,
                key: "click".to_owned(),
                reward: Some(1.0),
                accepted: Some(true),
                metadata,
            })
            .expect_err("secret-shaped retrieval outcome metadata must reject");
        assert_secret_scan_rejected(metadata_error, "gate.secret_scan.github_token");
        assert!(vault.retrieval_outcomes(run_id)?.is_empty());

        Ok(())
    }

    #[test]
    fn retrieval_runs_rejects_malformed_key_shape_and_run_id_mismatch() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = entity_id(0x40);
        put_text(&vault, id, "telemetry key shape")?;
        assert_eq!(vault.search_text("telemetry key shape", 10)?.len(), 1);
        let run_id = vault.retrieval_runs(1)?[0].run_id;
        let raw = raw_retrieval_run_row(&vault, run_id)?;
        let mut malformed_key = retrieval_run_key(run_id);
        malformed_key.push(0);
        vault.with_write_txn(|wtxn| {
            vault.store.vault_meta.put(wtxn, &malformed_key, &raw)?;
            Ok(())
        })?;
        let error = vault
            .retrieval_runs(10)
            .expect_err("malformed retrieval run key should fail closed");
        assert!(matches!(
            error,
            Error::CorruptedIndex("retrieval run telemetry")
        ));

        let (_dir, vault) = open_test_vault();
        let first_id = entity_id(0x41);
        let second_id = entity_id(0x42);
        put_text(&vault, first_id, "telemetrykeyfirst")?;
        put_text(&vault, second_id, "telemetrykeysecond")?;
        assert_eq!(vault.search_text("telemetrykeyfirst", 10)?.len(), 1);
        let first_run_id = vault.retrieval_runs(1)?[0].run_id;
        let first_raw = raw_retrieval_run_row(&vault, first_run_id)?;
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert_eq!(vault.search_text("telemetrykeysecond", 10)?.len(), 1);
        let second_run_id = vault.retrieval_runs(1)?[0].run_id;
        let second_key = retrieval_run_key(second_run_id);
        vault.with_write_txn(|wtxn| {
            vault.store.vault_meta.put(wtxn, &second_key, &first_raw)?;
            Ok(())
        })?;
        let error = vault
            .retrieval_runs(10)
            .expect_err("retrieval run key/value id mismatch should fail closed");
        assert!(matches!(
            error,
            Error::CorruptedIndex("retrieval run telemetry")
        ));
        Ok(())
    }

    #[test]
    fn retrieval_outcomes_rejects_key_value_mismatches() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = entity_id(0x43);
        put_text(&vault, id, "outcomekeymismatch")?;
        let first = vault
            .query()
            .search_text("outcomekeymismatch", 10)
            .run_with_telemetry()?;
        assert_eq!(first.value.len(), 1);
        let run_id = first.run_id.expect("outcome key mismatch run id");
        record_click_outcome(&vault, run_id)?;
        let raw = raw_retrieval_outcome_row(&vault, run_id, "click")?;
        let wrong_key = retrieval_outcome_key(run_id, "dismiss");
        vault.with_write_txn(|wtxn| {
            vault.store.vault_meta.put(wtxn, &wrong_key, &raw)?;
            Ok(())
        })?;
        let error = vault
            .retrieval_outcomes(run_id)
            .expect_err("outcome key/value key mismatch should fail closed");
        assert!(matches!(
            error,
            Error::CorruptedIndex("retrieval outcome telemetry")
        ));

        let (_dir, vault) = open_test_vault();
        let first_id = entity_id(0x44);
        let second_id = entity_id(0x45);
        put_text(&vault, first_id, "outcomerunfirst")?;
        put_text(&vault, second_id, "outcomerunsecond")?;
        let first = vault
            .query()
            .search_text("outcomerunfirst", 10)
            .run_with_telemetry()?;
        assert_eq!(first.value.len(), 1);
        let first_run_id = first.run_id.expect("first outcome run id");
        record_click_outcome(&vault, first_run_id)?;
        let first_raw = raw_retrieval_outcome_row(&vault, first_run_id, "click")?;
        let second = vault
            .query()
            .search_text("outcomerunsecond", 10)
            .run_with_telemetry()?;
        assert_eq!(second.value.len(), 1);
        let second_run_id = second.run_id.expect("second outcome run id");
        let second_key = retrieval_outcome_key(second_run_id, "click");
        vault.with_write_txn(|wtxn| {
            vault.store.vault_meta.put(wtxn, &second_key, &first_raw)?;
            Ok(())
        })?;
        let error = vault
            .retrieval_outcomes(second_run_id)
            .expect_err("outcome key/value run id mismatch should fail closed");
        assert!(matches!(
            error,
            Error::CorruptedIndex("retrieval outcome telemetry")
        ));
        Ok(())
    }

    #[test]
    fn search_falls_back_to_bootstrap_when_blend_weight_table_is_corrupt() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = entity_id(0x4E);
        put_text(&vault, id, "corrupt blend fallback")?;
        vault.with_write_txn(|wtxn| {
            vault
                .store
                .vault_meta
                .put(wtxn, RETRIEVAL_BLEND_WEIGHT_TABLE_KEY, b"not-msgpack")?;
            Ok(())
        })?;

        let table_error = vault
            .retrieval_blend_weight_table()
            .expect_err("administrative table read should still report corruption");
        assert!(matches!(
            table_error,
            Error::CorruptedIndex("retrieval blend weight table")
        ));

        let result = vault
            .query()
            .search_text("corrupt blend fallback", 10)
            .run_with_telemetry()?;
        assert_eq!(result.value.len(), 1);
        assert_eq!(result.value[0].id, id);
        Ok(())
    }

    #[test]
    fn retrieval_blend_tuning_updates_weight_table_from_rewarded_breakdowns() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let run_id = RetrievalRunId::now();
        let positive = entity_id(0x48);
        let negative = entity_id(0x49);
        let record = RetrievalRunRecord::new(
            run_id,
            RetrievalAction::Pipeline,
            100,
            10,
            vec![RetrievalSignal::Text],
            vec![
                RetrievalScoreBreakdown {
                    result_id: *positive.as_bytes(),
                    final_rank: 1,
                    final_score: 2.0,
                    components: vec![
                        RetrievalScoreComponent {
                            signal: RetrievalSignal::Recency,
                            rank: 1,
                            score: 1.0,
                        },
                        RetrievalScoreComponent {
                            signal: RetrievalSignal::Salience,
                            rank: 2,
                            score: -1.0,
                        },
                    ],
                },
                RetrievalScoreBreakdown {
                    result_id: *negative.as_bytes(),
                    final_rank: 2,
                    final_score: 1.0,
                    components: vec![
                        RetrievalScoreComponent {
                            signal: RetrievalSignal::Recency,
                            rank: 2,
                            score: -1.0,
                        },
                        RetrievalScoreComponent {
                            signal: RetrievalSignal::Salience,
                            rank: 1,
                            score: 1.0,
                        },
                    ],
                },
            ],
            2,
            0,
            None,
        );
        vault.store.record_retrieval_run(&record)?;
        vault.record_retrieval_outcome(RetrievalOutcome {
            run_id,
            key: "beam.reward".to_owned(),
            reward: Some(1.0),
            accepted: Some(true),
            metadata: BTreeMap::new(),
        })?;

        let before = vault.retrieval_blend_weight_table()?;
        let updated = vault.tune_retrieval_blend_weights(RetrievalBlendTuningConfig {
            max_runs: 10,
            learning_rate: 0.10,
            min_reward_count: 1,
        })?;

        assert!(updated.weights.recency > before.weights.recency);
        assert!(updated.weights.salience < before.weights.salience);
        assert_eq!(updated.data_window.run_count, 1);
        assert_eq!(updated.data_window.outcome_count, 1);
        assert_eq!(updated.data_window.candidate_count, 2);
        assert_eq!(updated.data_window.started_at_min, Some(100));
        assert_eq!(updated.data_window.started_at_max, Some(100));
        assert_eq!(
            updated.provenance.get("algorithm").map(String::as_str),
            Some(RETRIEVAL_BLEND_TUNER_ALGORITHM)
        );
        assert_eq!(vault.retrieval_blend_weight_table()?, updated);
        Ok(())
    }

    #[test]
    fn concurrent_retrieval_blend_tuning_applies_both_gradient_steps() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let run_id = RetrievalRunId::now();
        let record = RetrievalRunRecord::new(
            run_id,
            RetrievalAction::Pipeline,
            200,
            10,
            vec![RetrievalSignal::Text],
            vec![RetrievalScoreBreakdown {
                result_id: *entity_id(0x4F).as_bytes(),
                final_rank: 1,
                final_score: 1.0,
                components: vec![RetrievalScoreComponent {
                    signal: RetrievalSignal::Recency,
                    rank: 1,
                    score: 1.0,
                }],
            }],
            1,
            0,
            None,
        );
        vault.store.record_retrieval_run(&record)?;
        vault.record_retrieval_outcome(RetrievalOutcome {
            run_id,
            key: "beam.reward".to_owned(),
            reward: Some(1.0),
            accepted: Some(true),
            metadata: BTreeMap::new(),
        })?;

        let before = vault.retrieval_blend_weight_table()?;
        let expected_once =
            apply_retrieval_blend_weight_update(before.weights, [1.0, 0.0, 0.0, 0.0], 0.10, 1)?;
        let expected_twice =
            apply_retrieval_blend_weight_update(expected_once, [1.0, 0.0, 0.0, 0.0], 0.10, 1)?;

        let vault = Arc::new(vault);
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let vault = Arc::clone(&vault);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                vault.tune_retrieval_blend_weights(RetrievalBlendTuningConfig {
                    max_runs: 1,
                    learning_rate: 0.10,
                    min_reward_count: 1,
                })
            }));
        }
        barrier.wait();
        for handle in handles {
            handle.join().expect("tuning thread should not panic")?;
        }

        let final_entry = vault.retrieval_blend_weight_table()?;
        assert_eq!(final_entry.weights, expected_twice);
        Ok(())
    }

    #[test]
    fn retrieval_blend_tuning_max_runs_counts_completed_runs_not_provisional_rows() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let completed_run_id = RetrievalRunId::now();
        let completed = RetrievalRunRecord::new(
            completed_run_id,
            RetrievalAction::Pipeline,
            300,
            10,
            vec![RetrievalSignal::Text],
            vec![RetrievalScoreBreakdown {
                result_id: *entity_id(0x4A).as_bytes(),
                final_rank: 1,
                final_score: 1.0,
                components: vec![RetrievalScoreComponent {
                    signal: RetrievalSignal::Recency,
                    rank: 1,
                    score: 1.0,
                }],
            }],
            1,
            0,
            None,
        );
        vault.store.record_retrieval_run(&completed)?;
        vault.record_retrieval_outcome(RetrievalOutcome {
            run_id: completed_run_id,
            key: "beam.reward".to_owned(),
            reward: Some(1.0),
            accepted: Some(true),
            metadata: BTreeMap::new(),
        })?;

        std::thread::sleep(std::time::Duration::from_millis(2));
        let provisional_run_id = RetrievalRunId::now();
        let provisional = RetrievalRunRecord::new(
            provisional_run_id,
            RetrievalAction::ContextPack,
            400,
            10,
            vec![RetrievalSignal::Text],
            vec![RetrievalScoreBreakdown {
                result_id: *entity_id(0x4B).as_bytes(),
                final_rank: 1,
                final_score: 1.0,
                components: vec![RetrievalScoreComponent {
                    signal: RetrievalSignal::Salience,
                    rank: 1,
                    score: 1.0,
                }],
            }],
            1,
            0,
            None,
        );
        vault
            .store
            .record_context_pack_provisional_retrieval_run(&provisional)?;

        let before = vault.retrieval_blend_weight_table()?;
        let updated = vault.tune_retrieval_blend_weights(RetrievalBlendTuningConfig {
            max_runs: 1,
            learning_rate: 0.10,
            min_reward_count: 1,
        })?;

        assert!(updated.weights.recency > before.weights.recency);
        assert_eq!(updated.data_window.run_count, 1);
        assert_eq!(updated.data_window.outcome_count, 1);
        assert_eq!(updated.data_window.started_at_min, Some(300));
        assert_eq!(updated.data_window.started_at_max, Some(300));
        Ok(())
    }

    #[test]
    fn retrieval_blend_tuning_counts_only_blend_contributing_rewards() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let blend_run_id = RetrievalRunId::now();
        let blend = RetrievalRunRecord::new(
            blend_run_id,
            RetrievalAction::Pipeline,
            500,
            10,
            vec![RetrievalSignal::Text],
            vec![RetrievalScoreBreakdown {
                result_id: *entity_id(0x4C).as_bytes(),
                final_rank: 1,
                final_score: 1.0,
                components: vec![RetrievalScoreComponent {
                    signal: RetrievalSignal::Recency,
                    rank: 1,
                    score: 1.0,
                }],
            }],
            1,
            0,
            None,
        );
        vault.store.record_retrieval_run(&blend)?;
        vault.record_retrieval_outcome(RetrievalOutcome {
            run_id: blend_run_id,
            key: "beam.reward".to_owned(),
            reward: Some(1.0),
            accepted: Some(true),
            metadata: BTreeMap::new(),
        })?;

        std::thread::sleep(std::time::Duration::from_millis(2));
        let text_only_run_id = RetrievalRunId::now();
        let text_only = RetrievalRunRecord::new(
            text_only_run_id,
            RetrievalAction::VaultSearch,
            600,
            10,
            vec![RetrievalSignal::Text],
            vec![RetrievalScoreBreakdown {
                result_id: *entity_id(0x4D).as_bytes(),
                final_rank: 1,
                final_score: 10.0,
                components: vec![RetrievalScoreComponent {
                    signal: RetrievalSignal::Text,
                    rank: 1,
                    score: 10.0,
                }],
            }],
            1,
            0,
            None,
        );
        vault.store.record_retrieval_run(&text_only)?;
        vault.record_retrieval_outcome(RetrievalOutcome {
            run_id: text_only_run_id,
            key: "beam.reward".to_owned(),
            reward: Some(1.0),
            accepted: Some(true),
            metadata: BTreeMap::new(),
        })?;

        let error = vault
            .tune_retrieval_blend_weights(RetrievalBlendTuningConfig {
                max_runs: 2,
                learning_rate: 0.10,
                min_reward_count: 2,
            })
            .expect_err("text-only reward should not satisfy min_reward_count");
        assert!(matches!(error, Error::InvalidConfig(message) if message.contains("found 1")));

        let before = vault.retrieval_blend_weight_table()?;
        let expected_weights =
            apply_retrieval_blend_weight_update(before.weights, [1.0, 0.0, 0.0, 0.0], 0.10, 1)?;
        let updated = vault.tune_retrieval_blend_weights(RetrievalBlendTuningConfig {
            max_runs: 2,
            learning_rate: 0.10,
            min_reward_count: 1,
        })?;

        assert_eq!(updated.weights, expected_weights);
        assert_eq!(updated.data_window.run_count, 1);
        assert_eq!(updated.data_window.outcome_count, 1);
        assert_eq!(updated.data_window.candidate_count, 1);
        assert_eq!(updated.data_window.started_at_min, Some(500));
        assert_eq!(updated.data_window.started_at_max, Some(500));
        Ok(())
    }

    #[test]
    fn retrieval_blend_weight_table_load_normalizes_persisted_weights() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let mut provenance = BTreeMap::new();
        provenance.insert("source".to_owned(), "test".to_owned());
        provenance.insert("algorithm".to_owned(), "test.unnormalized".to_owned());
        let entry = RetrievalBlendWeightTableEntry {
            version: RETRIEVAL_BLEND_WEIGHT_TABLE_VERSION,
            weights: RetrievalBlendWeights::new(2.0, 3.0, 4.0, 1.0),
            tuned_at: 123,
            provenance,
            data_window: RetrievalBlendWeightDataWindow::default(),
        };
        let raw = rmp_serde::to_vec_named(&entry).expect("encode synthetic blend table");
        vault.with_write_txn(|wtxn| {
            vault
                .store
                .vault_meta
                .put(wtxn, RETRIEVAL_BLEND_WEIGHT_TABLE_KEY, &raw)?;
            Ok(())
        })?;

        let loaded = vault.retrieval_blend_weight_table()?;
        let sum = loaded.weights.recency
            + loaded.weights.salience
            + loaded.weights.confidence
            + loaded.weights.gravity;
        assert!((sum - 1.0).abs() < 1.0e-6);
        assert!((loaded.weights.recency - 0.2).abs() < 1.0e-6);
        assert!((loaded.weights.salience - 0.3).abs() < 1.0e-6);
        assert!((loaded.weights.confidence - 0.4).abs() < 1.0e-6);
        assert!((loaded.weights.gravity - 0.1).abs() < 1.0e-6);
        assert_eq!(loaded.tuned_at, 123);
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test_hooks {
    use std::cell::RefCell;

    use super::*;

    struct TargetedAfterLmdbOpenHook {
        path: PathBuf,
        hook: AfterLmdbOpenHook,
    }

    type AfterLmdbOpenHook = Box<dyn FnOnce(&Path) + Send>;

    static AFTER_LMDB_OPEN: LazyLock<Mutex<Option<TargetedAfterLmdbOpenHook>>> =
        LazyLock::new(|| Mutex::new(None));
    thread_local! {
        static FAIL_NEXT_RETRIEVAL_RUN_WRITE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    }

    pub(crate) fn arm_after_lmdb_open(path: PathBuf, hook: impl FnOnce(&Path) + Send + 'static) {
        *AFTER_LMDB_OPEN
            .lock()
            .expect("after-lmdb-open hook mutex poisoned") = Some(TargetedAfterLmdbOpenHook {
            path,
            hook: Box::new(hook),
        });
    }

    pub(crate) fn run_after_lmdb_open(path: &Path) {
        let hook = {
            let mut armed = AFTER_LMDB_OPEN
                .lock()
                .expect("after-lmdb-open hook mutex poisoned");
            if armed.as_ref().is_some_and(|hook| hook.path == path) {
                armed.take().map(|hook| hook.hook)
            } else {
                None
            }
        };
        if let Some(hook) = hook {
            hook(path);
        }
    }

    pub(crate) fn fail_next_retrieval_run_write_for(path: PathBuf) {
        FAIL_NEXT_RETRIEVAL_RUN_WRITE.with(|armed| {
            *armed.borrow_mut() = Some(path);
        });
    }

    pub(crate) fn take_fail_next_retrieval_run_write(path: &Path) -> bool {
        FAIL_NEXT_RETRIEVAL_RUN_WRITE.with(|armed| {
            let mut armed = armed.borrow_mut();
            if armed.as_ref().is_some_and(|armed_path| armed_path == path) {
                armed.take();
                true
            } else {
                false
            }
        })
    }
}
