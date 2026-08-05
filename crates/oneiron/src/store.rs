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
//!    persist-if-missing writes for the HNSW config / model id validated above
//!    (each re-checks under its own write transaction).
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
//!    and only here: it bypasses this analyzer gate so
//!    `MaintenanceBuilder::clear_text_index` can run; on a populated index it
//!    marks the text index untrusted so text reads/writes fail closed with
//!    `Error::CorruptedIndex` until the clear commits.
//! 9. The independent skill content-hash index sentinel migration
//!    (`vault_meta["skill_hub/content_hash_index_schema_version"]`) runs after
//!    the Vault claim doors are assembled, so pre-global scan verdicts can be
//!    reconciled transactionally. It still finishes before `Vault::open`
//!    returns a handle.
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
//! [`VaultConfig::skip_text_index_manifest_check`]: crate::config::VaultConfig::skip_text_index_manifest_check

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap, HashSet};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::str;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, RwLock, Weak};

use heed::types::{Bytes, Str};
use heed::{Database, DatabaseFlags, Env, EnvOpenOptions, RoTxn, RwTxn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::batch::{EntityMetadataHeader, secret_scan};
use crate::companion::{
    COMPANION_REGISTER_PACK_ID, COMPANION_REGISTER_SHORT_ID_PREFIX, ENTITY_TYPE_COMPANION_REGISTER,
};
use crate::config::VaultConfig;
use crate::edge::EdgeKind;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result, VaultRootEntry, VaultRootProblem};
use crate::off_record::OffRecordSessionRegistry;
use crate::overlay_db::{OverlayDb, OverlayStrDb};
use crate::pipeline::Signal;
use crate::registry::{
    ENTITY_TYPE_CLAIM, StructuralKindRegistration, TypeByteBand, band_of,
    entity_type_registry_entry, short_id_prefix, static_short_id_prefix_collision,
    validate_entity_type as validate_static_entity_type,
    validate_public_entity_type as validate_static_public_entity_type,
};

// Contract-pinned at 32 by ARCH-0019/ARCH-0031: 28 named DBs plus headroom.
pub const MAX_DBS: u32 = 32;
/// v15 (ONE-1743): IDENTITY_TOPOLOGY_EVENT was registered as a persistent,
/// delete-protected maintenance entity type byte 76 — the engine-authored
/// merge/split ledger (ARCH-0055). v14 readers do not know this persistent
/// entity kind and would not protect it from deletion, so v14 vaults fail closed
/// at the ABI gate — there is no silent migration; rebuild the vault.
///
/// v14 (ONE-1741): SKILL_CONTENT_ANCHOR was registered as persistent maintenance
/// entity type byte 138 — the immortal subject that content-global scan verdicts
/// anchor to. v13 readers do not know this persistent entity kind and would not
/// protect it from deletion, so v13 vaults fail closed at the ABI gate — there is
/// no silent migration; rebuild the vault.
///
/// v13 (ONE-1387): type-0 CLAIM bodies gained the optional `sess` key for
/// actor-bound session review bundles. v12 readers reject these bodies, so
/// vaults carrying session-tagged claims must fail closed at the ABI gate.
///
/// v11 (ONE-1576): off-record fence state became a supported vault contract.
/// v10 readers do not know the fence semantics, so v10 vaults fail closed at
/// the ABI gate — there is no silent downgrade that could expose fenced rows.
///
/// v10 (ONE-1443): AGENT_DEF was registered as a persistent CORE entity type
/// byte 17. v9 readers do not know this persistent entity kind, so v9 vaults
/// fail closed at the ABI gate — there is no silent migration; rebuild the
/// vault.
///
/// v9 (ONE-1530): OUTBOUND_GRANT was registered as persistent maintenance
/// entity type byte 133. v8 readers do not know this persistent entity kind,
/// so v8 vaults fail closed at the ABI gate — there is no silent migration;
/// rebuild the vault.
///
/// v8 (ONE-1213): attempt queue rows gained durable terminal states (`Completed`
/// and `Failed`) plus retry backoff metadata. v7 queue readers only understand
/// `Queued`/`Leased`, so v7 vaults fail closed at the ABI gate — there is no
/// silent migration; rebuild the vault.
///
/// v7 (ONE-1206): generic LMDB-backed attempt queue landed as three named DBs:
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
///
/// Receipt-family ABI-pin rule: changing
/// `GATE_DECISION_LEDGER_VERSION`, `ATTEMPT_RECORD_VERSION`,
/// `PENDING_GATE_CONSENT_INDEX_STATE_VERSION`, or
/// `RECEIPT_FAMILY_INDEX_VERSION` requires bumping this version too.
pub const STORAGE_ABI_VERSION: u16 = 15;
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
const HNSW_COMPATIBILITY_VERSION: u8 = 3;
const HNSW_COMPATIBILITY_V0_LEN: usize = 24;
const HNSW_COMPATIBILITY_V1_LEN: usize = 25;
const HNSW_COMPATIBILITY_V2_LEN: usize = 27;
/// v3 layout = v2 layout (version u8, dimensions u64le, m_max_0 u64le,
/// ef_construction u64le, distance_metric u8, index_structure u8) +
/// `fast_dims` u16le at bytes 27..29 (wire `0` = None).
const HNSW_COMPATIBILITY_LEN: usize = 29;
const HNSW_COMPATIBILITY_V2_VERSION: u8 = 2;
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
/// Crate-visible so the off-record close census can count the session's own
/// retrieval-run receipt rows in the overlay `VaultMeta` keyspace immediately
/// before they evaporate (ONE-1728 K8). The key FORMAT is owned here; the
/// census only tests the prefix.
pub(crate) const RETRIEVAL_RUN_KEY_PREFIX: &[u8] = b"retr_run:v0:";
const RETRIEVAL_RUN_PROVISIONAL_KEY_PREFIX: &[u8] = b"retr_run_prov:v0:";
const RETRIEVAL_TRACE_FORK_KEY_PREFIX: &[u8] = b"retr_trace_fork:v0:";
const RETRIEVAL_OUTCOME_KEY_PREFIX: &[u8] = b"retr_out:v0:";
const RETRIEVAL_BLEND_WEIGHT_TABLE_KEY: &[u8] = b"retr_blend_weights:v0:active";
const RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT: usize = 1024;
const RETRIEVAL_OUTCOME_KEY_MAX_LEN: usize = 128;
const RETRIEVAL_BLEND_WEIGHT_TABLE_VERSION: u8 = 1;
const RETRIEVAL_BLEND_TUNER_ALGORITHM: &str = "ret010d.reward_weighted_bandit.v1";
const RETRIEVAL_BLEND_BOOTSTRAP_SOURCE: &str = "ret010b.bootstrap";
/// Receipt-family ABI-pin rule: changing this requires a
/// [`STORAGE_ABI_VERSION`] bump.
pub(crate) const GATE_DECISION_LEDGER_VERSION: u8 = 0;
/// Accepted DECODE version for an in-place-redacted row (ONE-1637/ONE-1638).
/// [`GATE_DECISION_LEDGER_VERSION`] (0) remains the only APPEND version, so the
/// ABI-pinned const above is unchanged and existing v0 bytes still round-trip.
pub(crate) const GATE_DECISION_LEDGER_VERSION_REDACTED: u8 = 1;
const GATE_DECISION_KEY_PREFIX: &[u8] = b"gate_decision:v0:";
const PENDING_GATE_CONSENT_KEY_PREFIX: &[u8] = b"gate_pending:v0:";
/// Pre-commit crash-recovery sidecar for a deletion authority record. This is
/// not the Gate decision ledger: TXN3 consumes it with
/// `append_gate_decision_in_txn` in the active-store purge transaction.
const PENDING_DELETION_GATE_DECISION_KEY_PREFIX: &[u8] = b"gate_delete_pending:v0:";
/// Durable proof that a locally-authored deletion tombstone requires an
/// authority sidecar before recovery may purge its target. Kept separate
/// from the sidecar so corruption/loss of the latter is detectable instead
/// of being mistaken for a legitimate sidecar-free remote tombstone.
const DELETION_GATE_REQUIRED_KEY_PREFIX: &[u8] = b"gate_delete_required:v0:";
const PENDING_DELETION_GATE_DECISION_VERSION: u8 = 0;
// RCPT-1 keeps its materialized lookup rows in the existing `vault_meta`
// family.  These are additive sidecars, not named LMDB databases: older
// readers already ignore unknown `vault_meta` prefixes, while a current
// reader backfills them before exposing the store.
const RECEIPT_FAMILY_INDEX_VERSION_KEY: &[u8] = b"receipt_family_index:v1:version";
/// Receipt-family ABI-pin rule: changing this requires a
/// [`STORAGE_ABI_VERSION`] bump.
const RECEIPT_FAMILY_INDEX_VERSION: u8 = 1;
const GATE_DECISION_GRANT_REF_INDEX_PREFIX: &[u8] = b"gate_decision:grant_ref_index:v1:";
/// ERASE-A (ONE-1637) claim-keyed secondary index over the Gate decision
/// ledger: `prefix ‖ claim_id(16B) ‖ decision_id(16B)`, empty value.
///
/// ACCELERATION ONLY. Erase-completeness verification must never consult it —
/// an index cannot vouch for the completeness of the erase it accelerated (see
/// [`Store::verify_claim_erasure_by_scan_in_txn`]).
///
/// INVARIANT: every mutation of a `gate_decision:v0:` row MUST route through
/// `append_gate_decision_in_txn`, `delete_gate_decision_in_txn`, or
/// `delete_gate_decisions_for_missing_off_record_turn_in_txn`. Future deleters
/// inherit index coherence by using those, never a raw `vault_meta.delete`.
const GATE_DECISION_CLAIM_INDEX_PREFIX: &[u8] = b"gate_decision_by_claim:v0:";
/// Durable proof that every pre-existing ledger row is claim-indexed. While
/// ABSENT, per-claim discovery falls back to a full keyspace scan; erase is
/// never refused during backfill.
const GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_KEY: &[u8] =
    b"gate_decision_by_claim_backfill_complete";
/// Only accepted value byte for the backfill-complete flag row.
const GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_VALUE: [u8; 1] = [1];
const PENDING_GATE_CONSENT_RUN_INDEX_PREFIX: &[u8] = b"gate_pending:run_index:v1:";
const PENDING_GATE_CONSENT_GROUP_INDEX_PREFIX: &[u8] = b"gate_pending:group_index:v1:";
const PENDING_GATE_CONSENT_HASH_INDEX_PREFIX: &[u8] = b"gate_pending:hash_index:v1:";
const PENDING_GATE_CONSENT_INDEX_STATE_PREFIX: &[u8] = b"gate_pending:index_state:v1:";
/// Receipt-family ABI-pin rule: changing this requires a
/// [`STORAGE_ABI_VERSION`] bump.
const PENDING_GATE_CONSENT_INDEX_STATE_VERSION: u8 = 1;
// Storage/wire keys keep the legacy "job" spelling; ONE-1714 renamed code only.
const ATTEMPT_RUN_INDEX_PREFIX: &[u8] = b"job:run_index:v1:";
const CHANNEL_IDENTITY_LIFECYCLE_LEDGER_VERSION: u8 = 0;
const CHANNEL_IDENTITY_LIFECYCLE_KEY_PREFIX: &[u8] = b"channel_identity_lifecycle:v0:";
/// Maps a scheduled outbound attempt id to the gate surface its first dispatch
/// produced, so an idempotent replay can re-surface the original decision.
const OUTBOUND_GATE_BINDING_KEY_PREFIX: &[u8] = b"outbound_gate_binding:v0:";
/// Additive durable connector-send receipt rows. This keyspace is independent
/// of the ABI-pinned Gate decision ledger and carries its own record version.
pub(crate) const SEND_RECEIPT_RECORD_VERSION: u8 = 0;
const SEND_RECEIPT_KEY_PREFIX: &[u8] = b"send_receipt:v0:";
/// Additive delivered-send idempotency index. This is intentionally separate
/// from the attempt queue's lifecycle-scoped dedupe rows and from the
/// ABI-pinned Gate ledger.
pub(crate) const SEND_IDEMPOTENCY_INDEX_VERSION: u8 = 0;
const SEND_IDEMPOTENCY_KEY_PREFIX: &[u8] = b"send_idem:v0:";
const SEND_IDEMPOTENCY_HASH_DOMAIN: &[u8] = b"oneiron.send_idem.v0\0";
const GATE_DIFF_HANDLE_MAX_LEN: usize = 128;
const GATE_RECEIPT_REASON_MAX_LEN: usize = 128;
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
    pub(crate) fn from_bytes(bytes: [u8; 16]) -> Self {
        Self { bytes }
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
    /// EMB-5 speculative fire over an ASR partial. Only speculative fires
    /// carry this tag (the end-of-utterance full-quality pass logs as
    /// `Pipeline`) — that is what makes wasted-retrieval budget measurable.
    Speculative,
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
    /// RET-010 host-injected reranker component. Never a channel and never
    /// a blend signal: the blend weight table must not train on reranker
    /// output.
    Rerank,
}

impl RetrievalSignal {
    #[must_use]
    pub fn as_blend_signal(self) -> Option<RetrievalBlendSignal> {
        match self {
            Self::Recency => Some(RetrievalBlendSignal::Recency),
            Self::Salience => Some(RetrievalBlendSignal::Salience),
            Self::Confidence => Some(RetrievalBlendSignal::Confidence),
            Self::Gravity => Some(RetrievalBlendSignal::Gravity),
            Self::Vector
            | Self::Text
            | Self::Phonetic
            | Self::Temporal
            | Self::Ppr
            | Self::Rerank => None,
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
    pub(crate) const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }

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
pub struct GateSystemNoticeAction {
    pub label: String,
    pub target: String,
}

pub(crate) const GATE_SYSTEM_NOTICE_ROW_REF_MAX_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateSystemNoticeRecord {
    pub notice_type: String,
    pub channel: String,
    pub voice: String,
    pub audience: String,
    pub body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting_change_offer: Option<GateSystemNoticeAction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateDecisionRecord {
    pub version: u8,
    pub decision_id: GateDecisionId,
    pub created_at: u64,
    pub outcome: String,
    pub reason_codes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipt_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub system_notices: Vec<GateSystemNoticeRecord>,
    pub actor_class: String,
    pub actor_ref: Option<String>,
    pub content_kind: String,
    pub policy_manifest_version: String,
    pub claim_id: Option<[u8; 16]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_ref: Option<String>,
    pub diff_handle: Vec<u8>,
    pub read_frontier_hash: [u8; 32],
    /// Set when this row was redacted in place to its retention skeleton
    /// (version 1). Never set at append time; the erase coupling (ONE-1638)
    /// is the only writer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redacted_at: Option<u64>,
}

/// Outcome of one ERASE-A (ONE-1637) claim-index backfill run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GateClaimIndexBackfill {
    /// Pre-existing claim-bound ledger rows written into the index by this run.
    pub rows_indexed: u64,
    /// The durable flag was already set, so the run was a no-op.
    pub already_complete: bool,
}

/// Private TXN1 recovery data for a deletion authority record. The target and
/// wire reason bind the sidecar to exactly one tombstone, so a remote update
/// cannot consume a same-request-id sidecar for a different deletion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
struct PendingDeletionGateDecisionRecord {
    version: u8,
    target: [u8; 16],
    tombstone_reason: u8,
    decision: GateDecisionRecord,
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

/// Internal RCPT-1 deletion state for one run-scoped pending-consent row.
///
/// The primary pending row deliberately keeps its receipt-facing shape.  The
/// sidecar records the derived lookup keys so a later close/delete removes
/// exactly the index entries minted for the original pending body, even if a
/// stale proposal's claim has changed since it was queued.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PendingGateConsentIndexState {
    version: u8,
    run_id: String,
    group_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    semantic_claim_hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingGateConsentGroup {
    pub dreamer_run_id: Option<String>,
    pub records: Vec<PendingGateConsentRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChannelIdentityLifecycleReceiptId {
    bytes: [u8; 16],
}

impl ChannelIdentityLifecycleReceiptId {
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
pub struct ChannelIdentityLifecycleReceiptRecord {
    pub version: u8,
    pub receipt_id: ChannelIdentityLifecycleReceiptId,
    pub created_at: u64,
    pub identity_id: [u8; 16],
    pub actor_class: String,
    pub actor_ref: Option<String>,
    pub verb: String,
    pub intent_kind: String,
    pub outcome: String,
    pub gate_decision_id: Option<GateDecisionId>,
    pub channel: String,
    pub address_or_handle: String,
    pub state: String,
    pub fulfillment_mode: Option<String>,
    pub owner_visible_state: String,
    pub outbound_closed: bool,
    pub identity_retiring: bool,
    pub quarantine_until: Option<u64>,
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
    // Storage/wire keys keep the legacy "job" spelling; ONE-1714 renamed code
    // only. Group strings are embedded in export manifests and validated
    // exactly on import, so they are wire too.
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
            fast_dims: config.fast_dims,
        }
    }
}

pub(crate) enum HnswCompatibilityState {
    Missing,
    Legacy(PersistedHnswCompatibility),
    Current(PersistedHnswCompatibility),
}

/// Raw LMDB database handles for the 28 named databases (ARCH-0019 manifest).
///
/// These are the base handles a per-handle [`OverlayDb`] view wraps. They are
/// reserved for open-time machinery and for constructing accessor views —
/// runtime readers and writers MUST go through the [`OverlayDb`] accessors on
/// [`Store`] so a session write-overlay (ARCH-0052) composes at one seam.
pub struct RawDatabases {
    pub(crate) entities: Database<Bytes, Bytes>,
    pub(crate) edges_out: Database<Bytes, Bytes>,
    pub(crate) edges_in: Database<Bytes, Bytes>,
    pub(crate) vectors: Database<Bytes, Bytes>,
    pub(crate) hnsw_neighbors: Database<Bytes, Bytes>,
    pub(crate) hnsw_meta: Database<Bytes, Bytes>,
    pub(crate) text_postings: Database<Bytes, Bytes>,
    pub(crate) text_meta: Database<Bytes, Bytes>,
    pub(crate) text_forward: Database<Bytes, Bytes>,
    pub(crate) text_bm25_field_stats: Database<Bytes, Bytes>,
    pub(crate) text_doc_field_lengths: Database<Bytes, Bytes>,
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
    pub(crate) sync_state: Database<Str, Bytes>,
    pub(crate) sync_queue: Database<Bytes, Bytes>,
    /// Generic background attempt records keyed by attempt id.
    pub(crate) attempt_records: Database<Bytes, Bytes>,
    /// Ready-attempt ordering index keyed by ready-at time then attempt id.
    pub(crate) attempt_ready: Database<Bytes, Bytes>,
    /// Advisory dedupe index keys mapped to attempt ids.
    pub(crate) attempt_dedupe: Database<Bytes, Bytes>,
}

/// Arc-shared substrate of an open vault (ARCH-0052 store split).
///
/// Everything here is safe to share across handles: the environment handle
/// (a plain [`Env`] clone), the raw database handles, and the process-shared
/// registries. The Drop-sensitive singletons live in [`StoreOwner`] — a
/// `StoreCore` clone deliberately carries none of them, so a session vault
/// handle (ONE-1727) can hold `Arc<StoreCore>` without duplicating close,
/// path-deregistration, or clock-domain-release responsibilities.
///
/// INVARIANT: no `Arc<StoreCore>` may outlive the owning [`StoreOwner`]. The
/// owner's always-on drop assertion enforces this at runtime; the session
/// lifecycle drains leases before releasing its owner-bound handle.
pub struct StoreCore {
    /// Shared environment handle used to open transactions. The close-on-
    /// last-clone semantics live in the owner's [`OwnedEnv`] (ONE-1142).
    pub(crate) env: Env,
    /// Raw handles; runtime access goes through the [`Store`] accessors.
    /// Private so no code outside `store.rs` can bypass the [`OverlayDb`]
    /// seam — open-time machinery and accessor construction both live here.
    raw: RawDatabases,
    /// Vault-scoped dynamic StructuralKind registry loaded from `vault_meta`.
    pub(crate) kind_registry: RwLock<HashMap<u8, StructuralKindRegistration>>,
    /// Process-local off-record session source of truth. It is intentionally
    /// absent from every named database, so process loss evaporates sessions.
    pub(crate) off_record_sessions: OffRecordSessionRegistry,
    /// Serializes reward-to-weight tuning so concurrent callers cannot lose
    /// a gradient step between read, compute, and persist.
    retrieval_blend_tuning_lock: Mutex<()>,
    /// Process-local clock domain for monotonic authority first-seen windows.
    /// Read-only mirror; release-on-drop responsibility is the owner's.
    pub(crate) authority_clock_domain: usize,
}

/// Drop-sensitive singletons of an open vault; exactly one per open path
/// (ARCH-0052 store split). Deliberately NOT `Clone` and never Arc-shared:
/// duplicating any of these would corrupt the base vault (double clock-domain
/// release, premature path deregistration, early environment close).
pub struct StoreOwner {
    /// Always-on tripwire for the "no `Arc<StoreCore>` outlives the owner"
    /// invariant; see [`StoreCore`].
    core: Weak<StoreCore>,
    /// Sole owner of the environment's close-on-last-clone semantics
    /// (ONE-1142).
    #[expect(
        dead_code,
        reason = "held for Drop only: OwnedEnv's close-on-last-clone must fire \
                  before _registered_path releases the vault root (ONE-1142)"
    )]
    env: OwnedEnv,
    /// The clock domain this owner releases exactly once on drop.
    authority_clock_domain: usize,
    /// True only for the open call that created a previously absent LMDB root.
    created_new_vault: bool,
    // DROP-ORDER: keep this field after `env`. Fields drop in declaration
    // order, so the path registry releases the path only after [`OwnedEnv`]
    // has closed the LMDB environment — a reopen racing this drop can never
    // observe the path as free while the old environment is still live.
    _registered_path: RegisteredPath,
}

/// LMDB environment and database handles for a vault.
///
/// Dropping the last handle to a `Store` (normally via the owning
/// [`crate::Vault`]) CLOSES the LMDB environment — see `OwnedEnv` for the
/// close-path rationale (ONE-1142).
///
/// Split per ARCH-0052: `Store` is the canonical per-vault VIEW — 28
/// [`OverlayDb`] accessors (pure passthrough; a session handle composes its
/// overlay at the same seam) over the Arc-shared [`StoreCore`], plus the
/// single-owner [`StoreOwner`]. `Store` derefs to [`StoreCore`] so
/// `store.env`/`store.kind_registry` field access is preserved.
pub struct Store {
    // DROP-ORDER: `core` is declared before `owner` so this handle's Arc
    // reference drops first; `owner` then closes the environment (its
    // `OwnedEnv` holds the last remaining `Env` clone) and finally releases
    // the registered path. Private so no code outside `store.rs` can clone
    // the Arc past this handle's lifetime; deliberate sharing arrives with
    // the ONE-1727 session lease.
    core: Arc<StoreCore>,
    pub(crate) entities: OverlayDb,
    pub(crate) edges_out: OverlayDb,
    pub(crate) edges_in: OverlayDb,
    pub(crate) vectors: OverlayDb,
    pub(crate) hnsw_neighbors: OverlayDb,
    pub(crate) hnsw_meta: OverlayDb,
    /// Fielded inverted index, opened with `DUP_SORT` (storage ABI v4 /
    /// ONE-299). Key: term bytes. Each duplicate data item is ONE posting
    /// entry `entity_id(16) | field_count(u8) | (field_id_u16_be |
    /// tf_u32_le)*`; LMDB keeps duplicates bytewise sorted, so items order
    /// by entity-id prefix and an index append never reads the list.
    pub(crate) text_postings: OverlayDb,
    pub(crate) text_meta: OverlayDb,
    pub(crate) text_forward: OverlayDb,
    /// BM25F per-field corpus stats.
    /// Key: `field_id` big-endian u16.
    /// Value: `[doc_count_u32_le | total_length_u64_le]`.
    pub(crate) text_bm25_field_stats: OverlayDb,
    /// Per-doc, per-field surface-token lengths used by the BM25F length
    /// normalization term. Key: entity_id (16B). Value: a flat
    /// `[(field_id_u16_be | length_u32_le)*]` list over present fields.
    pub(crate) text_doc_field_lengths: OverlayDb,
    /// Vault-level metadata (analyzer manifest, schema version, field
    /// schema hash). Read on `Vault::open` to gate index compatibility.
    pub(crate) vault_meta: OverlayDb,
    /// PPR cache rows. Values carry the final scores and, for current rows,
    /// the residual/frontier state needed to resume a deeper Forward-Push run.
    pub(crate) ppr_cache: OverlayDb,
    /// Reverse dependency index for PPR cache invalidation:
    /// `[entity_id | cache_key]`.
    pub(crate) ppr_cache_deps: OverlayDb,
    pub(crate) type_index: OverlayDb,
    pub(crate) temporal_occurred_start: OverlayDb,
    pub(crate) temporal_occurred_end: OverlayDb,
    pub(crate) temporal_learned: OverlayDb,
    pub(crate) temporal_long_intervals: OverlayDb,
    pub(crate) phonetic_index: OverlayDb,
    pub(crate) phonetic_forward: OverlayDb,
    pub(crate) short_ids: OverlayDb,
    pub(crate) short_ids_reverse: OverlayDb,
    /// CRDT Doc states, state vectors, pending updates, metadata. Present in
    /// EVERY build (ONE-1132): the delete path writes its CRDT-independent
    /// `pt:` pending-tombstone marker here unconditionally, so deletion
    /// durability never depends on the `sync` cargo feature.
    pub(crate) sync_state: OverlayStrDb,
    /// Offline update queue, embed job queue, and hard-delete sweep queue.
    pub(crate) sync_queue: OverlayDb,
    /// Generic background attempt records keyed by attempt id.
    pub(crate) attempt_records: OverlayDb,
    /// Ready-attempt ordering index keyed by ready-at time then attempt id.
    pub(crate) attempt_ready: OverlayDb,
    /// Advisory dedupe index keys mapped to attempt ids.
    pub(crate) attempt_dedupe: OverlayDb,
    pub(crate) owner: StoreOwner,
}

/// One logical session view over all 28 manifest accessors. Every accessor
/// shares the exact same overlay snapshot; constructing accessors one by one
/// would permit a torn union if the overlay changed between constructions.
/// The borrowed owner marker prevents any view from outliving `StoreOwner`.
#[allow(
    dead_code,
    reason = "ONE-1727 constructs the complete D1 view; ONE-1728 witness/retrieval consumes the remaining accessors"
)]
pub(crate) struct SessionStoreView<'store> {
    _owner: &'store StoreOwner,
    pub(crate) entities: OverlayDb,
    pub(crate) edges_out: OverlayDb,
    pub(crate) edges_in: OverlayDb,
    pub(crate) vectors: OverlayDb,
    pub(crate) hnsw_neighbors: OverlayDb,
    pub(crate) hnsw_meta: OverlayDb,
    pub(crate) text_postings: OverlayDb,
    pub(crate) text_meta: OverlayDb,
    pub(crate) text_forward: OverlayDb,
    pub(crate) text_bm25_field_stats: OverlayDb,
    pub(crate) text_doc_field_lengths: OverlayDb,
    pub(crate) vault_meta: OverlayDb,
    pub(crate) ppr_cache: OverlayDb,
    pub(crate) ppr_cache_deps: OverlayDb,
    pub(crate) type_index: OverlayDb,
    pub(crate) temporal_occurred_start: OverlayDb,
    pub(crate) temporal_occurred_end: OverlayDb,
    pub(crate) temporal_learned: OverlayDb,
    pub(crate) temporal_long_intervals: OverlayDb,
    pub(crate) phonetic_index: OverlayDb,
    pub(crate) phonetic_forward: OverlayDb,
    pub(crate) short_ids: OverlayDb,
    pub(crate) short_ids_reverse: OverlayDb,
    pub(crate) sync_state: OverlayStrDb,
    pub(crate) sync_queue: OverlayDb,
    pub(crate) attempt_records: OverlayDb,
    pub(crate) attempt_ready: OverlayDb,
    pub(crate) attempt_dedupe: OverlayDb,
}

/// The session-side retrieval-telemetry surface (ONE-1728 §7 / K10).
///
/// Each method is the session sibling of the identically-named `Store`
/// method and rides the SAME extracted staging body, so the two targets
/// cannot drift in key format or side-write footprint. The difference is
/// purely which accessor bundle the body reaches: a session run's rows land
/// in the overlay `VaultMeta` keyspace and evaporate at close, so the base
/// telemetry ledger gains zero rows from an OffRecord session.
///
/// These take the caller's `wtxn` rather than opening their own, because a
/// session write must commit in the same transaction its overlay segment is
/// staged into — the segment guard applies staged rows only after the base
/// commit returns.
impl SessionStoreView<'_> {
    /// Session sibling of `Store::record_retrieval_run`.
    pub(crate) fn record_retrieval_run_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &RetrievalRunRecord,
    ) -> Result<()> {
        stage_retrieval_run_with_visibility(self, wtxn, record, true)
    }

    /// Session sibling of `Store::record_context_pack_provisional_retrieval_run`.
    pub(crate) fn record_context_pack_provisional_retrieval_run_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &RetrievalRunRecord,
    ) -> Result<()> {
        stage_retrieval_run_with_visibility(self, wtxn, record, false)
    }

    /// Session sibling of `Store::finalize_context_pack_retrieval_run`.
    ///
    /// Finalizes the same overlay row the session registration created; the
    /// base finalizer never sees that row and this one never reaches a base
    /// row.
    pub(crate) fn finalize_context_pack_retrieval_run_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        run_id: RetrievalRunId,
        elapsed_us: u64,
        claims_suppressed: usize,
        surfaced_result_ids: &[[u8; 16]],
        empty_reason: Option<String>,
    ) -> Result<()> {
        stage_context_pack_retrieval_run_finalize(
            self,
            wtxn,
            run_id,
            elapsed_us,
            claims_suppressed,
            surfaced_result_ids,
            empty_reason,
        )
    }

    /// Session sibling of `Store::delete_retrieval_run`, used to discard a
    /// failed session context-pack run's provisional overlay row.
    pub(crate) fn delete_retrieval_run_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        run_id: RetrievalRunId,
    ) -> Result<()> {
        stage_retrieval_run_delete(self, wtxn, run_id)
    }

    /// Composed read of the newest published retrieval-run rows: overlay ∪
    /// base, so an in-room caller sees its own runs and its ancestors'.
    pub(crate) fn retrieval_runs_in_txn(
        &self,
        rtxn: &RoTxn<'_>,
        limit: usize,
    ) -> Result<Vec<RetrievalRunRecord>> {
        read_retrieval_runs_in_txn(self, rtxn, limit)
    }

    /// Mode-aware VaultMeta write half consumed by
    /// `OffRecordSession::vault_meta_put`. Reuses the existing raw key/value
    /// representation; this pins routing, not a new encoding.
    pub(crate) fn vault_meta_put_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        key: &[u8],
        value: &[u8],
    ) -> Result<()> {
        self.vault_meta.put(wtxn, key, value)
    }

    /// Composed VaultMeta read half consumed by
    /// `OffRecordSession::vault_meta_get` — overlay ∪ base.
    pub(crate) fn vault_meta_get_in_txn(
        &self,
        rtxn: &RoTxn<'_>,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        Ok(self.vault_meta.get(rtxn, key)?.map(|raw| raw.into_owned()))
    }
}

/// Generates [`ManifestDbs`] and its two implementations from ONE list of the
/// manifest's named databases, so the trait cannot drift from the structs: a
/// database renamed in `Store` or `SessionStoreView` and not here fails to
/// compile.
macro_rules! manifest_dbs {
    ($($name:ident: $ty:ty),+ $(,)?) => {
        /// The manifest's named databases, addressed uniformly by write target
        /// (ARCH-0052 D2, ONE-1728 K11).
        ///
        /// [`Store`] answers with canonical accessors that read and write base
        /// LMDB rows. [`SessionStoreView`] answers with composed accessors over
        /// one shared overlay snapshot: reads see overlay ∪ base, writes stage
        /// into the session overlay and evaporate at close.
        ///
        /// This is what "write-target parameterization" means in this codebase.
        /// An index writer generic over `&impl ManifestDbs` has ONE body serving
        /// both targets — the base path is byte-identical because it is
        /// literally the same code reaching the same accessors, not a copy that
        /// could drift. `OverlayDb` already decides base-vs-overlay internally,
        /// so no writer needs a target branch.
        pub(crate) trait ManifestDbs {
            $(fn $name(&self) -> &$ty;)+
        }

        impl ManifestDbs for Store {
            $(fn $name(&self) -> &$ty { &self.$name })+
        }

        impl ManifestDbs for SessionStoreView<'_> {
            $(fn $name(&self) -> &$ty { &self.$name })+
        }
    };
}

manifest_dbs! {
    entities: OverlayDb,
    type_index: OverlayDb,
    short_ids: OverlayDb,
    short_ids_reverse: OverlayDb,
    vault_meta: OverlayDb,
    vectors: OverlayDb,
    hnsw_neighbors: OverlayDb,
    hnsw_meta: OverlayDb,
    text_postings: OverlayDb,
    text_meta: OverlayDb,
    text_forward: OverlayDb,
    text_bm25_field_stats: OverlayDb,
    text_doc_field_lengths: OverlayDb,
    edges_out: OverlayDb,
    edges_in: OverlayDb,
    ppr_cache: OverlayDb,
    ppr_cache_deps: OverlayDb,
    temporal_occurred_start: OverlayDb,
    temporal_occurred_end: OverlayDb,
    temporal_learned: OverlayDb,
    temporal_long_intervals: OverlayDb,
    phonetic_index: OverlayDb,
    phonetic_forward: OverlayDb,
    sync_state: OverlayStrDb,
    sync_queue: OverlayDb,
    attempt_records: OverlayDb,
    attempt_ready: OverlayDb,
    attempt_dedupe: OverlayDb,
}

impl std::ops::Deref for Store {
    type Target = StoreCore;

    fn deref(&self) -> &StoreCore {
        &self.core
    }
}

static NEXT_AUTHORITY_CLOCK_DOMAIN: AtomicUsize = AtomicUsize::new(1);

impl Drop for StoreOwner {
    fn drop(&mut self) {
        assert!(
            self.core.strong_count() == 0,
            "an Arc<StoreCore> outlived its StoreOwner; the path registry \
             would release the vault root while the environment is still \
             live (ARCH-0052 store-split invariant)"
        );
        crate::authority::release_authority_clock_domain(self.authority_clock_domain);
    }
}

impl Store {
    /// Captures one segment-aware snapshot and applies it to every database
    /// accessor in this logical read transaction.
    pub(crate) fn session_view(
        &self,
        overlay: Arc<crate::session_overlay::SessionOverlay>,
    ) -> Result<SessionStoreView<'_>> {
        use crate::session_overlay::OverlayKeyspace;

        let snapshot = Arc::new(overlay.snapshot()?);
        let db =
            |base, keyspace| OverlayDb::composed(base, overlay.clone(), snapshot.clone(), keyspace);
        Ok(SessionStoreView {
            _owner: &self.owner,
            entities: db(self.core.raw.entities, OverlayKeyspace::Entities),
            edges_out: db(self.core.raw.edges_out, OverlayKeyspace::EdgesOut),
            edges_in: db(self.core.raw.edges_in, OverlayKeyspace::EdgesIn),
            vectors: db(self.core.raw.vectors, OverlayKeyspace::Vectors),
            hnsw_neighbors: db(self.core.raw.hnsw_neighbors, OverlayKeyspace::HnswNeighbors),
            hnsw_meta: db(self.core.raw.hnsw_meta, OverlayKeyspace::HnswMeta),
            text_postings: db(self.core.raw.text_postings, OverlayKeyspace::TextPostings),
            text_meta: db(self.core.raw.text_meta, OverlayKeyspace::TextMeta),
            text_forward: db(self.core.raw.text_forward, OverlayKeyspace::TextForward),
            text_bm25_field_stats: db(
                self.core.raw.text_bm25_field_stats,
                OverlayKeyspace::TextBm25FieldStats,
            ),
            text_doc_field_lengths: db(
                self.core.raw.text_doc_field_lengths,
                OverlayKeyspace::TextDocFieldLengths,
            ),
            vault_meta: db(self.core.raw.vault_meta, OverlayKeyspace::VaultMeta),
            ppr_cache: db(self.core.raw.ppr_cache, OverlayKeyspace::PprCache),
            ppr_cache_deps: db(self.core.raw.ppr_cache_deps, OverlayKeyspace::PprCacheDeps),
            type_index: db(self.core.raw.type_index, OverlayKeyspace::TypeIndex),
            temporal_occurred_start: db(
                self.core.raw.temporal_occurred_start,
                OverlayKeyspace::TemporalOccurredStart,
            ),
            temporal_occurred_end: db(
                self.core.raw.temporal_occurred_end,
                OverlayKeyspace::TemporalOccurredEnd,
            ),
            temporal_learned: db(
                self.core.raw.temporal_learned,
                OverlayKeyspace::TemporalLearned,
            ),
            temporal_long_intervals: db(
                self.core.raw.temporal_long_intervals,
                OverlayKeyspace::TemporalLongIntervals,
            ),
            phonetic_index: db(self.core.raw.phonetic_index, OverlayKeyspace::PhoneticIndex),
            phonetic_forward: db(
                self.core.raw.phonetic_forward,
                OverlayKeyspace::PhoneticForward,
            ),
            short_ids: db(self.core.raw.short_ids, OverlayKeyspace::ShortIds),
            short_ids_reverse: db(
                self.core.raw.short_ids_reverse,
                OverlayKeyspace::ShortIdsReverse,
            ),
            sync_state: OverlayStrDb::composed(
                self.core.raw.sync_state,
                overlay.clone(),
                snapshot.clone(),
                OverlayKeyspace::SyncState,
            ),
            sync_queue: db(self.core.raw.sync_queue, OverlayKeyspace::SyncQueue),
            attempt_records: db(
                self.core.raw.attempt_records,
                OverlayKeyspace::AttemptRecords,
            ),
            attempt_ready: db(self.core.raw.attempt_ready, OverlayKeyspace::AttemptReady),
            attempt_dedupe: db(self.core.raw.attempt_dedupe, OverlayKeyspace::AttemptDedupe),
        })
    }

    /// Opens or creates a store at `path` and initializes all named databases.
    pub fn open(path: impl AsRef<Path>, config: &VaultConfig) -> Result<Self> {
        Self::open_with_storage_abi_version(path, config, STORAGE_ABI_VERSION)
    }

    #[cfg(test)]
    pub(crate) fn open_with_storage_abi_version_for_test(
        path: impl AsRef<Path>,
        config: &VaultConfig,
        storage_abi_version: u16,
    ) -> Result<Self> {
        Self::open_with_storage_abi_version(path, config, storage_abi_version)
    }

    fn open_with_storage_abi_version(
        path: impl AsRef<Path>,
        config: &VaultConfig,
        storage_abi_version: u16,
    ) -> Result<Self> {
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
        let vault_meta_view = OverlayDb::canonical(vault_meta);
        gate_storage_versions(
            &vault_meta_view,
            &mut wtxn,
            is_new_vault,
            storage_abi_version,
        )?;
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
        let attempt_records = create_manifest_db(&env, &mut wtxn, 25)?;
        let attempt_ready = create_manifest_db(&env, &mut wtxn, 26)?;
        let attempt_dedupe = create_manifest_db(&env, &mut wtxn, 27)?;
        if is_new_vault {
            validate_db_manifest_set(&env, &wtxn)?;
        }
        wtxn.commit()?;
        drop(db_open_guard);

        let kind_registry = RwLock::new(load_structural_kind_registry(&env, &vault_meta_view)?);

        let authority_clock_domain =
            NEXT_AUTHORITY_CLOCK_DOMAIN.fetch_add(1, AtomicOrdering::Relaxed);
        let shared_env: Env = (*env).clone();
        let core = Arc::new(StoreCore {
            env: shared_env,
            raw: RawDatabases {
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
                attempt_records,
                attempt_ready,
                attempt_dedupe,
            },
            kind_registry,
            off_record_sessions: OffRecordSessionRegistry::default(),
            retrieval_blend_tuning_lock: Mutex::new(()),
            authority_clock_domain,
        });
        let owner = StoreOwner {
            core: Arc::downgrade(&core),
            env,
            authority_clock_domain,
            created_new_vault: is_new_vault,
            _registered_path: registered_path,
        };
        let store = Self {
            entities: OverlayDb::canonical(core.raw.entities),
            edges_out: OverlayDb::canonical(core.raw.edges_out),
            edges_in: OverlayDb::canonical(core.raw.edges_in),
            vectors: OverlayDb::canonical(core.raw.vectors),
            hnsw_neighbors: OverlayDb::canonical(core.raw.hnsw_neighbors),
            hnsw_meta: OverlayDb::canonical(core.raw.hnsw_meta),
            text_postings: OverlayDb::canonical(core.raw.text_postings),
            text_meta: OverlayDb::canonical(core.raw.text_meta),
            text_forward: OverlayDb::canonical(core.raw.text_forward),
            text_bm25_field_stats: OverlayDb::canonical(core.raw.text_bm25_field_stats),
            text_doc_field_lengths: OverlayDb::canonical(core.raw.text_doc_field_lengths),
            vault_meta: OverlayDb::canonical(core.raw.vault_meta),
            ppr_cache: OverlayDb::canonical(core.raw.ppr_cache),
            ppr_cache_deps: OverlayDb::canonical(core.raw.ppr_cache_deps),
            type_index: OverlayDb::canonical(core.raw.type_index),
            temporal_occurred_start: OverlayDb::canonical(core.raw.temporal_occurred_start),
            temporal_occurred_end: OverlayDb::canonical(core.raw.temporal_occurred_end),
            temporal_learned: OverlayDb::canonical(core.raw.temporal_learned),
            temporal_long_intervals: OverlayDb::canonical(core.raw.temporal_long_intervals),
            phonetic_index: OverlayDb::canonical(core.raw.phonetic_index),
            phonetic_forward: OverlayDb::canonical(core.raw.phonetic_forward),
            short_ids: OverlayDb::canonical(core.raw.short_ids),
            short_ids_reverse: OverlayDb::canonical(core.raw.short_ids_reverse),
            sync_state: OverlayStrDb::canonical(core.raw.sync_state),
            sync_queue: OverlayDb::canonical(core.raw.sync_queue),
            attempt_records: OverlayDb::canonical(core.raw.attempt_records),
            attempt_ready: OverlayDb::canonical(core.raw.attempt_ready),
            attempt_dedupe: OverlayDb::canonical(core.raw.attempt_dedupe),
            core,
            owner,
        };

        // EMB-2 preflight: an out-of-range fast_dims is a caller bug and
        // fails closed before the HNSW compat check below can compare it.
        if let Some(fd) = config.fast_dims
            && (fd == 0 || usize::from(fd) >= config.dimensions)
        {
            return Err(Error::InvalidConfig(
                "fast_dims must be greater than zero and less than dimensions".to_owned(),
            ));
        }

        let should_persist_hnsw_config = preflight_hnsw_config(
            &store.env,
            &store.hnsw_meta,
            &store.vectors,
            &store.hnsw_neighbors,
            config,
        )?;
        let should_persist_model_id = preflight_embedding_model(
            &store.env,
            &store.hnsw_meta,
            &store.vectors,
            &store.hnsw_neighbors,
            config.embedding_model.as_deref(),
        )?;
        migrate_temporal_long_intervals_if_needed(
            &store.env,
            &store.hnsw_meta,
            &store.temporal_long_intervals,
        )?;

        if should_persist_hnsw_config {
            persist_hnsw_config_if_missing(
                &store.env,
                &store.hnsw_meta,
                &store.vectors,
                &store.hnsw_neighbors,
                config,
            )?;
        }

        if should_persist_model_id {
            let requested = config
                .embedding_model
                .as_deref()
                .ok_or_else(|| Error::InvalidConfig("missing embedding model".to_owned()))?;
            persist_model_id_if_missing(
                &store.env,
                &store.hnsw_meta,
                &store.vectors,
                &store.hnsw_neighbors,
                requested,
            )?;
        }

        store.ensure_receipt_family_indexes_on_open()?;
        store.ensure_gate_claim_index_flag_on_open()?;
        Ok(store)
    }

    pub(crate) fn created_new_vault(&self) -> bool {
        self.owner.created_new_vault
    }

    /// Builds RCPT-1's additive `vault_meta` sidecars before an opened store
    /// becomes visible.  The marker and every sidecar commit together, so an
    /// interrupted backfill is retried in full on the next open.
    fn ensure_receipt_family_indexes_on_open(&self) -> Result<()> {
        {
            let rtxn = self.env.read_txn()?;
            match self
                .vault_meta
                .get(&rtxn, RECEIPT_FAMILY_INDEX_VERSION_KEY)?
            {
                Some(version) if *version == [RECEIPT_FAMILY_INDEX_VERSION] => return Ok(()),
                Some(_) => return Err(Error::CorruptedIndex("receipt family index version")),
                None => {}
            }
        }

        let mut wtxn = self.env.write_txn()?;
        match self
            .vault_meta
            .get(&wtxn, RECEIPT_FAMILY_INDEX_VERSION_KEY)?
        {
            Some(version) if *version == [RECEIPT_FAMILY_INDEX_VERSION] => return Ok(()),
            Some(_) => return Err(Error::CorruptedIndex("receipt family index version")),
            None => {}
        }

        // The group aliases below resolve through the attempt run index, so build
        // it first.  Collect before writing to avoid mutating a DB while its
        // iterator is live.
        let mut attempts = Vec::new();
        for row in self.attempt_records.iter(&wtxn)? {
            let (key, raw) = row?;
            let id = crate::attempt_queue::AttemptId::from_bytes(&key)?;
            attempts.push(crate::attempt_queue::decode_record(&raw, id)?);
        }
        for attempt in &attempts {
            self.put_attempt_run_index_in_txn(
                &mut wtxn,
                attempt.run_id.as_deref(),
                attempt.id.as_bytes(),
            )?;
        }

        // Collect before writing (LMDB forbids mutating a DB while one of its
        // iterators is live), but keep only what the grant-ref index row needs
        // — not the whole decoded ledger.
        let mut grant_refs = Vec::new();
        self.for_each_gate_decision_in_txn(&wtxn, |record| {
            if let Some(grant_ref) = record.grant_ref {
                grant_refs.push((grant_ref, record.decision_id));
            }
            Ok(())
        })?;
        for (grant_ref, decision_id) in &grant_refs {
            self.put_gate_decision_grant_ref_index_row_in_txn(&mut wtxn, grant_ref, *decision_id)?;
        }

        let mut pending = Vec::new();
        let upper = pending_gate_consent_upper_bound();
        for row in self.vault_meta.range(
            &wtxn,
            &(
                std::ops::Bound::Included(PENDING_GATE_CONSENT_KEY_PREFIX),
                std::ops::Bound::Excluded(upper.as_slice()),
            ),
        )? {
            let (key, value) = row?;
            let claim_id = pending_gate_consent_claim_id_from_key(&key)?;
            let record = decode_pending_gate_consent(&value)?;
            if record.claim_id != claim_id {
                return Err(Error::CorruptedIndex("pending gate consent"));
            }
            pending.push(record);
        }
        for record in &pending {
            self.put_pending_gate_consent_indexes_in_txn(&mut wtxn, record)?;
        }

        self.vault_meta.put(
            &mut wtxn,
            RECEIPT_FAMILY_INDEX_VERSION_KEY,
            &[RECEIPT_FAMILY_INDEX_VERSION],
        )?;
        wtxn.commit()?;
        Ok(())
    }

    /// Sets the ERASE-A (ONE-1637) backfill-complete flag for the vaults whose
    /// backfill is trivially empty: a ledger with no rows is, vacuously, fully
    /// indexed. Covers brand-new vaults and existing never-gated ones without a
    /// maintenance run. A populated ledger leaves the flag unset, which costs
    /// discovery speed (scan fallback) and never correctness.
    fn ensure_gate_claim_index_flag_on_open(&self) -> Result<()> {
        // One predicate, checked twice: the write txn re-confirms under lock
        // what the optimistic read txn saw.
        let needs_flag = |txn: &RoTxn<'_>| -> Result<bool> {
            Ok(
                !self.gate_decision_claim_index_backfill_complete_in_txn(txn)?
                    && self.gate_decision_ledger_is_empty_in_txn(txn)?,
            )
        };
        {
            let rtxn = self.env.read_txn()?;
            if !needs_flag(&rtxn)? {
                return Ok(());
            }
        }

        let mut wtxn = self.env.write_txn()?;
        if !needs_flag(&wtxn)? {
            return Ok(());
        }
        self.vault_meta.put(
            &mut wtxn,
            GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_KEY,
            &GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_VALUE,
        )?;
        wtxn.commit()?;
        Ok(())
    }

    /// Single cursor seek over the primary ledger range.
    fn gate_decision_ledger_is_empty_in_txn(&self, txn: &RoTxn<'_>) -> Result<bool> {
        let upper = gate_decision_upper_bound();
        Ok(self
            .vault_meta
            .range(
                txn,
                &(
                    std::ops::Bound::Included(GATE_DECISION_KEY_PREFIX),
                    std::ops::Bound::Excluded(upper.as_slice()),
                ),
            )?
            .next()
            .transpose()?
            .is_none())
    }

    /// One-time ERASE-A (ONE-1637) backfill: indexes every pre-existing
    /// claim-bound ledger row and sets the durable completeness flag in ONE
    /// write txn, so a crash leaves either nothing or everything (RCPT-1
    /// crash-safety shape). Idempotent across reruns.
    pub(crate) fn backfill_gate_decision_claim_index(&self) -> Result<GateClaimIndexBackfill> {
        let mut wtxn = self.env.write_txn()?;
        if self.gate_decision_claim_index_backfill_complete_in_txn(&wtxn)? {
            return Ok(GateClaimIndexBackfill {
                rows_indexed: 0,
                already_complete: true,
            });
        }

        // Collect before writing: LMDB forbids mutating a DB while one of its
        // iterators is live. Only the two ids each index row needs are
        // retained — the decoded record is dropped inside the walk, so an
        // unbounded ledger of claim-free (or string-heavy) rows never
        // accumulates here.
        let mut claim_rows = Vec::new();
        self.for_each_gate_decision_in_txn(&wtxn, |record| {
            if let Some(claim_id) = record.claim_id {
                claim_rows.push((claim_id, record.decision_id));
            }
            Ok(())
        })?;
        for (claim_id, decision_id) in &claim_rows {
            self.vault_meta.put(
                &mut wtxn,
                &gate_decision_claim_index_key(claim_id, *decision_id),
                b"",
            )?;
        }
        self.vault_meta.put(
            &mut wtxn,
            GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_KEY,
            &GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_VALUE,
        )?;
        wtxn.commit()?;
        Ok(GateClaimIndexBackfill {
            rows_indexed: claim_rows.len() as u64,
            already_complete: false,
        })
    }

    pub(crate) fn put_attempt_run_index_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        run_id: Option<&str>,
        attempt_id: &[u8; 16],
    ) -> Result<()> {
        let Some(run_id) = run_id else {
            return Ok(());
        };
        self.vault_meta
            .put(wtxn, &attempt_run_index_key(run_id, attempt_id), b"1")?;
        self.refresh_pending_gate_consent_group_aliases_for_run_in_txn(wtxn, run_id)?;
        Ok(())
    }

    /// Removes the run sidecar for a test fixture's intentionally deleted
    /// primary attempt row in the same transaction. Readers remain fail-closed
    /// when a dangling sidecar is observed.
    #[cfg(test)]
    pub(crate) fn delete_attempt_run_index_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        run_id: Option<&str>,
        attempt_id: &[u8; 16],
    ) -> Result<()> {
        let Some(run_id) = run_id else {
            return Ok(());
        };
        self.vault_meta
            .delete(wtxn, &attempt_run_index_key(run_id, attempt_id))?;
        Ok(())
    }

    pub(crate) fn attempt_ids_for_run_in_txn(
        &self,
        txn: &RoTxn<'_>,
        run_id: &str,
    ) -> Result<Vec<[u8; 16]>> {
        let prefix = attempt_run_index_prefix(run_id);
        let mut ids = Vec::new();
        for row in self.vault_meta.prefix_iter(txn, &prefix)? {
            let (key, _) = row?;
            ids.push(index_suffix_id(&key, &prefix, "attempt run index")?);
        }
        Ok(ids)
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
        self.sync_state.delete(wtxn, key.as_str())
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
        Ok((*marker == current).then_some(marker.to_vec()))
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
        Ok((*marker == current).then_some(marker.to_vec()))
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
        Ok(*marker == current)
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
        if *marker != *token {
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
        Ok(current_claim_embedding_token_from_record(&record))
    }

    fn current_claim_embedding_token_in_txn(
        &self,
        wtxn: &RwTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<[u8; PENDING_EMBEDDING_MARKER_TOKEN_LEN]>> {
        let Some(record) = self.entities.get(wtxn, id.as_bytes())? else {
            return Ok(None);
        };
        Ok(current_claim_embedding_token_from_record(&record))
    }

    pub(crate) fn structural_kind_registration(
        &self,
        type_byte: u8,
    ) -> Option<StructuralKindRegistration> {
        let registry = self
            .kind_registry
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry.get(&type_byte).cloned()
    }

    pub(crate) fn structural_kind_registrations(&self) -> Vec<StructuralKindRegistration> {
        let registry = self
            .kind_registry
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            .unwrap_or_else(std::sync::PoisonError::into_inner);

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
        append_gate_decision_row_in_txn(self, wtxn, record)
    }

    pub(crate) fn delete_gate_decision_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        decision_id: GateDecisionId,
    ) -> Result<()> {
        let Some(record) = self.gate_decision_in_txn(&*wtxn, decision_id)? else {
            return Err(Error::InvariantViolation(
                "staged gate decision missing during rollback",
            ));
        };
        self.delete_gate_decision_grant_ref_index_in_txn(wtxn, &record)?;
        self.delete_gate_decision_claim_index_in_txn(wtxn, &record)?;
        self.vault_meta
            .delete(wtxn, &gate_decision_key(decision_id))?;
        Ok(())
    }

    /// Stages the required marker and deletion authority sidecar before a
    /// locally gated tombstone can be committed. The sidecar exists only so a
    /// crash before TXN3 can recover the exact evaluated actor/policy data; it
    /// is never queryable as a Gate decision and is consumed by TXN3.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn put_pending_deletion_gate_decision_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &GateDecisionRecord,
        target: &[u8; 16],
        tombstone_reason: u8,
    ) -> Result<()> {
        let pending = PendingDeletionGateDecisionRecord {
            version: PENDING_DELETION_GATE_DECISION_VERSION,
            target: *target,
            tombstone_reason,
            decision: record.clone(),
        };
        vet_pending_deletion_gate_decision_record(&pending)?;
        let key = pending_deletion_gate_decision_key(record.decision_id);
        let sidecar_exists = if let Some(existing) = self.vault_meta.get(&*wtxn, &key)? {
            let existing = decode_pending_deletion_gate_decision(&existing)?;
            if existing != pending {
                return Err(Error::InvariantViolation(
                    "pending deletion gate decision id collision",
                ));
            }
            true
        } else {
            false
        };
        if !sidecar_exists {
            let value = encode_pending_deletion_gate_decision(&pending)?;
            self.vault_meta.put(wtxn, &key, &value)?;
        }
        let required_key = deletion_gate_required_key(record.decision_id);
        let required_value = encode_deletion_gate_required(target, tombstone_reason);
        if let Some(existing) = self.vault_meta.get(&*wtxn, &required_key)? {
            if *existing != required_value {
                return Err(Error::InvariantViolation(
                    "deletion gate required marker id collision",
                ));
            }
        } else {
            self.vault_meta.put(wtxn, &required_key, &required_value)?;
        }
        Ok(())
    }

    /// Reads a staged deletion authority record by deletion request id.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn pending_deletion_gate_decision_in_txn(
        &self,
        txn: &RoTxn<'_>,
        request_id: GateDecisionId,
    ) -> Result<Option<GateDecisionRecord>> {
        let key = pending_deletion_gate_decision_key(request_id);
        let Some(value) = self.vault_meta.get(txn, &key)? else {
            return Ok(None);
        };
        let pending = decode_pending_deletion_gate_decision(&value)?;
        if pending.decision.decision_id != request_id {
            return Err(Error::CorruptedIndex("pending deletion gate decision"));
        }
        Ok(Some(pending.decision))
    }

    /// Appends a staged deletion authority record to the real Gate
    /// ledger and removes its recovery sidecar atomically with TXN3.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn append_pending_deletion_gate_decision_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        request_id: GateDecisionId,
        target: &[u8; 16],
        tombstone_reason: u8,
    ) -> Result<Option<GateDecisionRecord>> {
        let required_key = deletion_gate_required_key(request_id);
        let Some(required) = self.vault_meta.get(&*wtxn, &required_key)? else {
            return Ok(None);
        };
        let (required_target, required_reason) = decode_deletion_gate_required(&required)?;
        if required_target != *target || required_reason != tombstone_reason {
            return Ok(None);
        }
        let key = pending_deletion_gate_decision_key(request_id);
        let Some(value) = self.vault_meta.get(&*wtxn, &key)? else {
            return Err(Error::CorruptedIndex("pending deletion gate decision"));
        };
        let pending = decode_pending_deletion_gate_decision(&value)?;
        if pending.decision.decision_id != request_id {
            return Err(Error::CorruptedIndex("pending deletion gate decision"));
        }
        if pending.target != *target || pending.tombstone_reason != tombstone_reason {
            return Err(Error::CorruptedIndex("pending deletion gate decision"));
        }
        self.append_gate_decision_in_txn(wtxn, &pending.decision)?;
        self.vault_meta.delete(wtxn, &key)?;
        self.vault_meta.delete(wtxn, &required_key)?;
        Ok(Some(pending.decision))
    }

    /// Discards a staged recovery sidecar when a later ownership probe proves
    /// this request did not perform a purge. No final Gate record is emitted:
    /// gate evidence must not outlive an unperformed deletion mutation.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn discard_pending_deletion_gate_decision_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        request_id: GateDecisionId,
        target: &[u8; 16],
        tombstone_reason: u8,
    ) -> Result<bool> {
        let required_key = deletion_gate_required_key(request_id);
        let Some(required) = self.vault_meta.get(&*wtxn, &required_key)? else {
            return Ok(false);
        };
        let (required_target, required_reason) = decode_deletion_gate_required(&required)?;
        if required_target != *target || required_reason != tombstone_reason {
            return Ok(false);
        }
        let key = pending_deletion_gate_decision_key(request_id);
        let Some(value) = self.vault_meta.get(&*wtxn, &key)? else {
            return Err(Error::CorruptedIndex("pending deletion gate decision"));
        };
        let pending = decode_pending_deletion_gate_decision(&value)?;
        if pending.decision.decision_id != request_id {
            return Err(Error::CorruptedIndex("pending deletion gate decision"));
        }
        if pending.target != *target || pending.tombstone_reason != tombstone_reason {
            return Err(Error::CorruptedIndex("pending deletion gate decision"));
        }
        self.vault_meta.delete(wtxn, &key)?;
        self.vault_meta.delete(wtxn, &required_key)?;
        Ok(true)
    }

    #[cfg(all(test, feature = "sync"))]
    pub(crate) fn remove_pending_deletion_gate_sidecar_for_test(
        &self,
        wtxn: &mut RwTxn<'_>,
        request_id: GateDecisionId,
    ) -> Result<()> {
        self.vault_meta
            .delete(wtxn, &pending_deletion_gate_decision_key(request_id))?;
        Ok(())
    }

    /// Returns every gate decision carrying this grant reference, newest
    /// first, without scanning the global decision ledger.
    pub(crate) fn gate_decisions_for_grant_ref(
        &self,
        grant_ref: &str,
    ) -> Result<Vec<GateDecisionRecord>> {
        let rtxn = self.env.read_txn()?;
        let prefix = gate_decision_grant_ref_index_prefix(grant_ref);
        let mut records = Vec::new();
        for row in self.vault_meta.prefix_iter(&rtxn, &prefix)? {
            let (key, _) = row?;
            let decision_id = GateDecisionId::from_bytes(index_suffix_id(
                &key,
                &prefix,
                "gate decision grant ref index",
            )?);
            let Some(record) = self.gate_decision_in_txn(&rtxn, decision_id)? else {
                return Err(Error::CorruptedIndex("gate decision grant ref index"));
            };
            if record.grant_ref.as_deref() != Some(grant_ref) {
                return Err(Error::CorruptedIndex("gate decision grant ref index"));
            }
            records.push(record);
        }
        records.sort_by(|left, right| {
            right
                .decision_id
                .as_bytes()
                .cmp(&left.decision_id.as_bytes())
        });
        Ok(records)
    }

    /// Per-claim discovery for the erase coupling (ONE-1638) and any per-claim
    /// receipt read. Index-accelerated ONLY when the durable backfill flag is
    /// set; otherwise a full keyspace scan, so a vault mid-backfill can never
    /// hide rows from an erase. Both paths return records ascending by
    /// decision_id and are result-identical.
    ///
    /// Redacted (version 1) skeletons ARE returned — they retain `claim_id` by
    /// design. Completeness is decided by
    /// [`Store::verify_claim_erasure_by_scan_in_txn`], never by this reader.
    #[cfg_attr(not(test), allow(dead_code))] // seam for the ONE-1638 erase coupling
    pub(crate) fn gate_decisions_for_claim_in_txn(
        &self,
        txn: &RoTxn<'_>,
        claim_id: &[u8; 16],
    ) -> Result<Vec<GateDecisionRecord>> {
        if !self.gate_decision_claim_index_backfill_complete_in_txn(txn)? {
            return self.scan_gate_decisions_for_claim_in_txn(txn, claim_id);
        }
        let prefix = gate_decision_claim_index_prefix(claim_id);
        let mut records = Vec::new();
        for row in self.vault_meta.prefix_iter(txn, &prefix)? {
            let (key, _) = row?;
            let decision_id = GateDecisionId::from_bytes(index_suffix_id(
                &key,
                &prefix,
                "gate decision claim index",
            )?);
            let Some(record) = self.gate_decision_in_txn(txn, decision_id)? else {
                return Err(Error::CorruptedIndex("gate decision claim index"));
            };
            if record.claim_id != Some(*claim_id) {
                return Err(Error::CorruptedIndex("gate decision claim index"));
            }
            records.push(record);
        }
        Ok(records)
    }

    /// Full-keyspace per-claim discovery: the fallback path taken while the
    /// backfill flag is unset, and directly callable for parity checks.
    #[cfg_attr(not(test), allow(dead_code))] // seam for the ONE-1638 erase coupling
    pub(crate) fn scan_gate_decisions_for_claim_in_txn(
        &self,
        txn: &RoTxn<'_>,
        claim_id: &[u8; 16],
    ) -> Result<Vec<GateDecisionRecord>> {
        let mut records = Vec::new();
        self.for_each_gate_decision_in_txn(txn, |record| {
            if record.claim_id == Some(*claim_id) {
                records.push(record);
            }
            Ok(())
        })?;
        Ok(records)
    }

    /// ERASE step-5 completeness verify: the decision ids still claim-bound AND
    /// unredacted. ALWAYS a full `gate_decision:v0:` keyspace scan and NEVER a
    /// read of the claim index, in any flag state — an index that accelerated
    /// the erase cannot also certify it complete. An empty result means erasure
    /// is complete for this claim. Deliberately uncapped: a correctness scan
    /// takes no query-budget shortcut.
    #[cfg_attr(not(test), allow(dead_code))] // seam for the ONE-1638 erase coupling
    pub(crate) fn verify_claim_erasure_by_scan_in_txn(
        &self,
        txn: &RoTxn<'_>,
        claim_id: &[u8; 16],
    ) -> Result<Vec<GateDecisionId>> {
        let mut remaining = Vec::new();
        self.for_each_gate_decision_in_txn(txn, |record| {
            if record.claim_id == Some(*claim_id) && record.redacted_at.is_none() {
                remaining.push(record.decision_id);
            }
            Ok(())
        })?;
        Ok(remaining)
    }

    /// Streams every primary ledger row in ascending decision_id order,
    /// checking each row against its own key and handing ownership of the
    /// decoded record to `visit`.
    ///
    /// MEMORY CONTRACT: the caller's filter runs INSIDE the cursor walk, so a
    /// filtered read retains only its matches (or a projection of them) and the
    /// ledger's size stops bounding peak memory on a long-lived vault. The
    /// `Result<()>` return — not a `Vec` — is what enforces this; do not
    /// reintroduce an intermediate collection of every record.
    fn for_each_gate_decision_in_txn(
        &self,
        txn: &RoTxn<'_>,
        mut visit: impl FnMut(GateDecisionRecord) -> Result<()>,
    ) -> Result<()> {
        let upper = gate_decision_upper_bound();
        for row in self.vault_meta.range(
            txn,
            &(
                std::ops::Bound::Included(GATE_DECISION_KEY_PREFIX),
                std::ops::Bound::Excluded(upper.as_slice()),
            ),
        )? {
            let (key, value) = row?;
            let decision_id = gate_decision_id_from_key(&key)?;
            let record = decode_gate_decision(&value)?;
            if record.decision_id != decision_id {
                return Err(Error::CorruptedIndex("gate decision ledger"));
            }
            visit(record)?;
        }
        Ok(())
    }

    /// Reads the durable backfill-complete flag. A present row with any byte
    /// other than the pinned value is corruption, not a soft "incomplete".
    pub(crate) fn gate_decision_claim_index_backfill_complete_in_txn(
        &self,
        txn: &RoTxn<'_>,
    ) -> Result<bool> {
        match self
            .vault_meta
            .get(txn, GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_KEY)?
        {
            Some(value) if *value == GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_VALUE => Ok(true),
            Some(_) => Err(Error::CorruptedIndex(
                "gate decision claim index backfill flag",
            )),
            None => Ok(false),
        }
    }

    pub(crate) fn matching_gate_decision_in_txn(
        &self,
        txn: &RwTxn<'_>,
        expected: &GateDecisionRecord,
    ) -> Result<Option<GateDecisionRecord>> {
        let upper = gate_decision_upper_bound();
        for row in self.vault_meta.rev_range(
            txn,
            &(
                std::ops::Bound::Included(GATE_DECISION_KEY_PREFIX),
                std::ops::Bound::Excluded(upper.as_slice()),
            ),
        )? {
            let (key, value) = row?;
            if !key.starts_with(GATE_DECISION_KEY_PREFIX) {
                break;
            }
            let decision_id = gate_decision_id_from_key(&key)?;
            let record = decode_gate_decision(&value)?;
            if record.decision_id != decision_id {
                return Err(Error::CorruptedIndex("gate decision ledger"));
            }
            if gate_decision_matches_pending_candidate(&record, expected) {
                return Ok(Some(record));
            }
        }
        Ok(None)
    }

    /// Removes gate decisions for an id that remained unwritten when an
    /// off-record session closed. Such decisions can only be standalone
    /// preflight artifacts: retaining one would leave an accountability row
    /// for a fenced turn that never entered the vault.
    pub(crate) fn delete_gate_decisions_for_missing_off_record_turn_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        turn_id: &EntityId,
    ) -> Result<usize> {
        let upper = gate_decision_upper_bound();
        let mut records = Vec::new();
        for row in self.vault_meta.rev_range(
            wtxn,
            &(
                std::ops::Bound::Included(GATE_DECISION_KEY_PREFIX),
                std::ops::Bound::Excluded(upper.as_slice()),
            ),
        )? {
            let (key, value) = row?;
            if !key.starts_with(GATE_DECISION_KEY_PREFIX) {
                break;
            }
            let decision_id = gate_decision_id_from_key(&key)?;
            let record = decode_gate_decision(&value)?;
            if record.decision_id != decision_id {
                return Err(Error::CorruptedIndex("gate decision ledger"));
            }
            if record.claim_id == Some(*turn_id.as_bytes()) {
                records.push(record);
            }
        }
        for record in &records {
            self.delete_gate_decision_grant_ref_index_in_txn(wtxn, record)?;
            self.delete_gate_decision_claim_index_in_txn(wtxn, record)?;
            self.vault_meta
                .delete(wtxn, &gate_decision_key(record.decision_id))?;
        }
        Ok(records.len())
    }

    /// Persists the opaque gate-surface bytes for a scheduled outbound attempt id
    /// (its own committed write txn). Overwrites any prior value for the id.
    pub(crate) fn put_outbound_gate_binding(
        &self,
        attempt_id: &[u8; 16],
        value: &[u8],
    ) -> Result<()> {
        let key = outbound_gate_binding_key(attempt_id);
        let mut wtxn = self.env.write_txn()?;
        self.vault_meta.put(&mut wtxn, &key, value)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Reads the persisted gate-surface bytes for a scheduled outbound attempt id.
    pub(crate) fn outbound_gate_binding(&self, attempt_id: &[u8; 16]) -> Result<Option<Vec<u8>>> {
        let key = outbound_gate_binding_key(attempt_id);
        let rtxn = self.env.read_txn()?;
        Ok(self
            .vault_meta
            .get(&rtxn, &key)?
            .map(|value| value.to_vec()))
    }

    /// Inserts one connector-send receipt keyed by its originating TASK.
    /// Existing rows are left intact so executor retries cannot duplicate the
    /// transport record.
    pub(crate) fn put_send_receipt_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        task_id: &EntityId,
        value: &[u8],
    ) -> Result<bool> {
        let key = send_receipt_key(task_id);
        if self.vault_meta.get(&*wtxn, &key)?.is_some() {
            return Ok(false);
        }
        self.vault_meta.put(wtxn, &key, value)?;
        Ok(true)
    }

    /// Replaces one connector-send receipt row. Receipt semantics decide
    /// whether replacement is legal before calling this storage-only helper.
    pub(crate) fn set_send_receipt_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        task_id: &EntityId,
        value: &[u8],
    ) -> Result<()> {
        self.vault_meta
            .put(wtxn, &send_receipt_key(task_id), value)?;
        Ok(())
    }

    /// Reads one connector-send receipt inside a caller-owned transaction.
    pub(crate) fn get_send_receipt_by_task_in_txn(
        &self,
        txn: &RoTxn<'_>,
        task_id: &EntityId,
    ) -> Result<Option<Vec<u8>>> {
        Ok(self
            .vault_meta
            .get(txn, &send_receipt_key(task_id))?
            .map(std::borrow::Cow::into_owned))
    }

    /// Reads one connector-send receipt directly by its originating TASK.
    pub(crate) fn get_send_receipt_by_task(&self, task_id: &EntityId) -> Result<Option<Vec<u8>>> {
        let rtxn = self.env.read_txn()?;
        self.get_send_receipt_by_task_in_txn(&rtxn, task_id)
    }

    /// Records the first delivered TASK for one actor-scoped client
    /// idempotency key. Later deliveries keep the original winner.
    pub(crate) fn put_delivered_send_idempotency_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        actor_ref: &EntityId,
        idempotency_key: &str,
        task_ref: &EntityId,
    ) -> Result<()> {
        let key = send_idempotency_key(actor_ref, idempotency_key);
        if let Some(existing) = self.vault_meta.get(&*wtxn, &key)? {
            send_idempotency_task_ref_from_value(&existing)?;
            return Ok(());
        }
        let value = send_idempotency_value(task_ref);
        self.vault_meta.put(wtxn, &key, &value)?;
        Ok(())
    }

    /// Point-reads the delivered TASK for one actor-scoped client
    /// idempotency key.
    pub(crate) fn get_delivered_send_task_by_idempotency(
        &self,
        actor_ref: &EntityId,
        idempotency_key: &str,
    ) -> Result<Option<EntityId>> {
        let key = send_idempotency_key(actor_ref, idempotency_key);
        let rtxn = self.env.read_txn()?;
        self.vault_meta
            .get(&rtxn, &key)?
            .map(|value| send_idempotency_task_ref_from_value(&value))
            .transpose()
    }

    /// Returns all opaque connector-send receipt rows in TASK-id order.
    pub(crate) fn send_receipt_rows(&self) -> Result<Vec<([u8; 16], Vec<u8>)>> {
        let rtxn = self.env.read_txn()?;
        let mut rows = Vec::new();
        for row in self
            .vault_meta
            .prefix_iter(&rtxn, SEND_RECEIPT_KEY_PREFIX)?
        {
            let (key, value) = row?;
            rows.push((send_receipt_task_id_from_key(&key)?, value.into_owned()));
        }
        Ok(rows)
    }

    pub(crate) fn gate_decision_in_txn(
        &self,
        txn: &RoTxn<'_>,
        decision_id: GateDecisionId,
    ) -> Result<Option<GateDecisionRecord>> {
        let Some(value) = self.vault_meta.get(txn, &gate_decision_key(decision_id))? else {
            return Ok(None);
        };
        let record = decode_gate_decision(&value)?;
        if record.decision_id != decision_id {
            return Err(Error::CorruptedIndex("gate decision ledger"));
        }
        Ok(Some(record))
    }

    pub(crate) fn append_channel_identity_lifecycle_receipt_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &ChannelIdentityLifecycleReceiptRecord,
    ) -> Result<()> {
        vet_channel_identity_lifecycle_receipt_record(record)?;
        let key = channel_identity_lifecycle_key(record.receipt_id);
        if self.vault_meta.get(wtxn, &key)?.is_some() {
            return Err(Error::InvariantViolation(
                "channel identity lifecycle receipt id collision",
            ));
        }
        let value = encode_channel_identity_lifecycle_receipt(record)?;
        self.vault_meta.put(wtxn, &key, &value)?;
        Ok(())
    }

    pub(crate) fn put_pending_gate_consent_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &PendingGateConsentRecord,
    ) -> Result<()> {
        vet_pending_gate_consent_record(record)?;
        let key = pending_gate_consent_key(&record.claim_id);
        if let Some(existing) = self.vault_meta.get(&*wtxn, &key)? {
            let existing = decode_pending_gate_consent(&existing)?;
            if existing.claim_id != record.claim_id {
                return Err(Error::CorruptedIndex("pending gate consent"));
            }
            self.delete_pending_gate_consent_indexes_in_txn(wtxn, &existing)?;
        }
        let value = encode_pending_gate_consent(record)?;
        self.vault_meta.put(wtxn, &key, &value)?;
        self.put_pending_gate_consent_indexes_in_txn(wtxn, record)?;
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
        let record = decode_pending_gate_consent(&value)?;
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
        let key = pending_gate_consent_key(claim_id.as_bytes());
        if let Some(value) = self.vault_meta.get(&*wtxn, &key)? {
            let record = decode_pending_gate_consent(&value)?;
            if record.claim_id != *claim_id.as_bytes() {
                return Err(Error::CorruptedIndex("pending gate consent"));
            }
            self.delete_pending_gate_consent_indexes_in_txn(wtxn, &record)?;
        }
        self.vault_meta.delete(wtxn, &key)?;
        Ok(())
    }

    /// Parts-based form, so a streaming backfill can write the row without
    /// holding the decoded record it came from. The append path builds the
    /// same row inline in [`append_gate_decision_row_in_txn`], which is
    /// target-parameterized and so cannot route through a `Store` method.
    fn put_gate_decision_grant_ref_index_row_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        grant_ref: &str,
        decision_id: GateDecisionId,
    ) -> Result<()> {
        self.vault_meta.put(
            wtxn,
            &gate_decision_grant_ref_index_key(grant_ref, decision_id),
            b"1",
        )?;
        Ok(())
    }

    fn delete_gate_decision_grant_ref_index_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &GateDecisionRecord,
    ) -> Result<()> {
        let Some(grant_ref) = record.grant_ref.as_deref() else {
            return Ok(());
        };
        self.vault_meta.delete(
            wtxn,
            &gate_decision_grant_ref_index_key(grant_ref, record.decision_id),
        )?;
        Ok(())
    }

    fn delete_gate_decision_claim_index_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &GateDecisionRecord,
    ) -> Result<()> {
        let Some(claim_id) = record.claim_id.as_ref() else {
            return Ok(());
        };
        self.vault_meta.delete(
            wtxn,
            &gate_decision_claim_index_key(claim_id, record.decision_id),
        )?;
        Ok(())
    }

    fn pending_gate_consent_index_state_for_record_in_txn(
        &self,
        wtxn: &RwTxn<'_>,
        record: &PendingGateConsentRecord,
    ) -> Result<Option<PendingGateConsentIndexState>> {
        let Some(run_id) = record.dreamer_run_id.as_deref() else {
            return Ok(None);
        };
        let claim_id = EntityId::from_bytes(record.claim_id)
            .map_err(|_| Error::CorruptedIndex("pending gate consent"))?;
        // Low-level receipt tests and generic pending asks can legitimately
        // lack a claim body. They remain run-indexed; only readable CLAIM
        // rows participate in the inbox's semantic duplicate sidecar.
        let semantic_claim_hash = match self.entities.get(wtxn, claim_id.as_bytes())? {
            None => None,
            Some(raw) => {
                let Some(header) = EntityMetadataHeader::parse(&raw) else {
                    return Err(Error::CorruptedIndex("entity header"));
                };
                if header.entity_type != ENTITY_TYPE_CLAIM {
                    None
                } else {
                    let body = raw
                        .get(ENTITY_BODY_OFFSET..)
                        .ok_or(Error::CorruptedIndex("pending gate consent"))?;
                    Some(crate::inbox::inbox_claim_hash(
                        &crate::claim::decode_claim_body(body, true)?,
                    )?)
                }
            }
        };
        let group_key = crate::attempt_queue::dreamer_run_root_id_in_txn(self, wtxn, run_id)?
            .map_or_else(
                || run_id.to_owned(),
                |root| bytes_to_hex_lower(root.as_bytes()),
            );
        Ok(Some(PendingGateConsentIndexState {
            version: PENDING_GATE_CONSENT_INDEX_STATE_VERSION,
            run_id: run_id.to_owned(),
            group_key,
            semantic_claim_hash,
        }))
    }

    fn put_pending_gate_consent_indexes_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &PendingGateConsentRecord,
    ) -> Result<()> {
        let Some(state) = self.pending_gate_consent_index_state_for_record_in_txn(wtxn, record)?
        else {
            return Ok(());
        };
        self.vault_meta.put(
            wtxn,
            &pending_gate_consent_run_index_key(&state.run_id, &record.claim_id),
            b"1",
        )?;
        self.vault_meta.put(
            wtxn,
            &pending_gate_consent_group_index_key(&state.group_key, &record.claim_id),
            b"1",
        )?;
        if let Some(semantic_claim_hash) = state.semantic_claim_hash.as_ref() {
            self.vault_meta.put(
                wtxn,
                &pending_gate_consent_hash_index_key(semantic_claim_hash, &record.claim_id),
                b"1",
            )?;
        }
        let encoded = encode_pending_gate_consent_index_state(&state)?;
        self.vault_meta.put(
            wtxn,
            &pending_gate_consent_index_state_key(&record.claim_id),
            &encoded,
        )?;
        Ok(())
    }

    /// Recomputes the derived group aliases after a run gains an attempt. A
    /// pending consent can predate its durable root, so its old alias may no
    /// longer match the run tree that the inbox projection resolves.
    fn refresh_pending_gate_consent_group_aliases_for_run_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        run_id: &str,
    ) -> Result<()> {
        let prefix = pending_gate_consent_run_index_prefix(run_id);
        let mut records = Vec::new();
        for row in self.vault_meta.prefix_iter(&*wtxn, &prefix)? {
            let (key, _) = row?;
            let claim_id = EntityId::from_bytes(index_suffix_id(
                &key,
                &prefix,
                "pending gate consent run index",
            )?)
            .map_err(|_| Error::CorruptedIndex("pending gate consent run index"))?;
            let Some(record) = self.pending_gate_consent_in_txn(&*wtxn, &claim_id)? else {
                return Err(Error::CorruptedIndex("pending gate consent run index"));
            };
            let Some(state) = self.pending_gate_consent_index_state_in_txn(&*wtxn, &record)? else {
                return Err(Error::CorruptedIndex("pending gate consent run index"));
            };
            if state.run_id != run_id {
                return Err(Error::CorruptedIndex("pending gate consent run index"));
            }
            records.push(record);
        }

        for record in &records {
            self.delete_pending_gate_consent_indexes_in_txn(wtxn, record)?;
            self.put_pending_gate_consent_indexes_in_txn(wtxn, record)?;
        }
        Ok(())
    }

    fn pending_gate_consent_index_state_in_txn(
        &self,
        txn: &RoTxn<'_>,
        record: &PendingGateConsentRecord,
    ) -> Result<Option<PendingGateConsentIndexState>> {
        let Some(raw) = self
            .vault_meta
            .get(txn, &pending_gate_consent_index_state_key(&record.claim_id))?
        else {
            return Ok(None);
        };
        let state = decode_pending_gate_consent_index_state(&raw)?;
        if record.dreamer_run_id.as_deref() != Some(state.run_id.as_str()) {
            return Err(Error::CorruptedIndex("pending gate consent index state"));
        }
        Ok(Some(state))
    }

    fn delete_pending_gate_consent_indexes_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &PendingGateConsentRecord,
    ) -> Result<()> {
        let Some(state) = self.pending_gate_consent_index_state_in_txn(&*wtxn, record)? else {
            if record.dreamer_run_id.is_some() {
                return Err(Error::CorruptedIndex("pending gate consent index state"));
            }
            return Ok(());
        };
        self.vault_meta.delete(
            wtxn,
            &pending_gate_consent_run_index_key(&state.run_id, &record.claim_id),
        )?;
        self.vault_meta.delete(
            wtxn,
            &pending_gate_consent_group_index_key(&state.group_key, &record.claim_id),
        )?;
        if let Some(semantic_claim_hash) = state.semantic_claim_hash.as_ref() {
            self.vault_meta.delete(
                wtxn,
                &pending_gate_consent_hash_index_key(semantic_claim_hash, &record.claim_id),
            )?;
        }
        self.vault_meta.delete(
            wtxn,
            &pending_gate_consent_index_state_key(&record.claim_id),
        )?;
        Ok(())
    }

    pub(crate) fn let_go_pending_gate_consent_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        claim_id: &EntityId,
        created_at: u64,
    ) -> Result<Option<GateDecisionRecord>> {
        self.close_pending_gate_consent_in_txn(
            wtxn,
            claim_id,
            created_at,
            "let_go",
            vec!["gate.pending.gap_decayed".to_owned()],
            None,
        )
    }

    /// Closes one pending gate consent with an explicit resolution outcome:
    /// appends a decision-ledger row derived from the original pending
    /// decision, then removes the tray row. `let_go` (lapse) and the OF-234
    /// inbox bundle verbs (`approved`/`rejected`) share this path so every
    /// resolution leaves a per-item receipt.
    pub(crate) fn close_pending_gate_consent_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        claim_id: &EntityId,
        created_at: u64,
        outcome: &str,
        reason_codes: Vec<String>,
        grant_ref: Option<String>,
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
        let original = decode_gate_decision(&value)?;
        if original.decision_id != pending.decision_id {
            return Err(Error::CorruptedIndex("pending gate consent"));
        }
        let record = GateDecisionRecord {
            version: GATE_DECISION_LEDGER_VERSION,
            decision_id: GateDecisionId::now(),
            created_at,
            outcome: outcome.to_owned(),
            reason_codes,
            receipt_reasons: Vec::new(),
            system_notices: Vec::new(),
            actor_class: original.actor_class,
            actor_ref: original.actor_ref,
            content_kind: original.content_kind,
            policy_manifest_version: original.policy_manifest_version,
            claim_id: Some(pending.claim_id),
            grant_ref,
            diff_handle: pending.diff_handle,
            read_frontier_hash: pending.read_frontier_hash,
            // A resolution is a NEW decision, born unredacted: never propagate
            // `original.redacted_at`.
            redacted_at: None,
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
            let claim_id = pending_gate_consent_claim_id_from_key(&key)?;
            let record = decode_pending_gate_consent(&value)?;
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

    /// Reads all pending consent rows stamped with one exact run id through
    /// the RCPT-1 run-scope sidecar.
    pub(crate) fn pending_gate_consents_for_run(
        &self,
        run_id: &str,
    ) -> Result<Vec<PendingGateConsentRecord>> {
        let rtxn = self.env.read_txn()?;
        let prefix = pending_gate_consent_run_index_prefix(run_id);
        self.pending_gate_consents_for_index_in_txn(
            &rtxn,
            &prefix,
            "pending gate consent run index",
            |state| state.run_id == run_id,
        )
    }

    /// Reads the raw-run rows behind one canonical Dreamer root group.  This
    /// alias is part of the same run-scope index family and lets an RS3 door
    /// use its root attempt hex without falling back to a table scan.
    pub(crate) fn pending_gate_consents_for_group_key(
        &self,
        group_key: &str,
    ) -> Result<Vec<PendingGateConsentRecord>> {
        let rtxn = self.env.read_txn()?;
        let prefix = pending_gate_consent_group_index_prefix(group_key);
        self.pending_gate_consents_for_index_in_txn(
            &rtxn,
            &prefix,
            "pending gate consent group index",
            |state| state.group_key == group_key,
        )
    }

    /// Reads every open pending row with the inbox's semantic claim hash.
    /// This is a subordinate sidecar of the pending-consent family: it keeps
    /// #386's cross-run duplicate collapse exact without reopening the whole
    /// pending table for an explicit group.
    pub(crate) fn pending_gate_consents_for_semantic_claim_hash(
        &self,
        semantic_claim_hash: &[u8; 32],
    ) -> Result<Vec<PendingGateConsentRecord>> {
        let rtxn = self.env.read_txn()?;
        let prefix = pending_gate_consent_hash_index_prefix(semantic_claim_hash);
        self.pending_gate_consents_for_index_in_txn(
            &rtxn,
            &prefix,
            "pending gate consent hash index",
            |state| state.semantic_claim_hash.as_ref() == Some(semantic_claim_hash),
        )
    }

    fn pending_gate_consents_for_index_in_txn<F>(
        &self,
        txn: &RoTxn<'_>,
        prefix: &[u8],
        index_name: &'static str,
        state_matches: F,
    ) -> Result<Vec<PendingGateConsentRecord>>
    where
        F: Fn(&PendingGateConsentIndexState) -> bool,
    {
        let mut records = Vec::new();
        for row in self.vault_meta.prefix_iter(txn, prefix)? {
            let (key, _) = row?;
            let claim_id = EntityId::from_bytes(index_suffix_id(&key, prefix, index_name)?)
                .map_err(|_| Error::CorruptedIndex(index_name))?;
            let Some(record) = self.pending_gate_consent_in_txn(txn, &claim_id)? else {
                return Err(Error::CorruptedIndex(index_name));
            };
            let state = self.pending_gate_consent_index_state_in_txn(txn, &record)?;
            let Some(state) = state else {
                return Err(Error::CorruptedIndex(index_name));
            };
            if !state_matches(&state) {
                return Err(Error::CorruptedIndex(index_name));
            }
            records.push(record);
        }
        sort_pending_gate_consents(&mut records);
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
        self.gate_decisions_page(None, limit)
    }

    pub(crate) fn gate_decisions_page(
        &self,
        before: Option<GateDecisionId>,
        limit: usize,
    ) -> Result<Vec<GateDecisionRecord>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let rtxn = self.env.read_txn()?;
        let upper = before.map_or_else(gate_decision_upper_bound, gate_decision_key);
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
            let decision_id = gate_decision_id_from_key(&key)?;
            let record = decode_gate_decision(&value)?;
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

    pub fn channel_identity_lifecycle_receipts(
        &self,
        limit: usize,
    ) -> Result<Vec<ChannelIdentityLifecycleReceiptRecord>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let rtxn = self.env.read_txn()?;
        let upper = channel_identity_lifecycle_upper_bound();
        let mut records = Vec::with_capacity(limit.min(RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT));
        for row in self.vault_meta.rev_range(
            &rtxn,
            &(
                std::ops::Bound::Included(CHANNEL_IDENTITY_LIFECYCLE_KEY_PREFIX),
                std::ops::Bound::Excluded(upper.as_slice()),
            ),
        )? {
            let (key, value) = row?;
            if !key.starts_with(CHANNEL_IDENTITY_LIFECYCLE_KEY_PREFIX) {
                break;
            }
            let receipt_id = channel_identity_lifecycle_id_from_key(&key)?;
            let record = decode_channel_identity_lifecycle_receipt(&value)?;
            if record.receipt_id != receipt_id {
                return Err(Error::CorruptedIndex(
                    "channel identity lifecycle ledger key mismatch",
                ));
            }
            records.push(record);
            if records.len() >= limit {
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
        if test_hooks::take_fail_next_retrieval_run_write(&self.owner._registered_path.path) {
            return Err(Error::InvariantViolation(
                "forced retrieval telemetry write failure",
            ));
        }
        if active_write_txn_depth() > 0 {
            return Err(Error::ConcurrentWrite(
                "retrieval telemetry skipped inside active write transaction",
            ));
        }

        let mut wtxn = self.env.write_txn()?;
        stage_retrieval_run_with_visibility(self, &mut wtxn, record, published)?;
        wtxn.commit()?;
        Ok(())
    }

    pub(crate) fn delete_retrieval_run(&self, run_id: RetrievalRunId) -> Result<()> {
        if active_write_txn_depth() > 0 {
            return Err(Error::ConcurrentWrite(
                "retrieval telemetry delete skipped inside active write transaction",
            ));
        }

        let mut wtxn = self.env.write_txn()?;
        stage_retrieval_run_delete(self, &mut wtxn, run_id)?;
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

        let mut wtxn = self.env.write_txn()?;
        stage_context_pack_retrieval_run_finalize(
            self,
            &mut wtxn,
            run_id,
            elapsed_us,
            claims_suppressed,
            surfaced_result_ids,
            empty_reason,
        )?;
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
        let rtxn = self.env.read_txn()?;
        read_retrieval_runs_in_txn(self, &rtxn, limit)
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
        let record = decode_retrieval_run(&value)?;
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
            let run_id = retrieval_run_id_from_fork_key(&key)?;
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
            let record = decode_retrieval_run(&value)?;
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
        decode_retrieval_blend_weight_table(&value)
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
            let run_id = retrieval_run_id_from_key(&key)?;
            if self
                .vault_meta
                .get(&rtxn, &retrieval_run_provisional_key(run_id))?
                .is_some()
            {
                continue;
            }
            let record = decode_retrieval_run(&value)?;
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

/// Reads the newest published retrieval-run rows from `target`, newest first.
///
/// `Store` reads base rows; a `SessionStoreView` reads overlay ∪ base, so an
/// in-room caller sees its own run rows and a base caller never does.
fn read_retrieval_runs_in_txn(
    target: &impl ManifestDbs,
    rtxn: &RoTxn<'_>,
    limit: usize,
) -> Result<Vec<RetrievalRunRecord>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let mut records = Vec::with_capacity(limit.min(RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT));
    let upper = retrieval_run_upper_bound();
    for row in target.vault_meta().rev_range(
        rtxn,
        &(
            std::ops::Bound::Included(RETRIEVAL_RUN_KEY_PREFIX),
            std::ops::Bound::Excluded(upper.as_slice()),
        ),
    )? {
        let (key, value) = row?;
        if !key.starts_with(RETRIEVAL_RUN_KEY_PREFIX) {
            break;
        }
        let run_id = retrieval_run_id_from_key(&key)?;
        if target
            .vault_meta()
            .get(rtxn, &retrieval_run_provisional_key(run_id))?
            .is_some()
        {
            continue;
        }
        let record = decode_retrieval_run(&value)?;
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

/// Stages one retrieval-run row and its provisional/fork-index side writes
/// into `target`'s `vault_meta` (ONE-1728 K11).
///
/// The base path is byte-identical because it IS this body: `Store`'s
/// `record_retrieval_run_with_visibility` opens the txn and calls here. A
/// session target passes its `SessionStoreView`, so an OffRecord run's row
/// stages into the overlay keyspace and evaporates at close — the base
/// telemetry ledger gains nothing (ARCH-0052 §7 / K10).
fn stage_retrieval_run_with_visibility(
    target: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    record: &RetrievalRunRecord,
    published: bool,
) -> Result<()> {
    let key = retrieval_run_key(record.run_id);
    let value = encode_retrieval_run(record)?;
    let provisional_key = retrieval_run_provisional_key(record.run_id);
    target.vault_meta().put(wtxn, &key, &value)?;
    if published {
        target.vault_meta().delete(wtxn, &provisional_key)?;
        if let Some(trace) = &record.trace {
            put_retrieval_trace_fork_index(
                target.vault_meta(),
                wtxn,
                &trace.fork_hash,
                record.run_id,
            )?;
        }
    } else {
        target.vault_meta().put(wtxn, &provisional_key, b"1")?;
    }
    Ok(())
}

/// Stages the deletion of one retrieval-run row, its provisional marker, its
/// outcome rows, and its trace fork indexes into `target`'s `vault_meta`.
fn stage_retrieval_run_delete(
    target: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    run_id: RetrievalRunId,
) -> Result<()> {
    let key = retrieval_run_key(run_id);
    let provisional_key = retrieval_run_provisional_key(run_id);
    let outcome_prefix = retrieval_outcome_run_prefix(run_id);
    delete_retrieval_trace_fork_indexes_for_run(target.vault_meta(), wtxn, &key, run_id)?;
    let mut outcome_keys = Vec::new();
    for row in target.vault_meta().prefix_iter(wtxn, &outcome_prefix)? {
        let (key, _) = row?;
        outcome_keys.push(key.to_vec());
    }
    for key in outcome_keys {
        target.vault_meta().delete(wtxn, &key)?;
    }
    target.vault_meta().delete(wtxn, &provisional_key)?;
    target.vault_meta().delete(wtxn, &key)?;
    Ok(())
}

/// Stages the finalize of one provisional context-pack retrieval-run row —
/// clearing the provisional marker — into `target`'s `vault_meta`.
///
/// A session run finalizes the SAME overlay row its registration created:
/// the row is looked up through the composed accessor, so the base finalizer
/// never sees it and this one never reaches a base row (ARCH-0052 §7).
fn stage_context_pack_retrieval_run_finalize(
    target: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    run_id: RetrievalRunId,
    elapsed_us: u64,
    claims_suppressed: usize,
    surfaced_result_ids: &[[u8; 16]],
    empty_reason: Option<String>,
) -> Result<()> {
    let key = retrieval_run_key(run_id);
    let provisional_key = retrieval_run_provisional_key(run_id);
    let Some(raw) = target.vault_meta().get(wtxn, &key)? else {
        target.vault_meta().delete(wtxn, &provisional_key)?;
        return Ok(());
    };
    let mut record = decode_retrieval_run(&raw)?;
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
    target.vault_meta().put(wtxn, &key, &value)?;
    if let Some(trace) = &record.trace {
        put_retrieval_trace_fork_index(target.vault_meta(), wtxn, &trace.fork_hash, record.run_id)?;
    }
    target.vault_meta().delete(wtxn, &provisional_key)?;
    Ok(())
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
    vault_meta: &OverlayDb,
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
    vault_meta: &OverlayDb,
    wtxn: &mut RwTxn<'_>,
    run_key: &[u8],
    run_id: RetrievalRunId,
) -> Result<()> {
    if let Some(raw) = vault_meta.get(wtxn, run_key)?
        && let Ok(record) = decode_retrieval_run(&raw)
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
    vault_meta: &OverlayDb,
    rtxn: &RoTxn<'_>,
    run_id: RetrievalRunId,
) -> Result<Vec<RetrievalOutcomeRecord>> {
    let prefix = retrieval_outcome_run_prefix(run_id);
    let mut records = Vec::new();
    for row in vault_meta.prefix_iter(rtxn, &prefix)? {
        let (key, value) = row?;
        let (key_run_id, key_outcome_key) = retrieval_outcome_parts_from_key(&key)?;
        if key_run_id != run_id {
            return Err(Error::CorruptedIndex("retrieval outcome telemetry"));
        }
        let record = decode_retrieval_outcome(&value)?;
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

/// Appends one WRITE-PATH gate decision plus its two index rows, addressed by
/// write target (ONE-1728 K5).
///
/// TIER SEPARATION IS THE POINT. Write-path decisions are receipts ABOUT the
/// content they judged, so a decision on session content stages into the
/// overlay and evaporates with the transcript it describes. The EGRESS tier is
/// categorically different — those decisions and REDACTION_AUDIT are floor
/// survivors and keep crossing to base through
/// [`crate::off_record::FloorWrites`], never through here.
///
/// The key/encode functions and both index side writes are shared verbatim, so
/// a session decision is byte-identical to the base row it would have been —
/// which is what makes promote a replay rather than a re-derivation.
fn append_gate_decision_row_in_txn(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    record: &GateDecisionRecord,
) -> Result<()> {
    // Decode accepts the redacted skeleton (ONE-1637); APPEND never mints
    // one. Redaction is an in-place rewrite owned by the erase coupling.
    if record.version != GATE_DECISION_LEDGER_VERSION || record.redacted_at.is_some() {
        return Err(Error::InvariantViolation("gate decision born redacted"));
    }
    vet_gate_decision_record(record)?;
    let key = gate_decision_key(record.decision_id);
    if store.vault_meta().get(wtxn, &key)?.is_some() {
        return Err(Error::InvariantViolation("gate decision id collision"));
    }
    let value = encode_gate_decision(record)?;
    store.vault_meta().put(wtxn, &key, &value)?;
    if let Some(grant_ref) = record.grant_ref.as_deref() {
        store.vault_meta().put(
            wtxn,
            &gate_decision_grant_ref_index_key(grant_ref, record.decision_id),
            b"1",
        )?;
    }
    if let Some(claim_id) = record.claim_id.as_ref() {
        store.vault_meta().put(
            wtxn,
            &gate_decision_claim_index_key(claim_id, record.decision_id),
            b"",
        )?;
    }
    Ok(())
}

fn gate_decision_key(decision_id: GateDecisionId) -> Vec<u8> {
    let mut key = Vec::with_capacity(GATE_DECISION_KEY_PREFIX.len() + 16);
    key.extend_from_slice(GATE_DECISION_KEY_PREFIX);
    key.extend_from_slice(&decision_id.as_bytes());
    key
}

fn pending_deletion_gate_decision_key(decision_id: GateDecisionId) -> Vec<u8> {
    let mut key = Vec::with_capacity(PENDING_DELETION_GATE_DECISION_KEY_PREFIX.len() + 16);
    key.extend_from_slice(PENDING_DELETION_GATE_DECISION_KEY_PREFIX);
    key.extend_from_slice(&decision_id.as_bytes());
    key
}

fn deletion_gate_required_key(decision_id: GateDecisionId) -> Vec<u8> {
    let mut key = Vec::with_capacity(DELETION_GATE_REQUIRED_KEY_PREFIX.len() + 16);
    key.extend_from_slice(DELETION_GATE_REQUIRED_KEY_PREFIX);
    key.extend_from_slice(&decision_id.as_bytes());
    key
}

fn outbound_gate_binding_key(attempt_id: &[u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(OUTBOUND_GATE_BINDING_KEY_PREFIX.len() + 16);
    key.extend_from_slice(OUTBOUND_GATE_BINDING_KEY_PREFIX);
    key.extend_from_slice(attempt_id);
    key
}

fn send_receipt_key(task_id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(SEND_RECEIPT_KEY_PREFIX.len() + 16);
    key.extend_from_slice(SEND_RECEIPT_KEY_PREFIX);
    key.extend_from_slice(task_id.as_bytes());
    key
}

fn send_receipt_task_id_from_key(key: &[u8]) -> Result<[u8; 16]> {
    key.strip_prefix(SEND_RECEIPT_KEY_PREFIX)
        .ok_or(Error::CorruptedIndex("send receipt ledger"))?
        .try_into()
        .map_err(|_| Error::CorruptedIndex("send receipt ledger"))
}

fn send_idempotency_key(actor_ref: &EntityId, idempotency_key: &str) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SEND_IDEMPOTENCY_HASH_DOMAIN);
    hasher.update(actor_ref.as_bytes());
    hasher.update(&(idempotency_key.len() as u64).to_be_bytes());
    hasher.update(idempotency_key.as_bytes());
    let hash = hasher.finalize();
    let mut key = Vec::with_capacity(SEND_IDEMPOTENCY_KEY_PREFIX.len() + hash.as_bytes().len());
    key.extend_from_slice(SEND_IDEMPOTENCY_KEY_PREFIX);
    key.extend_from_slice(hash.as_bytes());
    key
}

fn send_idempotency_value(task_ref: &EntityId) -> [u8; 17] {
    let mut value = [0_u8; 17];
    value[0] = SEND_IDEMPOTENCY_INDEX_VERSION;
    value[1..].copy_from_slice(task_ref.as_bytes());
    value
}

fn send_idempotency_task_ref_from_value(value: &[u8]) -> Result<EntityId> {
    if value.len() != 17 || value[0] != SEND_IDEMPOTENCY_INDEX_VERSION {
        return Err(Error::CorruptedIndex("send idempotency index"));
    }
    EntityId::from_bytes(
        value[1..]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("send idempotency index"))?,
    )
    .map_err(|_| Error::CorruptedIndex("send idempotency index"))
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

fn string_index_prefix(prefix: &[u8], value: &str) -> Vec<u8> {
    let value = value.as_bytes();
    let mut key = Vec::with_capacity(prefix.len() + std::mem::size_of::<u64>() + value.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(&(value.len() as u64).to_be_bytes());
    key.extend_from_slice(value);
    key
}

fn index_key_with_id(prefix: &[u8], id: &[u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + id.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(id);
    key
}

fn index_suffix_id(key: &[u8], prefix: &[u8], index_name: &'static str) -> Result<[u8; 16]> {
    key.strip_prefix(prefix)
        .ok_or(Error::CorruptedIndex(index_name))?
        .try_into()
        .map_err(|_| Error::CorruptedIndex(index_name))
}

fn gate_decision_grant_ref_index_prefix(grant_ref: &str) -> Vec<u8> {
    string_index_prefix(GATE_DECISION_GRANT_REF_INDEX_PREFIX, grant_ref)
}

fn gate_decision_grant_ref_index_key(grant_ref: &str, decision_id: GateDecisionId) -> Vec<u8> {
    index_key_with_id(
        &gate_decision_grant_ref_index_prefix(grant_ref),
        &decision_id.as_bytes(),
    )
}

/// Both key components are fixed 16-byte ids, so the index needs no
/// `string_index_prefix` length header to stay unambiguous.
fn gate_decision_claim_index_prefix(claim_id: &[u8; 16]) -> Vec<u8> {
    index_key_with_id(GATE_DECISION_CLAIM_INDEX_PREFIX, claim_id)
}

fn gate_decision_claim_index_key(claim_id: &[u8; 16], decision_id: GateDecisionId) -> Vec<u8> {
    index_key_with_id(
        &gate_decision_claim_index_prefix(claim_id),
        &decision_id.as_bytes(),
    )
}

fn pending_gate_consent_run_index_prefix(run_id: &str) -> Vec<u8> {
    string_index_prefix(PENDING_GATE_CONSENT_RUN_INDEX_PREFIX, run_id)
}

fn pending_gate_consent_run_index_key(run_id: &str, claim_id: &[u8; 16]) -> Vec<u8> {
    index_key_with_id(&pending_gate_consent_run_index_prefix(run_id), claim_id)
}

fn pending_gate_consent_group_index_prefix(group_key: &str) -> Vec<u8> {
    string_index_prefix(PENDING_GATE_CONSENT_GROUP_INDEX_PREFIX, group_key)
}

fn pending_gate_consent_group_index_key(group_key: &str, claim_id: &[u8; 16]) -> Vec<u8> {
    index_key_with_id(
        &pending_gate_consent_group_index_prefix(group_key),
        claim_id,
    )
}

fn pending_gate_consent_hash_index_prefix(semantic_claim_hash: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(PENDING_GATE_CONSENT_HASH_INDEX_PREFIX.len() + 32);
    key.extend_from_slice(PENDING_GATE_CONSENT_HASH_INDEX_PREFIX);
    key.extend_from_slice(semantic_claim_hash);
    key
}

fn pending_gate_consent_hash_index_key(
    semantic_claim_hash: &[u8; 32],
    claim_id: &[u8; 16],
) -> Vec<u8> {
    index_key_with_id(
        &pending_gate_consent_hash_index_prefix(semantic_claim_hash),
        claim_id,
    )
}

fn pending_gate_consent_index_state_key(claim_id: &[u8; 16]) -> Vec<u8> {
    index_key_with_id(PENDING_GATE_CONSENT_INDEX_STATE_PREFIX, claim_id)
}

fn attempt_run_index_prefix(run_id: &str) -> Vec<u8> {
    string_index_prefix(ATTEMPT_RUN_INDEX_PREFIX, run_id)
}

fn attempt_run_index_key(run_id: &str, attempt_id: &[u8; 16]) -> Vec<u8> {
    index_key_with_id(&attempt_run_index_prefix(run_id), attempt_id)
}

fn sort_pending_gate_consents(records: &mut [PendingGateConsentRecord]) {
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
}

fn channel_identity_lifecycle_key(receipt_id: ChannelIdentityLifecycleReceiptId) -> Vec<u8> {
    let mut key = Vec::with_capacity(CHANNEL_IDENTITY_LIFECYCLE_KEY_PREFIX.len() + 16);
    key.extend_from_slice(CHANNEL_IDENTITY_LIFECYCLE_KEY_PREFIX);
    key.extend_from_slice(&receipt_id.as_bytes());
    key
}

fn channel_identity_lifecycle_id_from_key(key: &[u8]) -> Result<ChannelIdentityLifecycleReceiptId> {
    let bytes = key
        .strip_prefix(CHANNEL_IDENTITY_LIFECYCLE_KEY_PREFIX)
        .ok_or(Error::CorruptedIndex("channel identity lifecycle ledger"))?;
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| Error::CorruptedIndex("channel identity lifecycle ledger"))?;
    Ok(ChannelIdentityLifecycleReceiptId { bytes })
}

fn channel_identity_lifecycle_upper_bound() -> Vec<u8> {
    let mut key = Vec::from(CHANNEL_IDENTITY_LIFECYCLE_KEY_PREFIX);
    let last = key
        .last_mut()
        .expect("channel identity lifecycle key prefix must be non-empty");
    *last = last
        .checked_add(1)
        .expect("channel identity lifecycle key prefix upper bound must not overflow");
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

#[cfg_attr(not(feature = "sync"), allow(dead_code))]
fn encode_pending_deletion_gate_decision(
    record: &PendingDeletionGateDecisionRecord,
) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvariantViolation("pending deletion gate decision encode failed"))
}

#[cfg_attr(not(feature = "sync"), allow(dead_code))]
fn decode_pending_deletion_gate_decision(raw: &[u8]) -> Result<PendingDeletionGateDecisionRecord> {
    let record: PendingDeletionGateDecisionRecord = rmp_serde::from_slice(raw)
        .map_err(|_| Error::CorruptedIndex("pending deletion gate decision"))?;
    vet_pending_deletion_gate_decision_record(&record)?;
    Ok(record)
}

fn encode_deletion_gate_required(target: &[u8; 16], tombstone_reason: u8) -> [u8; 18] {
    let mut value = [0_u8; 18];
    value[0] = PENDING_DELETION_GATE_DECISION_VERSION;
    value[1] = tombstone_reason;
    value[2..].copy_from_slice(target);
    value
}

fn decode_deletion_gate_required(raw: &[u8]) -> Result<([u8; 16], u8)> {
    let raw: [u8; 18] = raw
        .try_into()
        .map_err(|_| Error::CorruptedIndex("deletion gate required marker"))?;
    if raw[0] != PENDING_DELETION_GATE_DECISION_VERSION || !matches!(raw[1], 1..=4) {
        return Err(Error::CorruptedIndex("deletion gate required marker"));
    }
    let mut target = [0_u8; 16];
    target.copy_from_slice(&raw[2..]);
    Ok((target, raw[1]))
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

fn encode_pending_gate_consent_index_state(
    state: &PendingGateConsentIndexState,
) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(state)
        .map_err(|_| Error::InvariantViolation("pending gate consent index state encode failed"))
}

fn decode_pending_gate_consent_index_state(raw: &[u8]) -> Result<PendingGateConsentIndexState> {
    let state: PendingGateConsentIndexState = rmp_serde::from_slice(raw)
        .map_err(|_| Error::CorruptedIndex("pending gate consent index state"))?;
    if state.version != PENDING_GATE_CONSENT_INDEX_STATE_VERSION
        || state.run_id.trim().is_empty()
        || state.group_key.trim().is_empty()
    {
        return Err(Error::CorruptedIndex("pending gate consent index state"));
    }
    Ok(state)
}

fn encode_channel_identity_lifecycle_receipt(
    record: &ChannelIdentityLifecycleReceiptRecord,
) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvariantViolation("channel identity lifecycle ledger encode failed"))
}

fn decode_channel_identity_lifecycle_receipt(
    raw: &[u8],
) -> Result<ChannelIdentityLifecycleReceiptRecord> {
    let record: ChannelIdentityLifecycleReceiptRecord = rmp_serde::from_slice(raw)
        .map_err(|_| Error::CorruptedIndex("channel identity lifecycle ledger"))?;
    vet_channel_identity_lifecycle_receipt_record(&record)?;
    Ok(record)
}

/// Version-dispatched ledger vet. Version 0 is the live row shape; version 1 is
/// the retention skeleton left behind by an in-place redaction (ONE-1638), whose
/// claim-bearing fields are required to be scrubbed. Only version 0 may be
/// APPENDED — decode accepts both.
///
/// ASYMMETRY, DELIBERATE: `actor_class` is required non-empty on the version-1
/// skeleton ONLY, though E-A's D1 table lists it non-empty for both columns.
/// The v0 exemption is load-bearing, not an oversight:
///
/// * On v0 the field is caller-asserted, attacker-influenced input. The
///   external-effect door records the class the caller SENT
///   (`record_external_effect_policy`), and `evaluate_gate` answers an empty
///   one with `DenyMissingActorClass` — a recorded, auditable denial. Vetting
///   it here would turn that fail-closed deny into
///   `CorruptedIndex("gate decision ledger")`, i.e. let any caller abort the
///   write txn (and, once a denial row is on disk, poison every later ledger
///   scan) with an empty string. Recording what was actually asserted is the
///   point of a decision ledger; the deny is the enforcement.
/// * On v1 the field is ours. A skeleton is minted only by the erase coupling,
///   from an already-vetted row, and `actor_class` is one of the few
///   accountability fields the retention design keeps. Empty there means the
///   redactor scrubbed something it must have retained — a real invariant
///   break, correctly fatal.
///
/// `diff_handle` on the v1 skeleton must be EMPTY. This TIGHTENS E-A's D1
/// table, which read "≤ `GATE_DIFF_HANDLE_MAX_LEN`, empty ALLOWED" and left the
/// sentinel bytes to E-B (open question 4). A length cap alone cannot tell a
/// fixed sentinel from a live handle, and the handle is a content binding — a
/// pointer at the very body the redaction exists to scrub — so "empty allowed"
/// let a redacted row keep one. Empty is the only self-evidently scrubbed
/// value. E-B may still mint a sentinel, but only by pinning its bytes in a vet
/// amendment here, which makes the sentinel checkable rather than assumed.
///
/// Pinned by `record_schema_v0_bytes_stable_and_v1_skeleton_vets` (empty-class
/// v1 rejected, empty-class v0 accepted),
/// `redacted_skeleton_must_not_retain_a_diff_handle`, and
/// `gate::tests::effect_actor_class_spoof_fails_closed` (the deny path stays a
/// deny). Tightening v0's `actor_class` is an E-B vet amendment, and needs the
/// effect door to stop recording caller-asserted classes verbatim first.
fn vet_gate_decision_record(record: &GateDecisionRecord) -> Result<()> {
    let shared_ok = !record.outcome.is_empty()
        && !record.content_kind.is_empty()
        && !record.policy_manifest_version.is_empty()
        && record.diff_handle.len() <= GATE_DIFF_HANDLE_MAX_LEN;
    let version_ok = match record.version {
        GATE_DECISION_LEDGER_VERSION => {
            record.redacted_at.is_none()
                && !record.reason_codes.is_empty()
                && record
                    .grant_ref
                    .as_deref()
                    .is_none_or(|grant_ref| !grant_ref.trim().is_empty())
                && !record.diff_handle.is_empty()
                && record
                    .reason_codes
                    .iter()
                    .all(|reason| reason.starts_with("gate."))
                && record
                    .receipt_reasons
                    .iter()
                    .all(|reason| valid_gate_receipt_reason(reason))
                && record
                    .system_notices
                    .iter()
                    .all(valid_gate_system_notice_record)
        }
        // The skeleton keeps only the accountability fields the retention
        // design retains; everything claim-bearing must already be gone.
        // `actor_class` is required here and NOT on v0 — see the asymmetry
        // note above. `diff_handle` must be EMPTY, not merely bounded — see the
        // handle note above.
        GATE_DECISION_LEDGER_VERSION_REDACTED => {
            record.redacted_at.is_some_and(|at| at > 0)
                && !record.actor_class.is_empty()
                && record.reason_codes.is_empty()
                && record.receipt_reasons.is_empty()
                && record.system_notices.is_empty()
                && record.actor_ref.is_none()
                && record.grant_ref.is_none()
                && record.diff_handle.is_empty()
        }
        _ => false,
    };
    if !shared_ok || !version_ok {
        return Err(Error::CorruptedIndex("gate decision ledger"));
    }
    Ok(())
}

#[cfg_attr(not(feature = "sync"), allow(dead_code))]
fn vet_pending_deletion_gate_decision_record(
    record: &PendingDeletionGateDecisionRecord,
) -> Result<()> {
    if record.version != PENDING_DELETION_GATE_DECISION_VERSION
        || !matches!(record.tombstone_reason, 1..=4)
        || record.decision.content_kind != "deletion"
    {
        return Err(Error::CorruptedIndex("pending deletion gate decision"));
    }
    vet_gate_decision_record(&record.decision)
}

/// `redacted_at` is deliberately uncompared: both sides of a recovery match are
/// freshly built and therefore born unredacted (ONE-1637).
fn gate_decision_matches_pending_candidate(
    record: &GateDecisionRecord,
    expected: &GateDecisionRecord,
) -> bool {
    record.outcome == expected.outcome
        && record.reason_codes == expected.reason_codes
        && record.receipt_reasons == expected.receipt_reasons
        && record.system_notices == expected.system_notices
        && record.actor_class == expected.actor_class
        && record.actor_ref == expected.actor_ref
        && record.content_kind == expected.content_kind
        && record.policy_manifest_version == expected.policy_manifest_version
        && record.claim_id == expected.claim_id
        && record.grant_ref == expected.grant_ref
        && record.diff_handle == expected.diff_handle
        && record.read_frontier_hash == expected.read_frontier_hash
}

fn valid_gate_system_notice_record(notice: &GateSystemNoticeRecord) -> bool {
    valid_gate_notice_token(&notice.notice_type, 64)
        && !notice.channel.trim().is_empty()
        && notice.channel.len() <= 64
        && valid_gate_notice_token(&notice.voice, 32)
        && valid_gate_notice_token(&notice.audience, 32)
        && !notice.body.trim().is_empty()
        && notice.body.len() <= 1024
        && notice.row_ref.as_deref().is_none_or(|row_ref| {
            !row_ref.trim().is_empty() && row_ref.len() <= GATE_SYSTEM_NOTICE_ROW_REF_MAX_LEN
        })
        && notice.setting_change_offer.as_ref().is_none_or(|offer| {
            !offer.label.trim().is_empty()
                && offer.label.len() <= 128
                && !offer.target.trim().is_empty()
                && offer.target.len() <= 512
        })
}

fn valid_gate_notice_token(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_gate_receipt_reason(reason: &str) -> bool {
    // Accepted receipt-reason prefix FAMILIES (everything else is rejected):
    // counterparty_* (OF-347 contact/consent), connector_key_* and
    // effector_budget_* (OF-277 GOV-01 status wall / budget exhaustion),
    // charter_* (GOV-10 drift / never-list). The charset and length rules
    // below apply to every family.
    !reason.is_empty()
        && reason.len() <= GATE_RECEIPT_REASON_MAX_LEN
        && (reason.starts_with("counterparty_")
            || reason.starts_with("connector_key_")
            || reason.starts_with("effector_budget_")
            || reason.starts_with("charter_"))
        && reason
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
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

fn vet_channel_identity_lifecycle_receipt_record(
    record: &ChannelIdentityLifecycleReceiptRecord,
) -> Result<()> {
    if record.version != CHANNEL_IDENTITY_LIFECYCLE_LEDGER_VERSION
        || record.identity_id == [0; 16]
        || record.actor_class.trim().is_empty()
        || record.verb.trim().is_empty()
        || record.intent_kind.trim().is_empty()
        || record.outcome.trim().is_empty()
        || record.channel.trim().is_empty()
        || record.address_or_handle.trim().is_empty()
        || record.state.trim().is_empty()
        || record.owner_visible_state.trim().is_empty()
    {
        return Err(Error::CorruptedIndex("channel identity lifecycle ledger"));
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
    vault_meta: &OverlayDb,
) -> Result<HashMap<u8, StructuralKindRegistration>> {
    let rtxn = env.read_txn()?;
    let mut registry = HashMap::new();
    let mut prefixes = HashSet::new();
    for row in vault_meta.prefix_iter(&rtxn, STRUCTURAL_KIND_REGISTRY_KEY_PREFIX)? {
        let (key, value) = row?;
        let registration = decode_structural_kind_registration(&key, &value)?;
        vet_structural_kind_registration_shape(&registration)
            .map_err(|_| Error::CorruptedIndex("structural kind registry"))?;
        vet_structural_kind_registration_band(&registration)
            .map_err(|_| Error::CorruptedIndex("structural kind registry"))?;
        if entity_type_registry_entry(registration.type_byte).is_some()
            || static_short_id_prefix_collision(&registration.short_id_prefix)
        {
            if is_compatible_legacy_companion_register_row(&registration) {
                continue;
            }
            if is_post_dynamic_static_collision(&registration) {
                // Forward-compat, not corruption (OF-368 ARTL-1 review): the
                // row was written while its byte/prefix was legitimately
                // dynamically registrable and a LATER engine release claimed
                // it statically. The static definition wins for the byte;
                // the persisted row stays in vault_meta untouched, and its
                // prefix stays reserved here so no new dynamic pack can mint
                // short ids colliding with rows already written under it.
                prefixes.insert(registration.short_id_prefix.clone());
                continue;
            }
            return Err(Error::CorruptedIndex("structural kind registry"));
        }
        if !prefixes.insert(registration.short_id_prefix.clone())
            || registry
                .insert(registration.type_byte, registration)
                .is_some()
        {
            return Err(Error::CorruptedIndex("structural kind registry"));
        }
    }
    Ok(registry)
}

/// Static kinds whose type byte (and short-id prefix) were claimed by a
/// release AFTER older releases already accepted arbitrary dynamic
/// registrations of them. A persisted dynamic row colliding with one of
/// these is legacy data from that window — tolerated at load, never
/// corruption. COMPANION_REGISTER is deliberately NOT in this set: its
/// static claim shipped together with dynamic registration itself, so only
/// its own exact legacy shape (handled separately above) can exist
/// legitimately and anything else at byte 64 stays fail-closed.
const POST_DYNAMIC_STATIC_KIND_BYTES: &[u8] = &[crate::registry::ENTITY_TYPE_BLOB_ARTIFACT];

fn is_post_dynamic_static_collision(registration: &StructuralKindRegistration) -> bool {
    POST_DYNAMIC_STATIC_KIND_BYTES.contains(&registration.type_byte)
        || POST_DYNAMIC_STATIC_KIND_BYTES.iter().any(|byte| {
            entity_type_registry_entry(*byte).and_then(|entry| entry.short_id_prefix)
                == Some(registration.short_id_prefix.as_str())
        })
}

fn is_compatible_legacy_companion_register_row(registration: &StructuralKindRegistration) -> bool {
    registration.type_byte == ENTITY_TYPE_COMPANION_REGISTER
        && registration.short_id_prefix == COMPANION_REGISTER_SHORT_ID_PREFIX
        && registration.band == TypeByteBand::Companion
        && registration.pack == COMPANION_REGISTER_PACK_ID
}

fn vault_meta_has_structural_kind_prefix(
    vault_meta: &OverlayDb,
    txn: &RwTxn<'_>,
    short_id_prefix: &str,
) -> Result<bool> {
    for row in vault_meta.prefix_iter(txn, STRUCTURAL_KIND_REGISTRY_KEY_PREFIX)? {
        let (key, value) = row?;
        let registration = decode_structural_kind_registration(&key, &value)?;
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
    vault_meta: &OverlayDb,
    wtxn: &mut RwTxn<'_>,
    new_vault: bool,
    storage_abi_version: u16,
) -> Result<()> {
    let stored_abi = read_vault_meta_u16(
        vault_meta,
        &*wtxn,
        STORAGE_ABI_VERSION_KEY,
        "storage ABI version",
    )?;
    if gate_storage_abi_value(stored_abi, storage_abi_version, new_vault)? {
        vault_meta.put(
            wtxn,
            STORAGE_ABI_VERSION_KEY,
            &storage_abi_version.to_le_bytes(),
        )?;
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

/// Applies the strict-equality storage-ABI handshake used by every
/// [`Store::open`] call. `Ok(true)` means a genuinely new vault must stamp the
/// current version; every existing-vault mismatch fails closed in both
/// directions, including a prior-version reader opening a newer vault.
fn gate_storage_abi_value(stored: Option<u16>, current: u16, new_vault: bool) -> Result<bool> {
    match stored {
        Some(stored) if stored == current => Ok(false),
        Some(stored) => Err(Error::StorageAbiVersionChanged {
            stored: Some(stored),
            current,
        }),
        None if new_vault => Ok(true),
        None => Err(Error::StorageAbiVersionChanged {
            stored: None,
            current,
        }),
    }
}

pub(crate) fn read_vault_meta_u16(
    vault_meta: &OverlayDb,
    txn: &heed::RoTxn<'_>,
    key: &[u8],
    context: &'static str,
) -> Result<Option<u16>> {
    let Some(raw) = vault_meta.get(txn, key)? else {
        return Ok(None);
    };
    let bytes: [u8; 2] = raw
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex(context))?;
    Ok(Some(u16::from_le_bytes(bytes)))
}

fn preflight_embedding_model(
    env: &Env,
    hnsw_meta: &OverlayDb,
    vectors: &OverlayDb,
    hnsw_neighbors: &OverlayDb,
    requested: Option<&str>,
) -> Result<bool> {
    let rtxn = env.read_txn()?;
    match hnsw_meta.get(&rtxn, MODEL_ID_KEY)? {
        Some(raw) => {
            let stored = parse_utf8_bytes(&raw)?;
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
    hnsw_meta: &OverlayDb,
    vectors: &OverlayDb,
    hnsw_neighbors: &OverlayDb,
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
    hnsw_meta: &OverlayDb,
    vectors: &OverlayDb,
    hnsw_neighbors: &OverlayDb,
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
    hnsw_meta: &OverlayDb,
    vectors: &OverlayDb,
    hnsw_neighbors: &OverlayDb,
    requested: &str,
) -> Result<()> {
    let mut wtxn = env.write_txn()?;
    match hnsw_meta.get(&wtxn, MODEL_ID_KEY)? {
        Some(raw) => {
            let stored = parse_utf8_bytes(&raw)?;
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
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    requested: Option<&str>,
) -> Result<()> {
    let requested = requested.ok_or_else(|| {
        Error::InvalidConfig(ERR_VECTOR_WRITE_REQUIRES_EMBEDDING_MODEL.to_owned())
    })?;
    match store.hnsw_meta().get(&*wtxn, MODEL_ID_KEY)? {
        Some(raw) => {
            let stored = parse_utf8_bytes(&raw)?;
            if stored != requested {
                return Err(Error::EmbeddingModelChanged {
                    stored,
                    requested: requested.to_owned(),
                });
            }
        }
        None => {
            if has_persisted_vector_or_hnsw_data(
                store.hnsw_meta(),
                store.vectors(),
                store.hnsw_neighbors(),
                &*wtxn,
            )? {
                return Err(Error::InvalidConfig(
                    ERR_POPULATED_MISSING_MODEL_ID.to_owned(),
                ));
            }
            store
                .hnsw_meta()
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
    encoded[27..29].copy_from_slice(&config.fast_dims.unwrap_or(0).to_le_bytes());
    Ok(encoded)
}

pub(crate) fn read_hnsw_compatibility(
    hnsw_meta: &OverlayDb,
    txn: &heed::RoTxn<'_>,
) -> Result<HnswCompatibilityState> {
    let Some(raw) = hnsw_meta.get(txn, HNSW_CONFIG_KEY)? else {
        return Ok(HnswCompatibilityState::Missing);
    };

    match raw.len() {
        HNSW_COMPATIBILITY_LEN => {
            decode_hnsw_compatibility(&raw).map(HnswCompatibilityState::Current)
        }
        // v2 records decode as CURRENT with `fast_dims: None`, never Legacy:
        // `preflight_hnsw_config` hard-errors Legacy on populated vaults, so
        // classifying v2 as legacy would brick every existing populated
        // vault. A v2 vault opens under `fast_dims: None` (struct equality
        // holds) and correctly fails `HnswConfigChanged` under `Some(_)`.
        HNSW_COMPATIBILITY_V2_LEN => {
            decode_v2_hnsw_compatibility(&raw).map(HnswCompatibilityState::Current)
        }
        HNSW_COMPATIBILITY_V1_LEN | HNSW_COMPATIBILITY_V0_LEN => {
            decode_legacy_hnsw_compatibility(&raw).map(HnswCompatibilityState::Legacy)
        }
        _ => Err(Error::InvalidKey),
    }
}

fn decode_hnsw_compatibility(raw: &[u8]) -> Result<PersistedHnswCompatibility> {
    if raw.len() != HNSW_COMPATIBILITY_LEN || raw[0] != HNSW_COMPATIBILITY_VERSION {
        return Err(Error::InvalidKey);
    }

    let decoded = decode_hnsw_compatibility_common_fields(raw)?;
    let fast_dims_raw = u16::from_le_bytes(raw[27..29].try_into().map_err(|_| Error::InvalidKey)?);
    Ok(PersistedHnswCompatibility {
        fast_dims: (fast_dims_raw != 0).then_some(fast_dims_raw),
        ..decoded
    })
}

fn decode_v2_hnsw_compatibility(raw: &[u8]) -> Result<PersistedHnswCompatibility> {
    if raw.len() != HNSW_COMPATIBILITY_V2_LEN || raw[0] != HNSW_COMPATIBILITY_V2_VERSION {
        return Err(Error::InvalidKey);
    }
    decode_hnsw_compatibility_common_fields(raw)
}

/// Decodes the shared v2/v3 field layout (bytes 0..27); `fast_dims` comes
/// back `None` and v3's decoder overlays it from bytes 27..29.
fn decode_hnsw_compatibility_common_fields(raw: &[u8]) -> Result<PersistedHnswCompatibility> {
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
        fast_dims: None,
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
    // Legacy (v0/v1) records predate the metric/structure tags AND
    // fast_dims; both stay "missing"/None below.

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
        fast_dims: None,
    })
}

fn format_hnsw_compatibility(config: &PersistedHnswCompatibility) -> String {
    format!(
        "dimensions={},m_max_0={},ef_construction={},distance_metric={},index_structure={},fast_dims={}",
        config.dimensions,
        config.m_max_0,
        config.ef_construction,
        format_hnsw_distance_metric(config.distance_metric),
        format_hnsw_index_structure(config.index_structure),
        match config.fast_dims {
            None => "none".to_owned(),
            Some(fd) => fd.to_string(),
        }
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
    hnsw_meta: &OverlayDb,
    vectors: &OverlayDb,
    hnsw_neighbors: &OverlayDb,
    txn: &heed::RoTxn<'_>,
) -> Result<bool> {
    Ok(database_has_entries(vectors, txn)?
        || database_has_entries(hnsw_neighbors, txn)?
        || crate::hnsw::has_population(hnsw_meta, txn)?)
}

fn database_has_entries(db: &OverlayDb, txn: &heed::RoTxn<'_>) -> Result<bool> {
    Ok(db.iter(txn)?.next().transpose()?.is_some())
}

fn migrate_temporal_long_intervals_if_needed(
    env: &Env,
    hnsw_meta: &OverlayDb,
    temporal_long_intervals: &OverlayDb,
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
                let old_key = key.as_ref().try_into().map_err(|_| Error::InvalidKey)?;
                let old_value = value.as_ref().try_into().map_err(|_| Error::InvalidKey)?;
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
mod tests;

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
