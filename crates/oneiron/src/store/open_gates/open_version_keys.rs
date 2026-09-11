//! Version stamps, vault-meta key consts, HNSW layout consts, error strings, process locks, DB manifest, and migration-plan/compat types.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex};

use crate::config::VaultConfig;

use super::vault_root_bind::VaultRootIdentity;

pub const MAX_DBS: u32 = 32;

/// v17 (ONE-1754, ARCH-0058): the owner-ratified BYTE-SPACE REDESIGN v3
/// persisted type-byte re-key. Every system/maintenance kind moved down into
/// the 64–99 system zone and the compiled-product kinds moved up into
/// 100–125, so byte 0 of every affected `entities` envelope, the `type_index`
/// keys, the `sid_counter:` keys, and the structural-kind registry records all
/// carry different bytes than a v16 vault does. This is the ONE ABI step with
/// a sanctioned migration branch rather than a plain fail-closed rebuild — see
/// `rekey_type_bytes_v3_in_txn` — because the strict-equality gate would
/// otherwise refuse every pre-1754 vault before the re-key could run.
///
/// v16 (ONE-1732, ARCH-0052 P7): the off-record fence families were removed
/// from the vault contract. Off-record state is session-ephemeral — it lives
/// in a process-local overlay and reaches no named database or `vault_meta`
/// row — so the durable fence rows v11 introduced, and the open/recovery
/// semantics that read them, no longer exist. A v15 vault may still carry
/// those rows, and this engine has no code that understands them, so v15
/// vaults fail closed at the ABI gate — there is no migration pass; rebuild
/// the vault.
///
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
/// `PENDING_GATE_CONSENT_VERSION`,
/// `PENDING_GATE_CONSENT_INDEX_STATE_VERSION`, or
/// `RECEIPT_FAMILY_INDEX_VERSION` requires bumping this version too.
pub const STORAGE_ABI_VERSION: u16 = 17;

pub(crate) const STORAGE_ABI_VERSION_KEY: &[u8] = b"storage_abi_version";

/// The single stamp the byte-space v3 migration branch accepts besides the
/// current one — derived from [`STORAGE_ABI_VERSION`], never written as a
/// historical literal.
pub(in crate::store) const STORAGE_ABI_VERSION_V3_REKEY_PREDECESSOR: u16 = STORAGE_ABI_VERSION - 1;

const _: () = assert!(
    STORAGE_ABI_VERSION == 17,
    "ABI bumped past ONE-1754: delete the byte-space v3 migration branch \
     (rekey_type_bytes_v3_in_txn, StorageAbiGate::RekeyByteSpaceV3, and \
     STORAGE_ABI_VERSION_V3_REKEY_PREDECESSOR) instead of letting it accept a \
     new predecessor stamp."
);

pub const STORAGE_SCHEMA_VERSION: u16 = 1;

pub(crate) const STORAGE_SCHEMA_VERSION_KEY: &[u8] = b"schema_version";

/// Version of the pinned DB-manifest shape surfaced in whole-vault exports.
pub const DB_MANIFEST_VERSION: u16 = 2;

pub(crate) const MODEL_ID_KEY: &[u8] = b"model_id";

pub(crate) const GRAPH_VERSION_KEY: &[u8] = b"graph_version";

pub(crate) const HNSW_CONFIG_KEY: &[u8] = b"hnsw_config";

pub(crate) const TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY: &[u8] =
    b"temporal_long_intervals_schema_version";

pub(super) const TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION: u8 = 2;

pub(crate) const VECTOR_VERSION_KEY: &[u8] = b"vector_version";

pub(crate) const EMBEDDING_MODEL_EPOCH_KEY: &[u8] = b"embedding_model_epoch";

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

pub(super) static OPEN_STORE_PATHS: LazyLock<Mutex<HashMap<PathBuf, Option<VaultRootIdentity>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(in crate::store) const RECEIPT_FAMILY_INDEX_VERSION_KEY: &[u8] =
    b"receipt_family_index:v1:version";

/// Receipt-family ABI-pin rule: changing this requires a
/// [`STORAGE_ABI_VERSION`] bump.
pub(in crate::store) const RECEIPT_FAMILY_INDEX_VERSION: u8 = 1;

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
    Legacy(PersistedHnswCompatibility),
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
