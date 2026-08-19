//! `Store::open` and the fail-closed open-time gate sequence: vault-root
//! preflight, DB-manifest create/validate, storage ABI/schema gates, HNSW
//! config and embedding-model gates, and open-time migrations. The exact
//! gate order is documented on [`crate::store`].

use std::collections::{HashMap, HashSet};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::str;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, RwLock};

use heed::types::{Bytes, Str};
use heed::{Database, DatabaseFlags, Env, EnvOpenOptions, RoTxn, RwTxn};

use crate::config::VaultConfig;
use crate::error::{Error, Result, VaultRootEntry, VaultRootProblem};
use crate::off_record::OffRecordSessionRegistry;
use crate::overlay_db::{OverlayDb, OverlayStrDb};

use super::*;

// Contract-pinned at 32 by ARCH-0019/ARCH-0031: 28 named DBs plus headroom.
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
/// `PENDING_GATE_CONSENT_INDEX_STATE_VERSION`, or
/// `RECEIPT_FAMILY_INDEX_VERSION` requires bumping this version too.
pub const STORAGE_ABI_VERSION: u16 = 17;

pub(crate) const STORAGE_ABI_VERSION_KEY: &[u8] = b"storage_abi_version";

/// The single stamp the byte-space v3 migration branch accepts besides the
/// current one — derived from [`STORAGE_ABI_VERSION`], never written as a
/// historical literal.
pub(crate) const STORAGE_ABI_VERSION_V3_REKEY_PREDECESSOR: u16 = STORAGE_ABI_VERSION - 1;

// TRIPWIRE, not a wall. The accept-the-predecessor branch is ONE-1754-scoped:
// it exists so a v16 vault can be re-keyed to v17 in place. If a later ticket
// bumps the ABI again, the derived predecessor would silently slide to the new
// N-1 and re-run a re-key that has already been applied. Breaking the build
// here forces that author to DELETE the migration branch (and this assert)
// rather than inherit a stale one.
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

const TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION: u8 = 2;

pub(crate) const VECTOR_VERSION_KEY: &[u8] = b"vector_version";

pub(crate) const EMBEDDING_MODEL_EPOCH_KEY: &[u8] = b"embedding_model_epoch";

pub(super) const HNSW_COMPATIBILITY_VERSION: u8 = 3;

const HNSW_COMPATIBILITY_V0_LEN: usize = 24;

const HNSW_COMPATIBILITY_V1_LEN: usize = 25;

pub(super) const HNSW_COMPATIBILITY_V2_LEN: usize = 27;

/// v3 layout = v2 layout (version u8, dimensions u64le, m_max_0 u64le,
/// ef_construction u64le, distance_metric u8, index_structure u8) +
/// `fast_dims` u16le at bytes 27..29 (wire `0` = None).
pub(super) const HNSW_COMPATIBILITY_LEN: usize = 29;

pub(super) const HNSW_COMPATIBILITY_V2_VERSION: u8 = 2;

const HNSW_DISTANCE_METRIC_MISSING: u8 = 0;

pub(super) const HNSW_DISTANCE_METRIC_COSINE: u8 = 1;

const HNSW_INDEX_STRUCTURE_MISSING: u8 = 0;

// ARCH-0019 fixes the graph as flat single-layer NSW; the upper-layer M value
// stays compile-time-only because this structure has no upper layers.
pub(super) const HNSW_INDEX_STRUCTURE_FLAT_NSW: u8 = 1;

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

// RCPT-1 keeps its materialized lookup rows in the existing `vault_meta`
// family.  These are additive sidecars, not named LMDB databases: older
// readers already ignore unknown `vault_meta` prefixes, while a current
// reader backfills them before exposing the store.
pub(super) const RECEIPT_FAMILY_INDEX_VERSION_KEY: &[u8] = b"receipt_family_index:v1:version";

/// Receipt-family ABI-pin rule: changing this requires a
/// [`STORAGE_ABI_VERSION`] bump.
pub(super) const RECEIPT_FAMILY_INDEX_VERSION: u8 = 1;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DefaultPolicySeedMode {
    Required,
    #[cfg(feature = "test-support")]
    TestUnseeded,
}

static NEXT_AUTHORITY_CLOCK_DOMAIN: AtomicUsize = AtomicUsize::new(1);

impl Store {
    /// Opens or creates a store at `path` and initializes all named databases.
    pub fn open(path: impl AsRef<Path>, config: &VaultConfig) -> Result<Self> {
        Self::open_with_storage_abi_version(
            path,
            config,
            STORAGE_ABI_VERSION,
            DefaultPolicySeedMode::Required,
        )
    }

    #[cfg(test)]
    pub(crate) fn open_with_storage_abi_version_for_test(
        path: impl AsRef<Path>,
        config: &VaultConfig,
        storage_abi_version: u16,
    ) -> Result<Self> {
        Self::open_with_storage_abi_version(
            path,
            config,
            storage_abi_version,
            DefaultPolicySeedMode::Required,
        )
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn open_unseeded_for_test(
        path: impl AsRef<Path>,
        config: &VaultConfig,
    ) -> Result<Self> {
        Self::open_with_storage_abi_version(
            path,
            config,
            STORAGE_ABI_VERSION,
            DefaultPolicySeedMode::TestUnseeded,
        )
    }

    fn open_with_storage_abi_version(
        path: impl AsRef<Path>,
        config: &VaultConfig,
        storage_abi_version: u16,
        seed_mode: DefaultPolicySeedMode,
    ) -> Result<Self> {
        // Declared before the environment so its Drop runs after the env has
        // closed, releasing LMDB's file handles before removing torn files.
        let mut torn_creation_cleanup = TornCreationCleanup { root: None };
        let (env, registered_path, is_new_vault) = {
            let _vault_root_open_guard = vault_root_open_guard()?;

            std::fs::create_dir_all(path.as_ref())?;
            let canonical_path = path.as_ref().canonicalize()?;
            let root_preflight = preflight_vault_root(&canonical_path)?;
            let is_new_vault = root_preflight.is_new_vault;
            if is_new_vault {
                torn_creation_cleanup.arm(canonical_path.clone());
            }
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
                // A root whose LMDB files gained a SECOND HARD LINK while this
                // open was creating them is an ALIAS, not a torn creation, and
                // the difference decides whether the next opener of that alias
                // can still see it. Torn-creation cleanup exists to unlink
                // files this open created so a retry starts clean; here the
                // inode is reachable through another name, so unlinking our
                // side cannot restore a clean root (the inode survives) and it
                // destroys the one fact that makes the alias rejectable —
                // `link_count >= 2`. An opener arriving at the alias afterwards
                // would find a single-link root holding an LMDB environment
                // with no committed `vault_meta`, and would report the ABI gate
                // (`StorageAbiVersionChanged { stored: None }`) instead of the
                // alias, admitting a second environment over shared files.
                //
                // So: disarm cleanup for exactly that verdict and let the
                // preflight error stand. Rejection is not weakened anywhere —
                // this open still fails closed with the SAME
                // `VaultRootPreflight(MultipleHardLinks)`, returns no handle,
                // and releases its path reservation; only the destructive
                // unlink is withheld. Every other failure keeps cleanup armed.
                let refreshed = match preflight_vault_root(&canonical_path) {
                    Ok(refreshed) => refreshed,
                    Err(error) => {
                        if preflight_rejected_aliased_root(&error) {
                            torn_creation_cleanup.disarm();
                        }
                        return Err(error);
                    }
                };
                registered_path.refresh_identity(refreshed.identity)?;
            }

            (env, registered_path, is_new_vault)
        };

        let db_open_guard = lmdb_database_open_guard()?;
        let mut wtxn = env.write_txn()?;
        let vault_meta = create_manifest_db(&env, &mut wtxn, 4)?;
        let vault_meta_view = OverlayDb::canonical(vault_meta);
        let abi_gate = gate_storage_versions(
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

        let raw = RawDatabases {
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
        };

        // ONE-1754: the one sanctioned migration branch. It runs in THIS
        // transaction, after every database exists and before the commit, so a
        // failure aborts the whole open — old bytes and the predecessor stamp
        // both survive, and the vault stays openable by the previous engine.
        // The new stamp is written only once the re-key's own count and id-set
        // assertions have passed.
        if abi_gate == StorageAbiGate::RekeyByteSpaceV3 {
            let edges_out_before = raw.edges_out.len(&wtxn)?;
            let edges_in_before = raw.edges_in.len(&wtxn)?;
            let counts = rekey_type_bytes_v3_in_txn(&raw, &mut wtxn, TYPE_BYTE_REKEY_V3)?;
            // Edges carry entity ids and edge data, never endpoint type bytes.
            // Asserting the totals is how "we did not touch them" stops being
            // a claim in a comment and becomes a checked fact.
            if raw.edges_out.len(&wtxn)? != edges_out_before
                || raw.edges_in.len(&wtxn)? != edges_in_before
            {
                return Err(Error::CorruptedIndex("byte-space v3 edge total changed"));
            }
            tracing::info!(
                entities = counts.entities,
                type_index = counts.type_index,
                short_id_counters = counts.short_id_counters,
                kind_registrations = counts.kind_registrations,
                kind_registrations_rezoned = counts.kind_registrations_rezoned,
                from = STORAGE_ABI_VERSION_V3_REKEY_PREDECESSOR,
                to = storage_abi_version,
                "byte-space v3 type-byte re-key applied"
            );
            vault_meta_view.put(
                &mut wtxn,
                STORAGE_ABI_VERSION_KEY,
                &storage_abi_version.to_le_bytes(),
            )?;
        }

        // ONE-1930: the presentation-prefix re-key. Runs in THIS transaction,
        // after the byte-space pass above so entity envelopes and
        // `sid_counter:<byte>` keys are already at their final v3 bytes — this
        // pass changes prefixes, never type bytes. It is gated on its own
        // `vault_meta` marker rather than a storage-ABI bump because it adds no
        // row family and removes none: a predecessor engine still reads every
        // row it writes.
        if read_vault_meta_u16(
            &vault_meta_view,
            &wtxn,
            SHORT_ID_GRAMMAR_VERSION_KEY,
            "short id grammar version",
        )? != Some(SHORT_ID_GRAMMAR_VERSION)
        {
            let entities_view = OverlayDb::canonical(raw.entities);
            let short_ids_view = OverlayDb::canonical(raw.short_ids);
            let short_ids_reverse_view = OverlayDb::canonical(raw.short_ids_reverse);
            let short_id_dbs = ShortIdDbs {
                entities: &entities_view,
                short_ids: &short_ids_view,
                short_ids_reverse: &short_ids_reverse_view,
                vault_meta: &vault_meta_view,
            };
            let rekeyed =
                rekey_short_ids_v1_in_txn(short_id_dbs, &mut wtxn, SHORT_ID_PREFIX_REKEY_V1)?;
            if rekeyed > 0 {
                tracing::info!(rekeyed, "short-id presentation prefix re-key applied");
            }
            vault_meta_view.put(
                &mut wtxn,
                SHORT_ID_GRAMMAR_VERSION_KEY,
                &SHORT_ID_GRAMMAR_VERSION.to_le_bytes(),
            )?;
        }

        if is_new_vault && matches!(seed_mode, DefaultPolicySeedMode::Required) {
            let id = crate::gate::default_policy_manifest_id()?;
            let entities = OverlayDb::canonical(raw.entities);
            let type_index = OverlayDb::canonical(raw.type_index);
            let temporal_occurred_start = OverlayDb::canonical(raw.temporal_occurred_start);
            let temporal_learned = OverlayDb::canonical(raw.temporal_learned);
            seed_default_policy_manifest_in_txn(
                &entities,
                &type_index,
                &temporal_occurred_start,
                &temporal_learned,
                &mut wtxn,
                &id,
            )?;
        }
        #[cfg(test)]
        if is_new_vault
            && matches!(seed_mode, DefaultPolicySeedMode::Required)
            && test_hooks::take_fail_initial_seed_commit_for(&registered_path.path)
        {
            return Err(Error::InvalidConfig(
                "test: initial seed transaction interrupted".to_owned(),
            ));
        }
        wtxn.commit()?;
        // The initial creation transaction is durable; later open failures
        // must preserve this committed vault.
        torn_creation_cleanup.disarm();
        drop(db_open_guard);

        let kind_registry = RwLock::new(load_structural_kind_registry(&env, &vault_meta_view)?);

        let authority_clock_domain =
            NEXT_AUTHORITY_CLOCK_DOMAIN.fetch_add(1, AtomicOrdering::Relaxed);
        let shared_env: Env = (*env).clone();
        let core = Arc::new(StoreCore {
            env: shared_env,
            raw,
            kind_registry,
            off_record_sessions: OffRecordSessionRegistry::default(),
            retrieval_blend_tuning_lock: Mutex::new(()),
            authority_clock_domain,
        });
        let owner = StoreOwner {
            core: Arc::downgrade(&core),
            env,
            authority_clock_domain,
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
        if matches!(seed_mode, DefaultPolicySeedMode::Required) {
            store.ensure_default_policy_manifest_on_open()?;
        }
        Ok(store)
    }

    fn ensure_default_policy_manifest_on_open(&self) -> Result<()> {
        // Healthy vaults should not hold the single LMDB writer slot merely to
        // inspect the manifest. Re-check under the writer before mutating.
        {
            let rtxn = self.env.read_txn()?;
            let policy = crate::gate::resolve_policy_manifest(self, &rtxn)?;
            let diagnostics = policy.diagnostics();
            if diagnostics.manifest_count > 0 || diagnostics.loaded_manifest_forces_fail_closed() {
                return Ok(());
            }
        }

        let mut wtxn = self.env.write_txn()?;
        let policy = crate::gate::resolve_policy_manifest(self, &wtxn)?;
        let diagnostics = policy.diagnostics();
        if diagnostics.manifest_count > 0 || diagnostics.loaded_manifest_forces_fail_closed() {
            return Ok(());
        }
        let id = crate::gate::default_policy_manifest_id()?;
        seed_default_policy_manifest_in_txn(
            &self.entities,
            &self.type_index,
            &self.temporal_occurred_start,
            &self.temporal_learned,
            &mut wtxn,
            &id,
        )?;
        let post_write_policy = crate::gate::resolve_policy_manifest(self, &wtxn)?;
        if post_write_policy.diagnostics().manifest_count != 1 || post_write_policy.is_fail_closed()
        {
            return Err(Error::CorruptedIndex("default policy manifest reseed"));
        }
        let read_frontier_hash = post_write_policy.read_frontier_hash()?;
        if read_frontier_hash == [0; 32] {
            return Err(Error::CorruptedIndex("default policy manifest frontier"));
        }
        let receipt = GateDecisionRecord {
            version: GATE_DECISION_LEDGER_VERSION,
            decision_id: GateDecisionId::now(),
            created_at: crate::unix_seconds_now(),
            outcome: "reseeded_after_loss".to_owned(),
            reason_codes: vec!["gate.policy_manifest.reseeded_after_loss".to_owned()],
            receipt_reasons: Vec::new(),
            system_notices: vec![GateSystemNoticeRecord {
                notice_type: "policy_manifest_reseeded".to_owned(),
                channel: "system".to_owned(),
                voice: "owner".to_owned(),
                audience: "owner".to_owned(),
                body: "Default policy manifest was restored after loss.".to_owned(),
                row_ref: Some(id.to_hex()),
                setting_change_offer: None,
                policy_plane: None,
                policy_version: None,
                docs_url: None,
            }],
            actor_class: "system".to_owned(),
            actor_ref: None,
            content_kind: "policy_manifest".to_owned(),
            policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
            claim_id: None,
            grant_ref: None,
            diff_handle: id.as_bytes().to_vec(),
            read_frontier_hash,
            redacted_at: None,
        };
        self.append_gate_decision_in_txn(&mut wtxn, &receipt)?;
        Ok(wtxn.commit()?)
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

/// Whether a post-`Env::open` preflight refusal says this root's LMDB files are
/// reachable under more than one name.
///
/// Used by the creation path to decide whether torn-creation cleanup may unlink
/// the files it just created. It may not when the inode is aliased: the unlink
/// would leave the alias behind as a single-link root and hide the aliasing
/// from the next opener. Deliberately narrow — only these two verdicts describe
/// a shared inode, and every other failure keeps cleanup armed.
fn preflight_rejected_aliased_root(error: &Error) -> bool {
    matches!(
        error,
        Error::VaultRootPreflight {
            problem: VaultRootProblem::MultipleHardLinks { .. }
                | VaultRootProblem::AliasedLmdbFiles { .. },
            ..
        }
    )
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

pub(super) struct RegisteredPath {
    pub(in crate::store) path: PathBuf,
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

/// Deletes only the LMDB files created during a failed first-open transaction.
///
/// The guard is armed only after an empty root has passed preflight. It remains
/// armed until the initial database-creation transaction commits, so every
/// `?` on that path receives the same cleanup without replacing its error.
struct TornCreationCleanup {
    root: Option<PathBuf>,
}

impl TornCreationCleanup {
    fn arm(&mut self, root: PathBuf) {
        self.root = Some(root);
    }

    fn disarm(&mut self) {
        self.root = None;
    }
}

impl Drop for TornCreationCleanup {
    fn drop(&mut self) {
        let Some(root) = self.root.take() else {
            return;
        };
        // Best effort by design: the original opening error is authoritative.
        for name in ["data.mdb", "lock.mdb"] {
            let _ = std::fs::remove_file(root.join(name));
        }
    }
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
) -> Result<StorageAbiGate> {
    let stored_abi = read_vault_meta_u16(
        vault_meta,
        &*wtxn,
        STORAGE_ABI_VERSION_KEY,
        "storage ABI version",
    )?;
    let abi_gate = gate_storage_abi_value(stored_abi, storage_abi_version, new_vault)?;
    if abi_gate == StorageAbiGate::StampCurrent {
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

    Ok(abi_gate)
}

/// What the storage-ABI handshake decided for this open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StorageAbiGate {
    /// The stamp already equals the current version; nothing to do.
    Current,
    /// A genuinely new vault: stamp the current version.
    StampCurrent,
    /// ONE-1754 ONLY: the vault is stamped at the immediate predecessor, so
    /// the byte-space v3 re-key runs inside this open's transaction and the
    /// current version is stamped after its assertions pass.
    RekeyByteSpaceV3,
}

/// Applies the strict-equality storage-ABI handshake used by every
/// [`Store::open`] call.
///
/// The handshake still fails closed in both directions — including a
/// prior-version reader opening a newer vault — with ONE sanctioned carve-out.
/// A vault stamped at exactly [`STORAGE_ABI_VERSION_V3_REKEY_PREDECESSOR`]
/// returns [`StorageAbiGate::RekeyByteSpaceV3`] instead of erroring, because
/// the strict gate would otherwise refuse every pre-1754 vault BEFORE the
/// re-key that makes it current could run. That carve-out is not a migration
/// framework: it accepts exactly one stamp, and the caller stamps the new
/// version only after the re-key's count and id-set assertions pass.
pub(super) fn gate_storage_abi_value(
    stored: Option<u16>,
    current: u16,
    new_vault: bool,
) -> Result<StorageAbiGate> {
    match stored {
        Some(stored) if stored == current => Ok(StorageAbiGate::Current),
        Some(stored)
            if current == STORAGE_ABI_VERSION
                && stored == STORAGE_ABI_VERSION_V3_REKEY_PREDECESSOR =>
        {
            Ok(StorageAbiGate::RekeyByteSpaceV3)
        }
        Some(stored) => Err(Error::StorageAbiVersionChanged {
            stored: Some(stored),
            current,
        }),
        None if new_vault => Ok(StorageAbiGate::StampCurrent),
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

pub(crate) fn validate_embedding_model_id(model_id: &str) -> Result<()> {
    let invalid =
        || Error::InvalidConfig("embedding model id must be org/name@revision".to_owned());
    // Preserve delimiter order as part of the grammar; split(['/', '@'])
    // loses it and accepts org@name/revision.
    let Some((org, name_and_revision)) = model_id.split_once('/') else {
        return Err(invalid());
    };
    let Some((name, revision)) = name_and_revision.split_once('@') else {
        return Err(invalid());
    };
    let valid_component = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    };
    if model_id.bytes().filter(|&b| b == b'/').count() != 1
        || model_id.bytes().filter(|&b| b == b'@').count() != 1
        || !valid_component(org)
        || !valid_component(name)
        || !valid_component(revision)
    {
        return Err(invalid());
    }
    Ok(())
}

fn preflight_embedding_model(
    env: &Env,
    hnsw_meta: &OverlayDb,
    vectors: &OverlayDb,
    hnsw_neighbors: &OverlayDb,
    requested: Option<&str>,
) -> Result<bool> {
    if let Some(requested) = requested {
        validate_embedding_model_id(requested)?;
    }
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
    validate_embedding_model_id(requested)?;
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
    validate_embedding_model_id(requested)?;
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
