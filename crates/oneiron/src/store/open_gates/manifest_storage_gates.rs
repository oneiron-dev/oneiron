//! Process path registry, owned environment close semantics, manifest create/open/validate pairs, and storage ABI/schema gates.

use std::collections::HashSet;
#[cfg(target_os = "linux")]
use std::fs::File;
use std::path::PathBuf;
use std::sync::MutexGuard;

use heed::types::{Bytes, Str};
use heed::{Database, DatabaseFlags, Env, RoTxn, RwTxn};

use crate::config::VaultConfig;
use crate::error::{Error, Result, VaultRootProblem};
use crate::overlay_db::OverlayDb;
use crate::store::{
    RawDatabases, SHORT_ID_GRAMMAR_VERSION, SHORT_ID_GRAMMAR_VERSION_KEY, SHORT_ID_PREFIX_REKEY_V1,
    ShortIdDbs, Store, rekey_short_ids_v1_in_txn,
};

use super::hnsw_model_gates::{
    format_hnsw_compatibility, parse_utf8_bytes, read_hnsw_compatibility, read_vault_meta_u16,
    validate_embedding_model_id,
};
use super::open_version_keys::{
    DB_MANIFEST, ERR_EXISTING_MISSING_HNSW_CONFIG, HnswCompatibilityState, LMDB_DATABASE_OPEN_LOCK,
    MODEL_ID_KEY, MODEL_ID_NONE, OPEN_STORE_PATHS, PersistedHnswCompatibility, STORAGE_ABI_VERSION,
    STORAGE_ABI_VERSION_KEY, STORAGE_ABI_VERSION_V3_REKEY_PREDECESSOR, STORAGE_SCHEMA_VERSION,
    STORAGE_SCHEMA_VERSION_KEY, StorageMigrationPlan, VAULT_ROOT_OPEN_LOCK,
};
use super::vault_root_bind::{VaultRootIdentity, duplicate_open_root, vault_root_preflight_error};

pub(in crate::store) struct RegisteredPath {
    pub(in crate::store) path: PathBuf,
}

impl RegisteredPath {
    pub(super) fn reserve(path: PathBuf, identity: Option<VaultRootIdentity>) -> Result<Self> {
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

    pub(super) fn refresh_identity(&mut self, identity: Option<VaultRootIdentity>) -> Result<()> {
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
    pub(super) env: Env,
    /// The existing-only door's bound root directory descriptor, kept alive for
    /// the whole environment lifetime so the `/proc/self/fd/<dirfd>` path LMDB
    /// was opened through can never become some recycled descriptor. `None` on
    /// the create-capable door, which opens the caller's pathname. Deliberately
    /// never read: holding it open IS the point.
    ///
    /// Declared AFTER `env` on purpose. `Drop` runs the body above first, then
    /// drops fields in declaration order, so the environment closes
    /// (`mdb_env_close`) while the descriptor is still open and the descriptor
    /// is released only afterwards.
    pub(super) _bound_root_dir: Option<std::fs::File>,
}

impl OwnedEnv {
    /// Moves the bound root directory descriptor into the environment that was
    /// opened through it.
    #[cfg(target_os = "linux")]
    pub(super) fn retain_bound_root(&mut self, dir: File) {
        self._bound_root_dir = Some(dir);
    }
}

/// Deletes only the LMDB files created during a failed first-open transaction.
///
/// The guard is armed only after an empty root has passed preflight. It remains
/// armed until the initial database-creation transaction commits, so every
/// `?` on that path receives the same cleanup without replacing its error.
pub(super) struct TornCreationCleanup {
    pub(super) root: Option<PathBuf>,
}

impl TornCreationCleanup {
    pub(super) fn arm(&mut self, root: PathBuf) {
        self.root = Some(root);
    }

    pub(super) fn disarm(&mut self) {
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

pub(super) fn create_db(
    env: &Env,
    wtxn: &mut RwTxn<'_>,
    name: &str,
) -> Result<Database<Bytes, Bytes>> {
    Ok(env.create_database::<Bytes, Bytes>(wtxn, Some(name))?)
}

pub(crate) fn lmdb_database_open_guard() -> Result<MutexGuard<'static, ()>> {
    LMDB_DATABASE_OPEN_LOCK
        .lock()
        .map_err(|_| Error::InvariantViolation("lmdb database-open mutex poisoned"))
}

pub(super) fn vault_root_open_guard() -> Result<MutexGuard<'static, ()>> {
    VAULT_ROOT_OPEN_LOCK
        .lock()
        .map_err(|_| Error::InvariantViolation("vault root open mutex poisoned"))
}

pub(super) fn create_manifest_db(
    env: &Env,
    wtxn: &mut RwTxn<'_>,
    manifest_index: usize,
) -> Result<Database<Bytes, Bytes>> {
    create_db(env, wtxn, DB_MANIFEST[manifest_index].name)
}

pub(super) fn create_manifest_str_db(
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
pub(super) fn create_manifest_dupsort_db(
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

/// Takes any transaction — the create-capable door validates inside its
/// creation write transaction, the existing-only door inside its read-only
/// gate transaction, and both compare the same materialized name set.
pub(super) fn validate_db_manifest_set(env: &Env, txn: &RoTxn<'_>) -> Result<()> {
    let env_names = materialized_database_names(env, txn)?;
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

/// Opens all 28 manifest databases in a READ transaction, so the existing-only
/// door needs no write transaction to reach the vault's rows.
///
/// `mdb_dbi_open` never creates here: a database the ARCH-0019 manifest
/// requires but the environment does not hold comes back `None` and becomes
/// the existing [`Error::DbManifestMismatch`].
pub(super) fn open_existing_databases(env: &Env, rtxn: &RoTxn<'_>) -> Result<RawDatabases> {
    Ok(RawDatabases {
        entities: open_manifest_db(env, rtxn, 0)?,
        type_index: open_manifest_db(env, rtxn, 1)?,
        short_ids: open_manifest_db(env, rtxn, 2)?,
        short_ids_reverse: open_manifest_db(env, rtxn, 3)?,
        vault_meta: open_manifest_db(env, rtxn, 4)?,
        vectors: open_manifest_db(env, rtxn, 5)?,
        hnsw_neighbors: open_manifest_db(env, rtxn, 6)?,
        hnsw_meta: open_manifest_db(env, rtxn, 7)?,
        text_postings: open_manifest_dupsort_db(env, rtxn, 8)?,
        text_meta: open_manifest_db(env, rtxn, 9)?,
        text_forward: open_manifest_db(env, rtxn, 10)?,
        text_bm25_field_stats: open_manifest_db(env, rtxn, 11)?,
        text_doc_field_lengths: open_manifest_db(env, rtxn, 12)?,
        edges_out: open_manifest_db(env, rtxn, 13)?,
        edges_in: open_manifest_db(env, rtxn, 14)?,
        ppr_cache: open_manifest_db(env, rtxn, 15)?,
        ppr_cache_deps: open_manifest_db(env, rtxn, 16)?,
        temporal_occurred_start: open_manifest_db(env, rtxn, 17)?,
        temporal_occurred_end: open_manifest_db(env, rtxn, 18)?,
        temporal_learned: open_manifest_db(env, rtxn, 19)?,
        temporal_long_intervals: open_manifest_db(env, rtxn, 20)?,
        phonetic_index: open_manifest_db(env, rtxn, 21)?,
        phonetic_forward: open_manifest_db(env, rtxn, 22)?,
        sync_state: open_manifest_str_db(env, rtxn, 23)?,
        sync_queue: open_manifest_db(env, rtxn, 24)?,
        attempt_records: open_manifest_db(env, rtxn, 25)?,
        attempt_ready: open_manifest_db(env, rtxn, 26)?,
        attempt_dedupe: open_manifest_db(env, rtxn, 27)?,
    })
}

pub(super) fn missing_manifest_db(manifest_index: usize) -> Error {
    Error::DbManifestMismatch {
        missing: vec![DB_MANIFEST[manifest_index].name.to_owned()],
        unexpected: Vec::new(),
    }
}

pub(super) fn open_manifest_db(
    env: &Env,
    rtxn: &RoTxn<'_>,
    manifest_index: usize,
) -> Result<Database<Bytes, Bytes>> {
    let name = DB_MANIFEST[manifest_index].name;
    let opened = env.open_database::<Bytes, Bytes>(rtxn, Some(name))?;
    opened.ok_or_else(|| missing_manifest_db(manifest_index))
}

pub(super) fn open_manifest_str_db(
    env: &Env,
    rtxn: &RoTxn<'_>,
    manifest_index: usize,
) -> Result<Database<Str, Bytes>> {
    let name = DB_MANIFEST[manifest_index].name;
    let opened = env.open_database::<Str, Bytes>(rtxn, Some(name))?;
    opened.ok_or_else(|| missing_manifest_db(manifest_index))
}

/// `text_postings` is the one `MDB_DUPSORT` database (storage ABI v4). LMDB
/// persists database flags, so opening it without `MDB_CREATE` and with the
/// same flag set neither creates nor rewrites anything.
pub(super) fn open_manifest_dupsort_db(
    env: &Env,
    rtxn: &RoTxn<'_>,
    manifest_index: usize,
) -> Result<Database<Bytes, Bytes>> {
    let opened = env
        .database_options()
        .types::<Bytes, Bytes>()
        .name(DB_MANIFEST[manifest_index].name)
        .flags(DatabaseFlags::DUP_SORT)
        .open(rtxn)?;
    opened.ok_or_else(|| missing_manifest_db(manifest_index))
}

/// The storage ABI and schema handshake for an existing-only open: strict
/// equality in both directions, read-only.
///
/// Both of [`gate_storage_versions`]'s non-error outcomes for an unstamped or
/// predecessor-stamped vault — stamp-on-new and the ONE-1754 byte-space re-key
/// — are WRITES against a vault whose identity has not been compared yet, so
/// this door refuses instead. Rebuild, or open through [`Store::open`].
pub(super) fn gate_existing_storage_versions(
    vault_meta: &OverlayDb,
    rtxn: &RoTxn<'_>,
) -> Result<()> {
    let stored_abi = read_vault_meta_u16(
        vault_meta,
        rtxn,
        STORAGE_ABI_VERSION_KEY,
        "storage ABI version",
    )?;
    if stored_abi != Some(STORAGE_ABI_VERSION) {
        return Err(Error::StorageAbiVersionChanged {
            stored: stored_abi,
            current: STORAGE_ABI_VERSION,
        });
    }

    let stored_schema = read_vault_meta_u16(
        vault_meta,
        rtxn,
        STORAGE_SCHEMA_VERSION_KEY,
        "storage schema version",
    )?;
    if stored_schema != Some(STORAGE_SCHEMA_VERSION) {
        return Err(Error::StorageSchemaVersionChanged {
            stored: stored_schema,
            current: STORAGE_SCHEMA_VERSION,
        });
    }
    Ok(())
}

/// EMB-2: an out-of-range `fast_dims` is a caller bug, and both doors refuse it
/// before any persisted graph shape is compared against it.
pub(super) fn validate_fast_dims(config: &VaultConfig) -> Result<()> {
    if let Some(fd) = config.fast_dims
        && (fd == 0 || usize::from(fd) >= config.dimensions)
    {
        return Err(Error::InvalidConfig(
            "fast_dims must be greater than zero and less than dimensions".to_owned(),
        ));
    }
    Ok(())
}

/// Compares the persisted HNSW shape with the requested one in a read
/// transaction.
///
/// [`preflight_hnsw_config`] answers "should this open PERSIST the shape?" and
/// its `Missing`/`Legacy` branches lead to a write on an unpopulated vault.
/// Here there is no such branch: an existing vault whose shape was never
/// recorded, or was recorded in a legacy layout, has no identity to be
/// reopened against and is refused.
pub(super) fn verify_existing_hnsw_config(store: &Store, config: &VaultConfig) -> Result<()> {
    let requested = PersistedHnswCompatibility::from_config(config);
    let rtxn = store.env.read_txn()?;
    let stored = read_hnsw_compatibility(&store.hnsw_meta, &rtxn)?;
    drop(rtxn);
    match stored {
        HnswCompatibilityState::Current(stored) if stored == requested => Ok(()),
        HnswCompatibilityState::Current(stored) | HnswCompatibilityState::Legacy(stored) => {
            Err(Error::HnswConfigChanged {
                stored: format_hnsw_compatibility(&stored),
                requested: format_hnsw_compatibility(&requested),
            })
        }
        HnswCompatibilityState::Missing => Err(Error::InvalidConfig(
            ERR_EXISTING_MISSING_HNSW_CONFIG.to_owned(),
        )),
    }
}

/// Exact nullable embedding-model identity, read-only, against the PRE-open
/// bytes.
///
/// Both asymmetric disagreements refuse: a stored `None` against a supplied id
/// (which [`preflight_embedding_model`] would answer by STAMPING the supplied
/// id) and a stored id against a supplied `none` (which it tolerates on a
/// vectorless vault). Vector population is deliberately never consulted — it
/// is not identity, and nothing is written before the comparison.
pub(super) fn verify_existing_embedding_model(
    store: &Store,
    requested: Option<&str>,
) -> Result<()> {
    if let Some(requested) = requested {
        validate_embedding_model_id(requested)?;
    }
    let rtxn = store.env.read_txn()?;
    let stored = match store.hnsw_meta.get(&rtxn, MODEL_ID_KEY)? {
        Some(raw) => Some(parse_utf8_bytes(&raw)?),
        None => None,
    };
    drop(rtxn);
    if stored.as_deref() == requested {
        return Ok(());
    }
    Err(Error::EmbeddingModelChanged {
        stored: stored.unwrap_or_else(|| MODEL_ID_NONE.to_owned()),
        requested: requested.unwrap_or(MODEL_ID_NONE).to_owned(),
    })
}

/// ONE-1930's presentation-prefix re-key, gated on its own `vault_meta` marker
/// rather than a storage-ABI bump because it adds no row family and removes
/// none: a predecessor engine still reads every row it writes.
///
/// Split out of [`Store::open`] so the existing-only door runs the SAME pass in
/// its own post-gate write transaction instead of carrying a copy.
pub(super) fn rekey_short_ids_if_needed_in_txn(
    raw: &RawDatabases,
    vault_meta: &OverlayDb,
    wtxn: &mut RwTxn<'_>,
) -> Result<()> {
    if read_vault_meta_u16(
        vault_meta,
        &*wtxn,
        SHORT_ID_GRAMMAR_VERSION_KEY,
        "short id grammar version",
    )? == Some(SHORT_ID_GRAMMAR_VERSION)
    {
        return Ok(());
    }

    let entities_view = OverlayDb::canonical(raw.entities);
    let short_ids_view = OverlayDb::canonical(raw.short_ids);
    let short_ids_reverse_view = OverlayDb::canonical(raw.short_ids_reverse);
    let short_id_dbs = ShortIdDbs {
        entities: &entities_view,
        short_ids: &short_ids_view,
        short_ids_reverse: &short_ids_reverse_view,
        vault_meta,
    };
    let rekeyed = rekey_short_ids_v1_in_txn(short_id_dbs, wtxn, SHORT_ID_PREFIX_REKEY_V1)?;
    if rekeyed > 0 {
        tracing::info!(rekeyed, "short-id presentation prefix re-key applied");
    }
    vault_meta.put(
        wtxn,
        SHORT_ID_GRAMMAR_VERSION_KEY,
        &SHORT_ID_GRAMMAR_VERSION.to_le_bytes(),
    )?;
    Ok(())
}

pub(super) fn gate_storage_versions(
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
pub(in crate::store) enum StorageAbiGate {
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
pub(in crate::store) fn gate_storage_abi_value(
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
