//! Top-level `Vault` API: the crate's main entry point for all LMDB-backed
//! entity / vector / edge / text / temporal operations. Also hosts
//! edge-record helpers kept for Vault-facing compatibility.

use std::path::Path;
use std::time::Instant;

use serde::Serialize;

use crate::affect::Vad;
use crate::analyzer::{AnalyzerChannel, AnalyzerManifest, AnalyzerMode, MultilingualAnalyzer};
use crate::batch::{
    BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops,
    encode_short_id_forward_key,
};
use crate::config::VaultConfig;
use crate::deletion::HydratedShortIdDeletion;
use crate::deletion::HydratedShortIdDeletionSource;
#[cfg(test)]
use crate::deletion::ReplayedTombstoneOutcome;
use crate::edge::{EdgeActorClass, EdgeInfo, EdgeKind, parse_strict_edge_record};
use crate::entity_id::{ENTITY_ID_LEN, EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::limits::{
    ERR_CHILD_OF_CYCLE_CHECK, MAX_ANCESTOR_DEPTH, MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS,
};
use crate::overlay_db::OverlayDb;
use crate::pipeline::ScoredEntity;
use crate::provenance::{EdgeProvenanceClaimBody, EdgeRef, SupersessionStatus};
use crate::registry::{ENTITY_TYPE_POLICY_MANIFEST, StructuralKindRegistration, TypeByteBand};
use crate::store::{
    DB_MANIFEST, GateDecisionRecord, HnswCompatibilityState, MODEL_ID_KEY, PendingGateConsentGroup,
    PendingGateConsentRecord, RetrievalAction, RetrievalBlendTuningConfig,
    RetrievalBlendWeightTableEntry, RetrievalOutcome, RetrievalOutcomeRecord, RetrievalRunId,
    RetrievalRunRecord, RetrievalScoreBreakdown, RetrievalScoreComponent, RetrievalSignal,
    RetrievalTrace, RetrievalTraceForkHash, STORAGE_ABI_VERSION_KEY, STORAGE_SCHEMA_VERSION_KEY,
    Store, TEXT_ANALYZER_MANIFEST_HASH_KEY, TEXT_ANALYZER_MANIFEST_KEY,
    TEXT_BM25_FIELD_SCHEMA_HASH_KEY, TEXT_INDEX_SCHEMA_VERSION, TEXT_INDEX_SCHEMA_VERSION_KEY,
    lmdb_database_open_guard,
};
use crate::temporal::TimeRange;
use crate::{
    BatchBuilder, ContextPackBuilder, MaintenanceBuilder, PipelineBuilder, RetrievalWithTelemetry,
    TxnBatchBuilder, bm25, hnsw, le_bytes_to_f32_vec, ppr, unix_seconds_now,
};

const MIN_MAP_SIZE_BYTES: usize = 1 << 20;

/// File name of the vault's advisory cross-process open lock, created inside the
/// vault directory alongside LMDB's own `data.mdb`/`lock.mdb`.
const OFF_RECORD_OPEN_LOCK_FILE: &str = "off_record_sweep.lock";

/// Acquires the vault's advisory open lock and reports whether THIS process is
/// the sole opener. The returned file is held (as a SHARED `flock`) for the
/// vault's lifetime so a peer process cannot claim exclusivity while this
/// process is live. `sole_opener` is `true` only when the exclusive,
/// non-blocking probe succeeds — proof that no peer process currently holds the
/// vault open — which is the only condition under which the destructive
/// off-record crash-orphan sweep may run. When a peer holds the lock, the probe
/// fails and the caller skips the sweep (non-destructive). Called after
/// `Store::open`, so the vault directory already exists.
#[cfg(unix)]
fn acquire_off_record_open_lock(dir: &Path) -> Result<(Option<std::fs::File>, bool)> {
    use std::os::unix::io::AsRawFd;
    // Canonicalize so two spellings of the same directory (symlinks, `.`) map to
    // one lock file, matching `Store::open`'s own canonicalization — otherwise
    // two processes opening the same vault by different paths would lock
    // different files and never observe each other.
    let dir = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let lock_path = dir.join(OFF_RECORD_OPEN_LOCK_FILE);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        // Never truncate: the file is a pure advisory-lock handle whose contents
        // are irrelevant, and a peer may already hold it open.
        .truncate(false)
        .open(&lock_path)?;
    let fd = file.as_raw_fd();
    // Exclusive, non-blocking probe: success proves no peer holds ANY lock on
    // the file right now (so no live peer session). A non-zero result (contended
    // or any error) fails closed to "not sole opener", skipping the sweep.
    // SAFETY: `fd` is the raw descriptor of the live, owned `file`, which stays
    // open for the whole call; `libc::flock` requires only a valid open
    // descriptor and its return value is inspected here.
    let sole_opener = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } == 0;
    if sole_opener {
        // Sole opener: KEEP the exclusive lock held through the caller's
        // crash-orphan sweep — do NOT downgrade to shared yet. While we hold
        // `LOCK_EX`, a peer opener's own `LOCK_EX` probe fails AND its blocking
        // `LOCK_SH` parks, so no peer can obtain a usable vault, enter a
        // session, and write a live fence row that our still-running sweep would
        // misread as an orphan and PolicyDelete. The caller MUST call
        // `downgrade_off_record_open_lock` once recovery finishes to admit
        // concurrent shared openers for the rest of the vault's lifetime.
        return Ok((Some(file), true));
    }
    // A peer already holds the lock (a live peer session): register as a
    // concurrent SHARED opener held for the vault's lifetime and skip the sweep.
    // The blocking `LOCK_SH` also parks here until any sole opener currently
    // running its exclusive sweep downgrades, so we never observe a vault
    // mid-recovery. If we cannot register as a live shared opener, hold no lock
    // and do not claim sole ownership.
    // SAFETY: same invariant as the probe above — `fd` is the descriptor of the
    // live, owned `file`, and the `libc::flock` return value is checked below.
    if unsafe { libc::flock(fd, libc::LOCK_SH) } != 0 {
        return Ok((None, false));
    }
    Ok((Some(file), false))
}

/// Non-unix fallback: no advisory `flock` is available, so conservatively never
/// claim sole ownership. The destructive off-record crash-orphan sweep is
/// skipped rather than risk deleting a live peer process's fenced turns.
#[cfg(not(unix))]
fn acquire_off_record_open_lock(_dir: &Path) -> Result<(Option<std::fs::File>, bool)> {
    Ok((None, false))
}

/// Downgrades the exclusive open lock — held through the crash-orphan sweep — to
/// a SHARED lock for the remainder of the vault's lifetime, admitting concurrent
/// shared openers now that recovery has finished and parked peers can proceed. A
/// no-op when no exclusive lock is held (a non-sole opener already holds SHARED).
#[cfg(unix)]
fn downgrade_off_record_open_lock(lock: &Option<std::fs::File>) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    if let Some(file) = lock {
        // SAFETY: `file` is the live, owned lock handle stored on the Vault;
        // downgrading a lock we already hold never blocks, and the `libc::flock`
        // return value is checked here.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) } != 0 {
            return Err(Error::InvariantViolation(
                "failed to downgrade off-record open lock to shared",
            ));
        }
    }
    Ok(())
}

/// Non-unix fallback: no advisory `flock` is held, so there is no exclusive lock
/// to downgrade.
#[cfg(not(unix))]
fn downgrade_off_record_open_lock(_lock: &Option<std::fs::File>) -> Result<()> {
    Ok(())
}

/// Contract stored-weight prior for `claim_of` edges (contracts.ts
/// `edgeKinds.pprWeight` = 1.0), unwrapped at COMPILE time: the writers below
/// hardwire kinds whose prior is pinned non-null, so a contract change to
/// `null` fails the build instead of the write.
pub(crate) const CLAIM_OF_DEFAULT_WEIGHT: f32 = match EdgeKind::ClaimOf.default_weight() {
    Some(weight) => weight,
    None => panic!("contract pins a non-null pprWeight for claim_of"),
};

/// Contract stored-weight prior for `supersedes` edges (contracts.ts
/// `edgeKinds.pprWeight` = 0.3); compile-time unwrapped like
/// [`CLAIM_OF_DEFAULT_WEIGHT`].
pub(crate) const SUPERSEDES_DEFAULT_WEIGHT: f32 = match EdgeKind::Supersedes.default_weight() {
    Some(weight) => weight,
    None => panic!("contract pins a non-null pprWeight for supersedes"),
};

/// Length of the edge-kind prefix: `entity_id (16) | kind (1)`.
const EDGE_KIND_PREFIX_LEN: usize = ENTITY_ID_LEN + 1;

/// Cap for `entities_by_type` to prevent unbounded allocation on large indexes.
const MAX_TYPE_QUERY_RESULTS: usize = 100_000;

/// Cap for `entities_in_learned_range` to prevent unbounded allocation on
/// wide time-range queries. Distinct from `MAX_TYPE_QUERY_RESULTS` so the two
/// APIs can be tuned independently.
const MAX_LEARNED_RANGE_RESULTS: usize = 100_000;

/// Cap for `targets`/`sources` to prevent unbounded allocation.
pub(crate) const MAX_EDGE_QUERY_RESULTS: usize = 100_000;

/// Cap for `subtree` to prevent unbounded allocation on deep trees.
const MAX_SUBTREE_RESULTS: usize = 50_000;

/// Cap for `sync_state_keys_with_prefix` to prevent unbounded allocation when
/// a pathological prefix scans a very large sync_state database.
#[cfg(feature = "sync")]
const MAX_SYNC_STATE_KEYS: usize = 10_000;

fn seed_default_policy_manifest(
    store: &Store,
    config: &VaultConfig,
    analyzer: &MultilingualAnalyzer,
    text_index_trusted: bool,
) -> Result<()> {
    let id = crate::gate::default_policy_manifest_id()?;
    let timestamp = crate::gate::DEFAULT_POLICY_MANIFEST_TIMESTAMP;
    let ops = vec![BatchOp::Put {
        id,
        entity_type: ENTITY_TYPE_POLICY_MANIFEST,
        occurred: TimeRange {
            start: timestamp,
            end: timestamp,
        },
        learned_at: timestamp,
        data: crate::gate::default_policy_manifest(),
        allow_maintenance: true,
        allow_reserved_predicate: false,
        hub_sync_imported: false,
    }];
    let mut wtxn = store.env.write_txn()?;
    apply_ops(
        store,
        config,
        analyzer,
        &mut wtxn,
        ops,
        text_index_trusted,
        false,
        true,
    )?;
    wtxn.commit()?;
    Ok(())
}

/// Build an edge prefix `[entity_id | kind]` for targeted LMDB prefix scans.
/// Avoids scanning all edge kinds for a given entity.
pub(crate) fn edge_kind_prefix(id: &EntityId, kind: EdgeKind) -> [u8; EDGE_KIND_PREFIX_LEN] {
    let mut prefix = [0u8; EDGE_KIND_PREFIX_LEN];
    prefix[..ENTITY_ID_LEN].copy_from_slice(id.as_bytes());
    prefix[ENTITY_ID_LEN] = kind as u8;
    prefix
}

pub(crate) fn require_key_len(key: &[u8], expected: usize, context: &'static str) -> Result<()> {
    if key.len() != expected {
        return Err(Error::CorruptedIndex(context));
    }
    Ok(())
}

pub(crate) fn entity_id_from_type_index_key(key: &[u8]) -> Result<EntityId> {
    require_key_len(key, 17, "type index key")?;
    EntityId::from_bytes(
        key[1..17]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("type index key"))?,
    )
    .map_err(|_| Error::CorruptedIndex("type index key"))
}

/// Returns the first outbound ChildOf parent for `node`, or `None` if it has
/// no ChildOf edge (i.e. it is a root).
///
/// Each node has at most one ChildOf parent. If multiple exist due to data
/// corruption, only the first by LMDB key order is returned.
fn first_child_of_parent(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    node: &EntityId,
) -> Result<Option<EntityId>> {
    let prefix = edge_kind_prefix(node, EdgeKind::ChildOf);
    if let Some(entry) = store.edges_out.prefix_iter(rtxn, &prefix)?.next() {
        let (key, value) = entry?;
        return Ok(Some(parse_edge_record(&key, &value)?.target));
    }
    Ok(None)
}

/// Result of resolving a context-pack short reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HydratedShortId {
    /// Entity id referenced by the short-id row.
    pub id: EntityId,
    /// Numeric entity type from the entity header, or zero for a dangling row.
    pub entity_type: u8,
    /// Entity learned-at timestamp from the header, or zero for a dangling row.
    pub learned_at: u64,
    /// Deletion metadata when the short-id row resolves to deleted state.
    pub deletion: Option<HydratedShortIdDeletion>,
    /// Entity body bytes. `None` means a deleted shell or dangling row.
    pub body: Option<Vec<u8>>,
}

/// Main vault API wrapping LMDB storage and configuration.
pub struct Vault {
    pub(crate) store: Store,
    pub(crate) config: VaultConfig,
    pub(crate) analyzer: MultilingualAnalyzer,
    /// `false` only when `Vault::open` ran with
    /// `skip_text_index_manifest_check = true` against a populated index.
    /// In that state the on-disk postings may have been written under a
    /// different analyzer manifest than the in-memory one, so scoring
    /// against them silently returns wrong results. `search_text` returns
    /// `Error::CorruptedIndex` until `MaintenanceBuilder::clear_text_index`
    /// rewrites the manifest. Reopening cleanly also restores trust via
    /// the regular handshake path.
    pub(crate) text_index_trusted: std::sync::atomic::AtomicBool,
    /// Live-window delete-routing seam (M4-10 / ONE-1135): a `Weak` to the
    /// production [`crate::sync::manager::WindowManager`], set by
    /// [`crate::sync::manager::WindowManager::attach_to_vault`]. When a
    /// deleted entity's window is OPEN, `write_crdt_tombstone` commits
    /// through the registry-owned live doc instead of a transient snapshot
    /// copy. `Weak` so the vault never keeps a dropped manager (and its
    /// observer subscriptions) alive.
    #[cfg(feature = "sync")]
    pub(crate) live_window_manager: std::sync::Mutex<std::sync::Weak<crate::sync::WindowManager>>,
    /// Distinguishes "no sync manager has ever been attached" from "a manager
    /// was attached but can no longer be queried". The latter is ambiguous for
    /// sweep safety and must defer.
    #[cfg(feature = "sync")]
    pub(crate) live_window_manager_attached: std::sync::atomic::AtomicBool,
    /// Advisory cross-process open lock proving sole ownership at open time.
    /// Held (as a SHARED flock) for the vault's lifetime so a peer process
    /// opening the same path cannot run the destructive off-record crash-orphan
    /// sweep against this process's live fenced turns. `None` when advisory file
    /// locking is unavailable (non-unix) or the lock file could not be held — in
    /// which case the destructive sweep is skipped. Named with a leading
    /// underscore: it exists purely for its `Drop` (closing the file releases
    /// the flock at vault teardown, so a subsequent sole opener can sweep).
    _off_record_open_lock: Option<std::fs::File>,
}

impl Vault {
    /// Opens or creates a vault at `path`.
    ///
    /// Open-time compatibility gates run in the canonical order documented at
    /// the top of [`crate::store`]: `Store::open` runs the storage gates
    /// (`vault_meta` created first → ABI gate → schema gate → DB-manifest set
    /// → DB opens → HNSW/dimension preflight → embedding-model preflight),
    /// then this function runs the analyzer / BM25F text-index handshake and
    /// the self-contained SKILL content-hash migration against `vault_meta`.
    /// The
    /// [`VaultConfig::skip_text_index_manifest_check`] escape hatch bypasses
    /// only that final handshake (and marks a populated text index untrusted
    /// so text reads/writes fail closed until
    /// [`crate::MaintenanceBuilder::clear_text_index`] commits).
    ///
    /// Every gate fails closed: the first failing gate returns its typed
    /// [`Error`] and no usable `Vault` handle is constructed.
    pub fn open(path: impl AsRef<Path>, config: VaultConfig) -> Result<Self> {
        // Production open always seeds the default policy manifest — the seed
        // decision is a compile-time `true` here, not a config field, so no
        // consumer build (including `--all-features`) can open a vault that
        // skips the default consent/policy gate.
        Self::open_seeded(path, config, true)
    }

    /// Opens a vault WITHOUT seeding the default policy manifest. TEST-SUPPORT
    /// ONLY — never call this from production code. It is compiled only under
    /// the `test-support` feature (enabled via this crate's own dev-dependency
    /// for the effect-spine integration oracle), hidden from the public docs,
    /// and named so it cannot be reached by accident. The production `open`
    /// above hardcodes seeding, so the normal, default way to open a vault can
    /// never skip the policy/consent gate; this explicit, doc-hidden, test-named
    /// opener is the only way to obtain an unseeded vault, and only when the test
    /// feature is deliberately enabled — the standard Rust `test-util`-feature
    /// pattern (cf. tokio's `test-util`).
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn open_unseeded_for_test(path: impl AsRef<Path>, config: VaultConfig) -> Result<Self> {
        Self::open_seeded(path, config, false)
    }

    fn open_seeded(
        path: impl AsRef<Path>,
        config: VaultConfig,
        seed_default_manifest: bool,
    ) -> Result<Self> {
        let path = path.as_ref();
        if config.dimensions == 0 {
            return Err(Error::InvalidConfig(
                "dimensions must be greater than zero".to_owned(),
            ));
        }
        if config.hnsw.m_max_0 == 0 {
            return Err(Error::InvalidConfig(
                "hnsw m_max_0 must be greater than zero".to_owned(),
            ));
        }
        if config.map_size < MIN_MAP_SIZE_BYTES {
            return Err(Error::InvalidConfig(format!(
                "map_size must be at least {MIN_MAP_SIZE_BYTES} bytes"
            )));
        }

        let store = Store::open(path, &config)?;
        let analyzer = MultilingualAnalyzer::discover(&config.dict_search_paths)
            .map_err(|e| Error::AnalyzerError(e.to_string()))?;
        let text_index_trusted = if config.skip_text_index_manifest_check {
            // Bypass-on-empty-index is fine — there are no postings under any
            // analyzer manifest yet, so anything we write next will be the
            // first authoritative state. Bypass-on-populated-index leaves the
            // on-disk postings potentially analyzer-incompatible with the
            // in-memory analyzer; mark the index untrusted so search fails
            // closed until `clear_text_index` runs. The same residual-rows
            // check used by the handshake applies — `total_docs == 0` alone
            // can still hide stale postings/forward/length/stats rows.
            let rtxn = store.env.read_txn()?;
            let empty = text_index_is_empty(&store, &rtxn)?;
            drop(rtxn);
            if empty {
                let mut wtxn = store.env.write_txn()?;
                write_text_index_manifest_if_empty(&store, &mut wtxn, &analyzer)?;
                wtxn.commit()?;
            }
            empty
        } else {
            handshake_text_index_manifest(&store, &analyzer)?;
            true
        };
        // Seed the default policy manifest for a fresh vault unless this is the
        // test-only open_unseeded_for_test path (seed_default_manifest = false).
        // Production `open` passes `true`, so seeding is never skippable through
        // the public API.
        if store.created_new_vault() && seed_default_manifest {
            seed_default_policy_manifest(&store, &config, &analyzer, text_index_trusted)?;
        }
        // The reserved system-agent-id occupancy census must complete BEFORE
        // any caller holds the handle — unconditionally, existing vaults
        // included. A legacy vault could otherwise DELETE an occupant of a
        // reserved id as its first operation (deletes never census), and the
        // later lazy census would record the id pristine, resurrecting the
        // preset's compiled Auto (delete-to-widen). New vaults already ran it
        // through the seed put above, making this a one-read no-op; a census
        // failure fails `open` rather than returning a handle whose preset
        // authority can never be established.
        {
            let mut wtxn = store.env.write_txn()?;
            crate::agent_def::scan_reserved_actor_ids_once(&store, &mut wtxn)?;
            wtxn.commit()?;
        }

        // Acquire the advisory cross-process open lock BEFORE the destructive
        // crash-orphan sweep, and learn whether this process is the sole opener
        // (no live peer currently holds the vault open).
        let (off_record_open_lock, sole_opener) = acquire_off_record_open_lock(path)?;
        let vault = Self {
            store,
            config,
            analyzer,
            text_index_trusted: std::sync::atomic::AtomicBool::new(text_index_trusted),
            #[cfg(feature = "sync")]
            live_window_manager: std::sync::Mutex::new(std::sync::Weak::new()),
            #[cfg(feature = "sync")]
            live_window_manager_attached: std::sync::atomic::AtomicBool::new(false),
            _off_record_open_lock: off_record_open_lock,
        };
        // Model A crash-orphan recovery: evaporate any durable off-record fence
        // rows left behind by a crash mid-session BEFORE the handle is usable,
        // so orphaned fenced base turns can never leak through whole-vault
        // export. No live window manager is attached yet, so the delete path
        // takes the durable route only. A no-op when there are zero orphans.
        // Runs before the content-hash backfill so the index reflects the
        // post-sweep state (evaporated turns are never indexed).
        //
        // CROSS-PROCESS SAFETY: run the sweep ONLY when this process holds sole
        // ownership of the vault (the exclusive open-lock probe succeeded) and
        // the open lock is STILL held exclusively for the duration of the sweep.
        // If a peer process is live on the same path, its in-process registry is
        // invisible here, so its live, non-empty fence rows would look exactly
        // like crash orphans; skipping the destructive sweep prevents this
        // process from PolicyDeleting the peer's live fenced turns. Holding
        // exclusivity through the sweep additionally blocks any NEW opener from
        // obtaining a usable vault and writing a fresh live fence mid-sweep (its
        // shared-lock acquisition parks until we downgrade below), so the sweep
        // can never delete a concurrently-created live turn. A later sole opener
        // (or the peer itself, on its next clean open) recovers the orphans
        // instead. The empty closed-fence markers never block export.
        if sole_opener {
            vault.sweep_orphaned_off_record_fences()?;
            // Companion recovery leg: evaporate orphaned off-record context
            // receipts (retrieval runs whose result_ids are activated-memory
            // ids) whose in-process registration was lost to a crash. Runs
            // under the same sole-ownership + still-exclusive open lock.
            vault.sweep_orphaned_off_record_receipts()?;
        }
        // Recovery is complete: downgrade the exclusive open lock to SHARED (a
        // no-op for a non-sole opener) so concurrent shared openers — parked on
        // their blocking shared-lock acquisition while we swept — can now
        // proceed. The shared lock is retained for the vault's lifetime.
        downgrade_off_record_open_lock(&vault._off_record_open_lock)?;
        // Rebuilds the content-hash → holder index (import/sync dedup) when it
        // is missing or stale; completes before any caller receives a usable
        // handle. ONE-1741 dropped the verdict-dedup half — scan verdicts now
        // anchor to the content bytes, so only the holder index is rebuilt.
        crate::skill_hub::backfill_content_hash_index_if_needed(&vault)?;
        Ok(vault)
    }

    /// Registers the production window manager as the live-window delete
    /// router (M4-10 / ONE-1135). Called by
    /// [`crate::sync::manager::WindowManager::attach_to_vault`].
    #[cfg(feature = "sync")]
    pub(crate) fn attach_live_window_manager(
        &self,
        manager: std::sync::Weak<crate::sync::WindowManager>,
    ) {
        self.live_window_manager_attached
            .store(true, std::sync::atomic::Ordering::Release);
        *self
            .live_window_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = manager;
    }

    /// Returns the registry-owned live window for `key` — paired with the
    /// manager's [`crate::sync::bridge::Materializer`], so the delete path
    /// can serialize its live-doc tombstone commit against Observer B
    /// callbacks — if a manager is attached AND currently has the window
    /// open. Lookup only — never opens a window (a delete must not fault a
    /// month into memory).
    #[cfg(feature = "sync")]
    pub(crate) fn live_window(
        &self,
        key: &crate::sync::WindowKey,
    ) -> Option<(
        std::sync::Arc<crate::sync::window::LoadedWindow>,
        std::sync::Arc<crate::sync::bridge::Materializer>,
        std::sync::Arc<crate::sync::WindowManager>,
    )> {
        let manager = self
            .live_window_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .upgrade()?;
        let window = manager.window(key)?;
        Some((
            window,
            std::sync::Arc::clone(manager.materializer()),
            manager,
        ))
    }

    /// Returns every registry-owned live window without faulting any closed
    /// month into memory. Promotion uses this because a newly unfenced target
    /// can release incident edges whose source belongs to another open month.
    #[cfg(feature = "sync")]
    pub(crate) fn live_windows(&self) -> Vec<std::sync::Arc<crate::sync::window::LoadedWindow>> {
        let Some(manager) = self
            .live_window_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .upgrade()
        else {
            return Vec::new();
        };
        manager
            .loaded_keys()
            .into_iter()
            .filter_map(|key| manager.window(&key))
            .collect()
    }

    /// Whether `key` is currently unsafe for sweep compaction: registered in
    /// an attached manager OR still retained by an outstanding orphaned
    /// `Arc<LoadedWindow>` after deregistration. A live doc holds the full op
    /// history in memory, and its next full-snapshot persist would rewrite
    /// that history over a shallow-compacted `d:w:` row, so the sweep must
    /// never compact while such a handle may persist.
    #[cfg(feature = "sync")]
    pub(crate) fn live_window_for_sweep(&self, key: &crate::sync::WindowKey) -> bool {
        let attached = self
            .live_window_manager_attached
            .load(std::sync::atomic::Ordering::Acquire);
        let manager = match self.live_window_manager.lock() {
            Ok(manager) => manager,
            Err(_) => return true,
        };
        match manager.upgrade() {
            Some(manager) => manager.window_live_for_sweep(key),
            None => attached,
        }
    }

    /// Internal guard: read paths over the text index must refuse to score
    /// when the analyzer-manifest handshake was bypassed on a populated
    /// index. See the docstring on `Vault::text_index_trusted`.
    pub(crate) fn ensure_text_index_trusted(&self) -> Result<()> {
        if self
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire)
        {
            Ok(())
        } else {
            Err(Error::CorruptedIndex(
                "text index handshake bypassed on populated index",
            ))
        }
    }

    /// Current text-index status. `analyzer_manifest` reflects the analyzer
    /// this vault was opened with; `schema_version` and `total_docs` reflect
    /// what was persisted by prior writes.
    pub fn text_index_status(&self) -> Result<TextIndexStatus> {
        let rtxn = self.store.env.read_txn()?;
        let total_docs = bm25::read_total_docs(&self.store, &rtxn)?;
        let schema_version = read_text_schema_version(&self.store, &rtxn)?;
        Ok(TextIndexStatus {
            total_docs,
            schema_version,
            analyzer_manifest: self.analyzer.manifest(),
        })
    }

    /// Read-only diagnostic snapshot of the persisted compatibility metadata
    /// that the open-time gates consume.
    ///
    /// This method describes the stored state without repairing, rebuilding,
    /// seeding, or validating it. Missing or legacy compatibility rows are
    /// reported as `None` plus an explicit state marker instead of being
    /// treated as gate failures.
    pub fn doctor(&self) -> Result<VaultDoctorReport> {
        let rtxn = self.store.env.read_txn()?;
        let mut unreadable_fields = Vec::new();
        let storage_abi_version = doctor_optional_u16(
            crate::store::read_vault_meta_u16(
                &self.store.vault_meta,
                &rtxn,
                STORAGE_ABI_VERSION_KEY,
                "storage ABI version",
            ),
            "vault_meta.storage_abi_version",
            &mut unreadable_fields,
        )?;
        let storage_schema_version = doctor_optional_u16(
            crate::store::read_vault_meta_u16(
                &self.store.vault_meta,
                &rtxn,
                STORAGE_SCHEMA_VERSION_KEY,
                "storage schema version",
            ),
            "vault_meta.schema_version",
            &mut unreadable_fields,
        )?;
        let embedding_model_id =
            doctor_embedding_model_id(&self.store, &rtxn, &mut unreadable_fields)?;
        let hnsw = doctor_hnsw(&self.store, &rtxn, &mut unreadable_fields)?;
        let analyzer_manifest_hash = doctor_hash_hex(
            &self.store,
            &rtxn,
            TEXT_ANALYZER_MANIFEST_HASH_KEY,
            "vault_meta.text_analyzer_manifest_hash",
            &mut unreadable_fields,
        )?;
        let bm25_field_schema_hash = doctor_hash_hex(
            &self.store,
            &rtxn,
            TEXT_BM25_FIELD_SCHEMA_HASH_KEY,
            "vault_meta.text_bm25_field_schema_hash",
            &mut unreadable_fields,
        )?;
        let text_index_schema_version = doctor_optional_u16(
            read_text_schema_version(&self.store, &rtxn),
            "vault_meta.text_index_schema_version",
            &mut unreadable_fields,
        )?;
        drop(rtxn);
        let db_manifest = {
            // Held for consistency with `Store::open`'s DB-open serialization;
            // the txn that performs `mdb_dbi_open` must finish before release.
            let _db_open_guard = lmdb_database_open_guard()?;
            let manifest_rtxn = self.store.env.read_txn()?;
            let report = doctor_db_manifest(&self.store, &manifest_rtxn)?;
            drop(manifest_rtxn);
            report
        };

        Ok(VaultDoctorReport {
            storage_abi_version,
            storage_schema_version,
            embedding_model_id,
            hnsw,
            analyzer_manifest_hash,
            bm25_field_schema_hash,
            text_index_schema_version,
            db_manifest,
            unreadable_fields,
        })
    }

    /// Registers a vault-scoped pack StructuralKind slot.
    ///
    /// The claim is persisted in `vault_meta` under the dynamic kind-registry
    /// key family and becomes visible to subsequent write validation and
    /// short-id allocation for this vault. The operation rejects reserved
    /// Semantic/CORE bytes, bytes outside `band`, maintenance-band bytes, and
    /// collisions with either static or already-registered runtime entries.
    pub fn register_structural_kind(
        &self,
        type_byte: u8,
        short_id_prefix: impl Into<String>,
        band: TypeByteBand,
        pack: impl Into<String>,
    ) -> Result<StructuralKindRegistration> {
        self.store
            .register_structural_kind(type_byte, short_id_prefix, band, pack)
    }

    /// Returns the dynamic StructuralKind registration for `type_byte`, if
    /// this vault has one. Static registry entries are not mirrored here.
    #[must_use]
    pub fn structural_kind_registration(
        &self,
        type_byte: u8,
    ) -> Option<StructuralKindRegistration> {
        self.store.structural_kind_registration(type_byte)
    }

    /// Returns all vault-scoped dynamic StructuralKind registrations sorted
    /// by type byte. Static registry entries are intentionally excluded.
    #[must_use]
    pub fn structural_kind_registrations(&self) -> Vec<StructuralKindRegistration> {
        self.store.structural_kind_registrations()
    }

    /// Stores an entity blob.
    pub fn put_entity(
        &self,
        id: &EntityId,
        entity_type: u8,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Result<()> {
        self.batch()
            .put(id, entity_type, occurred, learned_at, data)
            .commit()
    }

    /// Retrieves an entity blob by ID.
    pub fn get(&self, id: &EntityId) -> Result<Option<Vec<u8>>> {
        let rtxn = self.store.env.read_txn()?;
        let value = self.store.entities.get(&rtxn, id.as_bytes())?;
        let Some(bytes) = value else {
            return Ok(None);
        };

        if EntityMetadataHeader::parse(&bytes).is_none() {
            return Err(Error::CorruptedIndex("entity header"));
        }

        Ok(Some(bytes[ENTITY_METADATA_HEADER_LEN..].to_vec()))
    }

    // NOTE (ONE-1133): the bare non-txn `purge_entity_active_store` wrapper
    // was removed — both sync replay surfaces now route through the
    // reason-aware `apply_replayed_tombstone`, and a bare purge entry point
    // would be an invitation to bypass the ARCH-0038 reason semantics.

    pub(crate) fn read_entity_header(&self, id: &EntityId) -> Result<Option<EntityMetadataHeader>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("entity metadata"))
            .map(Some)
    }

    /// Stores a vector for an entity.
    pub fn put_vector(&self, id: &EntityId, vector: &[f32]) -> Result<()> {
        self.batch().vector(id, vector).commit()
    }

    /// Retrieves a vector for an entity.
    pub fn get_vector(&self, id: &EntityId) -> Result<Option<Vec<f32>>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(bytes) = self.store.vectors.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };

        let vector = le_bytes_to_f32_vec(&bytes)?;
        if vector.len() != self.config.dimensions {
            // Persisted-data corruption — the LMDB row decoded to a vector
            // whose length does not match the configured dimensionality.
            // Distinct from `DimensionMismatch`, which is reserved for
            // caller input validation in `search_vector` / `index_vector`.
            return Err(Error::CorruptedIndex("vector value"));
        }

        Ok(Some(vector))
    }

    /// Searches nearest neighbors by cosine similarity using the HNSW index.
    pub fn search_vector(&self, query: &[f32], limit: usize) -> Result<Vec<ScoredEntity>> {
        Ok(self.search_vector_with_telemetry(query, limit)?.value)
    }

    /// Searches nearest neighbors by cosine similarity and returns the
    /// retrieval telemetry run id when the best-effort telemetry row was
    /// persisted.
    pub fn search_vector_with_telemetry(
        &self,
        query: &[f32],
        limit: usize,
    ) -> Result<RetrievalWithTelemetry<Vec<ScoredEntity>>> {
        // EMB-2: a `fast_dims`-length query is a first-class prefix query.
        if query.len() != self.config.dimensions
            && self.config.fast_dims.map(usize::from) != Some(query.len())
        {
            return Err(Error::DimensionMismatch {
                expected: self.config.dimensions,
                got: query.len(),
            });
        }
        if let Some(error) = Error::invalid_vector_component(query) {
            return Err(error);
        }

        let started_at = unix_seconds_now();
        let started = Instant::now();
        let results = {
            let rtxn = self.store.env.read_txn()?;
            // The direct vault path stays the exact-quality path for
            // full-length queries; the skip-rescore hot lane is a pipeline
            // feature (a `fast_dims`-length query is inherently prefix-only
            // on every path — no full query exists to rescore).
            hnsw::hnsw_search(
                &self.store,
                &self.config,
                &rtxn,
                query,
                limit,
                /* skip_rescore = */ false,
            )?
        };
        let run_id = self.record_vault_search_retrieval_run(
            RetrievalSignal::Vector,
            started_at,
            started,
            &results,
            limit,
        );
        Ok(RetrievalWithTelemetry {
            value: results,
            run_id,
        })
    }

    /// Stores a directed edge and its reverse index entry.
    pub fn put_edge(
        &self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        weight: f32,
    ) -> Result<()> {
        self.batch().edge(src, kind, tgt, weight).commit()
    }

    /// Stores a directed edge with explicit VAD scores.
    pub fn put_edge_with_vad(
        &self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        weight: f32,
        vad: Vad,
    ) -> Result<()> {
        self.batch()
            .edge_with_vad(src, kind, tgt, weight, vad)
            .commit()
    }

    /// Operational weight setter (ONE-1113, ARCH-0034 #write-protection
    /// carve-out): rewrites ONLY the weight bytes (f32 LE at offset 0..4) of
    /// an EXISTING edge, writing IDENTICAL bytes to both `edges_out` and
    /// `edges_in`. Weight is a LOCAL operational field (M3 weight pin) — the
    /// provenance Claim asserts the relation, never the weight — so this
    /// setter works on bare AND provenanced edges alike, preserves the
    /// 26-byte hot-flag bytes verbatim, and never touches provenance Claims.
    /// Exempt from the [`Error::EdgeIsProvenanced`] reject gate by
    /// construction.
    ///
    /// For decay / retrieval-feedback loops use the batch form
    /// [`BatchBuilder::set_edge_weight`].
    ///
    /// Fail-closed: [`Error::EdgeNotFound`] when the edge does not exist
    /// (the setter never upserts); [`Error::InvalidEdgeWeight`] outside the
    /// contract \[0, 1\]. PPR caches for the edge endpoints are invalidated
    /// exactly like a plain edge write.
    pub fn set_edge_weight(
        &self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        weight: f32,
    ) -> Result<()> {
        self.batch()
            .set_edge_weight(src, kind, tgt, weight)
            .commit()
    }

    /// Operational VAD setter (ONE-1113, ARCH-0034 #write-protection
    /// carve-out): rewrites ONLY the VAD bytes (three f32 LE at offset
    /// 12..24) of an EXISTING semantic edge, writing IDENTICAL bytes to both
    /// directions. Weight, `created_at`, the value LENGTH (a 24-byte bare
    /// value stays 24 B; a 26-byte provenanced value keeps its hot-flag
    /// bytes verbatim), and provenance Claims are untouched. Exempt from the
    /// [`Error::EdgeIsProvenanced`] reject gate by construction.
    ///
    /// For batched feedback loops use [`BatchBuilder::set_edge_vad`].
    ///
    /// Fail-closed: [`Error::EdgeNotFound`] when the edge does not exist;
    /// [`Error::InvalidVad`] on non-finite/out-of-range components; a typed
    /// rejection on structural 12-byte kinds (the contract layout table —
    /// structural edges carry no VAD).
    pub fn set_edge_vad(
        &self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        vad: Vad,
    ) -> Result<()> {
        self.batch().set_edge_vad(src, kind, tgt, vad).commit()
    }

    /// Binds an actor to a session-scoped write handle (ONE-1113 ruling,
    /// session ergonomics): bind the actor ONCE, then write provenanced
    /// edges normally — the handle injects `actor_entity_ref` +
    /// `actor_class` on every provenance-path write, so prod callers (e.g.
    /// the MCP daemon's named-writes lane, ARCH-0028) never type provenance
    /// by hand.
    ///
    /// The handle is pure ergonomics: NO sessions registry, NO
    /// authorization — "sessions are correlation-only, never authorization".
    /// Binding validates nothing by itself; every write through the handle
    /// runs the full [`Vault::put_edge_provenance`] gate chain (actor
    /// existence, D13 class validation, D14 precedence, …).
    ///
    /// NAMING: `as_actor` / [`ActorBound`] are INDICATIVE, engine-internal
    /// names (the ruling pins the semantics, not the ABI surface); the
    /// public ABI name is pinned at the FFI/NAPI milestone.
    #[must_use]
    pub fn as_actor(&self, actor: EntityId, actor_class: EdgeActorClass) -> ActorBound<'_> {
        ActorBound {
            vault: self,
            actor,
            actor_class,
        }
    }

    pub(crate) fn scoped_read_search_candidate_limit(
        &self,
        requested: usize,
        include_text: bool,
        include_vector: bool,
    ) -> Result<usize> {
        if requested == 0 {
            return Ok(0);
        }

        let rtxn = self.store.env.read_txn()?;
        let mut limit = requested;
        let mut hybrid_union_limit = 0usize;
        if include_text {
            let indexed_docs = usize::try_from(crate::bm25::read_total_docs(&self.store, &rtxn)?)
                .map_err(|_| Error::IndexOverflow("bm25 total docs"))?;
            hybrid_union_limit = hybrid_union_limit.saturating_add(indexed_docs);
            limit = limit.max(indexed_docs);
        }
        if include_vector {
            let indexed_vectors = crate::hnsw::hnsw_entity_count(&self.store, &rtxn)?;
            hybrid_union_limit = hybrid_union_limit.saturating_add(indexed_vectors);
            limit = limit.max(indexed_vectors);
        }
        if include_text && include_vector {
            limit = limit.max(hybrid_union_limit);
        }
        Ok(limit)
    }

    /// Deletes a directed edge and its reverse index entry.
    pub fn delete_edge(&self, src: &EntityId, kind: EdgeKind, tgt: &EntityId) -> Result<bool> {
        let key_out = Store::encode_edge_key(src, kind, tgt);
        let key_in = Store::encode_edge_key(tgt, kind, src);

        self.with_write_txn(|wtxn| {
            let existed_out = self.store.edges_out.delete(wtxn, &key_out)?;
            let deleted_in = self.store.edges_in.delete(wtxn, &key_in)?;

            if !existed_out {
                // Inbound-only rows are opportunistic cleanup for an inconsistent
                // reverse index and do not affect the outbound graph PPR uses.
                let _ = deleted_in;
                return Ok(false);
            }

            ppr::invalidate_ppr_for_edge(&self.store, wtxn, src, tgt)?;
            ppr::increment_graph_version(&self.store, wtxn)?;
            Ok(true)
        })
    }

    /// Returns outbound edges for `src`.
    pub fn edges_out(&self, src: &EntityId) -> Result<Vec<EdgeInfo>> {
        let rtxn = self.store.env.read_txn()?;
        scan_edges(&self.store.edges_out, &rtxn, src.as_bytes())
    }

    /// Returns inbound edges for `tgt`.
    pub fn edges_in(&self, tgt: &EntityId) -> Result<Vec<EdgeInfo>> {
        let rtxn = self.store.env.read_txn()?;
        scan_edges(&self.store.edges_in, &rtxn, tgt.as_bytes())
    }

    /// Bounded neighbor-edge scan for one direction with the kind and
    /// minimum-weight filters pushed into the LMDB prefix iterator, stopping
    /// after `limit` matches.
    ///
    /// Unlike [`Self::edges_out`]/[`Self::edges_in`] (which materialize every
    /// edge and error with [`Error::IndexOverflow`] past
    /// `MAX_EDGE_QUERY_RESULTS`), this walks only until `limit` matches accrue,
    /// so a high-degree node never allocates its full edge set. When `kind` is
    /// set the walk is further narrowed to the `[id | kind]` key span.
    pub(crate) fn neighbor_edges_bounded(
        &self,
        center: &EntityId,
        outbound: bool,
        kind: Option<EdgeKind>,
        min_weight: Option<f32>,
        limit: usize,
    ) -> Result<Vec<EdgeInfo>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let db = if outbound {
            &self.store.edges_out
        } else {
            &self.store.edges_in
        };
        let prefix: Vec<u8> = match kind {
            Some(kind) => edge_kind_prefix(center, kind).to_vec(),
            None => center.as_bytes().to_vec(),
        };
        let rtxn = self.store.env.read_txn()?;
        let mut edges = Vec::new();
        for entry in db.prefix_iter(&rtxn, prefix.as_slice())? {
            let (key, value) = entry?;
            let edge = parse_edge_record(&key, &value)?;
            if min_weight.is_some_and(|min| edge.weight < min) {
                continue;
            }
            edges.push(edge);
            if edges.len() >= limit {
                break;
            }
        }
        Ok(edges)
    }

    /// Returns BM25 text matches for a query under the contract-default
    /// rank profile.
    pub fn search_text(&self, query: &str, limit: usize) -> Result<Vec<ScoredEntity>> {
        Ok(self.search_text_with_telemetry(query, limit)?.value)
    }

    /// Returns BM25 text matches and the retrieval telemetry run id when the
    /// best-effort telemetry row was persisted.
    pub fn search_text_with_telemetry(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<RetrievalWithTelemetry<Vec<ScoredEntity>>> {
        self.search_text_with_profile_and_telemetry(
            query,
            limit,
            &crate::config::Bm25RankProfile::default(),
        )
    }

    /// Returns BM25 text matches for a query under a caller-supplied
    /// scoring-only rank profile (ARCH-0031: Okapi vs `Plus { delta }`,
    /// per-channel weight / `b`). The profile never touches the on-disk
    /// index or the open-time manifest handshake — changing it does not
    /// require a reindex. Invalid profiles fail closed with
    /// [`crate::Error::InvalidRankProfile`].
    pub fn search_text_with_profile(
        &self,
        query: &str,
        limit: usize,
        profile: &crate::config::Bm25RankProfile,
    ) -> Result<Vec<ScoredEntity>> {
        Ok(self
            .search_text_with_profile_and_telemetry(query, limit, profile)?
            .value)
    }

    /// Returns BM25 text matches for a caller-supplied profile and the
    /// retrieval telemetry run id when the best-effort telemetry row was
    /// persisted.
    pub fn search_text_with_profile_and_telemetry(
        &self,
        query: &str,
        limit: usize,
        profile: &crate::config::Bm25RankProfile,
    ) -> Result<RetrievalWithTelemetry<Vec<ScoredEntity>>> {
        let config = profile.to_bm25_config()?;
        self.ensure_text_index_trusted()?;
        let started_at = unix_seconds_now();
        let started = Instant::now();
        let results = {
            let rtxn = self.store.env.read_txn()?;
            bm25::search_text(&self.store, &rtxn, &self.analyzer, &config, query, limit)?
        };
        let run_id = self.record_vault_search_retrieval_run(
            RetrievalSignal::Text,
            started_at,
            started,
            &results,
            limit,
        );
        Ok(RetrievalWithTelemetry {
            value: results,
            run_id,
        })
    }

    fn record_vault_search_retrieval_run(
        &self,
        signal: RetrievalSignal,
        started_at: u64,
        started: Instant,
        results: &[ScoredEntity],
        limit: usize,
    ) -> Option<RetrievalRunId> {
        let score_breakdown = vault_search_score_breakdown(signal, results);
        let run_id = RetrievalRunId::now();
        let record = RetrievalRunRecord::new(
            run_id,
            RetrievalAction::VaultSearch,
            started_at,
            started.elapsed().as_micros().min(u64::MAX as u128) as u64,
            vec![signal],
            score_breakdown,
            results.len(),
            0,
            (limit > 0 && results.is_empty()).then(|| "NoData".to_owned()),
        );
        if let Err(error) = self.store.record_retrieval_run(&record) {
            tracing::warn!(
                ?error,
                "vault search retrieval telemetry write failed; continuing retrieval"
            );
            None
        } else {
            Some(run_id)
        }
    }

    /// Creates a new write batch builder bound to this vault.
    pub fn batch(&self) -> BatchBuilder<'_> {
        BatchBuilder::new(self)
    }

    /// Creates a batch builder that writes into an externally-owned transaction.
    ///
    /// Call `.apply(wtxn)` to execute writes without committing.
    /// Use with `with_write_txn()` for atomic multi-operation writes (e.g. entity + pm marker).
    pub fn batch_in(&self) -> TxnBatchBuilder<'_> {
        TxnBatchBuilder::new(self)
    }

    /// Creates a query pipeline builder for multi-signal retrieval.
    pub fn query(&self) -> PipelineBuilder<'_> {
        PipelineBuilder::new(self)
    }

    /// Creates a context pack builder for retrieval + hydration + serialization.
    pub fn context_pack(&self) -> ContextPackBuilder<'_> {
        ContextPackBuilder::new(self)
    }

    /// Returns the newest retrieval telemetry run rows, newest first.
    pub fn retrieval_runs(&self, limit: usize) -> Result<Vec<RetrievalRunRecord>> {
        self.store.retrieval_runs(limit)
    }

    /// Returns one published retrieval telemetry row by id.
    pub fn retrieval_run(&self, run_id: RetrievalRunId) -> Result<Option<RetrievalRunRecord>> {
        self.store.retrieval_run(run_id)
    }

    /// Returns the published trace keyed by a content-addressed fork hash.
    pub fn retrieval_trace_by_fork_hash(
        &self,
        fork_hash: RetrievalTraceForkHash,
    ) -> Result<Option<RetrievalTrace>> {
        self.store.retrieval_trace_by_fork_hash(fork_hash)
    }

    /// Returns the active RET-010 retrieval-blend weight table entry.
    pub fn retrieval_blend_weight_table(&self) -> Result<RetrievalBlendWeightTableEntry> {
        self.store.retrieval_blend_weight_table()
    }

    /// Tunes and persists the active RET-010 retrieval-blend weight table
    /// from persisted retrieval rewards.
    pub fn tune_retrieval_blend_weights(
        &self,
        config: RetrievalBlendTuningConfig,
    ) -> Result<RetrievalBlendWeightTableEntry> {
        self.store.tune_retrieval_blend_weights(config)
    }

    /// Idempotently writes or replaces a retrieval outcome row for one run.
    pub fn record_retrieval_outcome(&self, outcome: RetrievalOutcome) -> Result<()> {
        self.store.record_retrieval_outcome(outcome)
    }

    /// Returns outcome rows recorded for `run_id`, sorted by outcome key.
    pub fn retrieval_outcomes(
        &self,
        run_id: RetrievalRunId,
    ) -> Result<Vec<RetrievalOutcomeRecord>> {
        self.store.retrieval_outcomes(run_id)
    }

    /// Returns pending Gate consent proposals ordered by their write decision.
    pub fn pending_gate_consents(&self, limit: usize) -> Result<Vec<PendingGateConsentRecord>> {
        self.store.pending_gate_consents(limit)
    }

    /// Returns recent Gate decisions ordered from newest to oldest.
    pub fn gate_decisions(&self, limit: usize) -> Result<Vec<GateDecisionRecord>> {
        self.store.gate_decisions(limit)
    }

    /// Checks whether the active Gate policy has an actor-ceiling row for an actor.
    pub fn gate_actor_ceiling_exists(&self, actor_class: &str, actor_ref: &str) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &rtxn)?;
        Ok(policy.has_matching_actor_ceiling(actor_class, Some(actor_ref)))
    }

    /// Returns pending Gate consent proposals grouped by Dreamer run id.
    ///
    /// Proposals without a Dreamer run id are returned in the default lane,
    /// represented by a group with `dreamer_run_id == None`.
    pub fn pending_gate_consent_groups(
        &self,
        limit: usize,
    ) -> Result<Vec<PendingGateConsentGroup>> {
        self.store.pending_gate_consent_groups(limit)
    }

    /// Creates a maintenance builder for index and cache upkeep operations.
    pub fn maintain(&self) -> MaintenanceBuilder<'_> {
        MaintenanceBuilder::new(self)
    }

    /// Checks if an entity exists in the LMDB vault.
    pub fn entity_exists(&self, id: &EntityId) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        Ok(self.store.entities.get(&rtxn, id.as_bytes())?.is_some())
    }

    /// Checks if a directed edge exists in the LMDB vault.
    pub fn edge_exists(&self, src: &EntityId, kind: EdgeKind, tgt: &EntityId) -> Result<bool> {
        let key = Store::encode_edge_key(src, kind, tgt);
        let rtxn = self.store.env.read_txn()?;
        Ok(self.store.edges_out.get(&rtxn, &key)?.is_some())
    }

    /// Returns the `learned_at` timestamp from an entity's header (bytes 17-24).
    pub fn get_learned_at(&self, id: &EntityId) -> Result<u64> {
        let rtxn = self.store.env.read_txn()?;
        let raw = self
            .store
            .entities
            .get(&rtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        Ok(header.learned_at)
    }

    /// Returns the greatest `learned_at` timestamp present in the temporal index.
    pub fn latest_learned_at(&self) -> Result<Option<u64>> {
        let rtxn = self.store.env.read_txn()?;
        let Some((key, _)) = self.store.temporal_learned.last(&rtxn)? else {
            return Ok(None);
        };
        require_key_len(&key, 24, "temporal learned key")?;
        Ok(Some(u64::from_be_bytes(key[..8].try_into().map_err(
            |_| Error::CorruptedIndex("temporal learned key"),
        )?)))
    }

    /// Returns the greatest `learned_at` timestamp whose entity type is not excluded.
    pub fn latest_learned_at_excluding_entity_types(
        &self,
        excluded_types: &[u8],
    ) -> Result<Option<u64>> {
        let rtxn = self.store.env.read_txn()?;
        for entry in self.store.temporal_learned.rev_iter(&rtxn)? {
            let (key, _) = entry?;
            require_key_len(&key, 24, "temporal learned key")?;
            let learned_at = u64::from_be_bytes(
                key[..8]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("temporal learned key"))?,
            );
            let id = EntityId::from_bytes(
                key[8..24]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("temporal learned key"))?,
            )
            .map_err(|_| Error::CorruptedIndex("temporal learned key"))?;
            let raw = self
                .store
                .entities
                .get(&rtxn, id.as_bytes())?
                .ok_or(Error::CorruptedIndex("temporal learned dangling entity"))?;
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if !excluded_types.contains(&header.entity_type) {
                return Ok(Some(learned_at));
            }
        }
        Ok(None)
    }

    /// Returns entity IDs whose `learned_at` falls within `[start, end)`.
    ///
    /// Range-seeks the `temporal_learned` index by timestamp prefix.
    /// Returns an empty result when `start >= end`.
    pub fn entities_in_learned_range(&self, start: u64, end: u64) -> Result<Vec<EntityId>> {
        if start >= end {
            return Ok(Vec::new());
        }

        let rtxn = self.store.env.read_txn()?;
        let mut ids = Vec::new();
        let start_key = start.to_be_bytes();
        let end_key = end.to_be_bytes();
        for entry in self.store.temporal_learned.range(
            &rtxn,
            &(
                std::ops::Bound::Included(&start_key[..]),
                std::ops::Bound::Excluded(&end_key[..]),
            ),
        )? {
            let (key, _) = entry?;
            require_key_len(&key, 24, "temporal learned key")?;
            // Cap check BEFORE push so an exact-MAX result set returns Ok,
            // matching scan_edges semantics. Only an MAX+1-th in-range row
            // triggers IndexOverflow.
            if ids.len() >= MAX_LEARNED_RANGE_RESULTS {
                return Err(Error::IndexOverflow("entities_in_learned_range"));
            }
            let id = EntityId::from_bytes(
                key[8..24]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("temporal learned key"))?,
            )
            .map_err(|_| Error::CorruptedIndex("temporal learned key"))?;
            ids.push(id);
        }
        Ok(ids)
    }

    /// Executes a closure within a single LMDB write transaction.
    ///
    /// The transaction commits on `Ok(())` return and rolls back on `Err`.
    /// Used by the sync layer to atomically write entity data + pending-mirror markers.
    pub fn with_write_txn<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut heed::RwTxn<'_>) -> Result<T>,
    {
        self.try_with_write_txn(f)
    }

    /// Executes a closure within a single LMDB write transaction and allows
    /// callers to return their own error type.
    ///
    /// The transaction commits on `Ok` return and rolls back on `Err`.
    pub fn try_with_write_txn<F, T, E>(&self, f: F) -> std::result::Result<T, E>
    where
        F: FnOnce(&mut heed::RwTxn<'_>) -> std::result::Result<T, E>,
        E: From<Error>,
    {
        let mut wtxn = self.store.env.write_txn().map_err(Error::from)?;
        let result = {
            let _active_write_txn = crate::store::active_write_txn_guard();
            f(&mut wtxn)?
        };
        wtxn.commit().map_err(Error::from)?;
        Ok(result)
    }

    // Read/write/list helpers intentionally remain behind `feature = "sync"`
    // instead of `cfg(test)` because the sync bridge regression suite is an
    // integration test crate. Production bridge code still uses direct
    // transactional `sync_state` access when multiple keys must update
    // atomically.

    /// Reads a value from the sync_state database for sync integration tests
    /// and diagnostics.
    ///
    /// Production bridge code uses direct transactional access so multi-key
    /// sync-state updates stay atomic.
    #[doc(hidden)]
    #[cfg(feature = "sync")]
    pub fn sync_state_get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let rtxn = self.store.env.read_txn()?;
        Ok(self
            .store
            .sync_state
            .get(&rtxn, key)?
            .map(|bytes| bytes.to_vec()))
    }

    /// Reads a value from `sync_state` using an existing write transaction.
    #[doc(hidden)]
    #[cfg(feature = "sync")]
    pub fn sync_state_get_in_write_txn(
        &self,
        wtxn: &heed::RwTxn<'_>,
        key: &str,
    ) -> Result<Option<Vec<u8>>> {
        Ok(self
            .store
            .sync_state
            .get(wtxn, key)?
            .map(|bytes| bytes.to_vec()))
    }

    /// Writes a value to the sync_state database for sync integration tests
    /// and diagnostics.
    ///
    /// Production bridge code uses direct transactional access so multi-key
    /// sync-state updates stay atomic.
    #[doc(hidden)]
    #[cfg(feature = "sync")]
    pub fn sync_state_put(&self, key: &str, value: &[u8]) -> Result<()> {
        self.with_write_txn(|wtxn| {
            self.store.sync_state.put(wtxn, key, value)?;
            Ok(())
        })
    }

    /// Writes a value to `sync_state` using an existing write transaction.
    #[doc(hidden)]
    #[cfg(feature = "sync")]
    pub fn sync_state_put_in_write_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        key: &str,
        value: &[u8],
    ) -> Result<()> {
        self.store.sync_state.put(wtxn, key, value)?;
        Ok(())
    }

    /// Deletes a key from the sync_state database for diagnostics and
    /// server-side sync metadata cleanup.
    #[doc(hidden)]
    #[cfg(feature = "sync")]
    pub fn sync_state_delete(&self, key: &str) -> Result<bool> {
        self.with_write_txn(|wtxn| self.store.sync_state.delete(wtxn, key))
    }

    /// Lists all keys with the given prefix in sync_state for sync integration
    /// tests and diagnostics.
    ///
    /// Production bridge code uses direct transactional access so multi-key
    /// sync-state updates stay atomic.
    #[doc(hidden)]
    #[cfg(feature = "sync")]
    pub fn sync_state_keys_with_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        let rtxn = self.store.env.read_txn()?;
        let mut keys = Vec::new();
        let iter = self.store.sync_state.prefix_iter(&rtxn, prefix)?;
        for entry in iter {
            // Cap check BEFORE push — matches scan_edges semantics.
            if keys.len() >= MAX_SYNC_STATE_KEYS {
                return Err(Error::IndexOverflow("sync_state_keys_with_prefix"));
            }
            let (k, _) = entry?;
            keys.push(k.to_string());
        }
        Ok(keys)
    }

    /// Lists `sync_queue` rows with the given key prefix for sync
    /// integration tests and diagnostics (e.g. the `h:{seq:8BE}` hard-erase
    /// sweep family a replayed remote hard tombstone must enqueue).
    ///
    /// Production code uses direct transactional access so multi-key
    /// updates stay atomic.
    #[doc(hidden)]
    #[cfg(feature = "sync")]
    pub fn sync_queue_rows_with_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let rtxn = self.store.env.read_txn()?;
        let mut rows = Vec::new();
        for entry in self.store.sync_queue.prefix_iter(&rtxn, prefix)? {
            // Cap check BEFORE push — matches scan_edges semantics.
            if rows.len() >= MAX_SYNC_STATE_KEYS {
                return Err(Error::IndexOverflow("sync_queue_rows_with_prefix"));
            }
            let (k, v) = entry?;
            rows.push((k.to_vec(), v.to_vec()));
        }
        Ok(rows)
    }

    /// Returns the raw entity blob (header + data) for an entity.
    ///
    /// Unlike `get()` which strips the header, this returns the full LMDB value.
    pub fn get_raw(&self, id: &EntityId) -> Result<Option<Vec<u8>>> {
        let rtxn = self.store.env.read_txn()?;
        self.get_raw_in(&rtxn, id)
    }

    pub(crate) fn get_raw_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<Vec<u8>>> {
        Ok(self
            .store
            .entities
            .get(rtxn, id.as_bytes())?
            .map(|bytes| bytes.to_vec()))
    }

    /// Resolves a context-pack short reference to a live or soft-deleted entity.
    ///
    /// The caller supplies the parsed short id and one-byte content hash from
    /// the public `short_id:hash` form. `Ok(None)` means no short-id row exists.
    /// `Ok(Some(result))` with `result.body == None` means the short id resolves
    /// to a deleted shell or dangling row; a live entity returns its body bytes.
    pub fn hydrate_short_id(
        &self,
        short_id: &str,
        content_hash: u8,
    ) -> Result<Option<HydratedShortId>> {
        let rtxn = self.store.env.read_txn()?;
        let forward_key = encode_short_id_forward_key(short_id, content_hash);
        let Some(raw_id) = self.store.short_ids.get(&rtxn, &forward_key)? else {
            return Ok(None);
        };
        require_key_len(&raw_id, ENTITY_ID_LEN, "short id entity id")?;
        let id = EntityId::from_bytes(
            raw_id
                .as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("short id entity id"))?,
        )
        .map_err(|_| Error::CorruptedIndex("short id entity id"))?;

        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(Some(HydratedShortId {
                id,
                entity_type: 0,
                learned_at: 0,
                deletion: Some(HydratedShortIdDeletion {
                    source: HydratedShortIdDeletionSource::DanglingShortId,
                    reason: None,
                    deleted_at: None,
                    request_id: None,
                    // No entity row remains to inspect, so hydrate treats this
                    // as an effectively hard deletion and keeps the source explicit.
                    hard: true,
                }),
                body: None,
            }));
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        let entity_type = header.entity_type;
        let learned_at = header.learned_at;
        let body = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
        drop(rtxn);

        if body.is_empty()
            && let Some(deletion) = self.entity_deletion_metadata(&id, learned_at)?
        {
            return Ok(Some(HydratedShortId {
                id,
                entity_type,
                learned_at,
                deletion: Some(deletion),
                body: None,
            }));
        }

        Ok(Some(HydratedShortId {
            id,
            entity_type,
            learned_at,
            deletion: None,
            body: Some(body),
        }))
    }

    /// Returns true when an entity row is a soft-delete shell, not a live
    /// zero-byte payload.
    pub fn is_deleted_shell(&self, id: &EntityId) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(false);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if raw.len() != ENTITY_METADATA_HEADER_LEN {
            return Ok(false);
        }
        drop(rtxn);

        Ok(self
            .entity_deletion_metadata(id, header.learned_at)?
            .is_some())
    }

    // ─── Tree Query API ───────────────────────────────────────

    /// Returns all entity IDs of a given type via prefix scan on type_index.
    ///
    /// Returns all matching entity IDs, or `Err(IndexOverflow("entities_by_type"))`
    /// if the scan would exceed `MAX_TYPE_QUERY_RESULTS`.
    pub fn entities_by_type(&self, entity_type: u8) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        let mut ids = Vec::new();
        for entry in self.store.type_index.prefix_iter(&rtxn, &[entity_type])? {
            if ids.len() >= MAX_TYPE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("entities_by_type"));
            }
            let (key, _) = entry?;
            ids.push(entity_id_from_type_index_key(&key)?);
        }
        Ok(ids)
    }

    /// Returns at most `limit` entity IDs of a given type after `after`.
    ///
    /// This is the bounded counterpart to [`Self::entities_by_type`] for
    /// callers that must walk large type indexes incrementally. Results follow
    /// the same LMDB type-index key order as `entities_by_type`; `after` is an
    /// exclusive lower bound.
    pub fn entities_by_type_page(
        &self,
        entity_type: u8,
        after: Option<&EntityId>,
        limit: usize,
    ) -> Result<Vec<EntityId>> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let limit = limit.min(MAX_TYPE_QUERY_RESULTS);
        let rtxn = self.store.env.read_txn()?;
        let start_key = match after {
            Some(id) => Store::encode_type_key(entity_type, id).to_vec(),
            None => vec![entity_type],
        };
        let start_bound: std::ops::Bound<&[u8]> = match after {
            Some(_) => std::ops::Bound::Excluded(&start_key[..]),
            None => std::ops::Bound::Included(&start_key[..]),
        };
        let end_bound: std::ops::Bound<&[u8]> = std::ops::Bound::Unbounded;

        let mut ids = Vec::with_capacity(limit.min(1024));
        for entry in self
            .store
            .type_index
            .range(&rtxn, &(start_bound, end_bound))?
        {
            let (key, _) = entry?;
            if key.first() != Some(&entity_type) {
                break;
            }
            ids.push(entity_id_from_type_index_key(&key)?);
            if ids.len() >= limit {
                break;
            }
        }
        Ok(ids)
    }

    /// Returns up to `limit` latest entity bodies of a given type.
    ///
    /// Scans at most `scan_limit` rows from the `temporal_learned` index in
    /// newest-first order and reads matching entity bodies from the same LMDB
    /// snapshot, returning `(id, learned_at, body)` tuples.
    pub fn latest_entity_bodies_by_type(
        &self,
        entity_type: u8,
        limit: usize,
        scan_limit: usize,
    ) -> Result<Vec<(EntityId, u64, Vec<u8>)>> {
        if limit == 0 || scan_limit == 0 {
            return Ok(Vec::new());
        }

        let rtxn = self.store.env.read_txn()?;
        let lower: std::ops::Bound<&[u8]> = std::ops::Bound::Unbounded;
        let upper: std::ops::Bound<&[u8]> = std::ops::Bound::Unbounded;
        let mut rows = Vec::with_capacity(limit.min(1024));
        for (scanned, entry) in self
            .store
            .temporal_learned
            .rev_range(&rtxn, &(lower, upper))?
            .enumerate()
        {
            if scanned >= scan_limit {
                break;
            }

            let (key, _) = entry?;
            require_key_len(&key, 24, "temporal learned key")?;
            let learned_at = u64::from_be_bytes(
                key[..8]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("temporal learned key"))?,
            );
            let id = EntityId::from_bytes(
                key[8..24]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("temporal learned key"))?,
            )
            .map_err(|_| Error::CorruptedIndex("temporal learned key"))?;

            let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
                continue;
            };
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != entity_type {
                continue;
            }
            if header.learned_at != learned_at {
                return Err(Error::CorruptedIndex("temporal learned key"));
            }
            rows.push((
                id,
                header.learned_at,
                raw[ENTITY_METADATA_HEADER_LEN..].to_vec(),
            ));
            if rows.len() >= limit {
                break;
            }
        }
        Ok(rows)
    }

    /// Counts entity IDs of a given type via the `type_index` prefix path.
    ///
    /// This is the exact count primitive for deterministic paginated list
    /// metadata. It does not materialize entity IDs or read entity bodies.
    pub fn count_entities_by_type(&self, entity_type: u8) -> Result<u64> {
        let rtxn = self.store.env.read_txn()?;
        let mut total = 0_u64;
        for entry in self.store.type_index.prefix_iter(&rtxn, &[entity_type])? {
            let (key, _) = entry?;
            entity_id_from_type_index_key(&key)?;
            total = total
                .checked_add(1)
                .ok_or(Error::IndexOverflow("count_entities_by_type"))?;
        }
        Ok(total)
    }

    /// Returns the entity type byte for a stored entity, or None if not found.
    pub fn get_entity_type(&self, id: &EntityId) -> Result<Option<u8>> {
        let rtxn = self.store.env.read_txn()?;
        self.get_entity_type_in_txn(&rtxn, id)
    }

    /// Transaction-composable body of [`Vault::get_entity_type`].
    pub(crate) fn get_entity_type_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<u8>> {
        let Some(raw) = self.store.entities.get(txn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        Ok(Some(header.entity_type))
    }

    /// Outbound edge targets filtered by kind and optional target entity type.
    ///
    /// For a ChildOf edge (child → parent), calling `targets(child, ChildOf, None)`
    /// returns the parent.
    pub fn targets(
        &self,
        src: &EntityId,
        kind: EdgeKind,
        target_type: Option<u8>,
    ) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        self.filtered_edge_peers(
            &rtxn,
            &self.store.edges_out,
            src,
            kind,
            target_type,
            "targets",
        )
    }

    /// Inbound edge sources filtered by kind and optional source entity type.
    ///
    /// For a ChildOf edge (child → parent), calling `sources(parent, ChildOf, None)`
    /// returns the children.
    pub fn sources(
        &self,
        tgt: &EntityId,
        kind: EdgeKind,
        source_type: Option<u8>,
    ) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        self.filtered_edge_peers(
            &rtxn,
            &self.store.edges_in,
            tgt,
            kind,
            source_type,
            "sources",
        )
    }

    /// Returns at most `limit` inbound edge sources after `after_source`.
    ///
    /// This is the bounded counterpart to [`Self::sources`]. Results follow
    /// the LMDB inbound edge key order `[target | kind | source]`, so
    /// `after_source` is an exclusive lower bound on the source entity id.
    pub fn sources_page(
        &self,
        tgt: &EntityId,
        kind: EdgeKind,
        source_type: Option<u8>,
        after_source: Option<&EntityId>,
        limit: usize,
    ) -> Result<Vec<EntityId>> {
        self.filtered_edge_peers_page(
            &self.store.edges_in,
            tgt,
            kind,
            source_type,
            after_source,
            limit,
        )
    }

    /// Scans an edge database (edges_out or edges_in) for entries matching `kind`,
    /// returning the peer entity IDs. Optionally filters by the peer's entity type.
    ///
    /// Capped at `MAX_EDGE_QUERY_RESULTS` scanned peer rows to prevent
    /// unbounded allocation and worst-case filtered scans.
    pub(crate) fn filtered_edge_peers(
        &self,
        rtxn: &heed::RoTxn<'_>,
        db: &OverlayDb,
        prefix_id: &EntityId,
        kind: EdgeKind,
        peer_type: Option<u8>,
        overflow_context: &'static str,
    ) -> Result<Vec<EntityId>> {
        let prefix = edge_kind_prefix(prefix_id, kind);
        let mut ids = Vec::new();
        for (scanned, entry) in db.prefix_iter(rtxn, &prefix)?.enumerate() {
            if scanned >= MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow(overflow_context));
            }
            let (key, value) = entry?;
            let peer = parse_edge_record(&key, &value)?.target;

            if let Some(req_type) = peer_type
                && !self.entity_has_type(rtxn, &peer, req_type)?
            {
                continue;
            }

            ids.push(peer);
        }
        Ok(ids)
    }

    fn filtered_edge_peers_page(
        &self,
        db: &OverlayDb,
        prefix_id: &EntityId,
        kind: EdgeKind,
        peer_type: Option<u8>,
        after_peer: Option<&EntityId>,
        limit: usize,
    ) -> Result<Vec<EntityId>> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let limit = limit.min(MAX_EDGE_QUERY_RESULTS);
        let rtxn = self.store.env.read_txn()?;
        let prefix = edge_kind_prefix(prefix_id, kind);
        let start_key = match after_peer {
            Some(peer) => Store::encode_edge_key(prefix_id, kind, peer).to_vec(),
            None => prefix.to_vec(),
        };
        let start_bound: std::ops::Bound<&[u8]> = match after_peer {
            Some(_) => std::ops::Bound::Excluded(&start_key[..]),
            None => std::ops::Bound::Included(&start_key[..]),
        };
        let end_bound: std::ops::Bound<&[u8]> = std::ops::Bound::Unbounded;

        let mut ids = Vec::with_capacity(limit.min(1024));
        for entry in db.range(&rtxn, &(start_bound, end_bound))? {
            let (key, value) = entry?;
            if !key.starts_with(&prefix) {
                break;
            }
            let peer = parse_edge_record(&key, &value)?.target;

            if let Some(req_type) = peer_type
                && !self.entity_has_type(&rtxn, &peer, req_type)?
            {
                continue;
            }

            ids.push(peer);
            if ids.len() >= limit {
                break;
            }
        }
        Ok(ids)
    }

    /// Returns true if the entity exists and has the given type byte.
    ///
    /// Returns `Ok(false)` for missing entities or unparsable headers (corruption).
    /// This is intentional for edge filtering: a corrupted peer should be skipped,
    /// not fail the entire query. Compare with `get_entity_type()` which returns
    /// `Err(CorruptedIndex("entity header"))` on corruption — appropriate for
    /// direct lookups where the caller should know about data issues.
    fn entity_has_type(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
        expected_type: u8,
    ) -> Result<bool> {
        let Some(raw) = self.store.entities.get(rtxn, id.as_bytes())? else {
            return Ok(false);
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            return Ok(false);
        };
        Ok(header.entity_type == expected_type)
    }

    /// Subtree descendants via ChildOf traversal, limited to `max_depth`.
    /// Returns `(id, depth)` pairs sorted by depth.
    ///
    /// Uses BFS internally (queue-based) so that when the result cap is hit,
    /// shallower nodes are always included before deeper ones. This ensures
    /// fair capping across wide trees.
    /// Children are found via inbound ChildOf edges (since ChildOf direction is
    /// child → parent, children appear in the parent's edges_in).
    ///
    /// Returns all descendants, or `Err(IndexOverflow("subtree"))` if the
    /// result set or pending frontier would exceed `MAX_SUBTREE_RESULTS`.
    pub fn subtree(&self, root: &EntityId, max_depth: u32) -> Result<Vec<(EntityId, u32)>> {
        let rtxn = self.store.env.read_txn()?;
        let mut result = Vec::new();
        let mut frontier = std::collections::VecDeque::from([(*root, 0_u32)]);
        let mut visited = std::collections::HashSet::new();
        visited.insert(*root);

        while let Some((node, depth)) = frontier.pop_front() {
            if depth > 0 {
                if result.len() >= MAX_SUBTREE_RESULTS {
                    return Err(Error::IndexOverflow("subtree"));
                }
                result.push((node, depth));
            }
            if depth >= max_depth {
                continue;
            }

            // Find children: inbound ChildOf edges (child --ChildOf--> node)
            let child_prefix = edge_kind_prefix(&node, EdgeKind::ChildOf);
            for entry in self.store.edges_in.prefix_iter(&rtxn, &child_prefix)? {
                let (key, value) = entry?;
                let child = parse_edge_record(&key, &value)?.target;
                if visited.insert(child) {
                    if result.len() + frontier.len() >= MAX_SUBTREE_RESULTS {
                        return Err(Error::IndexOverflow("subtree"));
                    }
                    frontier.push_back((child, depth + 1));
                }
            }
        }

        // BFS already produces depth-ordered results, but sort to ensure
        // deterministic ordering within each depth level (by entity ID).
        result.sort_unstable_by(|a, b| {
            a.1.cmp(&b.1)
                .then_with(|| a.0.as_bytes().cmp(b.0.as_bytes()))
        });
        Ok(result)
    }

    /// Walk ancestors via outbound ChildOf edges.
    ///
    /// Returns ancestor IDs from immediate parent to root (nearest first).
    /// The `visited` set prevents infinite loops on corrupted cyclic data, and
    /// `MAX_ANCESTOR_DEPTH` bounds pathological acyclic chains.
    pub fn ancestors(&self, node: &EntityId) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        let mut result = Vec::new();
        let mut current = *node;
        let mut visited = std::collections::HashSet::new();
        visited.insert(current);

        while let Some(parent) = first_child_of_parent(&self.store, &rtxn, &current)? {
            if !visited.insert(parent) {
                break; // Cycle detected — stop walking but don't error
            }
            if result.len() >= MAX_ANCESTOR_DEPTH {
                return Err(Error::IndexOverflow("ancestors"));
            }
            result.push(parent);
            current = parent;
        }

        Ok(result)
    }

    /// Checks whether making `target` a parent of `node` would create a cycle.
    ///
    /// Convenience wrapper that opens its own read transaction.
    /// For atomic check+insert, use `would_create_cycle_in_txn` within a
    /// write transaction (see `BatchBuilder::edge_checked`).
    pub fn would_create_cycle(&self, node: &EntityId, target: &EntityId) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        self.would_create_cycle_in_txn(&rtxn, node, target)
    }

    /// Checks whether making `target` a parent of `node` would create a cycle,
    /// using the provided read transaction for atomicity with subsequent writes.
    ///
    /// Walks ancestors of `target` — if `node` is found among them, it's a cycle.
    /// Short-circuits as soon as `node` is found instead of collecting all ancestors.
    /// The `visited` set prevents infinite loops on corrupted cyclic data, and
    /// `MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS` bounds pathological acyclic chains.
    pub(crate) fn would_create_cycle_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        node: &EntityId,
        target: &EntityId,
    ) -> Result<bool> {
        if node == target {
            return Ok(true);
        }
        let mut current = *target;
        let mut visited = std::collections::HashSet::new();
        visited.insert(current);
        let mut traversed_steps = 0usize;

        while let Some(parent) = first_child_of_parent(&self.store, rtxn, &current)? {
            if traversed_steps >= MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS {
                return Err(Error::IndexOverflow(ERR_CHILD_OF_CYCLE_CHECK));
            }
            traversed_steps += 1;
            if parent == *node {
                return Ok(true);
            }
            if !visited.insert(parent) {
                break; // Existing cycle in data — stop walking
            }
            current = parent;
        }
        Ok(false)
    }
}

/// A session-scoped actor binding created by [`Vault::as_actor`]
/// (ONE-1113 ruling, session ergonomics): the handle carries
/// `actor_entity_ref` + the caller-supplied D13 `actor_class` and injects
/// both on every provenance-path write, so a bound caller "writes normally"
/// after binding once. The MCP daemon injects the session actor on the
/// named-writes lane (ARCH-0028) through exactly this surface.
///
/// The binding is correlation-only ergonomics — NO sessions registry, NO
/// authorization, NO stored state. Every write delegates to
/// [`Vault::put_edge_provenance`] and runs its full fail-closed gate chain.
///
/// NAMING: engine-internal until ABI-pinned (the ruling pins semantics, not
/// names); expect the public surface name to be ratified at the FFI/NAPI
/// milestone.
#[derive(Clone, Copy)]
pub struct ActorBound<'a> {
    vault: &'a Vault,
    actor: EntityId,
    actor_class: EdgeActorClass,
}

impl ActorBound<'_> {
    /// The bound actor entity reference.
    #[must_use]
    pub fn actor(&self) -> EntityId {
        self.actor
    }

    /// The bound caller-supplied D13 actor class.
    #[must_use]
    pub fn actor_class(&self) -> EdgeActorClass {
        self.actor_class
    }

    /// Builds an `edge.provenance` value record pre-filled with the BOUND
    /// actor — the "write normally" entry point: fill `confidence` +
    /// `supersession_status`, set optional fields on the returned record,
    /// then pass it to [`ActorBound::put_edge_provenance`].
    #[must_use]
    pub fn provenance_body(
        &self,
        confidence: f32,
        supersession_status: SupersessionStatus,
    ) -> EdgeProvenanceClaimBody {
        EdgeProvenanceClaimBody::new(self.actor, confidence, supersession_status)
    }

    /// Writes an `edge.provenance` Claim for `subject` carrying the BOUND
    /// actor + class — delegates to [`Vault::put_edge_provenance`] with the
    /// bound `actor_class` injected, running the full gate chain (write-once
    /// id, subject-edge existence, D13 actor validation, D14 precedence,
    /// implicit supersession, winner restamp, PPR invalidation).
    ///
    /// Fail-closed binding check: a `body.actor_entity_ref` that names a
    /// DIFFERENT entity than the bound actor is rejected typed
    /// ([`Error::InvalidProvenanceBody`]) — the handle injects the actor, it
    /// never silently rewrites a conflicting one. Construct the record via
    /// [`ActorBound::provenance_body`] to avoid the mismatch entirely.
    pub fn put_edge_provenance(
        &self,
        claim_id: &EntityId,
        subject: &EdgeRef,
        body: &EdgeProvenanceClaimBody,
        learned_at: u64,
    ) -> Result<()> {
        if body.actor_entity_ref != self.actor {
            return Err(Error::InvalidProvenanceBody(
                "body actor_entity_ref conflicts with the session-bound actor",
            ));
        }
        self.vault
            .put_edge_provenance(claim_id, subject, body, self.actor_class, learned_at)
    }
}

fn scan_edges(
    database: &OverlayDb,
    rtxn: &heed::RoTxn<'_>,
    prefix: &[u8; 16],
) -> Result<Vec<EdgeInfo>> {
    let mut edges = Vec::new();
    for entry in database.prefix_iter(rtxn, prefix.as_slice())? {
        if edges.len() >= MAX_EDGE_QUERY_RESULTS {
            // Fail loud — sync mirror paths (replay_pending_mirrors,
            // reverse_rematerialize) must not silently truncate edges
            // for high-degree nodes.
            return Err(Error::IndexOverflow("scan_edges"));
        }
        let (key, value) = entry?;
        edges.push(parse_edge_record(&key, &value)?);
    }
    Ok(edges)
}

fn vault_search_score_breakdown(
    signal: RetrievalSignal,
    results: &[ScoredEntity],
) -> Vec<RetrievalScoreBreakdown> {
    results
        .iter()
        .enumerate()
        .map(|(index, result)| {
            let rank = u32::try_from(index.saturating_add(1)).unwrap_or(u32::MAX);
            RetrievalScoreBreakdown {
                result_id: *result.id.as_bytes(),
                final_rank: rank,
                final_score: result.score,
                components: vec![RetrievalScoreComponent {
                    signal,
                    rank,
                    score: result.score,
                }],
            }
        })
        .collect()
}

/// Snapshot of a vault's text-index state. Returned from
/// [`Vault::text_index_status`].
#[derive(Debug, Clone)]
pub struct TextIndexStatus {
    /// Number of logical documents currently indexed.
    pub total_docs: u32,
    /// Schema version recorded on disk. `None` for vaults with no text
    /// index writes yet.
    pub schema_version: Option<u16>,
    /// Analyzer manifest resolved at open time (reflects dict discovery
    /// against `VaultConfig.dict_search_paths`).
    pub analyzer_manifest: AnalyzerManifest,
}

/// Read-only report of vault open-integrity metadata returned by
/// [`Vault::doctor`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct VaultDoctorReport {
    /// Value read from `vault_meta["storage_abi_version"]`.
    pub storage_abi_version: Option<u16>,
    /// Value read from `vault_meta["schema_version"]`.
    pub storage_schema_version: Option<u16>,
    /// Value read from `hnsw_meta["model_id"]`.
    pub embedding_model_id: Option<String>,
    /// Vector/HNSW compatibility state read from `hnsw_meta["hnsw_config"]`.
    pub hnsw: VaultDoctorHnswReport,
    /// Lowercase hex of `vault_meta["text_analyzer_manifest_hash"]`.
    pub analyzer_manifest_hash: Option<String>,
    /// Lowercase hex of `vault_meta["text_bm25_field_schema_hash"]`.
    pub bm25_field_schema_hash: Option<String>,
    /// Value read from `vault_meta["text_index_schema_version"]`.
    pub text_index_schema_version: Option<u16>,
    /// ARCH-0019 named database manifest presence.
    pub db_manifest: VaultDoctorDbManifestReport,
    /// Metadata fields whose rows were present but could not be decoded.
    pub unreadable_fields: Vec<String>,
}

/// State of the persisted HNSW compatibility row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum VaultDoctorHnswRecordState {
    /// No `hnsw_config` row is present.
    Missing,
    /// Legacy row shape without metric/structure tags.
    Legacy,
    /// Current row shape with all compatibility fields.
    Current,
    /// Row exists but does not match any known compatibility encoding.
    Invalid,
}

/// Vector/HNSW compatibility values persisted in `hnsw_meta`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct VaultDoctorHnswReport {
    /// Encoding state of `hnsw_meta["hnsw_config"]`.
    pub record_state: VaultDoctorHnswRecordState,
    /// Persisted vector dimensions.
    pub vector_dimensions: Option<usize>,
    /// Persisted layer-0 HNSW neighbor cap.
    pub m_max_0: Option<usize>,
    /// Persisted HNSW construction beam width.
    pub ef_construction: Option<usize>,
    /// Persisted vector distance metric.
    pub distance_metric: Option<String>,
    /// Persisted vector index structure.
    pub index_structure: Option<String>,
}

/// Presence report for the ARCH-0019 named LMDB database manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct VaultDoctorDbManifestReport {
    /// Number of databases required by `DB_MANIFEST`.
    pub expected_count: usize,
    /// Number of required databases found in the LMDB unnamed database.
    pub present_count: usize,
    /// Required database names found in the LMDB unnamed database.
    pub present_names: Vec<String>,
    /// Required database names missing from the LMDB unnamed database.
    pub missing_names: Vec<String>,
    /// Extra named databases not listed in `DB_MANIFEST`.
    pub unexpected_names: Vec<String>,
}

/// Canonical hash over BM25F field-schema semantics that make existing
/// posting, forward, and field-length rows compatible with this build.
/// Scoring-only knobs such as weights and `b` are deliberately excluded.
fn bm25_field_schema_hash() -> [u8; 32] {
    bm25_field_schema_hash_for_records(&bm25_field_schema_records(
        &bm25::Bm25Config::default(),
        bm25::POSTINGS_VALUE_FORMAT_VERSION,
    ))
}

#[derive(Clone, Copy)]
struct Bm25FieldSchemaRecord {
    field_id: u16,
    channel_name: &'static str,
    length_policy: bm25::FieldLengthPolicy,
    permits_zero_doc_field_length: bool,
    postings_value_format_version: u16,
}

fn bm25_field_schema_records(
    config: &bm25::Bm25Config,
    postings_value_format_version: u16,
) -> Vec<Bm25FieldSchemaRecord> {
    AnalyzerChannel::ALL_V1
        .into_iter()
        .map(|channel| Bm25FieldSchemaRecord {
            field_id: channel.field_id(),
            channel_name: channel.as_str(),
            length_policy: config.field(channel).length_policy,
            permits_zero_doc_field_length: channel.permits_zero_doc_field_length(),
            postings_value_format_version,
        })
        .collect()
}

fn bm25_field_schema_hash_for_records(records: &[Bm25FieldSchemaRecord]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"oneiron-bm25-field-schema-v2");
    h.update([0]);
    for record in records {
        h.update(record.field_id.to_le_bytes());
        h.update([0]);
        h.update(record.channel_name.as_bytes());
        h.update([0]);
        h.update(record.length_policy.manifest_tag().as_bytes());
        h.update([0]);
        h.update([u8::from(record.permits_zero_doc_field_length)]);
        h.update([0]);
        h.update(record.postings_value_format_version.to_le_bytes());
        h.update([0]);
    }
    h.finalize().into()
}

fn read_text_schema_version(store: &Store, rtxn: &heed::RoTxn<'_>) -> Result<Option<u16>> {
    let Some(raw) = store.vault_meta.get(rtxn, TEXT_INDEX_SCHEMA_VERSION_KEY)? else {
        return Ok(None);
    };
    let bytes: [u8; 2] = raw
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex("text schema version"))?;
    Ok(Some(u16::from_le_bytes(bytes)))
}

fn read_hash_32(store: &Store, rtxn: &heed::RoTxn<'_>, key: &[u8]) -> Result<Option<[u8; 32]>> {
    let Some(raw) = store.vault_meta.get(rtxn, key)? else {
        return Ok(None);
    };
    let arr: [u8; 32] = raw
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex("text index hash"))?;
    Ok(Some(arr))
}

fn doctor_optional_u16(
    value: Result<Option<u16>>,
    field: &'static str,
    unreadable_fields: &mut Vec<String>,
) -> Result<Option<u16>> {
    match value {
        Ok(value) => Ok(value),
        Err(Error::CorruptedIndex(_) | Error::InvalidKey) => {
            unreadable_fields.push(field.to_owned());
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

fn doctor_hash_hex(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    key: &[u8],
    field: &'static str,
    unreadable_fields: &mut Vec<String>,
) -> Result<Option<String>> {
    match read_hash_32(store, rtxn, key) {
        Ok(Some(hash)) => Ok(Some(bytes_to_hex_lower(&hash))),
        Ok(None) => Ok(None),
        Err(Error::CorruptedIndex(_) | Error::InvalidKey) => {
            unreadable_fields.push(field.to_owned());
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

fn doctor_embedding_model_id(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    unreadable_fields: &mut Vec<String>,
) -> Result<Option<String>> {
    let Some(raw) = store.hnsw_meta.get(rtxn, MODEL_ID_KEY)? else {
        return Ok(None);
    };
    match crate::store::parse_utf8_bytes(&raw) {
        Ok(model_id) => Ok(Some(model_id)),
        Err(Error::InvalidKey | Error::CorruptedIndex(_)) => {
            unreadable_fields.push("hnsw_meta.model_id".to_owned());
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

fn doctor_hnsw(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    unreadable_fields: &mut Vec<String>,
) -> Result<VaultDoctorHnswReport> {
    match crate::store::read_hnsw_compatibility(&store.hnsw_meta, rtxn) {
        Ok(HnswCompatibilityState::Missing) => Ok(VaultDoctorHnswReport {
            record_state: VaultDoctorHnswRecordState::Missing,
            vector_dimensions: None,
            m_max_0: None,
            ef_construction: None,
            distance_metric: None,
            index_structure: None,
        }),
        Ok(HnswCompatibilityState::Legacy(config)) => Ok(VaultDoctorHnswReport {
            record_state: VaultDoctorHnswRecordState::Legacy,
            vector_dimensions: Some(config.dimensions),
            m_max_0: Some(config.m_max_0),
            ef_construction: Some(config.ef_construction),
            distance_metric: None,
            index_structure: None,
        }),
        Ok(HnswCompatibilityState::Current(config)) => Ok(VaultDoctorHnswReport {
            record_state: VaultDoctorHnswRecordState::Current,
            vector_dimensions: Some(config.dimensions),
            m_max_0: Some(config.m_max_0),
            ef_construction: Some(config.ef_construction),
            distance_metric: Some(crate::store::format_hnsw_distance_metric(
                config.distance_metric,
            )),
            index_structure: Some(crate::store::format_hnsw_index_structure(
                config.index_structure,
            )),
        }),
        Err(Error::InvalidKey | Error::CorruptedIndex(_)) => {
            unreadable_fields.push("hnsw_meta.hnsw_config".to_owned());
            Ok(VaultDoctorHnswReport {
                record_state: VaultDoctorHnswRecordState::Invalid,
                vector_dimensions: None,
                m_max_0: None,
                ef_construction: None,
                distance_metric: None,
                index_structure: None,
            })
        }
        Err(err) => Err(err),
    }
}

fn doctor_db_manifest(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
) -> Result<VaultDoctorDbManifestReport> {
    let env_names = crate::store::materialized_database_names(&store.env, rtxn)?;
    let mut present_names = Vec::new();
    let mut missing_names = Vec::new();

    for entry in DB_MANIFEST {
        if env_names.iter().any(|name| name == entry.name) {
            present_names.push(entry.name.to_owned());
        } else {
            missing_names.push(entry.name.to_owned());
        }
    }

    let mut unexpected_names: Vec<String> = env_names
        .into_iter()
        .filter(|name| !DB_MANIFEST.iter().any(|entry| entry.name == name))
        .collect();

    present_names.sort();
    missing_names.sort();
    unexpected_names.sort();

    Ok(VaultDoctorDbManifestReport {
        expected_count: DB_MANIFEST.len(),
        present_count: present_names.len(),
        present_names,
        missing_names,
        unexpected_names,
    })
}

/// Returns `true` when none of the text-index DBs hold residual rows.
///
/// The `total_docs` sentinel alone isn't authoritative — a zero or missing
/// sentinel coexisting with rows in any of the text DBs is corruption, not
/// emptiness.
fn text_index_residual_rows_empty(store: &Store, txn: &heed::RoTxn<'_>) -> Result<bool> {
    let residual = store.text_postings.len(txn)?
        + store.text_forward.len(txn)?
        + store.text_doc_field_lengths.len(txn)?
        + store.text_bm25_field_stats.len(txn)?;
    Ok(residual == 0)
}

/// Whether the on-disk text index is fully empty: zero `total_docs` AND
/// no residual rows in any text DB. Used by `Vault::open` to decide
/// whether bypassing the manifest handshake is safe.
fn text_index_is_empty(store: &Store, txn: &heed::RoTxn<'_>) -> Result<bool> {
    if bm25::read_total_docs(store, txn)? != 0 {
        return Ok(false);
    }
    text_index_residual_rows_empty(store, txn)
}

/// Validate the on-disk analyzer manifest against the in-memory one. Runs
/// once at `Vault::open`. States are handled per plan ONE-317 §4.2:
///
/// * empty index, any stored state → rewrite manifest, proceed
/// * non-empty, matching hashes → proceed
/// * non-empty, field schema mismatch → `Bm25FieldSchemaChanged`
/// * non-empty, manifest hash mismatch → `IncompatibleAnalyzer` naming the
///   first language whose mode flipped (or `*` when the stored manifest is
///   absent / unparsable, i.e. pre-ONE-317 vault)
fn handshake_text_index_manifest(store: &Store, analyzer: &MultilingualAnalyzer) -> Result<()> {
    let current_manifest = analyzer.manifest();
    let current_manifest_hash = current_manifest
        .canonical_hash()
        .map_err(|e| Error::AnalyzerError(format!("manifest hash: {e}")))?;
    let current_field_schema_hash = bm25_field_schema_hash();

    // Hash-match is the common path on Vault::open and is read-only; only
    // the empty-index rewrite branch mutates. Take a read txn first and
    // upgrade only when we actually need to write.
    let rtxn = store.env.read_txn()?;
    let total_docs = bm25::read_total_docs(store, &rtxn)?;

    if total_docs == 0 {
        // The `total_docs` sentinel alone isn't sufficient to declare the
        // index empty: a missing or zeroed sentinel coexisting with rows
        // in the inverted/forward/length/stats DBs would let us silently
        // rewrite the manifest over a populated incompatible index. Refuse
        // to rewrite unless every text DB is actually empty.
        if !text_index_residual_rows_empty(store, &rtxn)? {
            return Err(Error::CorruptedIndex(
                "text index sentinel missing with residual rows",
            ));
        }
        drop(rtxn);
        let mut wtxn = store.env.write_txn()?;
        write_text_index_manifest_if_empty(store, &mut wtxn, analyzer)?;
        wtxn.commit()?;
        return Ok(());
    }

    let stored_manifest_hash = read_hash_32(store, &rtxn, TEXT_ANALYZER_MANIFEST_HASH_KEY)?;
    let stored_field_schema_hash = read_hash_32(store, &rtxn, TEXT_BM25_FIELD_SCHEMA_HASH_KEY)?;
    let stored_manifest_bytes = store
        .vault_meta
        .get(&rtxn, TEXT_ANALYZER_MANIFEST_KEY)?
        .map(|b| b.to_vec());
    drop(rtxn);

    validate_stored_manifest_hashes(
        stored_manifest_hash,
        stored_field_schema_hash,
        current_manifest_hash,
        current_field_schema_hash,
        &current_manifest,
        stored_manifest_bytes,
    )
}

/// Compare a stored text-index manifest+field-schema hash pair against the
/// current analyzer state. Returns `Ok(())` on compatibility, or the
/// appropriate `IncompatibleAnalyzer` / `Bm25FieldSchemaChanged` /
/// `manifest_mismatch_error` outcome otherwise.
fn validate_stored_manifest_hashes(
    stored_manifest_hash: Option<[u8; 32]>,
    stored_field_schema_hash: Option<[u8; 32]>,
    current_manifest_hash: [u8; 32],
    current_field_schema_hash: [u8; 32],
    current_manifest: &AnalyzerManifest,
    stored_manifest_bytes: Option<Vec<u8>>,
) -> Result<()> {
    let Some(stored_hash) = stored_manifest_hash else {
        // Pre-ONE-317 vault with docs in it: fail closed.
        return Err(Error::IncompatibleAnalyzer {
            lang: "*".to_owned(),
            stored_mode: "unknown",
            current_mode: AnalyzerMode::Portable.as_str(),
        });
    };

    // A present manifest with a missing field-schema hash signals partial
    // corruption, not schema evolution — route it to IncompatibleAnalyzer.
    match stored_field_schema_hash {
        Some(hash) if hash == current_field_schema_hash => {}
        Some(_) => return Err(Error::Bm25FieldSchemaChanged),
        None => {
            return Err(Error::IncompatibleAnalyzer {
                lang: "*".to_owned(),
                stored_mode: "corrupt",
                current_mode: "any",
            });
        }
    }

    if stored_hash == current_manifest_hash {
        return Ok(());
    }

    Err(manifest_mismatch_error(
        current_manifest,
        stored_manifest_bytes,
    ))
}

fn manifest_mismatch_error(
    current_manifest: &AnalyzerManifest,
    stored_manifest_bytes: Option<Vec<u8>>,
) -> Error {
    // Manifest hash changed. Try to name the specific language whose mode
    // flipped; fall back to `*` if the stored manifest doesn't parse.
    if let Some(bytes) = stored_manifest_bytes
        && let Ok(stored) = serde_json::from_slice::<AnalyzerManifest>(&bytes)
    {
        for (lang, current_policy) in &current_manifest.langs {
            if let Some(stored_policy) = stored.langs.get(lang)
                && stored_policy.mode != current_policy.mode
            {
                return Error::IncompatibleAnalyzer {
                    lang: lang.clone(),
                    stored_mode: stored_policy.mode.as_str(),
                    current_mode: current_policy.mode.as_str(),
                };
            }
        }
    }

    Error::IncompatibleAnalyzer {
        lang: "*".to_owned(),
        stored_mode: "mismatched",
        current_mode: "mismatched",
    }
}

/// Validate that a text-index write can append rows compatible with the
/// current on-disk manifest in the same LMDB write transaction that will
/// receive the postings. If the index is still empty, stamp the current
/// manifest as the first authoritative text-index state.
pub(crate) fn ensure_text_index_manifest_matches_wtxn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    analyzer: &MultilingualAnalyzer,
) -> Result<()> {
    if text_index_is_empty(store, &*wtxn)? {
        write_text_index_manifest(store, wtxn, analyzer)?;
        return Ok(());
    }

    match read_text_schema_version(store, &*wtxn)? {
        Some(TEXT_INDEX_SCHEMA_VERSION) => {}
        Some(_) => return Err(Error::Bm25FieldSchemaChanged),
        None => {
            return Err(Error::IncompatibleAnalyzer {
                lang: "*".to_owned(),
                stored_mode: "corrupt",
                current_mode: "any",
            });
        }
    }

    let current_manifest = analyzer.manifest();
    let current_manifest_hash = current_manifest
        .canonical_hash()
        .map_err(|e| Error::AnalyzerError(format!("manifest hash: {e}")))?;
    let current_field_schema_hash = bm25_field_schema_hash();
    let stored_manifest_hash = read_hash_32(store, &*wtxn, TEXT_ANALYZER_MANIFEST_HASH_KEY)?;
    let stored_field_schema_hash = read_hash_32(store, &*wtxn, TEXT_BM25_FIELD_SCHEMA_HASH_KEY)?;
    let stored_manifest_bytes = store
        .vault_meta
        .get(&*wtxn, TEXT_ANALYZER_MANIFEST_KEY)?
        .map(|b| b.to_vec());

    validate_stored_manifest_hashes(
        stored_manifest_hash,
        stored_field_schema_hash,
        current_manifest_hash,
        current_field_schema_hash,
        &current_manifest,
        stored_manifest_bytes,
    )
}

fn write_text_index_manifest_if_empty(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    analyzer: &MultilingualAnalyzer,
) -> Result<()> {
    if !text_index_is_empty(store, &*wtxn)? {
        return Err(Error::CorruptedIndex(
            "text index populated before manifest write",
        ));
    }
    write_text_index_manifest(store, wtxn, analyzer)
}

/// Write the current analyzer manifest + field-schema hash + schema
/// version into `vault_meta`. Used by open-on-empty-index and by
/// `MaintenanceBuilder::clear_text_index`.
pub(crate) fn write_text_index_manifest(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    analyzer: &MultilingualAnalyzer,
) -> Result<()> {
    let manifest = analyzer.manifest();
    let manifest_json = manifest
        .canonical_json()
        .map_err(|e| Error::AnalyzerError(format!("manifest json: {e}")))?;
    let manifest_hash = manifest
        .canonical_hash()
        .map_err(|e| Error::AnalyzerError(format!("manifest hash: {e}")))?;
    let field_schema_hash = bm25_field_schema_hash();

    store.vault_meta.put(
        wtxn,
        TEXT_INDEX_SCHEMA_VERSION_KEY,
        &TEXT_INDEX_SCHEMA_VERSION.to_le_bytes(),
    )?;
    store
        .vault_meta
        .put(wtxn, TEXT_ANALYZER_MANIFEST_KEY, manifest_json.as_bytes())?;
    store
        .vault_meta
        .put(wtxn, TEXT_ANALYZER_MANIFEST_HASH_KEY, &manifest_hash)?;
    store
        .vault_meta
        .put(wtxn, TEXT_BM25_FIELD_SCHEMA_HASH_KEY, &field_schema_hash)?;
    Ok(())
}

/// Parses one `edges_out` / `edges_in` row into an [`EdgeInfo`].
///
/// Compatibility wrapper over [`crate::edge::parse_strict_edge_record`] so
/// Vault and context-pack readers classify malformed edge rows identically.
pub(crate) fn parse_edge_record(key: &[u8], value: &[u8]) -> Result<EdgeInfo> {
    Ok(parse_strict_edge_record(key, value)?.into_edge_info())
}

#[cfg(test)]
mod tests;
