use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use loro::{ExportMode, Frontiers, LoroDoc, LoroValue, ValueOrContainer, VersionVector};
use oneiron::DreamerAttemptProgressProducer;
use oneiron::SyncEngineContext;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::lease::{self, LEASE_DURATION_SECS, LeaseRecord, LeaseStatus, ROOT_LEASES_MAP};
use oneiron::sync::schema::{
    add_window_to_root, init_window_list, read_window_list, schema_version_bytes,
};
use oneiron::sync::server_state;
use oneiron::sync::{self, EphemeralStore, WindowKey, WindowManager};
use tokio::sync::{Mutex, broadcast};

use crate::config::SyncServerConfig;
use crate::mcp::{McpConnectorActorRegistry, McpCredentialHashKey};
use crate::usage::UsageLedger;

/// User id passed to the shared window loader. The server vault is
/// single-tenant (one vault per user per ARCH-0023b Fig. 1) and the loader
/// does not key storage by user, so this is a label only.
const SERVER_USER_ID: &str = "server";

/// Numeric lease ABI vault id for the legacy local single-vault server path.
/// Hosted paths set `SyncServerConfig::lease_vault_id` per tenant/vault.
const SERVER_LEASE_VAULT_ID: u64 = 0;
const LEASE_LIFECYCLE_TICK_INTERVAL: Duration = Duration::from_secs(60);
static NEXT_LIFECYCLE_SESSION_ID: AtomicU64 = AtomicU64::new(1);

/// Broadcast payload: (conn_id, encoded_message).
/// conn_id 0 = local/bridge writes (broadcast to all devices).
/// conn_id >= 1 = specific connection (echo suppression skips sender).
pub(crate) type BroadcastPayload = (u32, Vec<u8>);

/// Core sync server state shared across all connections.
pub struct SyncServer {
    pub(crate) vault: Arc<oneiron::Vault>,
    /// Root LoroDoc (server-authoritative, contains meta.windows).
    pub(crate) root_doc: LoroDoc,
    /// Hub-held Loro ephemeral state for late join/reconnect snapshots.
    pub(crate) ephemeral_store: EphemeralStore,
    /// Producer state for Dreamer live attempt-progress rows on the ephemeral lane.
    pub(crate) dreamer_progress: Mutex<DreamerAttemptProgressProducer>,
    /// Broadcast channel for fan-out to all connected clients.
    pub(crate) broadcast_tx: broadcast::Sender<BroadcastPayload>,
    /// Monotonic connection ID counter. 0 = reserved for bridge/local writes.
    pub(crate) next_conn_id: AtomicU32,
    /// Serializes lease-registry mutations (ONE-1140, OD-3): two concurrent
    /// connects racing the same client id must observe first-binding-wins,
    /// never a read-modify-write interleave.
    pub(crate) lease_registrar: Mutex<()>,
    /// Window manager used by server-side safe-point maintenance jobs.
    pub(crate) reassert_manager: Arc<WindowManager>,
    /// Process-local session component for lifecycle job debounce keys.
    lifecycle_session_id: u64,
    /// In-flight lifecycle jobs keyed by `(kind, vault_id, session_id)`.
    lifecycle_in_flight: Mutex<HashSet<LifecycleJobKey>>,
    /// Server configuration.
    pub(crate) config: SyncServerConfig,
    /// Tenant usage ledger over the server vault.
    pub(crate) usage_ledger: UsageLedger,
    /// Process-local connector actor registry for the MCP gateway.
    pub(crate) mcp_registry: Mutex<McpConnectorActorRegistry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LeaseExpiryReport {
    pub(crate) expired_rows: usize,
    pub(crate) skipped: bool,
    pub(crate) root_update: Option<Vec<u8>>,
}

impl LeaseExpiryReport {
    fn skipped() -> Self {
        Self {
            expired_rows: 0,
            skipped: true,
            root_update: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReassertDrainJobReport {
    pub(crate) report: sync::ReassertDrainReport,
    pub(crate) skipped: bool,
    pub(crate) window_updates: Vec<(String, Vec<u8>)>,
}

impl ReassertDrainJobReport {
    fn skipped() -> Self {
        Self {
            report: sync::ReassertDrainReport::default(),
            skipped: true,
            window_updates: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum LifecycleJobKind {
    LeaseExpiry,
    ReassertDrain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct LifecycleJobKey {
    kind: LifecycleJobKind,
    vault_id: u64,
    session_id: u64,
}

#[derive(Debug, Clone)]
struct RootLeaseEntry {
    key: String,
    vault_id: u64,
    client_id: u64,
    record: LeaseRecord,
}

impl SyncServer {
    /// Creates a SyncServer over the vault, reloading persisted CRDT state.
    ///
    /// Startup ordering per ARCH-0023b: (1) the root Doc loads from `d:root`
    /// plus pending `u:root:*`; (2) window Docs load on demand from
    /// `d:w:{key}` plus pending `u:w:{key}:*` in `Self::get_or_create_window`.
    /// A fresh vault initializes and persists a new root Doc.
    ///
    /// Boot also reconciles `meta.windows` against the persisted `d:w:*`
    /// snapshots, so a crash between window-snapshot persistence and root
    /// persistence cannot permanently hide a window from clients.
    ///
    /// Errors (fail-closed) on corrupt persisted state: the server must not
    /// boot empty over an undecodable snapshot — that silently discards
    /// relayed updates, including tombstones.
    pub fn new(
        vault: Arc<oneiron::Vault>,
        config: SyncServerConfig,
    ) -> Result<Self, oneiron::Error> {
        config.validate()?;

        let root_doc = match server_state::load_root_from_state(&vault)? {
            Some(doc) => doc,
            None => {
                let doc = LoroDoc::new();
                // Initialize root doc meta map
                let meta = doc.get_map("meta");
                // i64-LE BYTES (Loro Binary), conforming to the shared schema
                // (`schema::create_root_doc`) — NOT a Loro i64, which the
                // byte-only schema readers would not decode.
                meta.insert("schema_version", schema_version_bytes().as_slice())
                    .map_err(|e| {
                        oneiron::Error::sync_engine(SyncEngineContext::LoroMapInsert, e)
                    })?;
                // `meta.windows` must use the shared schema-owned encoding so
                // fresh server docs, root-doc creation, and client decoding
                // cannot drift.
                init_window_list(&doc, &[]);
                // Device-lease registry map (ONE-1140, OD-3) — server-write
                // only; lazily present on docs persisted before v2.
                let _leases = doc.get_map(ROOT_LEASES_MAP);
                doc.commit();
                // Boot is pre-connection/single-threaded; no root-writer
                // mutex can race this initial persist.
                server_state::persist_root_snapshot(&vault, &doc)?;
                doc
            }
        };

        // Reconcile meta.windows with the persisted window snapshots.
        let known: HashSet<String> = read_window_list(&root_doc)
            .iter()
            .map(|k| k.as_str().to_string())
            .collect();
        let mut reconciled = false;
        for key in server_state::persisted_window_keys(&vault)? {
            if !known.contains(key.as_str()) {
                add_window_to_root(&root_doc, &key);
                reconciled = true;
            }
        }
        if reconciled {
            // Boot reconciliation is pre-connection/single-threaded; no
            // root-writer mutex can race this persist.
            server_state::persist_root_snapshot(&vault, &root_doc)?;
        }

        let (broadcast_tx, _) = broadcast::channel(256);
        let mcp_registry = Mutex::new(McpConnectorActorRegistry::new(
            McpCredentialHashKey::from_bytes(mcp_registry_hash_key(&config)),
        ));

        let reassert_manager = Arc::new(WindowManager::new(
            vault.clone(),
            Arc::new(Materializer::with_lease_vault_id(config.lease_vault_id)),
            SERVER_USER_ID,
        ));
        reassert_manager.attach_to_vault();

        Ok(Self {
            usage_ledger: UsageLedger::new(vault.clone()),
            vault,
            root_doc,
            ephemeral_store: EphemeralStore::new(config.ephemeral_timeout_ms),
            broadcast_tx,
            next_conn_id: AtomicU32::new(1),
            lease_registrar: Mutex::new(()),
            reassert_manager,
            lifecycle_session_id: NEXT_LIFECYCLE_SESSION_ID.fetch_add(1, Ordering::Relaxed),
            lifecycle_in_flight: Mutex::new(HashSet::new()),
            dreamer_progress: Mutex::new(DreamerAttemptProgressProducer::new()),
            config,
            mcp_registry,
        })
    }

    /// Returns the vault backing this server (used by integration tests to
    /// assert sync_state durability).
    pub fn vault(&self) -> &Arc<oneiron::Vault> {
        &self.vault
    }

    /// Allocates a new unique nonzero connection ID.
    ///
    /// `conn_id = 0` is reserved as the bridge/local-broadcast sender
    /// sentinel; a real connection returning 0 would silently bypass echo
    /// suppression. `fetch_update` skips 0 on wraparound.
    pub(crate) fn alloc_conn_id(&self) -> u32 {
        self.next_conn_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                let next = current.wrapping_add(1);
                Some(if next == 0 { 1 } else { next })
            })
            .expect("fetch_update closure always returns Some")
    }

    /// Returns the window key (YYYY-MM) for a Unix timestamp.
    #[allow(dead_code)] // Used when WebSocket connected
    pub(crate) fn window_key_for_timestamp(ts: u64) -> String {
        WindowKey::from_timestamp(ts).as_str().to_string()
    }

    /// Exports root doc updates since the given version vector.
    #[allow(dead_code)] // Used when WebSocket connected
    pub(crate) fn export_root_updates(&self, from_vv: &VersionVector) -> Result<Vec<u8>, String> {
        self.root_doc
            .export(ExportMode::updates(from_vv))
            .map_err(|e| format!("root doc export failed: {e}"))
    }

    /// Exports all root doc state for a new client.
    pub(crate) fn export_root_snapshot(&self) -> Result<Vec<u8>, String> {
        self.root_doc
            .export(ExportMode::Snapshot)
            .map_err(|e| format!("root doc snapshot failed: {e}"))
    }

    /// Gets or creates the canonical live window LoroDoc.
    ///
    /// Server websocket sync and lifecycle maintenance both route through
    /// `WindowManager`, so a server-side reassertion drain commits into the
    /// same doc that active connections serve. First touch still preserves
    /// the server root contract: a fresh window is snapshotted to `d:w:*`,
    /// registered in `meta.windows`, and persisted to `d:root`.
    pub(crate) async fn get_or_create_window(
        &self,
        key: &WindowKey,
    ) -> Result<LoroDoc, oneiron::Error> {
        let snapshot_key = format!("d:w:{key}");
        let had_snapshot = self.vault.sync_state_get(&snapshot_key)?.is_some();
        let window = self.reassert_manager.open_window(key)?;

        if !had_snapshot {
            server_state::persist_window_snapshot(&self.vault, key, &window.doc)?;
        }

        if !read_window_list(&self.root_doc)
            .iter()
            .any(|existing| existing == key)
        {
            let _guard = self.lease_registrar.lock().await;
            if !read_window_list(&self.root_doc)
                .iter()
                .any(|existing| existing == key)
            {
                add_window_to_root(&self.root_doc, key);
                server_state::persist_root_snapshot(&self.vault, &self.root_doc)?;
            }
        }

        Ok(window.doc.clone())
    }

    /// Persists an imported client update to sync_state
    /// (Observer-A-equivalent — MUST run synchronously, before the update is
    /// broadcast to other devices).
    pub(crate) fn persist_imported_update(
        &self,
        key: &WindowKey,
        update_bytes: &[u8],
    ) -> Result<u32, oneiron::Error> {
        server_state::persist_imported_window_update(&self.vault, key, update_bytes)
    }

    /// Persists the canonical loaded window after a privacy scrub. This uses
    /// `LoadedWindow::persist_state` so the shallow snapshot and the exact
    /// set of durable update rows it subsumes are replaced/pruned atomically.
    pub(crate) fn persist_sanitized_window(&self, key: &WindowKey) -> Result<(), oneiron::Error> {
        let window =
            self.reassert_manager
                .window(key)
                .ok_or_else(|| oneiron::Error::WindowNotFound {
                    window_key: key.as_str().to_owned(),
                })?;
        window.persist_state(&self.vault)?;
        Ok(())
    }

    /// Evicts a window doc from the live manager registry.
    ///
    /// Used when the durable append of an imported update fails: the UPDATE
    /// arm imports into the loaded doc BEFORE persisting (that order is
    /// deliberate — persisting raw bytes that then fail `import_with` would
    /// durably append an undecodable `u:w:` row, and window load is
    /// fail-closed on pending updates, bricking the window at boot). On
    /// persist failure the loaded doc therefore holds state a restart would
    /// lose; evicting it forces the next access to reload from durable
    /// `d:w:` + `u:w:` state, so the manager can never serve state a restart
    /// loses.
    pub(crate) async fn evict_window(&self, key: &WindowKey) {
        self.reassert_manager.discard_window(key);
    }

    /// Starts the periodic lease-lifecycle maintenance loop.
    pub(crate) fn spawn_lifecycle_scheduler(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let server = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(LEASE_LIFECYCLE_TICK_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                server.run_scheduled_lifecycle_tick().await;
            }
        })
    }

    async fn run_scheduled_lifecycle_tick(&self) {
        let now_ms = unix_seconds_now().saturating_mul(1_000);
        self.dreamer_progress
            .lock()
            .await
            .remove_outdated(&self.ephemeral_store, now_ms);

        match self.expire_leases_once().await {
            Ok(report) => {
                if report.skipped {
                    tracing::debug!("lease expiry tick skipped: previous tick still in flight");
                } else {
                    tracing::debug!(
                        expired_rows = report.expired_rows,
                        "lease expiry tick complete"
                    );
                }
                if let Some(update) = report.root_update {
                    let msg = crate::protocol::encode_root_update(&update);
                    let _ = crate::broadcast::broadcast(&self.broadcast_tx, 0, msg);
                }
            }
            Err(err) => {
                tracing::error!(error = %err, "lease expiry tick failed");
            }
        }

        match self.drain_reassert_markers_once().await {
            Ok(report) => {
                if report.skipped {
                    tracing::debug!("ra drain tick skipped: previous tick still in flight");
                } else {
                    tracing::debug!(
                        drained = ?report.report.drained,
                        still_pending = ?report.report.still_pending,
                        "ra drain tick complete"
                    );
                }
                for (window_key, update) in report.window_updates {
                    match crate::protocol::encode_window_sync(
                        &window_key,
                        crate::protocol::window_sub_tags::UPDATE,
                        &update,
                    )
                    .into_result()
                    {
                        Ok(msg) => {
                            let _ = crate::broadcast::broadcast(&self.broadcast_tx, 0, msg);
                        }
                        Err(err) => {
                            tracing::error!(
                                window = %window_key,
                                error = crate::protocol::transport_err_msg(err),
                                "ra drain tick failed to encode window update"
                            );
                        }
                    }
                }
            }
            Err(err) => {
                tracing::error!(error = %err, "ra drain tick failed");
            }
        }
    }

    pub(crate) async fn expire_leases_once(&self) -> Result<LeaseExpiryReport, oneiron::Error> {
        self.expire_leases_once_at(unix_seconds_now()).await
    }

    async fn expire_leases_once_at(&self, now: u64) -> Result<LeaseExpiryReport, oneiron::Error> {
        if !self
            .begin_lifecycle_job(LifecycleJobKind::LeaseExpiry)
            .await
        {
            return Ok(LeaseExpiryReport::skipped());
        }

        let result = async {
            let _guard = self.lease_registrar.lock().await;
            let vv_before = self.root_doc.oplog_vv();
            let frontiers_before = self.root_doc.state_frontiers();
            let leases = self.root_doc.get_map(ROOT_LEASES_MAP);
            let mut entries = self.root_lease_entries()?;

            let mut expired_rows = 0usize;
            for entry in &mut entries {
                let mut record = entry.record;
                if record.status == LeaseStatus::Active && record.expires_at < now {
                    record.status = LeaseStatus::Expired;
                    let scoped_key = lease::lease_registry_key(entry.vault_id, entry.client_id);
                    if entry.key != scoped_key {
                        leases.delete(entry.key.as_str()).map_err(|e| {
                            oneiron::Error::sync_engine(SyncEngineContext::LoroMapDelete, e)
                        })?;
                        entry.key = scoped_key;
                    }
                    leases
                        .insert(
                            entry.key.as_str(),
                            lease::encode_lease_record(&record).as_slice(),
                        )
                        .map_err(|e| {
                            oneiron::Error::sync_engine(SyncEngineContext::LoroMapInsert, e)
                        })?;
                    entry.record = record;
                    expired_rows += 1;
                }
            }

            let root_update =
                self.commit_lease_changes(expired_rows > 0, &vv_before, &frontiers_before)?;
            Ok(LeaseExpiryReport {
                expired_rows,
                skipped: false,
                root_update,
            })
        }
        .await;

        self.end_lifecycle_job(LifecycleJobKind::LeaseExpiry).await;
        result
    }

    pub(crate) async fn drain_reassert_markers_once(
        &self,
    ) -> Result<ReassertDrainJobReport, oneiron::Error> {
        if !self
            .begin_lifecycle_job(LifecycleJobKind::ReassertDrain)
            .await
        {
            return Ok(ReassertDrainJobReport::skipped());
        }

        let live_versions = self.live_window_versions();
        let result =
            sync::drain_reassert_markers(&self.vault, SERVER_USER_ID, &self.reassert_manager)
                .and_then(|report| {
                    let window_updates = self.collect_live_window_updates(live_versions)?;
                    Ok(ReassertDrainJobReport {
                        report,
                        skipped: false,
                        window_updates,
                    })
                });

        self.end_lifecycle_job(LifecycleJobKind::ReassertDrain)
            .await;
        result
    }

    fn live_window_versions(&self) -> HashMap<WindowKey, VersionVector> {
        self.reassert_manager
            .loaded_keys()
            .into_iter()
            .filter_map(|key| {
                self.reassert_manager
                    .window(&key)
                    .map(|window| (key, window.doc.oplog_vv()))
            })
            .collect()
    }

    fn collect_live_window_updates(
        &self,
        before: HashMap<WindowKey, VersionVector>,
    ) -> Result<Vec<(String, Vec<u8>)>, oneiron::Error> {
        let mut updates = Vec::new();
        for (key, vv_before) in before {
            let Some(window) = self.reassert_manager.window(&key) else {
                continue;
            };
            if window.doc.oplog_vv() == vv_before {
                continue;
            }
            let update = window
                .doc
                .export(ExportMode::updates(&vv_before))
                .map_err(|e| {
                    oneiron::Error::sync_engine(SyncEngineContext::LoroExportUpdates, e)
                })?;
            updates.push((key.as_str().to_string(), update));
        }
        Ok(updates)
    }

    fn lifecycle_job_key(&self, kind: LifecycleJobKind) -> LifecycleJobKey {
        LifecycleJobKey {
            kind,
            vault_id: SERVER_LEASE_VAULT_ID,
            session_id: self.lifecycle_session_id,
        }
    }

    async fn begin_lifecycle_job(&self, kind: LifecycleJobKind) -> bool {
        self.lifecycle_in_flight
            .lock()
            .await
            .insert(self.lifecycle_job_key(kind))
    }

    async fn end_lifecycle_job(&self, kind: LifecycleJobKind) {
        self.lifecycle_in_flight
            .lock()
            .await
            .remove(&self.lifecycle_job_key(kind));
    }

    fn root_lease_entries(&self) -> Result<Vec<RootLeaseEntry>, oneiron::Error> {
        let leases = self.root_doc.get_map(ROOT_LEASES_MAP);
        let mut raw_entries: Vec<(String, Vec<u8>)> = Vec::new();
        let mut corrupt = false;
        leases.for_each(|key, value| {
            if let ValueOrContainer::Value(LoroValue::Binary(blob)) = value {
                raw_entries.push((key.to_string(), blob.to_vec()));
            } else {
                corrupt = true;
            }
        });
        if corrupt {
            return Err(oneiron::Error::CorruptedIndex(
                "non-binary root lease entry",
            ));
        }

        raw_entries
            .into_iter()
            .map(|(key, raw)| Self::decode_root_lease_entry(key, &raw))
            .collect()
    }

    fn root_lease_entry_for_vault_client(
        &self,
        vault_id: u64,
        client_id: u64,
    ) -> Result<Option<RootLeaseEntry>, oneiron::Error> {
        let leases = self.root_doc.get_map(ROOT_LEASES_MAP);
        let scoped_key = lease::lease_registry_key(vault_id, client_id);
        if let Some(value) = leases.get(&scoped_key) {
            return Self::decode_root_lease_value(scoped_key, value).map(Some);
        }

        let legacy_key = lease::client_id_hex(client_id);
        let Some(value) = leases.get(&legacy_key) else {
            return Ok(None);
        };
        let entry = Self::decode_root_lease_value(legacy_key, value)?;
        if entry.vault_id == vault_id {
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    fn decode_root_lease_value(
        key: String,
        value: ValueOrContainer,
    ) -> Result<RootLeaseEntry, oneiron::Error> {
        match value {
            ValueOrContainer::Value(LoroValue::Binary(raw)) => {
                Self::decode_root_lease_entry(key, &raw)
            }
            _ => Err(oneiron::Error::CorruptedIndex(
                "non-binary root lease entry",
            )),
        }
    }

    fn decode_root_lease_entry(key: String, raw: &[u8]) -> Result<RootLeaseEntry, oneiron::Error> {
        let record = lease::decode_lease_record(raw)?;
        let registry_key = lease::decode_lease_registry_key(&key)?;
        let vault_id = registry_key.effective_vault_id(&record)?;
        Ok(RootLeaseEntry {
            key,
            vault_id,
            client_id: registry_key.client_id,
            record,
        })
    }

    // ─── Device-lease registry (ONE-1140, OD-3) ──────────────────────────

    /// Handles a TAG_LEASE_REQUEST: verify proof of possession, then apply
    /// the pinned binding rules under the registrar lock —
    ///
    /// * binding absent → unless this pubkey is revoked under ANY client_id
    ///   (OD-8 amended, pubkey-bound floor: refuse, write NO row), write an
    ///   ACTIVE record (`granted_at = renewed_at = now`, `expires_at = now +
    ///   90 d`), grant;
    /// * same pubkey, status ≠ revoked → renew (`renewed_at`/`expires_at`
    ///   refreshed; an expired binding flips back to active), grant;
    /// * same client id, DIFFERENT pubkey → reject, binding untouched
    ///   (first-binding-wins);
    /// * revoked → reject, terminal (OD-8).
    ///
    /// Revocation binds to the Ed25519 PUBKEY, not the mintable client_id
    /// (OD-8 amended, RULING A): a revoked pubkey can never obtain a fresh
    /// active lease under ANY client_id, so a device that rotates client_id
    /// while reusing its key cannot recover — recovery requires a fresh
    /// KEYPAIR. The public wrapper uses `SyncServerConfig::lease_vault_id`
    /// so hosted callers scope the floor to `(vault, pubkey)` while the
    /// default config preserves the existing single-vault server id.
    ///
    /// Scan-at-connect expiry (OD-7): any ACTIVE binding past its
    /// `expires_at` flips to EXPIRED first — server-side liveness
    /// bookkeeping only; replay doors never enforce time.
    ///
    /// Registry writes go to the root doc's `leases` map (server-write-only
    /// by the existing client-root-update rejection), are persisted to
    /// `d:root`, and are mirrored to this vault's `ls:` rows in the same
    /// logical op. The returned `root_update` delta must be broadcast to
    /// ALL connections (conn_id 0 — the requester needs its own record).
    pub(crate) async fn register_lease(
        &self,
        client_id: u64,
        pubkey: &[u8; 32],
        pop_sig: &[u8; 64],
    ) -> Result<LeaseDecision, oneiron::Error> {
        self.register_lease_for_vault(self.config.lease_vault_id, client_id, pubkey, pop_sig)
            .await
    }

    async fn register_lease_for_vault(
        &self,
        vault_id: u64,
        client_id: u64,
        pubkey: &[u8; 32],
        pop_sig: &[u8; 64],
    ) -> Result<LeaseDecision, oneiron::Error> {
        // Invalid proof of possession: reject without touching state. The
        // transcript binds client_id AND pubkey, so a forged binding for a
        // key the requester does not hold can never reach the registry.
        if !lease::verify_lease_pop(client_id, pubkey, pop_sig) {
            return Ok(LeaseDecision::rejected());
        }

        let _guard = self.lease_registrar.lock().await;
        let now = unix_seconds_now();
        let leases = self.root_doc.get_map(ROOT_LEASES_MAP);
        let vv_before = self.root_doc.oplog_vv();
        let frontiers_before = self.root_doc.state_frontiers();
        let mut changed = false;

        // Scan-at-connect expiry flip (liveness bookkeeping, OD-7).
        //
        // The server is the SOLE registry writer and always stores BINARY
        // lease records, so ANY non-binary entry is local corruption that
        // could hide a revoked-pubkey row from the registration floor below.
        // Capture it out-of-band (Loro's `for_each` closure returns `()`) and
        // fail closed-HARD: refuse the WHOLE registration before any expiry
        // flip or registration decision — never best-effort skip the entry.
        let mut entries = self.root_lease_entries()?;
        for entry in &mut entries {
            // The server is the SOLE registry writer — a malformed record
            // is local corruption, fail closed (never best-effort decode).
            let mut record = entry.record;
            if record.status == LeaseStatus::Active && record.expires_at < now {
                record.status = LeaseStatus::Expired;
                let scoped_key = lease::lease_registry_key(entry.vault_id, entry.client_id);
                if entry.key != scoped_key {
                    leases.delete(entry.key.as_str()).map_err(|e| {
                        oneiron::Error::sync_engine(SyncEngineContext::LoroMapDelete, e)
                    })?;
                    entry.key = scoped_key;
                }
                leases
                    .insert(
                        entry.key.as_str(),
                        lease::encode_lease_record(&record).as_slice(),
                    )
                    .map_err(|e| {
                        oneiron::Error::sync_engine(SyncEngineContext::LoroMapInsert, e)
                    })?;
                entry.record = record;
                changed = true;
            }
        }

        let key_hex = lease::lease_registry_key(vault_id, client_id);
        let existing = entries
            .iter()
            .find(|entry| entry.key == key_hex)
            .or_else(|| {
                entries
                    .iter()
                    .find(|entry| entry.vault_id == vault_id && entry.client_id == client_id)
            });
        let pubkey_revoked = entries.iter().any(|entry| {
            entry.vault_id == vault_id
                && entry.record.pubkey == *pubkey
                && entry.record.status == LeaseStatus::Revoked
        });

        let decision = match existing {
            None => {
                // Pubkey-bound revocation FLOOR (OD-8 amended, RULING A):
                // refuse a fresh ACTIVE lease for a pubkey that ANY ls: row
                // has revoked — a revoked pubkey is terminal across all
                // client_ids, so a fresh client_id reusing a revoked key
                // cannot recover (recovery requires a fresh KEYPAIR). Reuses
                // the already-materialized `entries`; the server is the sole
                // writer, so a malformed record is local corruption and
                // propagates fail-closed (never best-effort decode).
                if pubkey_revoked {
                    // Binding refused — write NO row, grant nothing.
                    LeaseDecision::rejected()
                } else {
                    let record = LeaseRecord {
                        vault_id,
                        status: LeaseStatus::Active,
                        pubkey: *pubkey,
                        granted_at: now,
                        renewed_at: now,
                        expires_at: now + LEASE_DURATION_SECS,
                    };
                    leases
                        .insert(
                            key_hex.as_str(),
                            lease::encode_lease_record(&record).as_slice(),
                        )
                        .map_err(|e| {
                            oneiron::Error::sync_engine(SyncEngineContext::LoroMapInsert, e)
                        })?;
                    changed = true;
                    LeaseDecision::granted(record.expires_at)
                }
            }
            Some(entry) if entry.record.status == LeaseStatus::Revoked => {
                // Terminal (OD-8): a revoked binding never re-activates.
                LeaseDecision::rejected()
            }
            Some(entry) if entry.record.pubkey == *pubkey && pubkey_revoked => {
                // Renewal arm also honors the pubkey-bound revocation floor:
                // a sibling revoked row for this key is terminal across
                // client_ids, so an existing active binding cannot refresh.
                LeaseDecision::rejected()
            }
            Some(entry) if entry.record.pubkey == *pubkey => {
                let record = entry.record;
                let renewed = LeaseRecord {
                    vault_id: record.vault_id,
                    status: LeaseStatus::Active,
                    pubkey: record.pubkey,
                    granted_at: record.granted_at,
                    renewed_at: now,
                    expires_at: now + LEASE_DURATION_SECS,
                };
                if entry.key != key_hex {
                    leases.delete(entry.key.as_str()).map_err(|e| {
                        oneiron::Error::sync_engine(SyncEngineContext::LoroMapDelete, e)
                    })?;
                }
                leases
                    .insert(
                        key_hex.as_str(),
                        lease::encode_lease_record(&renewed).as_slice(),
                    )
                    .map_err(|e| {
                        oneiron::Error::sync_engine(SyncEngineContext::LoroMapInsert, e)
                    })?;
                changed = true;
                LeaseDecision::granted(renewed.expires_at)
            }
            // Same client id, different pubkey: first-binding-wins, the
            // existing binding is untouched.
            Some(_) => LeaseDecision::rejected(),
        };

        let root_update = self.commit_lease_changes(changed, &vv_before, &frontiers_before)?;
        Ok(LeaseDecision {
            root_update,
            ..decision
        })
    }

    /// Revokes a binding (owner recovery surface, OD-8). Terminal: the
    /// record keeps its timestamps, status flips to REVOKED. Returns the
    /// decision with `granted == false` and a `root_update` delta when the
    /// binding existed; `Ok(None)`-equivalent (no update) when it did not.
    pub(crate) async fn revoke_lease(
        &self,
        client_id: u64,
    ) -> Result<Option<Vec<u8>>, oneiron::Error> {
        self.revoke_lease_for_vault(self.config.lease_vault_id, client_id)
            .await
    }

    async fn revoke_lease_for_vault(
        &self,
        vault_id: u64,
        client_id: u64,
    ) -> Result<Option<Vec<u8>>, oneiron::Error> {
        let _guard = self.lease_registrar.lock().await;
        let leases = self.root_doc.get_map(ROOT_LEASES_MAP);
        let Some(entry) = self.root_lease_entry_for_vault_client(vault_id, client_id)? else {
            return Ok(None);
        };
        let mut record = entry.record;
        let vv_before = self.root_doc.oplog_vv();
        let frontiers_before = self.root_doc.state_frontiers();
        record.status = LeaseStatus::Revoked;
        let key_hex = lease::lease_registry_key(vault_id, client_id);
        if entry.key != key_hex {
            leases
                .delete(entry.key.as_str())
                .map_err(|e| oneiron::Error::sync_engine(SyncEngineContext::LoroMapDelete, e))?;
        }
        leases
            .insert(
                key_hex.as_str(),
                lease::encode_lease_record(&record).as_slice(),
            )
            .map_err(|e| oneiron::Error::sync_engine(SyncEngineContext::LoroMapInsert, e))?;
        self.commit_lease_changes(true, &vv_before, &frontiers_before)
    }

    /// Commits + persists + mirrors a registry mutation: root doc commit,
    /// `d:root` snapshot persist, `ls:` row mirror — then exports the
    /// update delta for broadcast. No-op (None) when nothing changed.
    ///
    /// ATOMICITY (ONE-1140): the `d:root` snapshot persist and the `ls:`
    /// mirror run in ONE `with_write_txn`, so a crash/failure after the
    /// `d:root` put rolls back the whole txn — never a new `d:root` over a
    /// stale/missing `ls:` mirror (which would let a revoked lease appear
    /// active at a replay door reading `ls:`). The `ls:` mirror derives from
    /// the in-memory (already-committed) `root_doc`, not by re-reading the
    /// staged `d:root`.
    fn commit_lease_changes(
        &self,
        changed: bool,
        vv_before: &VersionVector,
        frontiers_before: &Frontiers,
    ) -> Result<Option<Vec<u8>>, oneiron::Error> {
        if !changed {
            return Ok(None);
        }
        self.root_doc.commit();
        if let Err(err) = self.vault.with_write_txn(|wtxn| {
            server_state::persist_root_snapshot_in_txn(&self.vault, wtxn, &self.root_doc)?;
            lease::mirror_leases_from_root_in_txn(&self.vault, wtxn, &self.root_doc)?;
            Ok(())
        }) {
            if let Err(revert_err) = self.root_doc.revert_to(frontiers_before) {
                return Err(oneiron::Error::sync_engine_rollback(
                    SyncEngineContext::LoroRevert,
                    err,
                    revert_err,
                ));
            }
            return Err(err);
        }
        let delta = self
            .root_doc
            .export(ExportMode::updates(vv_before))
            .map_err(|e| oneiron::Error::sync_engine(SyncEngineContext::LoroExportUpdates, e))?;
        Ok(Some(delta))
    }
}

fn mcp_registry_hash_key(config: &SyncServerConfig) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron-server:mcp-connector-registry:v1");
    if let Some(secret) = config.auth_secret.as_deref() {
        hasher.update(secret.as_bytes());
    } else if config.allow_unauthenticated {
        hasher.update(b"unauthenticated-dev");
    } else {
        hasher.update(b"no-auth-secret-configured");
    }
    *hasher.finalize().as_bytes()
}

/// Outcome of a lease registration attempt (ONE-1140).
#[derive(Debug)]
pub(crate) struct LeaseDecision {
    pub(crate) granted: bool,
    /// `expires_at` for the GRANTED ack; 0 when rejected (wire literal).
    pub(crate) expires_at: u64,
    /// Root-doc update delta to broadcast when the registry changed.
    pub(crate) root_update: Option<Vec<u8>>,
}

impl LeaseDecision {
    fn granted(expires_at: u64) -> Self {
        Self {
            granted: true,
            expires_at,
            root_update: None,
        }
    }

    const fn rejected() -> Self {
        Self {
            granted: false,
            expires_at: 0,
            root_update: None,
        }
    }
}

/// Wall-clock Unix seconds, saturating to 0 pre-epoch (matches the
/// client-side SystemTime uses).
fn unix_seconds_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests;
