use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use loro::{ExportMode, LoroDoc, LoroValue, ValueOrContainer, VersionVector};
use oneiron::sync::WindowKey;
use oneiron::sync::lease::{self, LEASE_DURATION_SECS, LeaseRecord, LeaseStatus, ROOT_LEASES_MAP};
use oneiron::sync::schema::{add_window_to_root, read_window_list};
use oneiron::sync::server_state;
use oneiron::sync::window::load_window_from_state;
use tokio::sync::{Mutex, RwLock, broadcast};

use crate::config::SyncServerConfig;
use crate::protocol::AwarenessState;

/// User id passed to the shared window loader. The server vault is
/// single-tenant (one vault per user per ARCH-0023b Fig. 1) and the loader
/// does not key storage by user, so this is a label only.
const SERVER_USER_ID: &str = "server";

/// Broadcast payload: (conn_id, encoded_message).
/// conn_id 0 = local/bridge writes (broadcast to all devices).
/// conn_id >= 1 = specific connection (echo suppression skips sender).
pub(crate) type BroadcastPayload = (u32, Vec<u8>);

/// Core sync server state shared across all connections.
pub struct SyncServer {
    pub(crate) vault: Arc<oneiron::Vault>,
    /// Root LoroDoc (server-authoritative, contains meta.windows).
    pub(crate) root_doc: LoroDoc,
    /// Window key -> LoroDoc for each loaded window (RAM cache over
    /// sync_state `d:w:{key}` + `u:w:{key}:*`).
    pub(crate) windows: RwLock<HashMap<String, LoroDoc>>,
    /// Per-connection awareness state.
    pub(crate) awareness: RwLock<HashMap<u32, AwarenessState>>,
    /// Broadcast channel for fan-out to all connected clients.
    pub(crate) broadcast_tx: broadcast::Sender<BroadcastPayload>,
    /// Monotonic connection ID counter. 0 = reserved for bridge/local writes.
    pub(crate) next_conn_id: AtomicU32,
    /// Serializes lease-registry mutations (ONE-1140, OD-3): two concurrent
    /// connects racing the same client id must observe first-binding-wins,
    /// never a read-modify-write interleave.
    pub(crate) lease_registrar: Mutex<()>,
    /// Server configuration.
    pub(crate) config: SyncServerConfig,
}

impl SyncServer {
    /// Creates a SyncServer over the vault, reloading persisted CRDT state.
    ///
    /// Startup ordering per ARCH-0023b: (1) the root Doc loads from `d:root`
    /// plus pending `u:root:*`; (2) window Docs load on demand from
    /// `d:w:{key}` plus pending `u:w:{key}:*` in [`Self::get_or_create_window`].
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
        let root_doc = match server_state::load_root_from_state(&vault)? {
            Some(doc) => doc,
            None => {
                let doc = LoroDoc::new();
                // Initialize root doc meta map
                let meta = doc.get_map("meta");
                // i64-LE BYTES (Loro Binary), conforming to the shared schema
                // (`schema::create_root_doc`) — NOT a Loro i64, which the
                // byte-only schema readers would not decode.
                meta.insert("schema_version", 1i64.to_le_bytes().as_slice())
                    .map_err(|e| oneiron::Error::SyncProtocolError(e.to_string()))?;
                // `meta.windows` must be byte-encoded to match the schema
                // helpers (`schema::create_root_doc` / `add_window_to_root`)
                // and the client's `read_window_list` decoder, which only
                // accept `LoroValue::Binary`.
                meta.insert("windows", "".as_bytes())
                    .map_err(|e| oneiron::Error::SyncProtocolError(e.to_string()))?;
                // Device-lease registry map (ONE-1140, OD-3) — server-write
                // only; lazily present on docs persisted before v2.
                let _leases = doc.get_map(ROOT_LEASES_MAP);
                doc.commit();
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
            server_state::persist_root_snapshot(&vault, &root_doc)?;
        }

        let (broadcast_tx, _) = broadcast::channel(256);

        Ok(Self {
            vault,
            root_doc,
            windows: RwLock::new(HashMap::new()),
            awareness: RwLock::new(HashMap::new()),
            broadcast_tx,
            next_conn_id: AtomicU32::new(1),
            lease_registrar: Mutex::new(()),
            config,
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

    /// Gets or creates a window LoroDoc. Returns a clone (reference-counted).
    ///
    /// Lookup order: RAM cache → persisted sync_state (`d:w:{key}` snapshot
    /// plus pending `u:w:{key}:*` updates) → create fresh. Creation persists
    /// the initial snapshot, registers the key in the root doc's
    /// `meta.windows` via `add_window_to_root`, and persists the root to
    /// `d:root`, so the window survives a restart and future clients learn
    /// the key.
    ///
    /// Corrupt persisted state is an error (fail-closed): the server must
    /// not silently serve a fresh empty window over an undecodable snapshot
    /// — that would drop relayed updates and tombstones.
    pub(crate) async fn get_or_create_window(
        &self,
        key: &WindowKey,
    ) -> Result<LoroDoc, oneiron::Error> {
        {
            let windows = self.windows.read().await;
            if let Some(doc) = windows.get(key.as_str()) {
                return Ok(doc.clone());
            }
        }

        // Serialize load/create under the write lock so two connections
        // cannot race a double-create (each with a distinct Loro peer) or a
        // double-load.
        let mut windows = self.windows.write().await;
        if let Some(doc) = windows.get(key.as_str()) {
            return Ok(doc.clone());
        }

        let doc = match load_window_from_state(&self.vault, SERVER_USER_ID, key) {
            Ok(doc) => doc,
            Err(oneiron::Error::WindowNotFound { .. }) => {
                // Initialize window schema maps
                let doc = LoroDoc::new();
                let _entities = doc.get_map("entities");
                let _edges = doc.get_map("edges");
                let _tombstones = doc.get_map("tombstones");
                doc.commit();

                server_state::persist_window_snapshot(&self.vault, key, &doc)?;
                add_window_to_root(&self.root_doc, key);
                server_state::persist_root_snapshot(&self.vault, &self.root_doc)?;
                doc
            }
            Err(e) => return Err(e),
        };

        windows.insert(key.as_str().to_string(), doc.clone());
        Ok(doc)
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

    /// Evicts a window doc from the RAM cache.
    ///
    /// Used when the durable append of an imported update fails: the UPDATE
    /// arm imports into the cached doc BEFORE persisting (that order is
    /// deliberate — persisting raw bytes that then fail `import_with` would
    /// durably append an undecodable `u:w:` row, and window load is
    /// fail-closed on pending updates, bricking the window at boot). On
    /// persist failure the cached doc therefore holds state a restart would
    /// lose; evicting it forces the next access to reload from durable
    /// `d:w:` + `u:w:` state, so the RAM cache can never serve state a
    /// restart loses.
    pub(crate) async fn evict_window(&self, key: &WindowKey) {
        self.windows.write().await.remove(key.as_str());
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
    /// KEYPAIR. The per-`(vault, pubkey)` dimension is deferred to ONE-1161.
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
        let mut changed = false;

        // Scan-at-connect expiry flip (liveness bookkeeping, OD-7).
        let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
        leases.for_each(|key, value| {
            if let ValueOrContainer::Value(LoroValue::Binary(blob)) = value {
                entries.push((key.to_string(), blob.to_vec()));
            }
        });
        for (key, raw) in &entries {
            // The server is the SOLE registry writer — a malformed record
            // is local corruption, fail closed (never best-effort decode).
            let mut record = lease::decode_lease_record(raw)?;
            if record.status == LeaseStatus::Active && record.expires_at < now {
                record.status = LeaseStatus::Expired;
                leases
                    .insert(key.as_str(), lease::encode_lease_record(&record).as_slice())
                    .map_err(|e| oneiron::Error::SyncProtocolError(e.to_string()))?;
                changed = true;
            }
        }

        let key_hex = lease::client_id_hex(client_id);
        let existing = entries
            .iter()
            .find(|(key, _)| *key == key_hex)
            .map(|(_, raw)| lease::decode_lease_record(raw))
            .transpose()?;

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
                let mut pubkey_revoked = false;
                for (_, raw) in &entries {
                    let record = lease::decode_lease_record(raw)?;
                    if record.pubkey == *pubkey && record.status == LeaseStatus::Revoked {
                        pubkey_revoked = true;
                        break;
                    }
                }
                if pubkey_revoked {
                    // Binding refused — write NO row, grant nothing.
                    LeaseDecision::rejected()
                } else {
                    let record = LeaseRecord {
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
                        .map_err(|e| oneiron::Error::SyncProtocolError(e.to_string()))?;
                    changed = true;
                    LeaseDecision::granted(record.expires_at)
                }
            }
            Some(record) if record.status == LeaseStatus::Revoked => {
                // Terminal (OD-8): a revoked binding never re-activates.
                LeaseDecision::rejected()
            }
            Some(record) if record.pubkey == *pubkey => {
                let renewed = LeaseRecord {
                    status: LeaseStatus::Active,
                    pubkey: record.pubkey,
                    granted_at: record.granted_at,
                    renewed_at: now,
                    expires_at: now + LEASE_DURATION_SECS,
                };
                leases
                    .insert(
                        key_hex.as_str(),
                        lease::encode_lease_record(&renewed).as_slice(),
                    )
                    .map_err(|e| oneiron::Error::SyncProtocolError(e.to_string()))?;
                changed = true;
                LeaseDecision::granted(renewed.expires_at)
            }
            // Same client id, different pubkey: first-binding-wins, the
            // existing binding is untouched.
            Some(_) => LeaseDecision::rejected(),
        };

        let root_update = self.commit_lease_changes(changed, &vv_before)?;
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
        let _guard = self.lease_registrar.lock().await;
        let leases = self.root_doc.get_map(ROOT_LEASES_MAP);
        let key_hex = lease::client_id_hex(client_id);
        let Some(ValueOrContainer::Value(LoroValue::Binary(raw))) = leases.get(&key_hex) else {
            return Ok(None);
        };
        let mut record = lease::decode_lease_record(&raw)?;
        let vv_before = self.root_doc.oplog_vv();
        record.status = LeaseStatus::Revoked;
        leases
            .insert(
                key_hex.as_str(),
                lease::encode_lease_record(&record).as_slice(),
            )
            .map_err(|e| oneiron::Error::SyncProtocolError(e.to_string()))?;
        self.commit_lease_changes(true, &vv_before)
    }

    /// Commits + persists + mirrors a registry mutation: root doc commit,
    /// `d:root` snapshot persist, `ls:` row mirror — then exports the
    /// update delta for broadcast. No-op (None) when nothing changed.
    fn commit_lease_changes(
        &self,
        changed: bool,
        vv_before: &VersionVector,
    ) -> Result<Option<Vec<u8>>, oneiron::Error> {
        if !changed {
            return Ok(None);
        }
        self.root_doc.commit();
        server_state::persist_root_snapshot(&self.vault, &self.root_doc)?;
        lease::mirror_leases_from_root(&self.vault, &self.root_doc)?;
        let delta = self
            .root_doc
            .export(ExportMode::updates(vv_before))
            .map_err(|e| oneiron::Error::SyncProtocolError(format!("root delta export: {e}")))?;
        Ok(Some(delta))
    }
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
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oneiron::sync::transport::window_sub_tags;

    fn test_vault() -> (tempfile::TempDir, Arc<oneiron::Vault>) {
        let dir = tempfile::tempdir().unwrap();
        let vault =
            Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
        (dir, vault)
    }

    fn deep_map_bytes(doc: &LoroDoc, map: &str, key: &str) -> Option<Vec<u8>> {
        let deep = doc.get_deep_value();
        let root = deep.as_map()?;
        let inner = root.get(map)?.as_map()?;
        let value = inner.get(key)?.as_binary()?;
        Some(value.to_vec())
    }

    #[test]
    fn window_key_for_known_timestamps() {
        assert_eq!(SyncServer::window_key_for_timestamp(1771027200), "2026-02");
        assert_eq!(SyncServer::window_key_for_timestamp(1764547200), "2025-12");
        assert_eq!(SyncServer::window_key_for_timestamp(0), "1970-01");
    }

    #[test]
    fn root_doc_initialization() {
        let (_dir, vault) = test_vault();
        let server = SyncServer::new(vault, SyncServerConfig::default()).unwrap();

        // schema_version must be i64-LE bytes (Loro Binary), matching the
        // shared schema writer (`schema::create_root_doc`).
        assert_eq!(
            deep_map_bytes(&server.root_doc, "meta", "schema_version").unwrap(),
            1i64.to_le_bytes()
        );
        assert!(
            deep_map_bytes(&server.root_doc, "meta", "windows")
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn window_creation() {
        let (_dir, vault) = test_vault();
        let server = SyncServer::new(vault, SyncServerConfig::default()).unwrap();

        let doc = server
            .get_or_create_window(&WindowKey::new("2026-03"))
            .await
            .unwrap();
        let deep = doc.get_deep_value();
        let map = deep.as_map().unwrap();
        assert!(map.contains_key("entities"));
        assert!(map.contains_key("edges"));
        assert!(map.contains_key("tombstones"));
    }

    #[tokio::test]
    async fn window_creation_persists_snapshot_and_registers_in_root() {
        let (_dir, vault) = test_vault();
        let server = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();

        server
            .get_or_create_window(&WindowKey::new("2026-03"))
            .await
            .unwrap();

        // ARCH-0023b sync_state key layout literals.
        assert!(vault.sync_state_get("d:w:2026-03").unwrap().is_some());
        assert!(vault.sync_state_get("sv:w:2026-03").unwrap().is_some());
        assert_eq!(
            vault.sync_state_get("svf:w:2026-03").unwrap().unwrap(),
            vec![1u8]
        );
        assert!(vault.sync_state_get("d:root").unwrap().is_some());

        let windows = read_window_list(&server.root_doc);
        assert_eq!(windows, vec![WindowKey::new("2026-03")]);
    }

    #[tokio::test]
    async fn imported_updates_and_root_windows_survive_server_recreation() {
        let (_dir, vault) = test_vault();

        // ── Server instance 1: create a window, import an update (entity +
        //    tombstone), persist via the Observer-A-equivalent path.
        {
            let server = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();
            let key = WindowKey::new("2026-02");
            let doc = server.get_or_create_window(&key).await.unwrap();

            let author = LoroDoc::new();
            author
                .get_map("entities")
                .insert("e1", b"v1".as_slice())
                .unwrap();
            author
                .get_map("tombstones")
                .insert("deadbeef", b"1".as_slice())
                .unwrap();
            author.commit();
            let update = author.export(ExportMode::all_updates()).unwrap();

            doc.import_with(&update, "conn:1").unwrap();
            server.persist_imported_update(&key, &update).unwrap();
        }

        // ── Server instance 2 over the same vault: RAM state is gone;
        //    everything must come back from sync_state.
        let server = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();

        // Root doc reloaded from d:root — meta.windows still lists the key.
        assert_eq!(
            read_window_list(&server.root_doc),
            vec![WindowKey::new("2026-02")]
        );

        // Window doc reloaded from d:w: + pending u:w: — the relayed entity
        // AND the tombstone (delete propagation) survive the restart.
        let doc = server
            .get_or_create_window(&WindowKey::new("2026-02"))
            .await
            .unwrap();
        assert_eq!(deep_map_bytes(&doc, "entities", "e1").unwrap(), b"v1");
        assert_eq!(
            deep_map_bytes(&doc, "tombstones", "deadbeef").unwrap(),
            b"1",
            "a relayed tombstone must survive a server restart"
        );
    }

    #[tokio::test]
    async fn boot_reconciles_root_windows_with_persisted_snapshots() {
        let (_dir, vault) = test_vault();

        // Simulate a crash between window-snapshot persistence and root
        // persistence: a d:w: snapshot exists but meta.windows never
        // learned the key.
        {
            let doc = LoroDoc::new();
            doc.commit();
            oneiron::sync::server_state::persist_window_snapshot(
                &vault,
                &WindowKey::new("2026-06"),
                &doc,
            )
            .unwrap();
        }

        let server = SyncServer::new(vault, SyncServerConfig::default()).unwrap();
        assert_eq!(
            read_window_list(&server.root_doc),
            vec![WindowKey::new("2026-06")],
            "boot must self-heal meta.windows from persisted d:w:* snapshots"
        );
    }

    #[tokio::test]
    async fn corrupt_window_snapshot_fails_closed() {
        let (_dir, vault) = test_vault();
        vault.sync_state_put("d:w:2026-04", b"garbage").unwrap();

        // Boot-time reconcile sees the key but get_or_create_window must
        // refuse to serve a fresh empty window over the corrupt snapshot.
        let server = SyncServer::new(vault, SyncServerConfig::default()).unwrap();
        let err = server
            .get_or_create_window(&WindowKey::new("2026-04"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, oneiron::Error::CrdtDecodeError { .. }),
            "corrupt persisted window must error, got {err:?}"
        );
    }

    /// ONE-1140 lease lifecycle at the registrar (OD-3/OD-4/OD-7/OD-8):
    /// register writes the pinned 58 B record into the root-doc `leases`
    /// map AND the vault's `ls:` mirror row (byte-identical, OD-3);
    /// renewal refreshes `renewed_at`/`expires_at` and flips an expired
    /// binding back to active; a same-client/different-key request is
    /// REJECTED with the binding untouched (first-binding-wins); revocation
    /// is terminal; an invalid proof of possession never touches state.
    #[tokio::test]
    async fn lease_lifecycle_register_renew_conflict_revoke() {
        use ed25519_dalek::{Signer, SigningKey};

        let (_dir, vault) = test_vault();
        let server = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();

        let key = SigningKey::from_bytes(&[7u8; 32]);
        let pubkey = key.verifying_key().to_bytes();
        let client_id = 0x0123_4567_89ab_cdefu64;
        let pop = |signer: &SigningKey, cid: u64, pk: &[u8; 32]| {
            signer
                .sign(&lease::lease_pop_transcript(cid, pk))
                .to_bytes()
        };

        // ── Register: granted, record layout literals on BOTH surfaces.
        let decision = server
            .register_lease(client_id, &pubkey, &pop(&key, client_id, &pubkey))
            .await
            .unwrap();
        assert!(decision.granted);
        assert!(decision.root_update.is_some(), "registry change broadcasts");
        let map_record = deep_map_bytes(&server.root_doc, "leases", "0123456789abcdef").unwrap();
        let ls_row = vault
            .sync_state_get("ls:0123456789abcdef")
            .unwrap()
            .unwrap();
        assert_eq!(
            map_record, ls_row,
            "OD-3: map value ≡ ls: row, byte-identical"
        );
        assert_eq!(ls_row.len(), 58, "OD-4 record length");
        assert_eq!(ls_row[0], 0x01, "version byte");
        assert_eq!(ls_row[1], 0x01, "status active");
        assert_eq!(&ls_row[2..34], &pubkey);
        let granted_at = u64::from_le_bytes(ls_row[34..42].try_into().unwrap());
        let renewed_at = u64::from_le_bytes(ls_row[42..50].try_into().unwrap());
        let expires_at = u64::from_le_bytes(ls_row[50..58].try_into().unwrap());
        assert_eq!(granted_at, renewed_at);
        assert_eq!(
            expires_at,
            renewed_at + 7_776_000,
            "90-day lease literal (OD-4)"
        );
        assert_eq!(decision.expires_at, expires_at);

        // ── Renew: simulate an old, EXPIRED binding (server is sole
        // writer, so the test rewrites the registry record directly), then
        // re-request with the SAME key: flips back to active, renewed_at
        // and expires_at refresh, granted_at is preserved.
        let stale = lease::LeaseRecord {
            status: lease::LeaseStatus::Expired,
            pubkey,
            granted_at: 1_000,
            renewed_at: 2_000,
            expires_at: 3_000,
        };
        server
            .root_doc
            .get_map(ROOT_LEASES_MAP)
            .insert(
                "0123456789abcdef",
                lease::encode_lease_record(&stale).as_slice(),
            )
            .unwrap();
        server.root_doc.commit();
        let decision = server
            .register_lease(client_id, &pubkey, &pop(&key, client_id, &pubkey))
            .await
            .unwrap();
        assert!(
            decision.granted,
            "expired + same key = renewal, not rejection"
        );
        let renewed_row = vault
            .sync_state_get("ls:0123456789abcdef")
            .unwrap()
            .unwrap();
        assert_eq!(renewed_row[1], 0x01, "expired flips back to active");
        assert_eq!(
            u64::from_le_bytes(renewed_row[34..42].try_into().unwrap()),
            1_000,
            "granted_at preserved across renewal"
        );
        let renewed_at2 = u64::from_le_bytes(renewed_row[42..50].try_into().unwrap());
        assert!(renewed_at2 > 2_000, "renewed_at refreshed");
        assert_eq!(
            u64::from_le_bytes(renewed_row[50..58].try_into().unwrap()),
            renewed_at2 + 7_776_000
        );

        // ── Conflict: same client id, DIFFERENT key → rejected, binding
        // bytes untouched (first-binding-wins).
        let intruder = SigningKey::from_bytes(&[9u8; 32]);
        let intruder_pk = intruder.verifying_key().to_bytes();
        let decision = server
            .register_lease(
                client_id,
                &intruder_pk,
                &pop(&intruder, client_id, &intruder_pk),
            )
            .await
            .unwrap();
        assert!(!decision.granted);
        assert_eq!(
            decision.expires_at, 0,
            "rejected ack carries expires_at = 0"
        );
        assert_eq!(
            vault
                .sync_state_get("ls:0123456789abcdef")
                .unwrap()
                .unwrap(),
            renewed_row,
            "a binding conflict must not modify the existing binding"
        );

        // ── Invalid PoP (valid key, signature over the WRONG client id):
        // rejected, no state change.
        let other_client = client_id + 1;
        let decision = server
            .register_lease(other_client, &pubkey, &pop(&key, client_id, &pubkey))
            .await
            .unwrap();
        assert!(
            !decision.granted,
            "PoP transcript binds the claimed client id"
        );
        assert!(
            vault
                .sync_state_get(&lease::lease_key(other_client))
                .unwrap()
                .is_none(),
            "an invalid PoP never reaches the registry"
        );

        // ── Revoke: terminal (OD-8). Status flips on both surfaces and a
        // later re-request with the ORIGINAL key is rejected.
        let update = server.revoke_lease(client_id).await.unwrap();
        assert!(update.is_some(), "revocation broadcasts a registry change");
        let revoked_row = vault
            .sync_state_get("ls:0123456789abcdef")
            .unwrap()
            .unwrap();
        assert_eq!(revoked_row[1], 0x03, "status revoked");
        let decision = server
            .register_lease(client_id, &pubkey, &pop(&key, client_id, &pubkey))
            .await
            .unwrap();
        assert!(!decision.granted, "revoked is terminal — no re-activation");
        // Unknown binding: revoke is a no-op (no phantom records).
        assert!(server.revoke_lease(0xffff).await.unwrap().is_none());
    }

    /// ONE-1140 RULING A (OD-8 amended, pubkey-bound; delete-safety adjacent,
    /// cap-exempt): `register_lease` refuses a FRESH active lease for a
    /// pubkey that ANY `ls:` row has revoked. A revoked pubkey is terminal
    /// across ALL client_ids, so a device rotating client_id while reusing
    /// its key cannot recover (recovery requires a fresh KEYPAIR). The
    /// None-arm guard writes NO row and grants nothing. A wrong impl that
    /// grants any absent client_id would write `ls:{B}` active and FAIL here.
    #[tokio::test]
    async fn register_lease_refuses_active_lease_for_already_revoked_pubkey() {
        use ed25519_dalek::{Signer, SigningKey};

        let (_dir, vault) = test_vault();
        let server = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();

        let key = SigningKey::from_bytes(&[23u8; 32]);
        let pubkey = key.verifying_key().to_bytes();
        let pop = |signer: &SigningKey, cid: u64, pk: &[u8; 32]| {
            signer
                .sign(&lease::lease_pop_transcript(cid, pk))
                .to_bytes()
        };

        // Client A binds pubkey P, then the owner revokes it.
        let client_a = 0x0a0a_0a0a_0a0a_0a0au64;
        assert!(
            server
                .register_lease(client_a, &pubkey, &pop(&key, client_a, &pubkey))
                .await
                .unwrap()
                .granted
        );
        assert!(server.revoke_lease(client_a).await.unwrap().is_some());
        assert_eq!(
            vault
                .sync_state_get(&lease::lease_key(client_a))
                .unwrap()
                .unwrap()[1],
            0x03,
            "client A's binding is revoked"
        );

        // A FRESH client B presents the SAME (revoked) pubkey with a valid
        // proof of possession.
        let client_b = 0x0b0b_0b0b_0b0b_0b0bu64;
        assert_ne!(client_a, client_b);
        let decision = server
            .register_lease(client_b, &pubkey, &pop(&key, client_b, &pubkey))
            .await
            .unwrap();
        assert!(
            !decision.granted,
            "a revoked pubkey can never obtain a fresh active lease under any client_id"
        );
        assert_eq!(
            decision.expires_at, 0,
            "rejected ack carries expires_at = 0"
        );
        assert!(
            vault
                .sync_state_get(&lease::lease_key(client_b))
                .unwrap()
                .is_none(),
            "no ls: row is written for the refused fresh client_id"
        );
        assert!(
            deep_map_bytes(&server.root_doc, "leases", &lease::client_id_hex(client_b)).is_none(),
            "no leases-map entry exists for the refused fresh client_id"
        );
    }

    #[test]
    fn used_window_sub_tags_are_pinned() {
        // The handler relies on these wire literals; keep them pinned here
        // so the server crate notices a transport renumbering.
        assert_eq!(window_sub_tags::UPDATE, 0);
        assert_eq!(window_sub_tags::VV_REQUEST, 2);
        assert_eq!(window_sub_tags::VV_RESPONSE, 3);
    }
}
