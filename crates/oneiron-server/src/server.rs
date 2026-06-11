use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use loro::{ExportMode, LoroDoc, VersionVector};
use oneiron::sync::WindowKey;
use oneiron::sync::schema::{add_window_to_root, read_window_list};
use oneiron::sync::server_state;
use oneiron::sync::window::load_window_from_state;
use tokio::sync::{RwLock, broadcast};

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
                meta.insert("schema_version", 1i64)
                    .map_err(|e| oneiron::Error::SyncProtocolError(e.to_string()))?;
                // `meta.windows` must be byte-encoded to match the schema
                // helpers (`schema::create_root_doc` / `add_window_to_root`)
                // and the client's `read_window_list` decoder, which only
                // accept `LoroValue::Binary`.
                meta.insert("windows", "".as_bytes())
                    .map_err(|e| oneiron::Error::SyncProtocolError(e.to_string()))?;
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

        let deep = server.root_doc.get_deep_value();
        let meta = deep.as_map().unwrap().get("meta").unwrap();
        let meta_map = meta.as_map().unwrap();
        assert_eq!(
            *meta_map.get("schema_version").unwrap().as_i64().unwrap(),
            1i64
        );
        assert!(
            meta_map
                .get("windows")
                .unwrap()
                .as_binary()
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

    #[test]
    fn used_window_sub_tags_are_pinned() {
        // The handler relies on these wire literals; keep them pinned here
        // so the server crate notices a transport renumbering.
        assert_eq!(window_sub_tags::UPDATE, 0);
        assert_eq!(window_sub_tags::VV_REQUEST, 2);
        assert_eq!(window_sub_tags::VV_RESPONSE, 3);
    }
}
