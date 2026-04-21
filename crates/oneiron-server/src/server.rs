use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use loro::{ExportMode, LoroDoc, VersionVector};
use oneiron::sync::WindowKey;
use tokio::sync::{RwLock, broadcast};

use crate::config::SyncServerConfig;
use crate::protocol::AwarenessState;

/// Broadcast payload: (conn_id, encoded_message).
/// conn_id 0 = local/bridge writes (broadcast to all devices).
/// conn_id >= 1 = specific connection (echo suppression skips sender).
pub(crate) type BroadcastPayload = (u32, Vec<u8>);

/// Core sync server state shared across all connections.
pub(crate) struct SyncServer {
    pub vault: Arc<oneiron::Vault>,
    /// Root LoroDoc (server-authoritative, contains meta.windows).
    pub root_doc: LoroDoc,
    /// Window key -> LoroDoc for each loaded window.
    pub windows: RwLock<HashMap<String, LoroDoc>>,
    /// Per-connection awareness state.
    pub awareness: RwLock<HashMap<u32, AwarenessState>>,
    /// Broadcast channel for fan-out to all connected clients.
    pub broadcast_tx: broadcast::Sender<BroadcastPayload>,
    /// Monotonic connection ID counter. 0 = reserved for bridge/local writes.
    pub next_conn_id: AtomicU32,
    /// Server configuration.
    pub config: SyncServerConfig,
}

impl SyncServer {
    /// Creates a new SyncServer with an empty root doc and no windows loaded.
    pub(crate) fn new(vault: oneiron::Vault, config: SyncServerConfig) -> Self {
        let root_doc = LoroDoc::new();
        // Initialize root doc meta map
        let meta = root_doc.get_map("meta");
        meta.insert("schema_version", 1i64).unwrap();
        meta.insert("windows", "").unwrap();
        root_doc.commit();

        let (broadcast_tx, _) = broadcast::channel(256);

        Self {
            vault: Arc::new(vault),
            root_doc,
            windows: RwLock::new(HashMap::new()),
            awareness: RwLock::new(HashMap::new()),
            broadcast_tx,
            next_conn_id: AtomicU32::new(1),
            config,
        }
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
    pub(crate) async fn get_or_create_window(&self, key: &str) -> LoroDoc {
        {
            let windows = self.windows.read().await;
            if let Some(doc) = windows.get(key) {
                return doc.clone();
            }
        }

        let doc = LoroDoc::new();
        // Initialize window schema maps
        let _entities = doc.get_map("entities");
        let _edges = doc.get_map("edges");
        let _tombstones = doc.get_map("tombstones");
        doc.commit();

        let mut windows = self.windows.write().await;
        windows.entry(key.to_string()).or_insert(doc).clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_key_for_known_timestamps() {
        assert_eq!(SyncServer::window_key_for_timestamp(1771027200), "2026-02");
        assert_eq!(SyncServer::window_key_for_timestamp(1764547200), "2025-12");
        assert_eq!(SyncServer::window_key_for_timestamp(0), "1970-01");
    }

    #[test]
    fn root_doc_initialization() {
        let dir = tempfile::tempdir().unwrap();
        let vault = oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap();
        let server = SyncServer::new(vault, SyncServerConfig::default());

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
                .as_string()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn window_creation() {
        let dir = tempfile::tempdir().unwrap();
        let vault = oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap();
        let server = SyncServer::new(vault, SyncServerConfig::default());

        let doc = server.get_or_create_window("2026-03").await;
        let deep = doc.get_deep_value();
        let map = deep.as_map().unwrap();
        assert!(map.contains_key("entities"));
        assert!(map.contains_key("edges"));
        assert!(map.contains_key("tombstones"));
    }
}
