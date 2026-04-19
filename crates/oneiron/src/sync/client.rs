//! Client-side sync over WebSocket.
//!
//! Implements the device side of the ARCH-023 connection flow:
//! 1. Phase 1: Root doc sync (server sends snapshot, client imports)
//! 2. Phase 2: Default windows (current + previous) via VV exchange + updates
//! 3. Phase 3: Historical windows arrive via BulkTransfer + BulkTransferDone
//! 4. Ongoing: bidirectional incremental sync via WindowSync
//!
//! Reconnection with exponential backoff (1s → 60s cap).
//! 50ms debounce for rapid edits before sending.

use std::collections::HashMap;
use std::sync::Arc;

use loro::{ExportMode, LoroDoc};
use tokio::sync::mpsc;

use crate::Vault;
use crate::sync::transport::{
    self, TAG_BULK_TRANSFER, TAG_BULK_TRANSFER_DONE, TAG_SYNC_UPDATE, TAG_VERSION_VECTOR,
    TAG_WINDOW_SYNC, TransportError, window_sub_tags,
};
use crate::sync::types::{WindowKey, parse_window_key_str};

/// Client-side sync configuration.
#[derive(Debug, Clone)]
pub struct SyncClientConfig {
    /// WebSocket server URL (e.g., "wss://user-{id}.fly.dev/ws").
    pub server_url: String,
    /// Auth token (WorkOS JWT for production, shared secret for Phase 1).
    pub auth_token: String,
    /// Number of default windows to sync (current + previous). Default: 2.
    pub default_window_count: u8,
    /// Debounce interval for rapid edits before sending. Default: 50ms.
    pub sync_debounce_ms: u32,
    /// Maximum reconnection backoff delay. Default: 60s.
    pub reconnect_backoff_max_ms: u32,
    /// Initial reconnection delay. Default: 1s.
    pub reconnect_initial_ms: u32,
}

impl Default for SyncClientConfig {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            auth_token: String::new(),
            default_window_count: 2,
            sync_debounce_ms: 50,
            reconnect_backoff_max_ms: 60_000,
            reconnect_initial_ms: 1_000,
        }
    }
}

/// Sync status reported by the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncStatus {
    Disconnected,
    Connecting,
    Connected,
    Synced,
}

/// Events emitted by the sync client for the host application.
#[derive(Debug)]
pub enum SyncEvent {
    StatusChanged(SyncStatus),
    WindowUpdated { window_key: String },
    BulkTransferComplete { window_key: String },
    Error(String),
}

/// Client-side sync engine.
pub struct SyncClient {
    _vault: Arc<Vault>,
    root_doc: LoroDoc,
    windows: HashMap<String, LoroDoc>,
    _config: SyncClientConfig,
    status: SyncStatus,
    pub(crate) event_tx: mpsc::UnboundedSender<SyncEvent>,
    pending_updates: Vec<PendingUpdate>,
}

struct PendingUpdate {
    _window_key: String,
    _encoded: Vec<u8>,
}

impl SyncClient {
    /// Creates a new sync client.
    pub fn new(
        vault: Arc<Vault>,
        config: SyncClientConfig,
    ) -> (Self, mpsc::UnboundedReceiver<SyncEvent>) {
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let root_doc = LoroDoc::new();
        // Root doc will be populated by server snapshot on connect
        let _meta = root_doc.get_map("meta");

        let client = Self {
            _vault: vault,
            root_doc,
            windows: HashMap::new(),
            _config: config,
            status: SyncStatus::Disconnected,
            event_tx,
            pending_updates: Vec::new(),
        };

        (client, event_rx)
    }

    pub fn status(&self) -> &SyncStatus {
        &self.status
    }

    /// Queues a local update for a window to be sent to the server.
    pub fn queue_update(&mut self, window_key: &str, update_bytes: Vec<u8>) {
        if parse_window_key_str(window_key).is_none() {
            let _ = self.event_tx.send(SyncEvent::Error(format!(
                "Invalid window key for local update: {window_key}"
            )));
            return;
        }
        let msg = transport::encode_window_sync(window_key, window_sub_tags::UPDATE, &update_bytes);
        self.pending_updates.push(PendingUpdate {
            _window_key: window_key.to_string(),
            _encoded: msg,
        });
    }

    /// Ensures a window LoroDoc exists for the given key.
    pub fn ensure_window(&mut self, key: &str) -> Result<&LoroDoc, TransportError> {
        if parse_window_key_str(key).is_none() {
            return Err(TransportError::InvalidWindowKey);
        }
        Ok(self.windows.entry(key.to_string()).or_insert_with(|| {
            let doc = LoroDoc::new();
            let _entities = doc.get_map("entities");
            let _edges = doc.get_map("edges");
            let _tombstones = doc.get_map("tombstones");
            doc.commit();
            doc
        }))
    }

    pub fn window(&self, key: &str) -> Option<&LoroDoc> {
        self.windows.get(key)
    }

    pub fn root_doc(&self) -> &LoroDoc {
        &self.root_doc
    }

    /// Returns the list of window keys from the root doc (set by server).
    pub fn server_windows(&self) -> Vec<String> {
        let windows_str = self.root_doc.get_deep_value().as_map().and_then(|m| {
            m.get("meta")?
                .as_map()?
                .get("windows")?
                .as_string()
                .cloned()
        });

        match windows_str {
            Some(s) if !s.is_empty() => s
                .split(',')
                .filter_map(|s| {
                    let key = s.trim();
                    if parse_window_key_str(key).is_some() {
                        Some(key.to_string())
                    } else {
                        tracing::warn!(window_key = %key, "sync client: ignoring invalid server window key");
                        None
                    }
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Handles an incoming wire message from the server.
    pub fn handle_server_message(&mut self, data: &[u8]) -> Result<Vec<Vec<u8>>, TransportError> {
        if data.is_empty() {
            return Err(TransportError::InvalidPayload("empty message"));
        }

        let tag = data[0];
        let payload = &data[1..];
        let mut responses = Vec::new();

        match tag {
            TAG_SYNC_UPDATE => {
                // Root doc update/snapshot from server — import it
                self.root_doc
                    .import(payload)
                    .map_err(|_| TransportError::InvalidPayload("root doc import failed"))?;
            }
            TAG_VERSION_VECTOR => {
                // Server sent its root VV — we could compute a diff, but root is
                // server-authoritative so we just wait for the snapshot/update.
            }
            TAG_WINDOW_SYNC => {
                let (window_key, sub_tag, inner) = transport::decode_window_sync(payload)?;
                let reply = self.handle_window_sync(window_key, sub_tag, inner)?;
                if let Some(r) = reply {
                    responses.push(r);
                }
            }
            TAG_BULK_TRANSFER => {
                let (window_key, compressed) = transport::decode_bulk_transfer(payload)?;
                self.handle_bulk_transfer(window_key, compressed)?;
            }
            TAG_BULK_TRANSFER_DONE => {
                let (window_key, doc_state) = transport::decode_bulk_transfer_done(payload)?;
                self.handle_bulk_transfer_done(window_key, doc_state)?;
            }
            _ => return Err(TransportError::UnknownTag(tag)),
        }

        Ok(responses)
    }

    fn handle_window_sync(
        &mut self,
        window_key: &str,
        sub_tag: u8,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, TransportError> {
        self.ensure_window(window_key)?;
        let doc = self.windows.get(window_key).unwrap();

        match sub_tag {
            window_sub_tags::VV_REQUEST => {
                // Server asking for our VV — send our updates
                let updates = doc
                    .export(ExportMode::all_updates())
                    .map_err(|_| TransportError::InvalidPayload("export failed"))?;
                let response =
                    transport::encode_window_sync(window_key, window_sub_tags::UPDATE, &updates);
                Ok(Some(response))
            }
            window_sub_tags::UPDATE => {
                // Server sending Loro update bytes — import
                doc.import(payload)
                    .map_err(|_| TransportError::InvalidPayload("window import failed"))?;
                let _ = self.event_tx.send(SyncEvent::WindowUpdated {
                    window_key: window_key.to_string(),
                });
                Ok(None)
            }
            window_sub_tags::VV_RESPONSE => {
                // Server's VV — we could use this to compute what to send.
                // For now, just note it.
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn handle_bulk_transfer(
        &mut self,
        window_key: &str,
        compressed: &[u8],
    ) -> Result<(), TransportError> {
        // Streaming decompression with size limit to prevent decompression bombs.
        const MAX_BULK_DECOMPRESSED: usize = 8 * 1024 * 1024; // 8 MB
        let mut decoder = zstd::Decoder::new(compressed)
            .map_err(|_| TransportError::InvalidPayload("zstd decoder init failed"))?;
        let mut buf = Vec::with_capacity(std::cmp::min(
            compressed.len().saturating_mul(2),
            MAX_BULK_DECOMPRESSED,
        ));
        let mut chunk = [0u8; 8192];
        loop {
            let n = std::io::Read::read(&mut decoder, &mut chunk)
                .map_err(|_| TransportError::InvalidPayload("zstd decompress failed"))?;
            if n == 0 {
                break;
            }
            if buf.len() + n > MAX_BULK_DECOMPRESSED {
                return Err(TransportError::FrameTooLarge {
                    size: buf.len() + n,
                    max: MAX_BULK_DECOMPRESSED,
                });
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        // TODO: deserialize MessagePack and apply to LMDB vault
        let _ = (window_key, buf);
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "Result<(), TransportError> preserved for forward-compat; LMDB persistence in handler body is TODO"
    )]
    fn handle_bulk_transfer_done(
        &mut self,
        window_key: &str,
        doc_state: &[u8],
    ) -> Result<(), TransportError> {
        if !doc_state.is_empty() {
            // Persist Loro Doc state for future incremental sync
            // TODO: Write to sync_state LMDB database
        }
        let _ = self.event_tx.send(SyncEvent::BulkTransferComplete {
            window_key: window_key.to_string(),
        });
        Ok(())
    }

    /// Generates initial sync messages for the connection flow.
    ///
    /// Returns messages to send to the server:
    /// 1. Root doc VV (so server knows what we have)
    /// 2. Default window VV requests (current + previous month)
    pub fn generate_initial_sync(&mut self) -> Vec<Vec<u8>> {
        let mut messages = Vec::new();

        // Phase 1: Send our root VV (empty for new client — server will send snapshot)
        let root_vv = self.root_doc.oplog_vv();
        let vv_bytes = serde_json::to_vec(&root_vv).unwrap_or_default();
        let mut vv_msg = vec![TAG_VERSION_VECTOR];
        vv_msg.extend_from_slice(&vv_bytes);
        messages.push(vv_msg);

        // Phase 2: Default window VV requests for current + previous month
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let current_key = WindowKey::from_timestamp(now_secs);
        if let Err(e) = self.ensure_window(current_key.as_str()) {
            let _ = self.event_tx.send(SyncEvent::Error(format!(
                "Initial sync invalid current window key: {e}"
            )));
            return messages;
        }

        if let Some(prev_key) = current_key.previous_month()
            && let Err(e) = self.ensure_window(prev_key.as_str())
        {
            let _ = self.event_tx.send(SyncEvent::Error(format!(
                "Initial sync invalid previous window key: {e}"
            )));
            return messages;
        }

        // Send VV request for each default window
        for (key, doc) in &self.windows {
            let vv = doc.oplog_vv();
            let vv_bytes = serde_json::to_vec(&vv).unwrap_or_default();
            let msg = transport::encode_window_sync(key, window_sub_tags::VV_REQUEST, &vv_bytes);
            messages.push(msg);
        }

        messages
    }
}

/// Computes the next backoff delay with exponential growth capped at max.
pub fn next_backoff(current_ms: u32, max_ms: u32) -> u32 {
    std::cmp::min(current_ms.saturating_mul(2), max_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_vault() -> Arc<Vault> {
        let dir = tempfile::tempdir().unwrap();
        let config = crate::types::VaultConfig::device();
        Arc::new(Vault::open(dir.path(), config).unwrap())
    }

    #[test]
    fn sync_client_creation() {
        let vault = test_vault();
        let (client, _rx) = SyncClient::new(vault, SyncClientConfig::default());
        assert_eq!(client.status(), &SyncStatus::Disconnected);
        assert!(client.server_windows().is_empty());
    }

    #[test]
    fn sync_client_ensure_window() {
        let vault = test_vault();
        let (mut client, _rx) = SyncClient::new(vault, SyncClientConfig::default());
        client.ensure_window("2026-03").unwrap();
        assert!(client.window("2026-03").is_some());
        assert!(client.window("2026-04").is_none());
    }

    #[test]
    fn sync_client_rejects_invalid_window_creation() {
        let vault = test_vault();
        let (mut client, _rx) = SyncClient::new(vault, SyncClientConfig::default());
        assert!(matches!(
            client.ensure_window("2026-13"),
            Err(TransportError::InvalidWindowKey)
        ));
        assert!(matches!(
            client.ensure_window("1969-12"),
            Err(TransportError::InvalidWindowKey)
        ));
    }

    #[test]
    fn sync_client_generate_initial_sync() {
        let vault = test_vault();
        let (mut client, _rx) = SyncClient::new(vault, SyncClientConfig::default());
        let messages = client.generate_initial_sync();
        // Should have: 1 root VV + 2 window VV requests (current + prev)
        assert!(messages.len() >= 2);
    }

    #[test]
    fn sync_client_queue_update() {
        let vault = test_vault();
        let (mut client, _rx) = SyncClient::new(vault, SyncClientConfig::default());
        client.queue_update("2026-03", vec![1, 2, 3]);
        assert_eq!(client.pending_updates.len(), 1);
    }

    #[test]
    fn sync_client_rejects_invalid_queue_update() {
        let vault = test_vault();
        let (mut client, mut rx) = SyncClient::new(vault, SyncClientConfig::default());
        client.queue_update("2026-13", vec![1, 2, 3]);
        assert!(client.pending_updates.is_empty());
        match rx.try_recv() {
            Ok(SyncEvent::Error(msg)) => assert!(msg.contains("Invalid window key")),
            other => panic!("expected invalid window key error, got {other:?}"),
        }
    }

    #[test]
    fn sync_client_filters_invalid_server_windows() {
        let vault = test_vault();
        let (client, _rx) = SyncClient::new(vault, SyncClientConfig::default());
        let meta = client.root_doc.get_map("meta");
        meta.insert("windows", "2026-03,1969-12,2026-13,2026-04")
            .unwrap();
        client.root_doc.commit();

        let windows = client.server_windows();
        assert_eq!(windows, vec!["2026-03".to_string(), "2026-04".to_string()]);
    }

    #[test]
    fn backoff_calculation() {
        assert_eq!(next_backoff(1_000, 60_000), 2_000);
        assert_eq!(next_backoff(2_000, 60_000), 4_000);
        assert_eq!(next_backoff(32_000, 60_000), 60_000);
        assert_eq!(next_backoff(60_000, 60_000), 60_000);
    }
}
