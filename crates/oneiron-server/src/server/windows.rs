//! Window serving: snapshots, exports, and the local-change broadcast bridge.
use std::sync::Arc;

use loro::{ExportMode, LoroDoc, VersionVector};
use oneiron::sync::schema::{add_window_to_root, read_window_list};
use oneiron::sync::server_state;
use oneiron::sync::{WindowKey, WindowManager};
use tokio::sync::broadcast;

use super::core::{BroadcastPayload, SyncServer};

/// User id passed to the shared window loader. The server vault is
/// single-tenant (one vault per user per ARCH-0023b Fig. 1) and the loader
/// does not key storage by user, so this is a label only.
pub(super) const SERVER_USER_ID: &str = "server";

impl SyncServer {
    // ─── Device-lease registry (ONE-1140, OD-3) ──────────────────────────

    /// Exports root doc updates since the given version vector.
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
}

/// Bridges the engine's Observer-A local-update path into `broadcast_tx`.
///
/// Until now only *relayed* writes produced a change notice: a client's update
/// was re-broadcast by the WebSocket handler, but a change this process
/// committed itself — an LMDB→CRDT mirror, a reassertion drain, a scrub —
/// reached the broadcast channel only where some call site remembered to
/// publish it. `WindowManager` already funnels every persisted local window
/// commit through one shared `OutboundSink` (bridge.rs Observer A), so the
/// server attaches its own receiver there and re-publishes each update as the
/// existing WindowSync `UPDATE` frame with `conn_id = 0`, the local/bridge
/// sender sentinel. Local writes then look exactly like relayed ones to anyone
/// reading the channel, which is what makes an in-process reactive local read
/// (ONE-1437, `api::reactive`) possible without a second notification path.
///
/// The frames are CRDT updates, so the handful of call sites that also publish
/// their own coarse delta stay correct: a client importing the same update
/// twice converges to the same state.
///
/// Does nothing outside a Tokio runtime (synchronous unit-test construction).
/// The attach therefore happens only once the relay task can actually run, so
/// Observer A keeps its durable `SyncQueue` fallback and no unread sender can
/// accumulate updates.
pub(super) fn spawn_local_change_producer(
    reassert_manager: &Arc<WindowManager>,
    broadcast_tx: &broadcast::Sender<BroadcastPayload>,
) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let (updates_tx, mut updates_rx) = tokio::sync::mpsc::unbounded_channel();
    reassert_manager.outbound().attach(updates_tx);

    let broadcast_tx = broadcast_tx.clone();
    runtime.spawn(async move {
        while let Some(update) = updates_rx.recv().await {
            let window_key = update.window_key;
            match crate::protocol::encode_window_sync(
                &window_key,
                crate::protocol::window_sub_tags::UPDATE,
                &update.update_bytes,
            )
            .into_result()
            {
                Ok(msg) => {
                    let _ = crate::broadcast::broadcast(&broadcast_tx, 0, msg);
                }
                Err(err) => {
                    tracing::error!(
                        window = %window_key,
                        error = crate::protocol::transport_err_msg(err),
                        "local-change producer failed to encode window update"
                    );
                }
            }
        }
    });
}
