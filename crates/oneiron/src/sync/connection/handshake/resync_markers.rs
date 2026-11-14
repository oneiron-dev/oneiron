//! The `fr:w:` full-resync markers: the windows a reconnect re-bootstraps.

use crate::sync::types::parse_window_key_str;
use crate::sync::window_rows::WINDOW_FULL_RESYNC_MARKER;

use super::super::SyncConnection;
use super::super::session::{FullResyncMarker, SessionFault};
use crate::sync::SyncClient;
use crate::sync::types::WindowKey;

/// The fault of an opened-item session holding a marked window it cannot
/// re-bootstrap over its own exchange.
const SYNC_ALL_RECOVERY: &str = "opened-item full-resync requires explicit sync-all recovery";

impl SyncConnection {
    pub(super) fn full_resync_markers(&self) -> Result<Vec<FullResyncMarker>, SessionFault> {
        let vault = self.manager.vault();
        let rtxn =
            vault.store.env.read_txn().map_err(|e| {
                SessionFault::Local(format!("Read full-resync markers failed: {e}"))
            })?;
        let keys = WINDOW_FULL_RESYNC_MARKER
            .scan_keys(&vault.store, &rtxn, &[])
            .map_err(|e| SessionFault::Local(format!("Read full-resync markers failed: {e}")))?;
        let mut markers = Vec::with_capacity(keys.len());
        for window_key in keys {
            if parse_window_key_str(&window_key).is_none() {
                return Err(SessionFault::Local(format!(
                    "Invalid full-resync marker key: fr:w:{window_key}"
                )));
            }
            markers.push(FullResyncMarker { window_key });
        }
        Ok(markers)
    }

    /// The marked windows an opened-item session re-bootstraps over this
    /// connection (FIX 20202): each window this device promoted and the home
    /// may read, over its promoted exchange, and each window of a world it
    /// follows that the home granted on this connection, over that follow
    /// (FOLLOWED-WINDOW-FULL-RESYNC). A followed window the home refused, or
    /// was not asked for, keeps its marker for a later connection. Any other
    /// marked window still needs sync-all.
    pub(super) fn opened_resync_markers(
        client: &SyncClient,
        markers: Vec<FullResyncMarker>,
    ) -> Result<Vec<FullResyncMarker>, SessionFault> {
        let mut recoverable = Vec::with_capacity(markers.len());
        for marker in markers {
            let Some(key) = WindowKey::try_new(marker.window_key.as_str()) else {
                return Err(SessionFault::local(SYNC_ALL_RECOVERY));
            };
            let promoted = client
                .opened_window_promoted(&key)
                .map_err(SessionFault::local)?;
            if !promoted && client.follows_full_window(key.as_str()) {
                if client.promotion_granted_on_connection(&key) && client.home_may_request(&key) {
                    recoverable.push(marker);
                }
                continue;
            }
            if !(promoted && client.home_may_promote(&key) && client.home_may_request(&key)) {
                return Err(SessionFault::local(SYNC_ALL_RECOVERY));
            }
            recoverable.push(marker);
        }
        Ok(recoverable)
    }

    pub(in crate::sync::connection) fn set_full_resync_markers(
        &self,
        markers: &[FullResyncMarker],
    ) -> Result<(), SessionFault> {
        if markers.is_empty() {
            return Ok(());
        }
        let vault = self.manager.vault();
        vault
            .with_write_txn_grouped(|wtxn| {
                for marker in markers {
                    WINDOW_FULL_RESYNC_MARKER.put(
                        &vault.store,
                        wtxn,
                        &marker.window_key,
                        &[1u8],
                    )?;
                }
                Ok(())
            })
            .map_err(|e| SessionFault::Local(format!("Set full-resync markers failed: {e}")))
    }

    pub(in crate::sync::connection) fn clear_full_resync_markers(
        &self,
        markers: &[FullResyncMarker],
    ) -> Result<(), SessionFault> {
        if markers.is_empty() {
            return Ok(());
        }
        let vault = self.manager.vault();
        vault
            .with_write_txn_grouped(|wtxn| {
                for marker in markers {
                    WINDOW_FULL_RESYNC_MARKER.delete(&vault.store, wtxn, &marker.window_key)?;
                }
                Ok(())
            })
            .map_err(|e| SessionFault::Local(format!("Clear full-resync markers failed: {e}")))
    }
}
