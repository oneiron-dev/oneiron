//! The `fr:w:` full-resync markers: the windows a reconnect re-bootstraps.

use crate::sync::types::parse_window_key_str;
use crate::sync::window_rows::WINDOW_FULL_RESYNC_MARKER;

use super::super::SyncConnection;
use super::super::session::{FullResyncMarker, SessionFault};

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
