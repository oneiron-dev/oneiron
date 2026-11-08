//! An opened-item device's connect leaves a policy wake's full-resync
//! markers to their windows' promoted exchange (FIX 20202).

use crate::sync::window_rows::{FullResyncForm, full_resync_form_in_txn};

use super::super::SyncConnection;
use super::super::session::{FullResyncMarker, SessionFault};

impl SyncConnection {
    /// Phase 3's full-resync markers on an opened-item device. When every one
    /// holds the policy wake's form, each stays in place for its window's
    /// promoted exchange, which takes it away once the home holds the window
    /// at the wake's generation: `markers` empties, so no window is
    /// re-bootstrapped and the queue goes on as with none. A plain marker
    /// leaves `markers` whole, and with it the refusal that asks for explicit
    /// sync-all recovery.
    pub(super) fn defer_policy_wake_markers(
        &self,
        markers: &mut Vec<FullResyncMarker>,
    ) -> Result<(), SessionFault> {
        if markers.is_empty() {
            return Ok(());
        }
        let vault = self.manager.vault();
        let rtxn =
            vault.store.env.read_txn().map_err(|e| {
                SessionFault::Local(format!("Read full-resync markers failed: {e}"))
            })?;
        for marker in &*markers {
            let form = full_resync_form_in_txn(vault, &rtxn, &marker.window_key).map_err(|e| {
                SessionFault::Local(format!("Read full-resync markers failed: {e}"))
            })?;
            // A plain marker keeps the refusal; one that went since the scan
            // asks nothing more.
            if form == Some(FullResyncForm::Plain) {
                return Ok(());
            }
        }
        tracing::info!(
            marker_count = markers.len(),
            "opened-item full-resync markers a policy wake left wait for their windows' promoted exchange"
        );
        markers.clear();
        Ok(())
    }
}
