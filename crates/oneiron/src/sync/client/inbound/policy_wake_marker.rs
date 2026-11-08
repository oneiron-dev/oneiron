//! A policy wake's full-resync marker goes once its window's promoted
//! exchange proves the home holds the window (FIX 20202).

use std::cmp::Ordering::{Equal, Less};

use super::super::base::SyncClient;
use crate::error::Result;
use crate::sync::WindowManager;
use crate::sync::types::WindowKey;
use crate::sync::window_rows::{
    FullResyncForm, clear_covered_policy_wake_marker_in_txn, full_resync_form_in_txn,
};

impl SyncClient {
    /// Takes away window `window_key`'s full-resync marker in the policy
    /// wake's form once this home session's exchange of the promoted window,
    /// the ready exchange or the connect's, proved the home holds everything
    /// this device holds of it: the home's vector the exchange recorded as
    /// its convergence witness covers the window's, and the window's ready
    /// generation reached the marker's. A plain marker never goes here.
    /// Nothing goes on a peer session (FIX 4748), on a window not promoted
    /// here, or while the home lacks part of the window: the send that
    /// carries it up is not the home's receipt, and a later exchange, the
    /// next connection's at the latest, proves it. A marker the store cannot
    /// read or clear now stays for that later exchange.
    pub(super) fn settle_policy_wake_marker(&self, window_key: &str) {
        let Some(key) = WindowKey::try_new(window_key) else {
            return;
        };
        if self.peer_session.is_some() || !self.opened_window_promoted(&key).unwrap_or(false) {
            return;
        }
        let covered = match (self.window(window_key), self.server_vvs.get(window_key)) {
            (Some(window), Some(home)) => {
                matches!(window.doc.oplog_vv().partial_cmp(home), Some(Less | Equal))
            }
            _ => false,
        };
        if !covered {
            return;
        }
        if let Err(error) = self.clear_policy_wake_marker(&key) {
            tracing::warn!(
                window = %key,
                %error,
                "a policy wake's full-resync marker stays for a later exchange"
            );
        }
    }

    /// Clears window `key`'s policy-wake marker at its current ready
    /// generation, in one transaction with that generation's read, so a
    /// plain marker put over it meanwhile stays. A window holding no wake
    /// form takes no write.
    fn clear_policy_wake_marker(&self, key: &WindowKey) -> Result<()> {
        let vault = &self.vault;
        {
            let rtxn = vault.store.env.read_txn()?;
            if !matches!(
                full_resync_form_in_txn(vault, &rtxn, key.as_str())?,
                Some(FullResyncForm::PolicyWake { .. })
            ) {
                return Ok(());
            }
        }
        let cleared = vault.with_write_txn_grouped(|wtxn| {
            let ready = WindowManager::ready_generation_in_txn(vault, wtxn, key.as_str())?;
            clear_covered_policy_wake_marker_in_txn(vault, wtxn, key.as_str(), ready)
        })?;
        if cleared {
            tracing::info!(window = %key, "a policy wake's full-resync marker went with its window's exchange");
        }
        Ok(())
    }
}
