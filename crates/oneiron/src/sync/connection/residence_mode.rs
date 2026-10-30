//! FIX 8869: the residence mode follows the committed home. A connection
//! resolves its mode when it is made, and the elected home always runs All.
//! This worker resolves it again each time this machine becomes or stops
//! being the elected home: the topology's first election, a host update, or
//! an election a vault wake brings with no topology feed at all. It resolves
//! from the host's configured mode and the owner's stored choice (`rs:mode`),
//! never from the mode the connection ran, so a machine that loses the home
//! goes back to the owner's choice rather than keep the home's forced All.
//! Only a real change is published; the steady loop then queues what it
//! buffered and renegotiates ([`RENEGOTIATE_AT_ONCE`]).
//!
//! The owner's mode setter never runs here: nothing records All as the
//! owner's choice, and nothing waits for the home. On the way to All the
//! opened read caches go, as an owner's switch to All drops them, since the
//! full windows supersede them. On the way back the held windows and the
//! queue stay; the opened lane's own grant path takes them.

use std::convert::Infallible;
use std::sync::Arc;

use tokio::sync::mpsc;

use super::SyncConnection;
use crate::Vault;
use crate::sync::client::{SyncEvent, SyncResidenceMode};

/// CALLS renegotiate at once: a residence-mode change reconnects with the
/// new hello at once, past the outage backoff and `auto_reconnect: false`
/// alike. It is a renegotiation of a live lane, not an outage.
pub(super) const RENEGOTIATE_AT_ONCE: bool = true;

impl SyncConnection {
    /// Resolves the mode at start, then on each wake whose committed home
    /// moved this machine in or out of the home, for the connection's whole
    /// life. A federation lane keeps its configured mode and runs none. Each
    /// change holds the host's admission, a pause waited out (FIX 12036).
    pub(super) async fn run_residence_mode(
        &self,
        events: mpsc::UnboundedSender<SyncEvent>,
    ) -> Infallible {
        if self.config.client_config.federation_peer.is_some() {
            return std::future::pending().await;
        }
        let vault = Arc::clone(self.manager.vault());
        let mut wakes = vault.subscribe_proactivity_changes();
        let mut home = None;
        loop {
            match crate::sync::residence::local_is_elected_home(&vault) {
                Ok(is_home) if home != Some(is_home) => {
                    // `follow_home` resolves the mode afresh past a pause.
                    let _change = self.admit_round().await;
                    if let Err(error) = self.follow_home(&vault) {
                        let _ = events.send(SyncEvent::Error(format!(
                            "Residence mode refresh failed: {error}"
                        )));
                    } else {
                        home = Some(is_home);
                    }
                }
                Ok(_) => {}
                Err(error) => {
                    let _ = events.send(SyncEvent::Error(format!(
                        "Residence mode refresh failed: {error}"
                    )));
                }
            }
            if wakes.changed().await.is_err() {
                return std::future::pending().await;
            }
        }
    }

    /// Publishes the mode the committed home and the owner's stored choice
    /// resolve to now, when it differs from the one this connection runs.
    /// A change to All drops the opened read caches first.
    fn follow_home(&self, vault: &Vault) -> crate::error::Result<()> {
        let mode = crate::sync::residence::resolve_residence_mode(
            vault,
            self.config.client_config.residence_mode,
        )?;
        if mode == *self.mode.borrow() {
            return Ok(());
        }
        if mode == SyncResidenceMode::All {
            crate::sync::residence::prune_thin_items(vault, u64::MAX)?;
        }
        self.mode.send_if_modified(|running| {
            let changed = *running != mode;
            *running = mode;
            changed
        });
        Ok(())
    }
}
