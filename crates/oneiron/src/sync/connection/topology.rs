//! Host-authorized home-node candidate updates, independent of socket liveness.

use std::sync::Arc;

use tokio::sync::{mpsc, watch};

use crate::Vault;
use crate::dreamer_runner::{DreamerHomeNodeCandidate, DreamerRunnerStore};
use crate::error::Result;
use crate::sync::client::SyncEvent;

/// The host's current MACRO home-node candidates for one vault.
///
/// The host publishes a full authoritative snapshot on membership/role
/// changes. A WebSocket connect, timeout, or disconnect does not publish.
/// `watch` coalesces bursts to the newest snapshot without dropping the
/// final state. Only hosts that own this topology should hold this handle.
#[derive(Debug, Clone)]
pub struct HomeNodeTopology {
    updates: watch::Sender<Vec<DreamerHomeNodeCandidate>>,
}

impl HomeNodeTopology {
    #[must_use]
    pub fn new(initial: Vec<DreamerHomeNodeCandidate>) -> Self {
        let (updates, _) = watch::channel(initial);
        Self { updates }
    }

    /// Publish a new host-authorized candidate snapshot, including explicit
    /// cloud detach or local role changes. An empty set removes the home.
    pub fn publish(&self, candidates: Vec<DreamerHomeNodeCandidate>) {
        self.updates.send_replace(candidates);
    }

    fn subscribe(&self) -> watch::Receiver<Vec<DreamerHomeNodeCandidate>> {
        self.updates.subscribe()
    }
}

/// Aborts the vault-scoped update consumer if its owning connection stops or
/// is cancelled. No process-global watcher outlives the connection.
pub(super) struct TopologyWatcher(tokio::task::JoinHandle<()>);

impl Drop for TopologyWatcher {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

/// Apply the initial snapshot before any socket work, then consume later
/// host updates even while the socket is disconnected/backing off.
pub(super) fn watch_topology(
    vault: Arc<Vault>,
    source: &HomeNodeTopology,
    events: mpsc::UnboundedSender<SyncEvent>,
) -> Result<TopologyWatcher> {
    let mut updates = source.subscribe();
    DreamerRunnerStore::new(&vault)
        .sync_topology_changed(&updates.borrow_and_update().clone(), now_secs())?;
    Ok(TopologyWatcher(tokio::spawn(async move {
        while updates.changed().await.is_ok() {
            let candidates = updates.borrow_and_update().clone();
            if let Err(error) =
                DreamerRunnerStore::new(&vault).sync_topology_changed(&candidates, now_secs())
            {
                let _ = events.send(SyncEvent::Error(format!(
                    "Home-node topology update failed: {error}"
                )));
            }
        }
    })))
}
