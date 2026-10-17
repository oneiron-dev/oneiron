//! Host-authorized home-node candidate updates, independent of socket liveness.

use std::collections::BTreeMap;
use std::sync::Arc;

use tokio::sync::{mpsc, watch};

use crate::Vault;
use crate::dreamer_runner::{
    DreamerHomeNodeCandidate, DreamerHomeNodeDesignation, DreamerRunnerStore,
};
use crate::error::Result;
use crate::sync::client::{ResidenceHomeRoute, SyncEvent};

/// The host's current MACRO home-node candidates for one vault.
///
/// The host publishes a full authoritative snapshot on membership/role
/// changes. A WebSocket connect, timeout, or disconnect does not publish.
/// `watch` coalesces bursts to the newest snapshot without dropping the
/// final state. Only hosts that own this topology should hold this handle.
#[derive(Debug, Clone)]
pub struct HomeNodeTopology {
    updates: watch::Sender<TopologySnapshot>,
}

/// One host snapshot: the candidates, and the sync endpoint of each when the
/// host names them.
#[derive(Debug, Clone)]
struct TopologySnapshot {
    candidates: Vec<DreamerHomeNodeCandidate>,
    /// Each candidate's WebSocket endpoint, by node id. `None` leaves the
    /// residence route to the host.
    endpoints: Option<BTreeMap<u64, String>>,
}

impl HomeNodeTopology {
    #[must_use]
    pub fn new(initial: Vec<DreamerHomeNodeCandidate>) -> Self {
        let (updates, _) = watch::channel(TopologySnapshot {
            candidates: initial,
            endpoints: None,
        });
        Self { updates }
    }

    /// Publish a new host-authorized candidate snapshot, including explicit
    /// cloud detach or local role changes. An empty set removes the home.
    pub fn publish(&self, candidates: Vec<DreamerHomeNodeCandidate>) {
        self.updates.send_replace(TopologySnapshot {
            candidates,
            endpoints: None,
        });
    }

    /// Publish a snapshot with each candidate's sync WebSocket endpoint, by
    /// node id. After each election the connection routes residence reads
    /// to the elected home's endpoint; a home with none named falls back to
    /// the configured sync server.
    pub fn publish_with_endpoints(
        &self,
        candidates: Vec<DreamerHomeNodeCandidate>,
        endpoints: BTreeMap<u64, String>,
    ) {
        self.updates.send_replace(TopologySnapshot {
            candidates,
            endpoints: Some(endpoints),
        });
    }

    fn subscribe(&self) -> watch::Receiver<TopologySnapshot> {
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

/// Points residence reads at the elected home's endpoint when the snapshot
/// names endpoints; otherwise the host's own route stands.
fn route_home(
    route: Option<&ResidenceHomeRoute>,
    snapshot: &TopologySnapshot,
    home: Option<&DreamerHomeNodeDesignation>,
) {
    if let (Some(route), Some(endpoints)) = (route, snapshot.endpoints.as_ref()) {
        route.publish(home.and_then(|home| endpoints.get(&home.node_id).cloned()));
    }
}

/// Apply the initial snapshot before any socket work, then consume later
/// host updates even while the socket is disconnected/backing off. Each
/// election also moves `route` to the elected home's named endpoint.
pub(super) fn watch_topology(
    vault: Arc<Vault>,
    source: &HomeNodeTopology,
    route: Option<ResidenceHomeRoute>,
    events: mpsc::UnboundedSender<SyncEvent>,
) -> Result<TopologyWatcher> {
    let mut updates = source.subscribe();
    let snapshot = updates.borrow_and_update().clone();
    let home =
        DreamerRunnerStore::new(&vault).sync_topology_changed(&snapshot.candidates, now_secs())?;
    route_home(route.as_ref(), &snapshot, home.as_ref());
    Ok(TopologyWatcher(tokio::spawn(async move {
        while updates.changed().await.is_ok() {
            let snapshot = updates.borrow_and_update().clone();
            match DreamerRunnerStore::new(&vault)
                .sync_topology_changed(&snapshot.candidates, now_secs())
            {
                Ok(home) => route_home(route.as_ref(), &snapshot, home.as_ref()),
                Err(error) => {
                    let _ = events.send(SyncEvent::Error(format!(
                        "Home-node topology update failed: {error}"
                    )));
                }
            }
        }
    })))
}
