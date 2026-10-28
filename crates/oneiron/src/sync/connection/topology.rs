//! Host-authorized home-node candidate updates, independent of socket liveness.
//! Each committed election also publishes the route device sync dials the
//! elected home by (FIX 3131).

use std::collections::BTreeMap;
use std::sync::Arc;

use tokio::sync::{mpsc, watch};

use crate::dreamer_runner::{
    DreamerHomeNodeCandidate, DreamerHomeNodeDesignation, DreamerRunnerStore,
};
use crate::error::Result;
use crate::sync::client::{ResidenceHomeRoute, SyncEvent};
use crate::{EntityId, Vault};

/// The host's current MACRO home-node candidates for one vault.
///
/// The host publishes a full authoritative snapshot on membership/role
/// changes. A WebSocket connect, timeout, or disconnect does not publish.
/// `watch` coalesces bursts to the newest snapshot without dropping the
/// final state. Only hosts that own this topology should hold this handle.
#[derive(Debug, Clone)]
pub struct HomeNodeTopology {
    updates: watch::Sender<TopologySnapshot>,
    /// The route each committed election names (FIX 3131).
    routes: watch::Sender<Option<HomeRoute>>,
}

/// The home a committed election names, as device sync dials it (FIX
/// 3131): its sync node, the MACHINE whose home candidacy declares that node
/// when one alone does, and the endpoint the host's topology names for it.
/// Nothing here elects, dials or waits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeRoute {
    pub node_id: u64,
    pub machine: Option<EntityId>,
    pub endpoint: Option<String>,
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
        let (routes, _) = watch::channel(None);
        Self { updates, routes }
    }

    /// The route the last committed election named, and each one after it:
    /// `None` before the connection's first election, or while it names no
    /// home.
    #[must_use]
    pub fn home_route(&self) -> watch::Receiver<Option<HomeRoute>> {
        self.routes.subscribe()
    }

    /// Publish a new host-authorized candidate snapshot, including explicit
    /// cloud detach or local role changes. An empty set clears only the host's
    /// own candidacy; signed HomeCandidacy declarations still elect.
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

/// Publishes the route of the committed election's `home` (FIX 3131), when
/// it moved.
fn publish_route(
    vault: &Vault,
    routes: &watch::Sender<Option<HomeRoute>>,
    snapshot: &TopologySnapshot,
    home: Option<&DreamerHomeNodeDesignation>,
) {
    let route = home.map(|home| HomeRoute {
        node_id: home.node_id,
        machine: declaring_machine(vault, home.node_id),
        endpoint: snapshot
            .endpoints
            .as_ref()
            .and_then(|endpoints| endpoints.get(&home.node_id).cloned()),
    });
    routes.send_if_modified(|current| {
        let moved = *current != route;
        if moved {
            current.clone_from(&route);
        }
        moved
    });
}

/// The MACHINE whose folded home candidacy declares `node`, when one alone
/// does; `None` when none does, two do, or the fold does not read.
fn declaring_machine(vault: &Vault, node: u64) -> Option<EntityId> {
    let txn = vault.store.env.read_txn().ok()?;
    let fold = vault.authority_view_readonly_in_txn(&txn).ok()?;
    let mut declaring = fold
        .home_candidacy
        .iter()
        .filter(|(_, declared)| declared.node_id == node)
        .map(|(machine, _)| *machine);
    let machine = declaring.next()?;
    declaring.next().is_none().then_some(machine)
}

/// FIX 6459: feeds the routes a home move's target is captured at, before
/// the election they inform: each candidate's endpoint when the snapshot
/// names them, and the route residence reads take where it names none (the
/// host's route, else `server`). The election's own writer captures each
/// move's route from them; delivery dials it only while its socket proves
/// the move's target.
fn feed_routes(
    vault: &Vault,
    snapshot: &TopologySnapshot,
    route: Option<&ResidenceHomeRoute>,
    server: &str,
) {
    let fallback = route
        .and_then(ResidenceHomeRoute::current)
        .unwrap_or_else(|| server.to_owned());
    super::home_handoff::feed_move_routes(vault, snapshot.endpoints.clone(), fallback);
}

/// Apply the initial snapshot before any socket work, then consume later
/// host updates even while the socket is disconnected/backing off. Each
/// election also moves `route` to the elected home's named endpoint. An
/// owner's home pick re-elects where it lands, in its own commit; on the
/// wake that follows, the route moves to the committed home over the last
/// host snapshot, and only a host update replaces that snapshot. Each
/// snapshot's routes are fed before its election, which captures a move's
/// route as it commits the move (FIX 6459).
pub(super) fn watch_topology(
    vault: Arc<Vault>,
    source: &HomeNodeTopology,
    route: Option<ResidenceHomeRoute>,
    server: String,
    events: mpsc::UnboundedSender<SyncEvent>,
) -> Result<TopologyWatcher> {
    let mut updates = source.subscribe();
    let routes = source.routes.clone();
    let mut wakes = vault.subscribe_proactivity_changes();
    let mut snapshot = updates.borrow_and_update().clone();
    feed_routes(&vault, &snapshot, route.as_ref(), &server);
    let mut routed =
        DreamerRunnerStore::new(&vault).sync_topology_changed(&snapshot.candidates, now_secs())?;
    route_home(route.as_ref(), &snapshot, routed.as_ref());
    publish_route(&vault, &routes, &snapshot, routed.as_ref());
    Ok(TopologyWatcher(tokio::spawn(async move {
        loop {
            let home = tokio::select! {
                changed = updates.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    snapshot = updates.borrow_and_update().clone();
                    feed_routes(&vault, &snapshot, route.as_ref(), &server);
                    DreamerRunnerStore::new(&vault)
                        .sync_topology_changed(&snapshot.candidates, now_secs())
                }
                Ok(()) = wakes.changed() => {
                    let home = DreamerRunnerStore::new(&vault).home_node_designation();
                    if matches!(&home, Ok(home) if *home == routed) {
                        continue;
                    }
                    home
                }
            };
            match home {
                Ok(home) => {
                    route_home(route.as_ref(), &snapshot, home.as_ref());
                    publish_route(&vault, &routes, &snapshot, home.as_ref());
                    routed = home;
                }
                Err(error) => {
                    let _ = events.send(SyncEvent::Error(format!(
                        "Home-node topology update failed: {error}"
                    )));
                }
            }
        }
    })))
}
