//! FIX 3131: the home device sync dials over the mesh. Each attempt, the
//! steady socket, each residence socket and each renewal, captures its own
//! target: the MACHINE the connection's last committed election routes to
//! (`HomeNodeTopology::home_route`), else the home the link was configured
//! with. A route to this machine, or to one with no paired mesh address
//! here, keeps the configured home. When the target moves, the link
//! rebuilds its connection on its current credential, as it does on a
//! renewed one, so the steady socket follows the elected home; queued work
//! stays in the vault for the next connection. Nothing here elects, judges
//! liveness or waits for a route.

use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::sync::HomeRoute;
use oneiron_mesh_transport::sync_dialer::HomeResolver;
use tokio::sync::watch;

/// The routes a connection's committed elections publish, when it has a
/// home-node topology.
pub(super) type Routes = Option<watch::Receiver<Option<HomeRoute>>>;

/// The connection's home-node topology: the one named home, as this
/// device's own candidate beside the vault's authorized candidates, reached
/// at `url`, so residence reads go there while it is the elected home. It
/// is the sync URL itself, so residence reads ride the same mesh dialer.
/// The link's configuration names `node` and `machine` together, so the
/// host binds the node to that MACHINE (FIX 11154): until the home's own
/// signed declaration names the node, its route still names the MACHINE.
pub(super) fn home_topology(
    node: u64,
    machine: EntityId,
    url: &str,
) -> oneiron::sync::HomeNodeTopology {
    let home = super::home_candidate(node);
    let topology = oneiron::sync::HomeNodeTopology::new(vec![home]);
    topology.publish_with_bindings(
        vec![home],
        BTreeMap::from([(node, url.to_owned())]),
        BTreeMap::from([(node, machine)]),
    );
    topology
}

/// The home each dial targets: the routed MACHINE when it is another machine
/// with a paired mesh address here, else `configured`. `local` is this
/// machine.
pub(super) fn resolver(
    vault: Arc<oneiron::Vault>,
    configured: EntityId,
    local: EntityId,
    routes: Routes,
) -> HomeResolver {
    Arc::new(move || {
        let routed = routes
            .as_ref()
            .and_then(|routes| routes.borrow().clone())
            .and_then(|route| route.machine);
        match routed {
            Some(machine)
                if machine != local
                    && vault
                        .mesh_machine(machine)
                        .is_ok_and(|address| address.is_some()) =>
            {
                machine
            }
            _ => configured,
        }
    })
}

/// Watches for the home the dials resolve to to move: the link then
/// rebuilds its connection on it.
pub(super) struct RouteChanges {
    routes: Routes,
    resolve: HomeResolver,
    /// The home the dials resolved to when last looked at.
    target: EntityId,
}

impl RouteChanges {
    /// Watches `routes` through `resolve`; with no routes it never fires.
    pub(super) fn new(routes: Routes, resolve: HomeResolver) -> Self {
        let target = resolve();
        Self {
            routes,
            resolve,
            target,
        }
    }

    /// Returns once the home the dials resolve to has moved. Cancel-safe: it
    /// awaits nothing but the route watch.
    pub(super) async fn changed(&mut self) {
        loop {
            let Some(routes) = self.routes.as_mut() else {
                return std::future::pending().await;
            };
            if routes.changed().await.is_err() {
                self.routes = None;
                continue;
            }
            let target = (self.resolve)();
            if target != self.target {
                self.target = target;
                return;
            }
        }
    }
}
