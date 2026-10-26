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

use std::sync::Arc;

use oneiron::EntityId;
use oneiron::sync::HomeRoute;
use oneiron_mesh_transport::sync_dialer::HomeResolver;
use tokio::sync::watch;

/// The routes a connection's committed elections publish, when it has a
/// home-node topology.
pub(super) type Routes = Option<watch::Receiver<Option<HomeRoute>>>;

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
