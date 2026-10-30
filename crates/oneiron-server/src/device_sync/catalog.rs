//! The device's view of the models the owner's other nodes offer (OF-575),
//! learned while its home connection is synced. On a managed vault each
//! refresh holds an admission of the reap freeze of its own (FIX 5127).

use std::sync::Arc;

use crate::server::HousekeepingAdmission;

/// How often a synced device asks the owner's other nodes for their models
/// again. A catalog is pulled, never pushed: no mesh signal says a peer's
/// roster entry or offer changed.
const MESH_CATALOG_EVERY: std::time::Duration = std::time::Duration::from_secs(30);

/// The device's view of the models the owner's other nodes offer
/// ([`oneiron_llm_own_server::OwnServerBackend::refresh_from_mesh`]), over the
/// mesh listener's own transport.
pub(super) struct MeshCatalog {
    vault: Arc<oneiron::Vault>,
    transport: Arc<dyn oneiron_mesh_transport::MeshTransport>,
    /// Built at the first refresh; a failed build is tried again at the next.
    backend:
        Option<oneiron_llm_own_server::OwnServerBackend<oneiron_llm_own_server::MeshLlmTransport>>,
    /// The router's routes to those models (FIX 3229), published after each
    /// refresh.
    routes: crate::models::MeshRoutes,
    /// The vault's one mesh budget its transport's calls hold bytes on.
    staging: oneiron_llm_own_server::StagingBudget,
    /// Each refresh's admission of the reap freeze; none while frozen.
    admit: HousekeepingAdmission,
}

impl MeshCatalog {
    pub(super) fn new(
        vault: Arc<oneiron::Vault>,
        transport: Arc<dyn oneiron_mesh_transport::MeshTransport>,
        routes: crate::models::MeshRoutes,
        staging: oneiron_llm_own_server::StagingBudget,
        admit: HousekeepingAdmission,
    ) -> Self {
        Self {
            vault,
            transport,
            backend: None,
            routes,
            staging,
            admit,
        }
    }

    /// Refreshes on each `Synced`, then every [`MESH_CATALOG_EVERY`] while
    /// the connection stays synced. Ends when `statuses` closes, after any
    /// refresh in flight: its catalog call runs on a task of its own, so a
    /// dropped refresh would leave that call running past the mesh.
    pub(super) async fn run(
        mut self,
        mut statuses: tokio::sync::mpsc::UnboundedReceiver<oneiron::sync::SyncStatus>,
        home: &str,
    ) {
        let mut synced = false;
        let mut every = tokio::time::interval(MESH_CATALOG_EVERY);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                status = statuses.recv() => match status {
                    None => return,
                    Some(oneiron::sync::SyncStatus::Synced) => {
                        synced = true;
                        self.refresh(home).await;
                        every.reset();
                    }
                    Some(_) => synced = false,
                },
                _ = every.tick(), if synced => self.refresh(home).await,
            }
        }
    }

    /// One refresh, under an admission of its own: none while frozen.
    async fn refresh(&mut self, home: &str) {
        use oneiron_llm_own_server::{MeshLlmTransport, OwnServerBackend, VaultLlmNodes};

        let Some(_admitted) = (self.admit)() else {
            return;
        };
        if self.backend.is_none() {
            let transport = MeshLlmTransport::new(
                Arc::clone(&self.transport),
                Arc::new(VaultLlmNodes(Arc::clone(&self.vault))),
                tokio::runtime::Handle::current(),
                // What its calls hold at once (FIX 8619, FIX 9323).
                self.staging.clone(),
            );
            match OwnServerBackend::from_registry(&self.vault, transport) {
                Ok(backend) => self.backend = Some(backend),
                Err(error) => {
                    tracing::warn!(%home, %error, "mesh model catalog unavailable");
                    return;
                }
            }
        }
        let Some(backend) = &self.backend else {
            return;
        };
        match backend.refresh_from_mesh(&self.vault).await {
            Ok(refresh) => {
                self.routes.publish(&self.vault);
                if !refresh.conflicts.is_empty() {
                    tracing::warn!(
                        %home,
                        conflicts = ?refresh.conflicts,
                        "mesh model catalog kept the vault's own routes"
                    );
                }
                tracing::debug!(
                    %home,
                    written = ?refresh.written,
                    unreached = ?refresh.unreached,
                    "mesh model catalog refreshed"
                );
            }
            Err(error) => tracing::warn!(%home, %error, "mesh model catalog refresh failed"),
        }
    }
}
