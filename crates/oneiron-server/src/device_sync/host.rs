//! The existing served host, or an app's already-open device vault.

use std::sync::Arc;

#[cfg(feature = "mesh")]
use super::DeviceSyncHost;
use crate::server::SyncServer;

pub(super) enum Host<'a> {
    Served(&'a Arc<SyncServer>),
    #[cfg(feature = "mesh")]
    Device {
        vault: &'a Arc<oneiron::Vault>,
        windows: Arc<oneiron::sync::WindowManager>,
    },
}

impl Host<'_> {
    pub(super) fn vault(&self) -> &Arc<oneiron::Vault> {
        match self {
            Self::Served(server) => &server.vault,
            #[cfg(feature = "mesh")]
            Self::Device { vault, .. } => vault,
        }
    }

    #[cfg(feature = "mesh")]
    pub(super) fn windows(&self) -> Arc<oneiron::sync::WindowManager> {
        match self {
            Self::Served(server) => Arc::clone(&server.reassert_manager),
            Self::Device { windows, .. } => Arc::clone(windows),
        }
    }

    #[cfg(feature = "mesh")]
    pub(super) fn candidacy(&self, always_on: bool, primary: bool) -> Option<super::Candidacy> {
        match self {
            Self::Served(server) => Some(super::Candidacy {
                always_on,
                primary,
                macro_ready: server.ai.dreamer_runs(),
            }),
            Self::Device { .. } => None,
        }
    }

    #[cfg(feature = "mesh")]
    pub(super) fn catalog(
        &self,
        mesh: Option<&crate::handler::mesh::MeshHost>,
        freeze: &super::ReapFreeze,
    ) -> Option<super::catalog::MeshCatalog> {
        match self {
            Self::Served(server) => mesh.map(|mesh| {
                super::catalog::MeshCatalog::new(
                    Arc::clone(&server.vault),
                    mesh.transport(),
                    server
                        .ai
                        .models()
                        .mesh_routes(&server.vault, mesh.transport()),
                    server.model_budgets.mesh_staging(),
                    freeze.admission(),
                )
            }),
            Self::Device { .. } => None,
        }
    }
}

#[cfg(feature = "mesh")]
impl DeviceSyncHost {
    /// The app has already opened, keyed and profiled this vault. Its only
    /// background host is this device's ordinary URL connection to home.
    pub(crate) async fn start_device(
        vault: &Arc<oneiron::Vault>,
        config: &crate::config::ServeConfig,
    ) -> Option<Self> {
        let dial = Self::dial_for_vault(vault, config, super::EnrolmentSource::Plain)?;
        let windows = Arc::new(oneiron::sync::WindowManager::new(
            Arc::clone(vault),
            Arc::new(oneiron::sync::bridge::Materializer::with_lease_vault_id(
                config.lease_vault_id,
            )),
            "device",
        ));
        windows.attach_to_vault();
        Self::open_logged(
            Host::Device { vault, windows },
            dial,
            None,
            super::ReapFreeze::never(),
        )
        .await
    }
}
