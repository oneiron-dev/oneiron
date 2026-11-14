//! The existing served host, or the macOS app's device-mode server over its
//! already-open vault (L7-47).

use std::sync::Arc;

#[cfg(feature = "mesh")]
use super::DeviceSyncHost;
use crate::server::SyncServer;

pub(super) enum Host<'a> {
    Served(&'a Arc<SyncServer>),
    #[cfg(feature = "mesh")]
    Device(&'a Arc<SyncServer>),
}

impl Host<'_> {
    pub(super) fn vault(&self) -> &Arc<oneiron::Vault> {
        match self {
            #[cfg(feature = "mesh")]
            Self::Served(server) | Self::Device(server) => &server.vault,
            #[cfg(not(feature = "mesh"))]
            Self::Served(server) => &server.vault,
        }
    }

    #[cfg(feature = "mesh")]
    pub(super) fn windows(&self) -> Arc<oneiron::sync::WindowManager> {
        match self {
            Self::Served(server) | Self::Device(server) => Arc::clone(&server.reassert_manager),
        }
    }

    #[cfg(feature = "mesh")]
    pub(super) fn transport(
        &self,
        mesh: Option<&crate::handler::mesh::MeshHost>,
    ) -> Option<Arc<dyn oneiron_mesh_transport::MeshTransport>> {
        match self {
            Self::Served(_) | Self::Device(_) => mesh.map(|mesh| mesh.transport()),
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
            Self::Device(_) => None,
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
            Self::Device(_) => None,
        }
    }
}

/// The macOS app's home, resolved before its device-mode server is built, so
/// a vault with no home to dial builds none (L7-47).
#[cfg(feature = "mesh")]
pub(crate) struct DeviceDial(super::Dial);

#[cfg(feature = "mesh")]
impl DeviceSyncHost {
    /// What the app's already-open vault dials, or `None` with the ordinary
    /// line that says why (L7-47).
    pub(crate) fn device_dial(
        vault: &Arc<oneiron::Vault>,
        config: &crate::config::ServeConfig,
    ) -> Option<DeviceDial> {
        Self::dial_for_vault(vault, config, super::EnrolmentSource::Plain).map(DeviceDial)
    }

    /// The link over the app's device-mode server, whose vault the app already
    /// opened, keyed and profiled: its ordinary connection to home, and, while
    /// the home is down, to its peers through the listener (L7-47).
    pub(crate) async fn start_device(
        server: &Arc<SyncServer>,
        DeviceDial(dial): DeviceDial,
        mesh: Option<&crate::handler::mesh::MeshHost>,
    ) -> Option<Self> {
        Self::open_logged(Host::Device(server), dial, mesh, super::ReapFreeze::never()).await
    }
}
