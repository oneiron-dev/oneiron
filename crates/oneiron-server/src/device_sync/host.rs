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
        transport: Option<Arc<dyn oneiron_mesh_transport::MeshTransport>>,
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
    pub(super) fn transport(
        &self,
        mesh: Option<&crate::handler::mesh::MeshHost>,
    ) -> Option<Arc<dyn oneiron_mesh_transport::MeshTransport>> {
        match self {
            Self::Served(_) => mesh.map(|mesh| mesh.transport()),
            Self::Device { transport, .. } => transport.clone(),
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
    /// background host is this device's ordinary connection to home.
    pub(crate) async fn start_device(
        vault: &Arc<oneiron::Vault>,
        config: &crate::config::ServeConfig,
    ) -> Option<(
        Self,
        Option<Arc<oneiron_mesh_transport::iroh_transport::IrohTransport>>,
    )> {
        let dial = Self::dial_for_vault(vault, config, super::EnrolmentSource::Plain)?;
        let transport = device_transport(vault).await;
        let windows = Arc::new(oneiron::sync::WindowManager::new(
            Arc::clone(vault),
            Arc::new(oneiron::sync::bridge::Materializer::with_lease_vault_id(
                config.lease_vault_id,
            )),
            "device",
        ));
        windows.attach_to_vault();
        let host = Self::open_logged(
            Host::Device {
                vault,
                windows,
                transport: transport.as_ref().map(|transport| {
                    Arc::clone(transport) as Arc<dyn oneiron_mesh_transport::MeshTransport>
                }),
            },
            dial,
            None,
            super::ReapFreeze::never(),
        )
        .await;
        if let Some(host) = host {
            Some((host, transport))
        } else {
            if let Some(transport) = transport {
                let _ = transport.shutdown().await;
            }
            None
        }
    }
}

#[cfg(feature = "mesh")]
async fn device_transport(
    vault: &Arc<oneiron::Vault>,
) -> Option<Arc<oneiron_mesh_transport::iroh_transport::IrohTransport>> {
    use oneiron_mesh_transport::iroh_transport::{IrohTransport, private_relay_map};
    use oneiron_mesh_transport::transport_key::TransportKey;
    use oneiron_mesh_transport::{
        AcceptPolicy, PairedMachineGrants, SYNC_ALPN, VaultMachineRoster, VaultPathReceipts,
    };

    let result: anyhow::Result<_> = async {
        let config = crate::handler::mesh::MeshConfig::from_env()?;
        let Some((bind, relays)) = config.outbound_settings() else {
            return Ok(None);
        };
        let (_, key) = TransportKey::for_install(vault)?
            .ok_or(oneiron_mesh_transport::MeshError::Unavailable)?;
        let policy = AcceptPolicy {
            roster: Arc::new(VaultMachineRoster(Arc::clone(vault))),
            grants: Arc::new(PairedMachineGrants(Arc::clone(vault))),
        };
        let transport = IrohTransport::bind_outbound_paired(
            key,
            policy,
            vec![SYNC_ALPN.to_vec()],
            bind,
            private_relay_map(relays)?,
            Arc::new(VaultPathReceipts(Arc::clone(vault))),
        )
        .await?;
        Ok(Some(Arc::new(transport)))
    }
    .await;
    match result {
        Ok(transport) => transport,
        Err(error) => {
            tracing::warn!(%error, "device mesh unavailable; keeping the ordinary home URL path");
            None
        }
    }
}
