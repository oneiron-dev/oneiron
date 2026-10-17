//! The device side of sync (ARCH-0023b): a machine that is not the elected
//! home dials its home and keeps its vault in sync there. It dials over the
//! paired mesh, on the mesh listener's own endpoint, and presents the paired
//! owner-grade credential its `[device_sync]` section names.
//!
//! One connection runs for the server's life. Its own loop reconnects with
//! backoff, so there is no second loop here. It attaches its outbound channel
//! beside the server's relay to its own clients, never in place of it. Logs
//! carry machine ids only, never a slip or a key.

use std::sync::Arc;

use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::config::DeviceSyncConfig;
use crate::handler::mesh::MeshHost;
use crate::server::SyncServer;

/// The running connection to the home.
#[cfg_attr(not(feature = "mesh"), allow(dead_code))]
pub(crate) struct DeviceSyncHost {
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl DeviceSyncHost {
    /// Dials the home `config` names, when it names one and this machine may:
    /// an enrolled machine that is not the elected home, with the home a live
    /// paired machine and a mesh listener to ride. Otherwise one "disabled"
    /// line says why, and serve runs on without it.
    pub(crate) async fn start(
        server: &Arc<SyncServer>,
        config: Option<&DeviceSyncConfig>,
        mesh: Option<&MeshHost>,
    ) -> Option<Self> {
        let config = config?;
        match open(server, config, mesh).await {
            Ok(host) => Some(host),
            Err(reason) => {
                tracing::warn!("device sync disabled: {reason:#}");
                None
            }
        }
    }

    /// Stops the connection and waits for its loop to end, so its channel
    /// detaches before the mesh it rides closes.
    pub(crate) async fn stop(self) {
        let _ = self.stop.send(());
        if let Err(error) = self.task.await {
            tracing::warn!(%error, "device sync task");
        }
    }
}

#[cfg(not(feature = "mesh"))]
async fn open(
    _server: &Arc<SyncServer>,
    _config: &DeviceSyncConfig,
    _mesh: Option<&MeshHost>,
) -> anyhow::Result<DeviceSyncHost> {
    anyhow::bail!("this server was built without the `mesh` feature")
}

#[cfg(feature = "mesh")]
async fn open(
    server: &Arc<SyncServer>,
    config: &DeviceSyncConfig,
    mesh: Option<&MeshHost>,
) -> anyhow::Result<DeviceSyncHost> {
    use oneiron::sync::{
        ConnectionConfig, SyncClientConfig, SyncConnection, SyncEvent, SyncTransportCredential,
    };
    use oneiron_mesh_transport::sync_dialer::MeshSyncDialer;

    let mesh = mesh
        .ok_or_else(|| anyhow::anyhow!("no mesh listener to dial from; set ONEIRON_MESH_BIND"))?;
    let home = config.home()?;
    let vault = Arc::clone(&server.vault);
    let machine = tokio::task::spawn_blocking(move || standing(&vault, home)).await??;
    let credential =
        crate::commands::credential_file::PairedCredentialFile::read(&config.credential_file)?;
    let key = credential.signing_key()?;
    let client_config = SyncClientConfig {
        server_url: config.home_url.clone(),
        transport_credential: Some(SyncTransportCredential::new(credential.token, key)),
        followed_worlds: Some(config.followed_worlds()?),
        mesh_dialer: Some(Arc::new(MeshSyncDialer::new(mesh.transport(), home))),
        ..SyncClientConfig::default()
    };
    let connection = SyncConnection::new(
        Arc::clone(&server.reassert_manager),
        ConnectionConfig {
            client_config,
            auto_reconnect: true,
        },
    )?;
    let (stop, stop_rx) = oneshot::channel();
    let home = home.to_hex();
    tracing::info!(machine = %machine.to_hex(), %home, "device sync started");
    let task = tokio::spawn(async move {
        let ran = connection
            .run_observed(stop_rx, |event| match event {
                SyncEvent::StatusChanged(status) => {
                    tracing::debug!(%home, ?status, "device sync");
                }
                SyncEvent::Error(error) => tracing::warn!(%home, %error, "device sync"),
                _ => {}
            })
            .await;
        match ran {
            Ok(()) => tracing::info!(%home, "device sync stopped"),
            Err(error) => tracing::warn!(%home, %error, "device sync ended"),
        }
    });
    Ok(DeviceSyncHost { stop, task })
}

/// This install's MACHINE, when it may dial `home`: enrolled and live, not
/// the elected home, and `home` a live machine with a paired mesh address.
#[cfg(feature = "mesh")]
fn standing(vault: &oneiron::Vault, home: oneiron::EntityId) -> anyhow::Result<oneiron::EntityId> {
    let live = |machine: &oneiron::authority::FoldedMachine| {
        machine.chains().any(|(_, chain)| chain.is_live())
    };
    let local = vault
        .local_machine()?
        .ok_or_else(|| anyhow::anyhow!("this install is not a machine yet"))?;
    anyhow::ensure!(
        local.profile.as_ref().is_some_and(live),
        "this machine is not enrolled live in the vault"
    );
    anyhow::ensure!(local.id != home, "home_machine names this machine");
    anyhow::ensure!(
        !oneiron::sync::residence::local_is_elected_home(vault)?,
        "this machine is the elected home, which dials no one"
    );
    anyhow::ensure!(
        vault.mesh_machine(home)?.is_some(),
        "home_machine {} has no paired mesh address",
        home.to_hex()
    );
    anyhow::ensure!(
        vault.authority_fold()?.machine(home).is_some_and(live),
        "home_machine {} is not a live machine",
        home.to_hex()
    );
    Ok(local.id)
}
