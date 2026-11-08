//! Device sync for an app that already opened and profiled its own vault.

use std::sync::Arc;

use crate::config::ServeConfig;
use crate::device_sync::DeviceSyncHost;

/// The ordinary home connection over an app's already-open vault.
///
/// This starts no server, inbound mesh service, model worker or Dreamer,
/// and never declares the app as a home-node candidate. With an explicit
/// `ONEIRON_MESH_BIND`, the paired home is reached through a client-only mesh
/// endpoint, using `ONEIRON_MESH_RELAYS` when supplied. Otherwise its URL
/// keeps the existing paired credential and TLS path.
/// The app must not serve this vault through a second window manager while
/// this handle runs.
///
/// Keep the handle for the app's lifetime. Flush local producers before
/// calling [`Self::stop`], and await that stop before closing the vault or
/// its Tokio runtime. Dropping the handle also signals its tasks to stop,
/// but only the explicit stop waits for them.
pub struct EmbeddedDeviceSync {
    host: Option<DeviceSyncHost>,
    transport: Option<Arc<oneiron_mesh_transport::iroh_transport::IrohTransport>>,
    runtime: tokio::runtime::Handle,
}

impl EmbeddedDeviceSync {
    /// Starts on the current Tokio runtime, sharing `vault` without opening
    /// its directory, changing its configuration, rooting or profiling it.
    /// `config` is the server resolver's configuration for that same vault.
    ///
    /// With no configured or enrolled home this returns `None`. A disabled
    /// connection keeps the ordinary device-sync diagnostic and log; an
    /// archive receiver may still run after membership loss, as in serve.
    pub async fn start(vault: Arc<oneiron::Vault>, config: &ServeConfig) -> Option<Self> {
        let (host, transport) = DeviceSyncHost::start_device(&vault, config).await?;
        Some(Self {
            host: Some(host),
            transport,
            runtime: tokio::runtime::Handle::current(),
        })
    }

    /// Stops and joins the connection, credential renewal and archive
    /// receiver. This does not close or reconfigure the app's vault.
    pub async fn stop(mut self) {
        if let Some(host) = self.host.take() {
            let cleanup = self.runtime.spawn(stop(host, self.transport.take()));
            if let Err(error) = cleanup.await {
                tracing::warn!(%error, "device sync cleanup task");
            }
        }
    }
}

impl Drop for EmbeddedDeviceSync {
    fn drop(&mut self) {
        if let Some(host) = self.host.take() {
            drop(self.runtime.spawn(stop(host, self.transport.take())));
        }
    }
}

async fn stop(
    host: DeviceSyncHost,
    transport: Option<Arc<oneiron_mesh_transport::iroh_transport::IrohTransport>>,
) {
    host.stop().await;
    if let Some(transport) = transport {
        if let Err(error) = transport.shutdown().await {
            tracing::warn!(%error, "device mesh shutdown");
        }
    }
}
