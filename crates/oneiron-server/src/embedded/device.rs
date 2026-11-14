//! Device sync for an app that already opened and profiled its own vault.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::config::ServeConfig;
use crate::device_sync::DeviceSyncHost;
use crate::handler::mesh::{MeshConfig, MeshHost, MeshRouteSet};
use crate::server::SyncServer;

/// The Mac app's device sync: a device-mode server over the app's vault with
/// its link to home, and, with an explicit `ONEIRON_MESH_BIND`, its mesh
/// listener serving the sync route alone (L7-47).
///
/// It builds a device-mode server over the app's already-open vault: no TCP
/// listener, no AI host, no Dreamer, no model workers, no home candidacy. With
/// an explicit `ONEIRON_MESH_BIND` it starts a mesh listener that serves the
/// sync route alone to the owner's other machines marked mine, as a peer,
/// never as their home, and the link dials its home and, while the home is
/// down, its peers through that listener; without one, the home's URL path as
/// before and no inbound service. The server's window manager is the one the
/// link uses, so the "no second window manager" rule holds.
///
/// Keep the handle for the app's lifetime. Flush local producers before
/// calling [`Self::stop`], and await that stop before closing the vault or
/// its Tokio runtime. Dropping the handle also signals its tasks to stop,
/// but only the explicit stop waits for them.
pub struct EmbeddedDeviceSync {
    host: Option<DeviceSyncHost>,
    listener: Option<MeshHost>,
    /// The device-mode server: its window manager is the link's and its router
    /// the listener's, so it goes last at the stop.
    server: Arc<SyncServer>,
    /// The upgrade lifetime's stop: each socket upgraded on the listener sees
    /// it turn.
    stopping: tokio::sync::watch::Sender<bool>,
    /// Resolves once every socket upgraded on the listener has ended.
    drained: Option<Drain>,
    runtime: tokio::runtime::Handle,
}

/// The upgrade lifetime's drain ([`crate::embedded::upgrade_lifetime`]).
type Drain = Pin<Box<dyn Future<Output = ()> + Send>>;

impl EmbeddedDeviceSync {
    /// Starts on the current Tokio runtime, sharing `vault` without opening
    /// its directory, changing its configuration, rooting or profiling it.
    /// `config` is the server resolver's configuration for that same vault.
    ///
    /// With no configured or enrolled home this returns `None`. A disabled
    /// connection keeps the ordinary device-sync diagnostic and log; an
    /// archive receiver may still run after membership loss, as in serve.
    ///
    /// With an explicit `ONEIRON_MESH_BIND` it also serves the sync route
    /// alone to the owner's other machines marked mine, as a peer (L7-47).
    pub async fn start(vault: Arc<oneiron::Vault>, config: &ServeConfig) -> Option<Self> {
        let mesh = match MeshConfig::from_env() {
            Ok(mesh) => mesh,
            Err(error) => {
                tracing::warn!(%error, "device mesh unavailable; keeping the ordinary home URL path");
                MeshConfig::default()
            }
        };
        Self::start_with(vault, config, mesh).await
    }

    /// [`Self::start`] with the mesh settings given, so a test sets a bind
    /// without the process environment (L7-47).
    pub(crate) async fn start_with(
        vault: Arc<oneiron::Vault>,
        config: &ServeConfig,
        mesh: MeshConfig,
    ) -> Option<Self> {
        // A vault with no home to dial builds no server.
        let dial = DeviceSyncHost::device_dial(&vault, config)?;
        let server = match SyncServer::new(vault, config.sync_server_config()) {
            Ok(server) => Arc::new(server),
            Err(error) => {
                tracing::warn!("device sync disabled: {error:#}");
                return None;
            }
        };
        // Before the listener starts, so its first socket already reads as a
        // peer's, never as a home's.
        server.mark_device_link();
        let (stopping, stopped) = tokio::sync::watch::channel(false);
        let (app, drained) = crate::embedded::upgrade_lifetime(
            crate::build_sync_router(Arc::clone(&server)),
            stopped,
        );
        let drained: Drain = Box::pin(drained);
        let listener = match crate::handler::mesh::start(
            Arc::clone(&server),
            &mesh,
            &app,
            config.limits.connections(),
            MeshRouteSet::SyncOnly,
        )
        .await
        {
            Ok(listener) => listener,
            Err(error) => {
                tracing::warn!(%error, "device mesh unavailable; keeping the ordinary home URL path");
                None
            }
        };
        let Some(host) = DeviceSyncHost::start_device(&server, dial, listener.as_ref()).await
        else {
            let _ = stopping.send(true);
            cleanup(None, listener, Some(drained), server).await;
            return None;
        };
        Some(Self {
            host: Some(host),
            listener,
            server,
            stopping,
            drained: Some(drained),
            runtime: tokio::runtime::Handle::current(),
        })
    }

    /// The listener's offered ALPNs, `None` with no listener (L7-47).
    #[cfg(oneiron_test_support)]
    pub(crate) fn listener_alpns(&self) -> Option<Vec<Vec<u8>>> {
        self.listener
            .as_ref()
            .map(|listener| listener.alpns().to_vec())
    }

    /// Whether this device serves the vault's other machines as a peer rather
    /// than as their home: the check every inbound sync socket meets (L7-47).
    #[cfg(oneiron_test_support)]
    pub(crate) fn serves_as_peer(&self) -> bool {
        crate::handler::serves_as_peer(&self.server)
    }

    /// Whether the link dials the vault's other machines while its home is
    /// down (L7-47).
    #[cfg(oneiron_test_support)]
    pub(crate) fn has_peer_dialer(&self) -> bool {
        self.host.as_ref().is_some_and(DeviceSyncHost::dials_peers)
    }

    /// Stops and joins the connection, credential renewal and archive
    /// receiver, then the listener. This does not close or reconfigure the
    /// app's vault.
    pub async fn stop(mut self) {
        let _ = self.stopping.send(true);
        let done = self.runtime.spawn(cleanup(
            self.host.take(),
            self.listener.take(),
            self.drained.take(),
            Arc::clone(&self.server),
        ));
        if let Err(error) = done.await {
            tracing::warn!(%error, "device sync cleanup task");
        }
    }
}

impl Drop for EmbeddedDeviceSync {
    fn drop(&mut self) {
        let _ = self.stopping.send(true);
        if self.host.is_none() && self.listener.is_none() && self.drained.is_none() {
            return;
        }
        drop(self.runtime.spawn(cleanup(
            self.host.take(),
            self.listener.take(),
            self.drained.take(),
            Arc::clone(&self.server),
        )));
    }
}

/// Ends what [`EmbeddedDeviceSync`] started, in the phones' engine's order
/// (`serve_prepared`): the listener's sync streams end, the upgraded sockets
/// drain, then the link stops, then the listener, and the server goes last
/// (L7-47).
async fn cleanup(
    host: Option<DeviceSyncHost>,
    listener: Option<MeshHost>,
    drained: Option<Drain>,
    server: Arc<SyncServer>,
) {
    if let Some(listener) = &listener {
        listener.end_streams().await;
    }
    if let Some(drained) = drained {
        drained.await;
    }
    if let Some(host) = host {
        host.stop().await;
    }
    if let Some(listener) = listener {
        listener.stop().await;
    }
    drop(server);
}
