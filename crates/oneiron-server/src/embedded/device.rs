//! Device sync for an app that already opened and profiled its own vault.

use std::sync::Arc;

use crate::config::ServeConfig;
use crate::device_sync::DeviceSyncHost;

/// The ordinary home connection over an app's already-open vault.
///
/// This starts no server, listener, mesh endpoint, model worker or Dreamer,
/// and never declares the app as a home-node candidate. The configured or
/// enrolled home is reached at its URL with the existing paired credential.
/// The app must not serve this vault through a second window manager while
/// this handle runs.
///
/// Keep the handle for the app's lifetime. Flush local producers before
/// calling [`Self::stop`], and await that stop before closing the vault or
/// its Tokio runtime. Dropping the handle also signals its tasks to stop,
/// but only the explicit stop waits for them.
pub struct EmbeddedDeviceSync(DeviceSyncHost);

impl EmbeddedDeviceSync {
    /// Starts on the current Tokio runtime, sharing `vault` without opening
    /// its directory, changing its configuration, rooting or profiling it.
    /// `config` is the server resolver's configuration for that same vault.
    ///
    /// With no configured or enrolled home this returns `None`. A disabled
    /// connection keeps the ordinary device-sync diagnostic and log; an
    /// archive receiver may still run after membership loss, as in serve.
    pub async fn start(vault: Arc<oneiron::Vault>, config: &ServeConfig) -> Option<Self> {
        DeviceSyncHost::start_device(&vault, config).await.map(Self)
    }

    /// Stops and joins the connection, credential renewal and archive
    /// receiver. This does not close or reconfigure the app's vault.
    pub async fn stop(self) {
        self.0.stop().await;
    }
}
