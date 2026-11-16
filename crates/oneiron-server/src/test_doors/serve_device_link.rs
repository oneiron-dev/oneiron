//! Doors for the serve device-link root test (FIX-LIST SERVE-DEVICE-PEER-STALE-ROOT): the server
//! `serve` builds over an enrolled device vault, its link to home started as serve starts it
//! (`DeviceSyncHost::start`, no mesh), and what that server exports to a peer that reads its root.

use std::sync::Arc;

use oneiron::sync::WindowKey;
use oneiron::sync::schema::read_window_list;
use oneiron::sync::server_state;

use crate::config::ServeConfig;
use crate::device_sync::DeviceSyncHost;
use crate::server::{BroadcastPayload, SyncServer};

/// The server `serve` builds over a device vault, with its link to home.
pub struct ServedDeviceLink {
    server: Arc<SyncServer>,
    host: Option<DeviceSyncHost>,
}

/// Builds the server `serve` builds over `vault` with `config` (`commands::build_server`; no
/// listener binds and no worker starts), then starts its link to home as serve does, with no
/// mesh. `config` must resolve an enrolled home, as
/// [`enrolled_device`](super::embedded_peer_fixture::enrolled_device) builds.
///
/// # Errors
///
/// What `build_server` returns.
pub async fn start_served_device_link(
    vault: Arc<oneiron::Vault>,
    config: &ServeConfig,
) -> anyhow::Result<ServedDeviceLink> {
    let owner_host =
        crate::owner::schedule::OwnerHost::from_config(config, oneiron::VaultConfig::device());
    let (server, _gpu_poller) = crate::commands::build_server(
        vault,
        config,
        config.sync_server_config(),
        owner_host,
        &crate::config::ServeArgs::default(),
    )
    .await?;
    let server = Arc::new(server);
    let host = DeviceSyncHost::start(&server, config, None).await;
    Ok(ServedDeviceLink { server, host })
}

impl ServedDeviceLink {
    /// Whether the link to the home opened, rather than only its archive receiver running.
    #[must_use]
    pub fn linked(&self) -> bool {
        self.host.as_ref().is_some_and(DeviceSyncHost::linked)
    }

    /// Whether this server serves the vault's other machines as a peer rather than as their
    /// home: the check every inbound sync socket meets.
    #[must_use]
    pub fn serves_as_peer(&self) -> bool {
        crate::handler::serves_as_peer(&self.server)
    }

    /// The root snapshot this server exports to a socket that reads its root.
    ///
    /// # Errors
    ///
    /// The export's own error.
    pub fn served_root_snapshot(&self) -> anyhow::Result<Vec<u8>> {
        self.server
            .export_root_snapshot()
            .map_err(anyhow::Error::msg)
    }

    /// The root updates this server exports to a peer that holds `snapshot`, as a socket asks
    /// for them with that snapshot's version.
    ///
    /// # Errors
    ///
    /// What decoding `snapshot` or the export returns.
    pub fn served_root_updates_since(&self, snapshot: &[u8]) -> anyhow::Result<Vec<u8>> {
        let doc = loro::LoroDoc::new();
        doc.import(snapshot)?;
        self.server
            .export_root_updates(&doc.oplog_vv())
            .map_err(anyhow::Error::msg)
    }

    /// Opens `window` as a socket that reads it does: a window the root does not name yet is
    /// added to it, and the root is persisted.
    ///
    /// # Errors
    ///
    /// What opening the window returns.
    pub async fn open_window(&self, window: &str) -> anyhow::Result<()> {
        self.server
            .serve_window(&WindowKey::new(window))
            .await
            .map(drop)
            .map_err(anyhow::Error::from)
    }

    /// The root updates this server sends its connected sockets from now on, as a socket that
    /// is open now receives them.
    #[must_use]
    pub fn subscribe_root_notices(&self) -> RootNotices {
        RootNotices(self.server.broadcast_tx.subscribe())
    }

    /// Stops the link and waits for it to end.
    pub async fn stop(mut self) {
        if let Some(host) = self.host.take() {
            host.stop().await;
        }
    }
}

/// The root updates a server sends its connected sockets ([`ServedDeviceLink::subscribe_root_notices`]).
pub struct RootNotices(tokio::sync::broadcast::Receiver<BroadcastPayload>);

impl RootNotices {
    /// Every root update sent since the subscription or the last call, in order, without waiting.
    pub fn drain(&mut self) -> Vec<Vec<u8>> {
        let mut updates = Vec::new();
        while let Ok(payload) = self.0.try_recv() {
            if let BroadcastPayload::Frame(_, frame) = payload
                && let Some((&tag, update)) = frame.split_first()
                && tag == crate::protocol::TAG_SYNC_UPDATE
            {
                updates.push(update.to_vec());
            }
        }
        updates
    }
}

/// The windows a root names: `snapshot`, with `updates` imported over it when given.
///
/// # Errors
///
/// What decoding either returns.
pub fn root_windows(snapshot: &[u8], updates: Option<&[u8]>) -> anyhow::Result<Vec<String>> {
    root_windows_after(snapshot, updates.into_iter())
}

/// The windows a root names: `snapshot`, with each of `updates` imported over it in order, as a
/// socket's client imports the root updates it receives. An update whose ops rest on ops the
/// root lacks stays pending, and names nothing.
///
/// # Errors
///
/// What decoding any of them returns.
pub fn root_windows_after<'a>(
    snapshot: &[u8],
    updates: impl Iterator<Item = &'a [u8]>,
) -> anyhow::Result<Vec<String>> {
    let doc = loro::LoroDoc::new();
    doc.import(snapshot)?;
    for update in updates {
        doc.import(update)?;
    }
    Ok(windows_of(&doc))
}

/// The windows the vault's persisted root (`d:root`) names.
///
/// # Errors
///
/// What reading `d:root` returns, or that none is persisted.
pub fn persisted_root_windows(vault: &oneiron::Vault) -> anyhow::Result<Vec<String>> {
    let root = server_state::load_root_from_state(vault)?
        .ok_or_else(|| anyhow::anyhow!("the device vault has no persisted root"))?;
    Ok(windows_of(&root))
}

fn windows_of(doc: &loro::LoroDoc) -> Vec<String> {
    read_window_list(doc)
        .iter()
        .map(|key| key.as_str().to_owned())
        .collect()
}
