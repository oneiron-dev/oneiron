//! Doors for the Mac app's peer path test (L7-47): starting
//! [`EmbeddedDeviceSync`](crate::embedded::EmbeddedDeviceSync) on a mesh bind
//! without the process environment, and reading what it serves.
//!
//! Also the doors for the serve device-link root test (FIX-LIST
//! SERVE-DEVICE-PEER-STALE-ROOT, `tests/serve_device_peer_root.rs`): the server
//! `serve` builds over an enrolled device vault, its link to home started as
//! serve starts it (`DeviceSyncHost::start`, no mesh), and what that server
//! sends a peer that reads its root.
//!
//! And the doors for the two-machine mesh peer test (FIX-LIST
//! MESH-TWO-MACHINE-PEER-E2E, `tests/mesh_two_machine_peer_e2e.rs`): a served
//! host's paired-machine mesh listener on a bind address, as serve starts it
//! with `--mesh-bind` (`handler::mesh::start`), so a test runs several engine
//! machines of one vault on the mesh and dials them by their roster rows; and
//! the window manager the host's device link runs on.

use std::net::SocketAddr;
use std::sync::Arc;

use oneiron::sync::WindowKey;
use oneiron::sync::schema::{add_window_to_root, read_window_list};
use oneiron::sync::server_state;

use crate::config::ServeConfig;
use crate::device_sync::DeviceSyncHost;
use crate::embedded::EmbeddedDeviceSync;
use crate::server::{BroadcastPayload, SyncServer};

/// The Loro peer the device's home writes its root as, in
/// [`persist_link_learned_window`]: any id the device's own docs do not use.
const HOME_ROOT_PEER: u64 = 0x4c37_4c37;

/// Starts the Mac app's device sync on `bind`, without reading the process
/// environment, so a test sets a bind directly (L7-47).
pub async fn start_on_mesh_bind(
    vault: Arc<oneiron::Vault>,
    config: &ServeConfig,
    bind: Option<SocketAddr>,
) -> Option<EmbeddedDeviceSync> {
    EmbeddedDeviceSync::start_with(
        vault,
        config,
        crate::handler::mesh::MeshConfig::from_parts(bind, Vec::new()),
    )
    .await
}

/// The listener's offered ALPNs, `None` with no listener (L7-47).
pub fn listener_alpns(sync: &EmbeddedDeviceSync) -> Option<Vec<Vec<u8>>> {
    sync.listener_alpns()
}

/// Whether the device serves the vault's other machines as a peer rather than
/// as their home (L7-47).
pub fn serves_as_peer(sync: &EmbeddedDeviceSync) -> bool {
    sync.serves_as_peer()
}

/// Whether the device's link dials the vault's other machines while its home
/// is down: exactly when it opened with a mesh listener here (L7-47).
pub fn has_peer_dialer(sync: &EmbeddedDeviceSync) -> bool {
    sync.has_peer_dialer()
}

/// The windows the device's server names to a socket that reads its root: the
/// window list of the root snapshot it exports (L7-47).
pub fn served_root_windows(sync: &EmbeddedDeviceSync) -> anyhow::Result<Vec<String>> {
    let snapshot = sync.served_root_snapshot().map_err(anyhow::Error::msg)?;
    let doc = loro::LoroDoc::new();
    doc.import(&snapshot)?;
    Ok(read_window_list(&doc)
        .iter()
        .map(|key| key.as_str().to_owned())
        .collect())
}

/// Persists the vault's root with `window` added by the home, as the device's
/// link persists a root update from its home that names a window it learned
/// after start (L7-47).
pub fn persist_link_learned_window(vault: &oneiron::Vault, window: &str) -> anyhow::Result<()> {
    let root = server_state::load_root_from_state(vault)?
        .ok_or_else(|| anyhow::anyhow!("the device vault has no persisted root"))?;
    root.set_peer_id(HOME_ROOT_PEER)?;
    add_window_to_root(&root, &WindowKey::new(window));
    root.commit();
    server_state::persist_root_snapshot(vault, &root)?;
    Ok(())
}

/// The server `serve` builds over a device vault, with its link to home.
pub struct ServedDeviceLink {
    server: Arc<SyncServer>,
    ai: Option<crate::ai_host::AiHost>,
    host: Option<DeviceSyncHost>,
}

/// Builds the server `serve` builds over `vault` with `config` (`commands::build_server`; no
/// listener binds), attaches its AI host as serve's workers do, a device when the config dials a
/// home (`commands/serve/workers.rs`; with no `[models]` it starts no Dreamer and no model
/// worker), then starts its link to home as serve does, with no mesh. `config` must resolve an
/// enrolled home, as [`enrolled_device`](super::embedded_peer_fixture::enrolled_device) builds.
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
    let device = crate::device_sync::dials_home(config, server.vault());
    let (server, ai) =
        crate::ai_host::AiHost::attach_device(server, config.models.as_ref(), device).await;
    let server = Arc::new(server);
    let host = DeviceSyncHost::start(&server, config, None).await;
    Ok(ServedDeviceLink {
        server,
        ai: Some(ai),
        host,
    })
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

    /// Stops the link and waits for it to end, then the AI host.
    pub async fn stop(mut self) {
        if let Some(host) = self.host.take() {
            host.stop().await;
        }
        if let Some(ai) = self.ai.take() {
            ai.shutdown().await;
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

/// One served host's running mesh listener ([`start_mesh_listener`]).
pub struct MeshListener(crate::handler::mesh::MeshHost);

impl MeshListener {
    /// The listener's endpoint, which this machine's own dials ride.
    #[must_use]
    pub fn transport(&self) -> Arc<dyn oneiron_mesh_transport::MeshTransport> {
        self.0.transport()
    }

    /// Stops the listener and closes its endpoint.
    pub async fn stop(self) {
        self.0.stop().await;
    }
}

/// Starts `server`'s mesh listener on `bind` with no relay, offering serve's
/// full route set (`MeshRouteSet::Full`) with sync on `app`, under the default
/// connection limits.
///
/// # Errors
///
/// What the listener's start returns: no enrolled machine on this install, a
/// bind that fails, an endpoint already attached.
pub async fn start_mesh_listener(
    server: Arc<SyncServer>,
    bind: SocketAddr,
    app: &axum::Router,
) -> anyhow::Result<MeshListener> {
    let limits = crate::config::LimitsConfig::default().connections();
    let config = crate::handler::mesh::MeshConfig::from_parts(Some(bind), Vec::new());
    crate::handler::mesh::start(
        server,
        &config,
        app,
        limits,
        crate::handler::mesh::MeshRouteSet::Full,
    )
    .await?
    .map(MeshListener)
    .ok_or_else(|| anyhow::anyhow!("a mesh listener with a bind address did not start"))
}

/// The window manager a served host's device link runs on, as device sync
/// takes it for a host that serves (`device_sync::host`): the server's own.
#[must_use]
pub fn device_link_windows(server: &SyncServer) -> Arc<oneiron::sync::WindowManager> {
    Arc::clone(&server.reassert_manager)
}
