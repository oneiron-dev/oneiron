//! Doors for the Mac app's peer path test (L7-47): starting
//! [`EmbeddedDeviceSync`](crate::embedded::EmbeddedDeviceSync) on a mesh bind
//! without the process environment, and reading what it serves.

use std::net::SocketAddr;
use std::sync::Arc;

use oneiron::sync::WindowKey;
use oneiron::sync::schema::{add_window_to_root, read_window_list};
use oneiron::sync::server_state;

use crate::config::ServeConfig;
use crate::embedded::EmbeddedDeviceSync;

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
