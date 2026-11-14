//! Doors for the Mac app's peer path test (L7-47): starting
//! [`EmbeddedDeviceSync`](crate::embedded::EmbeddedDeviceSync) on a mesh bind
//! without the process environment, and reading what it serves.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::ServeConfig;
use crate::embedded::EmbeddedDeviceSync;

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
