//! What plain serve stops beside its workers, in its order, once its
//! listeners have stopped or its start failed past the workers' start
//! (FIX 7386, FIX 4757).

use std::future::Future;

use crate::device_sync::DeviceSyncHost;
use crate::handler::mesh::MeshHost;
use crate::server::SyncServer;

/// Stops what serve started beside its workers, before they stop: the
/// mesh's sync streams end where they are, so an upgrade none of them
/// finished gives back its place, then `upgrades`, the drain
/// [`crate::embedded::upgrade_lifetime`] gave, is awaited with no deadline:
/// each socket upgraded on the API listener or the mesh has seen the stop
/// and ends once every call it admitted has. Then the device-sync
/// connection and the mesh stop, and every public live voice session ends
/// through its own teardown, its journal finished, with none started after,
/// as managed serve ends them. What never started is passed as `None`.
pub(super) async fn stop_serving(
    server: &SyncServer,
    mesh: Option<MeshHost>,
    device_sync: Option<DeviceSyncHost>,
    upgrades: impl Future<Output = ()>,
) {
    if let Some(mesh) = &mesh {
        mesh.end_streams().await;
    }
    upgrades.await;
    if let Some(device_sync) = device_sync {
        device_sync.stop().await;
    }
    if let Some(mesh) = mesh {
        mesh.stop().await;
    }
    server.live_voice.stop_all().await;
    // The recall doors' buffered retrieval rows go in one grouped write, before
    // the vault closes (FIX 11011).
    server.flush_retrieval_meters();
}
