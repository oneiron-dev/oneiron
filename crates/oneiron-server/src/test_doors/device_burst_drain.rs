//! Door for `tests/device_burst_response.rs`: one pass of the home's drain
//! of its own devices' retained bursts (L7-41), run now instead of on the
//! lifecycle tick, which a test server never starts.

use crate::server::SyncServer;

/// Lands each own device's retained update that is due now, as one tick's
/// pass does, and answers how many batches ended complete.
///
/// # Errors
///
/// What the pass returns.
pub async fn drain_device_bursts_once(server: &SyncServer) -> oneiron::Result<usize> {
    server.drain_device_bursts().await
}
