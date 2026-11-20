//! Door for `tests/device_burst_replay.rs`: one pass of the home's drain
//! of its own devices' retained bursts (L7-41), run now instead of on the
//! lifecycle tick, which a test server never starts; and a claim on one
//! batch's landing, as a socket's UPDATE arm or the drain holds it (FIX
//! DEVICE-BURST-ALLOW-DRAIN-OVERLAP).

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

/// Claims the landing of the own device's batch at `batch_ref` until the
/// claim is dropped, as a socket's UPDATE arm holds it while it lands the
/// batch, or the drain while it lands it; `None` while another landing holds
/// it.
pub fn claim_device_burst_landing(
    server: &SyncServer,
    batch_ref: String,
) -> Option<impl std::fmt::Debug + '_> {
    server.claim_device_burst_landing(batch_ref)
}
