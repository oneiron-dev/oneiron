//! Door for `tests/resident_pump_claim_latency.rs`: the agent run pump on a
//! test's server, started as `serve` starts it.

use std::sync::Arc;

use crate::server::SyncServer;

/// Starts the server's agent run pump, which admits every pass and run.
/// `None` when no engine-native code host serves the vault.
pub fn spawn_resident_pump(server: &Arc<SyncServer>) -> Option<tokio::task::JoinHandle<()>> {
    server.spawn_resident_pump()
}
