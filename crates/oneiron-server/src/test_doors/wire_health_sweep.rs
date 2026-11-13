//! Door for `tests/own_rate_health_ask.rs`: one pass of the health check's
//! worker (`wire_health::sweep`), run now instead of on its 15 s tick.

use crate::server::SyncServer;

/// Folds every new crossing in, asks each held check on the host's ladder
/// and looks for role holders' answers, once.
///
/// # Errors
///
/// What the pass returns.
pub fn sweep_once(server: &SyncServer) -> oneiron::Result<()> {
    crate::wire_health::sweep(server)
}
