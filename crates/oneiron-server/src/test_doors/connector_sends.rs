//! Door for `tests/inquiry_federation.rs`: one pass of the served
//! connector-send drain (`server::connector_sends`), run now instead of on
//! its commit signal or timer, with the sink the drain builds, so a test
//! sees which channel's sends the host's own executor carries (the
//! member's told statements among them).

use crate::server::SyncServer;

/// Runs every claimable connector send once, on the drain's sink, and
/// answers the second the next one is ready. Blocking: call it off the
/// async runtime, since the pass's HTTP clients are blocking ones.
///
/// # Errors
///
/// What the pass returns.
pub fn connector_send_pass(server: &SyncServer) -> oneiron::Result<Option<u64>> {
    server.run_connector_send_pass()
}
