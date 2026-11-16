//! The served connector-send drain's pass (`crate::server::connector_sends`),
//! for an integration test that proves what one pass does to a send that
//! waits in the `bridge.outbound.schedule` queue.

use oneiron::Vault;

/// One pass of the served drain over `vault`: every claimable send runs
/// through the engine's served sink, which holds the transports this engine
/// drives, then the instant the next send is ready. The pass builds fresh
/// send clients, so call it on a blocking thread, never on an async worker.
/// `line_push_allowance` is the account plan's monthly LINE push allowance.
///
/// # Errors
///
/// The pass's failure, as the drain logs it.
pub fn pass(vault: &Vault, line_push_allowance: u32) -> oneiron::Result<Option<u64>> {
    crate::server::send_pass_once(vault, line_push_allowance)
}
