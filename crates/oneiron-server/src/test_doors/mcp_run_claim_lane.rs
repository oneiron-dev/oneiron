//! Door for `tests/mcp_run_claim_row_identity_key.rs` (FIX-LIST 25102): the
//! lane a code run's claim and edge rows read on over `/mcp`.

use std::sync::Arc;

use oneiron::code_run::SelfEffect;

use crate::server::SyncServer;

/// Whether `effect`, one call a run serves itself, reads on its connector's
/// credential lane when a vault-wide connector presents `token` with its
/// holder proof (`timestamp`, `nonce`, hex `signature`): `true` is a key,
/// `false` the actor's own key.
///
/// # Errors
///
/// The refusal, or the proof failure, in its own words.
pub fn run_call_reads_on_credential_lane(
    server: &Arc<SyncServer>,
    token: &str,
    timestamp: u64,
    nonce: &str,
    signature: &str,
    effect: SelfEffect,
) -> Result<bool, String> {
    crate::api::admit_run_call_for_test(server, token, timestamp, nonce, signature, effect)
}
