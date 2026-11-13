//! Door for `tests/eval_authoring_execute_lapsed_lease.rs`: one Coach host
//! round, the nightly worker's unit of work.

use crate::server::SyncServer;

/// Runs one Coach host round (the jobs it admits, `run_one`, `settle`) on the
/// calling thread. Blocking: the Coach's model calls block on the server's
/// runtime, so call it inside `tokio::task::spawn_blocking` on the test's
/// multi-thread runtime.
///
/// # Errors
///
/// What the round returns: a storage or queue error (a failed job settles
/// and does not fail the round).
pub fn coach_host_round(server: &SyncServer) -> oneiron::Result<()> {
    crate::ai_host::coach_host::round_once(server)
}
