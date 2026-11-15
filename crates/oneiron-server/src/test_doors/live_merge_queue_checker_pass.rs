//! Door for `tests/code_roundtrip_served.rs`: one merge queue checker pass
//! on a test's server, run as the lifecycle tick runs it, through the
//! server's own `[merge_queue]` executor.

use crate::server::SyncServer;

/// Runs one checker pass to its end on the calling thread: the enrolled
/// queues' steps, the accepted pushes' intake, then every queued check the
/// host may claim. Blocking; call it from a blocking thread. How many
/// checks settled.
///
/// # Errors
/// The pass's own store or check-store failure.
pub fn run_merge_queue_checker_pass(server: &SyncServer) -> oneiron::Result<usize> {
    server.run_merge_queue_checker_pass()
}
