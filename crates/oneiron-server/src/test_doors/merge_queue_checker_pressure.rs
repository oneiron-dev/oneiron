//! Doors for `tests/merge_queue_checker_pressure.rs`
//! ([GUEST-PIDS-PRESSURE-MERGE-QUEUE-CHECKER], FIX 8013 follow-up): one
//! isolated merge-queue check, with no commands, on a guest session the
//! test started.

use oneiron::Result;
use oneiron::merge_queue::QueueCheckExecution;
use oneiron_container::{SessionLease, SessionManifest};

/// Runs one isolated check with no commands on `lease`, the test's guest
/// session whose start `manifest` names, through the isolated executor's
/// own path after its backend started the session; an in-process helper
/// answers as `checker.py` does for an empty tree. Answers what the run
/// came to.
///
/// # Errors
/// An engine failure of the run, or of the door's own pipes.
pub fn run_empty_isolated_check(
    lease: Box<dyn SessionLease>,
    manifest: SessionManifest,
) -> Result<QueueCheckExecution> {
    crate::server::run_empty_isolated_check(lease, manifest)
}
