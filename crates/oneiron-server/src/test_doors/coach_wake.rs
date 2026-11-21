//! Door for `tests/eval_authoring_execute_unrecorded_end.rs`: one admitted
//! coach-host job through the wake executor, as a wake pass with the Coach
//! lent runs it.

use std::sync::Arc;

use oneiron::{DreamerAdmittedAttempt, DreamerAttemptExecution};

use crate::server::SyncServer;

/// Runs `admitted` through the Coach wake executor and answers what the
/// wake pass would settle. Async: the executor runs the job on a blocking
/// thread, so call it from the test's multi-thread runtime.
///
/// # Errors
///
/// What the executor answers: only a stopped worker errs; a failed job
/// answers its execution.
pub async fn coach_wake_execute(
    server: &Arc<SyncServer>,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<DreamerAttemptExecution> {
    crate::ai_host::coach_host::wake_execute_for_test(server, admitted, now).await
}
