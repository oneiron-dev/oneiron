//! The executor a seatless, unplanned run records (FIX 1876, OF-540).

use super::{AttemptQueue, AttemptRecord, EngineExecutorConfig, Vault};

/// Stamps `config.model`, the model a run no seat bore and no plan bound
/// actually runs on, as its attempt's executor, so its pack attribution
/// names what ran it. Call it once the run's config is settled and before
/// any pack loads. A stamp that fails is logged and leaves the executor
/// unknown; the run goes on as it would today.
pub(super) fn stamp_seatless_executor(
    vault: &Vault,
    attempt: &AttemptRecord,
    config: &EngineExecutorConfig,
) {
    let Some(lease_owner) = attempt.lease_owner.as_deref() else {
        tracing::warn!(attempt = ?attempt.id, "a seatless run holds no lease; its executor stays unknown");
        return;
    };
    if let Err(error) = AttemptQueue::new(vault).set_executor_model(
        attempt.id,
        lease_owner,
        attempt.attempt_count,
        config.model.as_str(),
    ) {
        tracing::warn!(%error, attempt = ?attempt.id, "a seatless run's executor was not stamped; its attribution stays unknown");
    }
}
