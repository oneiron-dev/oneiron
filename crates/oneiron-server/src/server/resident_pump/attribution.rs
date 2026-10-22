//! The executor a seatless, unplanned run records (FIX 1876, OF-540), and
//! the run's attribution bound before its executor enters (FIX 3103).

use super::{AttemptQueue, AttemptRecord, DreamerRunnerStore, EngineExecutorConfig, Vault};

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

/// Binds the run's attribution once its executor is stamped and before its
/// executor enters (FIX 3103), so the writes it witnesses land on a bound
/// row; settlement still binds a run this could not. Only a stamped run
/// binds here, so the bind names the model its packs load under. A bind
/// that fails is logged; the run goes on as it would today.
pub(super) fn bind_before_entry(vault: &Vault, attempt: &AttemptRecord) {
    let Some(lease_owner) = attempt.lease_owner.as_deref() else {
        return;
    };
    let stamped = DreamerRunnerStore::new(vault)
        .status(attempt.id)
        .is_ok_and(|status| status.is_some_and(|status| status.attempt.executor_model.is_some()));
    if !stamped {
        return;
    }
    if let Err(error) =
        oneiron::skill_attribution::bind_agent_run_attribution(vault, attempt.id, lease_owner)
    {
        tracing::warn!(%error, attempt = ?attempt.id, "an agent run's pack attribution did not bind before entry");
    }
}
