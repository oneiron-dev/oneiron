//! Single wake-pass assembly and engine delegation.
use oneiron::attempt_queue::{AttemptLandingReserve, LANDING_RESERVE_PERCENT};
use oneiron::{
    BudgetGuard, DreamerConsolidationScope, DreamerWakeDriver, RunWakePass, Vault,
    WakeCancellation, WakePassDeadline, WakePassReport, WakeTrigger,
};

use super::config::{NowSeconds, WakeSupervisorConfig};
use super::factory::PassExecutorFactory;
use crate::tick::Tick;

/// Distinguishes setup failures (no attempt admitted) from in-pass failures so
/// the supervisor can re-drive a consumed push tick after backoff.
pub(super) enum PassRunError {
    PreAdmission(oneiron::Error),
    Failed(oneiron::Error),
}

/// One wake pass: fresh deadline, fresh wake-budget counter, per-pass
/// durable budget id, per-pass executor, then `run_wake_pass`. Budget
/// admission/settle stays entirely inside the engine call — this function
/// never touches the runner store.
///
/// Factory errors surface as [`PassRunError::PreAdmission`] (no attempt row
/// mutated); errors from `run_wake_pass` as [`PassRunError::Failed`].
pub(super) async fn run_one_pass<F: PassExecutorFactory>(
    vault: &Vault,
    config: &WakeSupervisorConfig,
    pass_budget_id: &str,
    now_secs: &NowSeconds,
    factory: &mut F,
    tick: &Tick,
    cancel: &WakeCancellation,
) -> std::result::Result<WakePassReport, PassRunError> {
    let (scope, trigger) = pass_shape(tick);
    let deadline = WakePassDeadline::new(config.pass_ceiling_ms);
    // ONE wake-budget counter per pass (the LLM-4 guard), shared between
    // the driver's legibility reads and the executor's admissions. The
    // durable store id matches so settle/reserve land on the pass's own
    // row.
    // ONE-1896 §4: the ORDINARY meter is built with the pass total MINUS the
    // dialed landing reserve, so running work cannot spend the reserve at all
    // — it is not a rule the meter has to remember, it is units the meter was
    // never given. The durable wake ledger below still receives the FULL total,
    // because the reserve is real budget the landing rung spends through
    // `AttemptQueue::spend_landing_reserve`, per attempt, after landing.
    let ordinary_budget_units = pass_ordinary_budget_units(config.budget_total_units);
    let guard = match factory.actor() {
        Some(actor) => vault
            .policy_budget_guard(
                pass_budget_id.to_owned(),
                ordinary_budget_units,
                config.reserve_units,
                config.exhaustion_policy,
                actor,
            )
            .map_err(PassRunError::PreAdmission)?,
        None => BudgetGuard::with_reserve_units(
            pass_budget_id.to_owned(),
            ordinary_budget_units,
            config.reserve_units,
            config.exhaustion_policy,
        ),
    };
    // Only attach when the existing owner supplied a connection and outputs.
    // Extraction-only configuration must not construct a throwaway host here.
    #[cfg(all(unix, feature = "voice"))]
    let voice = match factory
        .voice_serve_bindings()
        .map_err(PassRunError::PreAdmission)?
    {
        Some(bindings) => {
            let host = factory
                .voice_host(vault, &guard)
                .map_err(PassRunError::PreAdmission)?
                .ok_or_else(|| {
                    PassRunError::PreAdmission(oneiron::Error::InvalidConfig(
                        "voice serve bindings require an attached host".into(),
                    ))
                })?;
            Some((host, bindings))
        }
        None => None,
    };
    let mut driver = DreamerWakeDriver::new(vault, pass_budget_id.to_owned(), deadline)
        .with_budget_guard(guard.clone());
    if let Some(author) = config.milestones.clone() {
        driver = driver.with_milestone_author(author);
    }
    let mut executor = factory
        .executor(&guard)
        .map_err(PassRunError::PreAdmission)?;
    let input = RunWakePass {
        trigger,
        scope,
        local_node_id: config.local_node_id,
        lease_owner: config.lease_owner.clone(),
        budget_total_units: config.budget_total_units,
        reserve_units: config.reserve_units,
        now: (*now_secs)(),
    };
    let pass = driver.run_wake_pass(input, &mut executor, cancel);
    #[cfg(all(unix, feature = "voice"))]
    if let Some((host, bindings)) = voice {
        let (result, served) = bindings.serve_for_pass(host, pass).await;
        let report = result.map_err(PassRunError::Failed)?;
        served.map_err(|error| {
            PassRunError::Failed(oneiron::Error::InvalidConfig(format!(
                "voice serve failed: {error}"
            )))
        })?;
        return Ok(report);
    }
    pass.await.map_err(PassRunError::Failed)
}

/// The units ORDINARY pass execution may spend: the dialed total minus the
/// ONE-1896 landing reserve carved from it.
///
/// One formula, shared with the durable per-attempt dial
/// (`AttemptLandingReserve::dialed`), so "what the meter was built with" and
/// "what the attempt row says its ordinary limit is" cannot drift. Integer
/// percent, rounded DOWN, so the reserve can never exceed the budget: a total
/// too small to carve a reserve from (0, or anything under `100 /
/// LANDING_RESERVE_PERCENT` units) yields a zero reserve and the whole total
/// stays ordinary — a landing there simply has nothing to spend and fails
/// closed at the spend door rather than silently overdrawing.
#[must_use]
pub(super) fn pass_ordinary_budget_units(budget_total_units: u64) -> u64 {
    AttemptLandingReserve::dialed(budget_total_units, LANDING_RESERVE_PERCENT)
        .ordinary_limit_units()
}

/// Maps a tick to the pass it may drive. Deadline ticks drain the lane the
/// due commitment belongs to; wake pushes carry their own authority; hints
/// are pinned to the LEAST-privileged shape — a hint producer cannot
/// escalate scope or forge a trigger (H-S4).
pub(super) fn pass_shape(tick: &Tick) -> (DreamerConsolidationScope, WakeTrigger) {
    match tick {
        Tick::Deadline(deadline) => (deadline.scope, WakeTrigger::Timer),
        Tick::Wake(wake) => (wake.scope, wake.trigger),
        Tick::Hint(_) => (DreamerConsolidationScope::Micro, WakeTrigger::Event),
    }
}
