//! Doors for `tests/live_lease_pending_spend.rs`
//! ([RUN-STEP-CHARGE-LOST-ON-PROCESS-DEATH]): a live lease on a spend scope
//! whose call settled, and that books it, or dies after staging it. And for
//! `tests/live_lease_overdraft.rs`: what a lease admits under an overdraft,
//! and what a restored meter admits once the owner approved one.

use oneiron::agent_dispatch::{AgentDispatcher, SpendScopeId};
use oneiron::{BudgetGuard, Error, Result, Vault};

use crate::ai_host::live_lease::LeaseLine;

/// The meter a host opens on `scope` (`guard_for_scope`), with one call of
/// `units` settled on it, as a provider's answer settles it.
fn settled_meter(vault: &Vault, scope: &SpendScopeId, units: u64) -> Result<BudgetGuard> {
    let meter = AgentDispatcher::new(vault).guard_for_scope(scope)?;
    let refused =
        |denied: oneiron::llm::BudgetDenied| Error::InvalidConfig(format!("test meter: {denied}"));
    let admission = meter.admit().map_err(refused)?;
    meter
        .settle_usage(&admission.lease, units)
        .map_err(refused)?;
    Ok(meter)
}

/// A live lease's call of `units` on `scope` settles, and the look after
/// its answer makes its first commit, the stage. The lease is then dropped
/// before any drain books the call, as a process that dies there.
pub fn settle_call_and_die_after_stage(
    vault: &Vault,
    scope: &SpendScopeId,
    units: u64,
) -> Result<()> {
    let meter = settled_meter(vault, scope, units)?;
    LeaseLine::new(scope.clone(), meter).on(vault).stage_only()
}

/// A live lease's call of `units` on `scope` settles, and its try ends: the
/// lease books what it spent (`book_rest`).
pub fn settle_call_and_book_rest(vault: &Vault, scope: &SpendScopeId, units: u64) -> Result<()> {
    let meter = settled_meter(vault, scope, units)?;
    LeaseLine::new(scope.clone(), meter).on(vault).book_rest()
}

/// A live lease on `scope` whose meter runs a line of `limit_units` under
/// `exhausted`, each call reserving and spending `call_units`, as a step's
/// try runs its paid rungs: a look before each admission, then the call's
/// settlement. Answers how many calls it admitted before one was refused, at
/// most `bound`; the try's end then books the rest on the scope.
pub fn calls_a_lease_admits(
    vault: &Vault,
    scope: &SpendScopeId,
    limit_units: u64,
    call_units: u64,
    exhausted: oneiron::BudgetExhaustionPolicy,
    bound: u64,
) -> Result<u64> {
    let refused =
        |denied: oneiron::llm::BudgetDenied| Error::InvalidConfig(format!("test meter: {denied}"));
    let meter =
        BudgetGuard::with_reserve_units("live-lease-door", limit_units, call_units, exhausted);
    let lease = crate::ai_host::live_lease::LiveLease::new(
        vault,
        Some(scope.clone()),
        meter.clone(),
        limit_units,
        0,
    );
    let mut admitted = 0;
    while admitted < bound {
        lease.stage_and_revise()?;
        let Ok(admission) = meter.admit() else {
            break;
        };
        meter
            .settle_usage(&admission.lease, call_units)
            .map_err(refused)?;
        admitted += 1;
    }
    lease.book_rest()?;
    Ok(admitted)
}

/// A try's meter on a line of `limit_units` that one call of `limit_units`
/// spent whole, checkpointed as a workflow step's tool cursor saves it and
/// restored as the step resumes, with the overdraft the owner approved for
/// the run since (`overdraft`): whether the restored meter admits one more
/// call of `limit_units`.
pub fn a_restored_meter_admits_a_call(limit_units: u64, overdraft: Option<u64>) -> Result<bool> {
    let refused =
        |denied: oneiron::llm::BudgetDenied| Error::InvalidConfig(format!("test meter: {denied}"));
    let meter = BudgetGuard::with_reserve_units(
        "restored-meter-door",
        limit_units,
        limit_units,
        oneiron::BudgetExhaustionPolicy::Suspend,
    );
    let admission = meter.admit().map_err(refused)?;
    meter
        .settle_usage(&admission.lease, limit_units)
        .map_err(refused)?;
    let saved = meter.checkpoint().map_err(refused)?;
    let restored =
        crate::ai_host::live_lease::restore_try_meter(saved, overdraft).map_err(refused)?;
    Ok(restored.admit().is_ok())
}
