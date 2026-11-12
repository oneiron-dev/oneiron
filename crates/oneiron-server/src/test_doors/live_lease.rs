//! Doors for `tests/live_lease_pending_spend.rs`
//! ([RUN-STEP-CHARGE-LOST-ON-PROCESS-DEATH]): a live lease on a spend scope
//! whose call settled, and that books it, or dies after staging it.

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
