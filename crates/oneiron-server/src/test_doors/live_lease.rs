//! Doors for `tests/live_lease_pending_spend.rs`
//! ([RUN-STEP-CHARGE-LOST-ON-PROCESS-DEATH]): a live lease on a spend scope
//! whose call settled, and that books it, or dies after staging it. And for
//! `tests/live_lease_overdraft.rs`: what a lease admits under an overdraft,
//! and what a step's meter admits across its saved cursors as the owner
//! approves overdrafts for its run.

use oneiron::agent_dispatch::{AgentDispatcher, RunOverdraft, SpendScopeId};
use oneiron::llm::BudgetCheckpoint;
use oneiron::{BudgetGuard, Error, Result, Vault};

use crate::ai_host::live_lease::{self, LeaseLine};

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

/// One stretch of a step's try between two saves of its tool cursor: the
/// overdraft the owner approved for the run before it began, if any, and
/// the most calls it makes.
pub struct TryStretch {
    pub overdraft: Option<RunOverdraft>,
    pub most_calls: u64,
}

/// A step's try on a line of `limit_units` under `exhausted` (the owner's
/// `on_budget_exhausted` knob, or `Suspend`), each call reserving and
/// spending `limit_units`, over `stretches`. The first opens a fresh meter,
/// as a step that begins does; each later one restores the meter the
/// stretch before it saved, as a step that resumes from its tool cursor
/// does. Each takes its stretch's overdraft as the step takes it. Answers
/// how many calls each stretch admitted before one was refused, or its most.
pub fn calls_per_stretch(
    limit_units: u64,
    exhausted: oneiron::BudgetExhaustionPolicy,
    stretches: &[TryStretch],
) -> Result<Vec<u64>> {
    let refused =
        |denied: oneiron::llm::BudgetDenied| Error::InvalidConfig(format!("test meter: {denied}"));
    let mut saved: Option<BudgetCheckpoint> = None;
    let mut admitted = Vec::with_capacity(stretches.len());
    for stretch in stretches {
        let meter = match saved.take() {
            None => {
                let fresh = BudgetGuard::with_reserve_units(
                    "try-stretch-door",
                    limit_units,
                    limit_units,
                    exhausted,
                );
                live_lease::grant_run_overdraft(&fresh, stretch.overdraft.as_ref());
                fresh
            }
            Some(checkpoint) => {
                live_lease::restore_try_meter(checkpoint, stretch.overdraft.as_ref())
                    .map_err(refused)?
            }
        };
        let mut calls = 0;
        while calls < stretch.most_calls {
            let Ok(admission) = meter.admit() else {
                break;
            };
            meter
                .settle_usage(&admission.lease, limit_units)
                .map_err(refused)?;
            calls += 1;
        }
        admitted.push(calls);
        saved = Some(meter.checkpoint().map_err(refused)?);
    }
    Ok(admitted)
}
