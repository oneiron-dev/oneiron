//! A metered try's spend lease, read live (FIX 1819): a workflow step's
//! try, a reader child's run, or an engine-native run's entry (FIX 11750).
//! Each call the try makes
//! is admitted against what its spend scope has left at that moment, never
//! against what it had when the try began, and each call's spend is booked
//! on the scope once it settled: siblings spending under the same scope see
//! this try's spend, and it sees theirs, so together they stop where one
//! try alone would. Nothing is reserved on the scope ahead of a call, and a
//! call already admitted is never stopped: its spend books whole, past the
//! cap if it must.
//!
//! One lease can be lent ([`LeaseLine`], FIX 11747) to the calls of its
//! entry that run beside its backend, on its meter: each handle books on the
//! one ledger, so their spend is booked once.

use std::sync::{Arc, Mutex};

use oneiron::agent_dispatch::{AgentDispatcher, SpendScopeId};
use oneiron::{BudgetGuard, Vault};

/// One try's meter, bounded by its spend scope's live room.
pub(crate) struct LiveLease<'a> {
    vault: &'a Vault,
    /// The scope the try spends under; `None` when it spends unmetered,
    /// and then nothing is booked or bounded here.
    scope: Option<SpendScopeId>,
    meter: BudgetGuard,
    /// The try's own budget (a step's, shared by its tries): the meter's
    /// limit never rises past it.
    budget_units: u64,
    /// How much of the meter's spend is on the scope already: the replayed
    /// tries', which booked their own, then what this try booked since.
    /// Shared by every handle its [`LeaseLine`] lends.
    booked: Arc<Mutex<u64>>,
}

/// A lease without its vault, lent to the calls of one entry that run
/// beside its backend on its meter (FIX 11747): the run's `ai.speech` and
/// its planner's pattern capture. [`LeaseLine::on`] is the lease itself,
/// on the one ledger.
#[derive(Clone)]
pub(crate) struct LeaseLine {
    scope: SpendScopeId,
    meter: BudgetGuard,
    budget_units: u64,
    booked: Arc<Mutex<u64>>,
}

impl LeaseLine {
    /// The lease of a meter opened on `scope` that has spent nothing yet,
    /// never past the limit it was opened with.
    pub(crate) fn new(scope: SpendScopeId, meter: BudgetGuard) -> Self {
        Self {
            budget_units: meter.read().limit_units,
            scope,
            meter,
            booked: Arc::default(),
        }
    }

    /// The lease, on `vault`.
    pub(crate) fn on<'a>(&self, vault: &'a Vault) -> LiveLease<'a> {
        LiveLease {
            vault,
            scope: Some(self.scope.clone()),
            meter: self.meter.clone(),
            budget_units: self.budget_units,
            booked: Arc::clone(&self.booked),
        }
    }
}

impl<'a> LiveLease<'a> {
    /// `meter` has spent `booked` already, all of it on `scope`.
    pub(crate) fn new(
        vault: &'a Vault,
        scope: Option<SpendScopeId>,
        meter: BudgetGuard,
        budget_units: u64,
        booked: u64,
    ) -> Self {
        Self {
            vault,
            scope,
            meter,
            budget_units,
            booked: Arc::new(Mutex::new(booked)),
        }
    }

    /// Books on the scope what the try spent since the last look, then
    /// moves the meter's limit to its spend so far plus what the scope has
    /// left now, never past the step's own budget. Asked before each call
    /// is admitted: a scope its siblings spent down refuses the next
    /// admission as the meter's own exhaustion, and an admitted call goes
    /// on. A booking or read that fails leaves the limit, and what is
    /// unbooked, as they were: the next look or the try's end books it.
    pub(crate) fn book_and_revise(&self) {
        let Some(scope) = &self.scope else {
            return;
        };
        let mut booked = self.booked.lock().expect("step lease mutex poisoned");
        let line = self.meter.read();
        let unbooked = line.used_units.saturating_sub(*booked);
        let dispatcher = AgentDispatcher::new(self.vault);
        let available = if unbooked == 0 {
            dispatcher.available_units(scope)
        } else {
            dispatcher.record_guard_spend(scope, unbooked).map(|read| {
                *booked = line.used_units;
                read.available_units
            })
        };
        match available {
            Ok(available) => {
                let limit = self
                    .budget_units
                    .min(line.used_units.saturating_add(available));
                if limit != line.limit_units {
                    self.meter.revise_line(limit, self.meter.reserve_units());
                }
            }
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                scope = scope.as_str(),
                unbooked,
                "a spend lease was not read live"
            ),
        }
    }

    /// Books on the scope what the try spent and no look booked, at the
    /// try's end, whatever its calls answered.
    pub(crate) fn book_rest(&self) -> oneiron::Result<()> {
        let Some(scope) = &self.scope else {
            return Ok(());
        };
        let mut booked = self.booked.lock().expect("step lease mutex poisoned");
        let used = self.meter.read().used_units;
        AgentDispatcher::new(self.vault).record_guard_spend(scope, used.saturating_sub(*booked))?;
        *booked = used;
        Ok(())
    }
}
