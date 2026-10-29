//! A step try's spend lease, read live (FIX 1819). Each call the try makes
//! is admitted against what its spend scope has left at that moment, never
//! against what it had when the try began, and each call's spend is booked
//! on the scope once it settled: siblings spending under the same scope see
//! this try's spend, and it sees theirs, so together they stop where one
//! try alone would. Nothing is reserved on the scope ahead of a call, and a
//! call already admitted is never stopped: its spend books whole, past the
//! cap if it must.

use std::sync::Mutex;

use oneiron::agent_dispatch::{AgentDispatcher, SpendScopeId};
use oneiron::{BudgetGuard, Vault};

/// One try's meter, bounded by its spend scope's live room.
pub(super) struct LiveLease<'a> {
    vault: &'a Vault,
    /// The scope the try spends under; `None` when it spends unmetered,
    /// and then nothing is booked or bounded here.
    scope: Option<SpendScopeId>,
    meter: BudgetGuard,
    /// The step's own budget, shared by all its tries: the meter's limit
    /// never rises past it.
    budget_units: u64,
    /// How much of the meter's spend is on the scope already: the replayed
    /// tries', which booked their own, then what this try booked since.
    booked: Mutex<u64>,
}

impl<'a> LiveLease<'a> {
    /// `meter` has spent `booked` already, all of it on `scope`.
    pub(super) fn new(
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
            booked: Mutex::new(booked),
        }
    }

    /// Books on the scope what the try spent since the last look, then
    /// moves the meter's limit to its spend so far plus what the scope has
    /// left now, never past the step's own budget. Asked before each call
    /// is admitted: a scope its siblings spent down refuses the next
    /// admission as the meter's own exhaustion, and an admitted call goes
    /// on. A booking or read that fails leaves the limit, and what is
    /// unbooked, as they were: the next look or the try's end books it.
    pub(super) fn book_and_revise(&self) {
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
                "a workflow step's spend lease was not read live"
            ),
        }
    }

    /// Books on the scope what the try spent and no look booked, at the
    /// try's end, whatever its calls answered.
    pub(super) fn book_rest(&self) -> oneiron::Result<()> {
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
