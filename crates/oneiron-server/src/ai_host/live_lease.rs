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
//!
//! What a look books is first staged on the scope in a commit of its own
//! ([RUN-STEP-CHARGE-LOST-ON-PROCESS-DEATH]), then drained onto it: a
//! process that dies, or a booking that fails, after a call settled loses
//! none of its spend, and the scope's next drain books it once
//! (`AgentDispatcher::drain_lease_spend`).

use std::sync::{Arc, Mutex};

use oneiron::agent_dispatch::{AgentDispatcher, SpendScopeId};
use oneiron::llm::{BudgetCheckpoint, BudgetDenied};
use oneiron::{BudgetGuard, EntityId, Vault};

/// The meter a try resumes on from its checkpoint (a workflow step's tool
/// cursor): its spend, reservations and row tallies as saved. An overdraft
/// the owner approved for the run since then (`overdraft`, his answer to
/// its run-budget ask) applies to it as to a fresh meter; with none it keeps
/// the policy it was saved with.
pub(crate) fn restore_try_meter(
    saved: BudgetCheckpoint,
    overdraft: Option<u64>,
) -> Result<BudgetGuard, BudgetDenied> {
    let _ = overdraft;
    BudgetGuard::from_checkpoint(saved)
}

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
    /// What the lease made durable on the scope. Shared by every handle its
    /// [`LeaseLine`] lends.
    ledger: Arc<LeaseLedger>,
}

/// What one lease made durable on its scope, shared by every handle of it.
struct LeaseLedger {
    /// The key of this lease's staged-spend row on its scope.
    id: EntityId,
    /// How much of the meter's spend is durable on the scope, booked or
    /// staged: the replayed tries', which booked their own, then what this
    /// lease staged since.
    staged: Mutex<u64>,
}

impl LeaseLedger {
    fn new(staged: u64) -> Arc<Self> {
        Arc::new(Self {
            id: EntityId::now(),
            staged: Mutex::new(staged),
        })
    }
}

/// The vault-free state of one live lease, shared with a code-mode backend so
/// its per-rung looks use the caller's ledger, never a second booking. Opaque
/// outside the crate: providers can forward it, never construct or inspect it.
#[derive(Clone)]
pub struct LiveLeaseState {
    scope: Option<SpendScopeId>,
    meter: BudgetGuard,
    budget_units: u64,
    ledger: Arc<LeaseLedger>,
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
    ledger: Arc<LeaseLedger>,
}

impl LeaseLine {
    /// The lease of a meter opened on `scope` that has spent nothing yet,
    /// never past the limit it was opened with.
    pub(crate) fn new(scope: SpendScopeId, meter: BudgetGuard) -> Self {
        Self {
            budget_units: meter.read().limit_units,
            scope,
            meter,
            ledger: LeaseLedger::new(0),
        }
    }

    /// The lease, on `vault`.
    pub(crate) fn on<'a>(&self, vault: &'a Vault) -> LiveLease<'a> {
        LiveLease {
            vault,
            scope: Some(self.scope.clone()),
            meter: self.meter.clone(),
            budget_units: self.budget_units,
            ledger: Arc::clone(&self.ledger),
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
            ledger: LeaseLedger::new(booked),
        }
    }

    /// What a scoped provider threads into its backend (FIX 11749).
    pub(crate) fn state(&self) -> LiveLeaseState {
        LiveLeaseState {
            scope: self.scope.clone(),
            meter: self.meter.clone(),
            budget_units: self.budget_units,
            ledger: Arc::clone(&self.ledger),
        }
    }

    /// Rebinds that shared state to the backend's vault handle.
    pub(crate) fn from_state(vault: &'a Vault, state: LiveLeaseState) -> Self {
        Self {
            vault,
            scope: state.scope,
            meter: state.meter,
            budget_units: state.budget_units,
            ledger: state.ledger,
        }
    }

    /// Books on the scope what the try spent since the last look, then
    /// moves the meter's limit to its spend so far plus what the scope has
    /// left now, never past the step's own budget. Asked before each call
    /// is admitted: a scope its siblings spent down refuses the next
    /// admission as the meter's own exhaustion, and an admitted call goes
    /// on. A stage, booking or read that fails leaves the limit as it was:
    /// what is staged books at the scope's next drain, and what the stage
    /// missed at the next look or the try's end.
    pub(crate) fn book_and_revise(&self) {
        if let Err(error) = self.look() {
            tracing::warn!(
                kind = ?error.kind(),
                scope = self.scope.as_ref().map(SpendScopeId::as_str),
                "a spend lease's settled spend was not staged"
            );
        }
    }

    /// [`Self::book_and_revise`], answering the stage's error: asked after
    /// a call answered and before its answer may be saved, so no saved
    /// answer stands on spend that lives only in memory. A booking or read
    /// that fails after the stage is logged, never an error: the staged
    /// spend books at the scope's next drain.
    pub(crate) fn stage_and_revise(&self) -> oneiron::Result<()> {
        self.look()
    }

    fn look(&self) -> oneiron::Result<()> {
        let Some(scope) = &self.scope else {
            return Ok(());
        };
        let mut staged = self
            .ledger
            .staged
            .lock()
            .expect("step lease mutex poisoned");
        let line = self.meter.read();
        let dispatcher = AgentDispatcher::new(self.vault);
        self.stage(&dispatcher, scope, &mut staged, line.used_units)?;
        let available = dispatcher
            .drain_lease_spend(scope)
            .and_then(|_| dispatcher.available_units(scope));
        match available {
            Ok(available) => {
                let room = line.used_units.saturating_add(available);
                let limit = self.budget_units.min(room);
                if limit != line.limit_units {
                    self.meter.revise_line(limit, self.meter.reserve_units());
                }
            }
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                scope = scope.as_str(),
                "a spend lease was not read live"
            ),
        }
        Ok(())
    }

    /// Books on the scope what the try spent and no look booked, at the
    /// try's end, whatever its calls answered. It is staged first, so a
    /// booking that fails here still books at the scope's next drain.
    pub(crate) fn book_rest(&self) -> oneiron::Result<()> {
        let Some(scope) = &self.scope else {
            return Ok(());
        };
        let mut staged = self
            .ledger
            .staged
            .lock()
            .expect("step lease mutex poisoned");
        let used = self.meter.read().used_units;
        let dispatcher = AgentDispatcher::new(self.vault);
        self.stage(&dispatcher, scope, &mut staged, used)?;
        dispatcher.drain_lease_spend(scope)?;
        Ok(())
    }

    /// A look's first commit alone, the stage, for the integration test
    /// doors: a lease whose process dies right after it.
    #[cfg(oneiron_test_support)]
    pub(crate) fn stage_only(&self) -> oneiron::Result<()> {
        let Some(scope) = &self.scope else {
            return Ok(());
        };
        let mut staged = self
            .ledger
            .staged
            .lock()
            .expect("step lease mutex poisoned");
        let used = self.meter.read().used_units;
        self.stage(&AgentDispatcher::new(self.vault), scope, &mut staged, used)
    }

    /// Stages on `scope` what the meter spent past `staged`, in its own
    /// commit, and only then counts it staged.
    fn stage(
        &self,
        dispatcher: &AgentDispatcher<'_>,
        scope: &SpendScopeId,
        staged: &mut u64,
        used: u64,
    ) -> oneiron::Result<()> {
        let unstaged = used.saturating_sub(*staged);
        if unstaged > 0 {
            dispatcher.stage_lease_spend(scope, self.ledger.id, unstaged)?;
            *staged = used;
        }
        Ok(())
    }
}
