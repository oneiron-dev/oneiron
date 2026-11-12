//! Doors for `tests/media_job_staged_spend.rs`
//! ([MEDIA-JOB-SPEND-LOST-ON-PROCESS-DEATH]): a scoped media job's own guard
//! on its spend scope, whose use the job's ledger books there, or stages
//! before its process dies.

use oneiron::agent_dispatch::{AgentDispatcher, SpendScopeId};
use oneiron::{BudgetGuard, Error, Result, Vault};

use crate::models::JobSpendLedger;

/// One scoped media job's spend: its scope, the guard of the scope's own
/// its run holds its permit on (`guard_for_scope`, as the media runtime
/// opens it), and the ledger the runtime books that guard's use with.
pub struct ScopedJobSpend {
    scope: SpendScopeId,
    guard: BudgetGuard,
    ledger: JobSpendLedger,
}

impl ScopedJobSpend {
    /// A job `scope` funds, on a fresh guard of the scope's own, nothing
    /// charged and nothing booked yet.
    pub fn open(vault: &Vault, scope: &SpendScopeId) -> Result<Self> {
        Ok(Self {
            scope: scope.clone(),
            guard: AgentDispatcher::new(vault).guard_for_scope(scope)?,
            ledger: JobSpendLedger::new(),
        })
    }

    /// A charge of `units` settles on the job's guard, as a settled rung of
    /// its submit's walk, or its permit at its end, charges it.
    pub fn settle(&self, units: u64) -> Result<()> {
        let refused = |denied: oneiron::llm::BudgetDenied| {
            Error::InvalidConfig(format!("test guard: {denied}"))
        };
        let admission = self.guard.admit().map_err(refused)?;
        self.guard
            .settle_usage(&admission.lease, units)
            .map_err(refused)?;
        Ok(())
    }

    /// The runtime's booking of the job's spend on its scope, as its submit
    /// and its end make it: what the guard used past what is durable there.
    pub fn book(&mut self, vault: &Vault) {
        let used = self.guard.read().used_units;
        self.ledger.book(vault, &self.scope, used);
    }

    /// A booking's first commit alone, the stage. The job is then dropped
    /// before any drain books it, as a process that dies there.
    pub fn stage_and_die(mut self, vault: &Vault) -> Result<()> {
        let used = self.guard.read().used_units;
        self.ledger.stage_only(vault, &self.scope, used)
    }
}
