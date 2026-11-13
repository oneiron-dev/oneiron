//! Doors for `tests/media_job_staged_spend.rs`
//! ([MEDIA-JOB-SPEND-LOST-ON-PROCESS-DEATH], S7299-P1): a scoped media job's
//! own guard on its spend scope, whose use the job's ledger books there, or
//! stages before its process dies; and a video job a scope funds, kept in
//! the vault by a media runtime, whose end its poll writes.

use std::sync::Arc;

use oneiron::agent_dispatch::{AgentDispatcher, SpendScopeId};
use oneiron::llm::media::MediaJobState;
use oneiron::{BudgetGuard, Error, Result, Vault};

use crate::models::{JobSpendLedger, ModelRuntime};

/// The run name a door's video job is submitted under.
const DOOR_RUN: &str = "door-video-run";

/// A charge of `units` settles on `guard`, as a settled rung of a job's
/// submit walk, or its permit at its end, charges it.
fn settle_on(guard: &BudgetGuard, units: u64) -> Result<()> {
    let refused =
        |denied: oneiron::llm::BudgetDenied| Error::InvalidConfig(format!("test guard: {denied}"));
    let admission = guard.admit().map_err(refused)?;
    guard
        .settle_usage(&admission.lease, units)
        .map_err(refused)?;
    Ok(())
}

fn door_error(error: oneiron::LlmError) -> Error {
    Error::InvalidConfig(format!("media job door: {error}"))
}

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
        settle_on(&self.guard, units)
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

/// A video job a spend scope funds, on a media runtime that keeps its jobs
/// in the vault (`ModelRuntime::with_media_vault`), its run on a guard of
/// the scope's own that this door settles charges on.
pub struct ScopedMediaJob {
    runtime: ModelRuntime,
    scope: SpendScopeId,
    guard: BudgetGuard,
}

impl ScopedMediaJob {
    /// A job `scope` funds, on a fresh guard of the scope's own, on a
    /// runtime with no seat that keeps its jobs in `vault`.
    pub fn open(vault: Arc<Vault>, scope: &SpendScopeId) -> Result<Self> {
        let guard = AgentDispatcher::new(&vault).guard_for_scope(scope)?;
        Ok(Self {
            runtime: ModelRuntime::unconfigured().with_media_vault(vault),
            scope: scope.clone(),
            guard,
        })
    }

    /// A charge of `units` settles on the job's guard.
    pub fn settle(&self, units: u64) -> Result<()> {
        settle_on(&self.guard, units)
    }

    /// Keeps the job as its scoped submit leaves it once its provider
    /// answered, and answers its ticket: what the guard used so far is
    /// booked on the scope, and its running row is kept, naming the scope.
    pub fn keep_submitted(&self) -> Result<String> {
        self.runtime
            .media()
            .keep_scoped_job_for_test(DOOR_RUN, self.scope.clone(), self.guard.clone())
            .map_err(door_error)
    }

    /// The job's poll sees its end `state`, its permit settled: the poll's
    /// whole end path, its drain included.
    pub fn end(&self, ticket: &str, state: &MediaJobState) -> Result<MediaJobState> {
        self.runtime
            .media()
            .complete_kept_job_for_test(ticket, state)
            .map_err(door_error)
    }

    /// The job's poll sees its end `state`, and its process dies after the
    /// commit that writes that end, before any drain: the runtime is
    /// dropped there.
    pub fn end_and_die(self, ticket: &str, state: &MediaJobState) -> Result<()> {
        self.runtime
            .media()
            .write_kept_end_for_test(ticket, state)
            .map(drop)
            .map_err(door_error)
    }
}
