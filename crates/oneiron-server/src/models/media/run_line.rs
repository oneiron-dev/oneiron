//! A program's media jobs on its run's line (FIX 780, FIX 6083). A code-mode
//! run, or an owner's own program, submits its `ai.video` job on the line its
//! steps spend on: code mode's own meter, under the run's name. The job's
//! permit is held on that line until the job ends, and its end, its cancel
//! and its take-up after a restart all settle there, never on the media
//! meter, so the job is reserved and paid for once. Its row names the run, so
//! a restart takes it up again on that line once the code host binds it. A
//! run that is not the owner's reaches only the jobs its own run submitted.
//! A job a pumped run's entry funds from its attempt's spend scope runs on a
//! guard of that scope's own, and what it used is booked on the scope once,
//! at its end, as an entry's meter is (FIX 11496).
//! Entry: `MediaRuntime::submit_run_admitted` (calls.rs), `submit_scoped`,
//! `poll_on_line`.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use oneiron::agent_dispatch::{AgentDispatcher, SpendScopeId};
use oneiron::llm::media::{MediaJobState, MediaReplayKey, MediaRequest};
use oneiron::llm::run_admission::{PayerPerson, RunAdmission};
use oneiron::{BudgetGuard, EntityId};
use serde::{Deserialize, Serialize};

use super::{FatalLlmError, JobRow, KeptJob, LlmResult, MediaRuntime, MediaTicket, funded_run};

/// The run line a program's job was submitted on: its run's name on the
/// program line, and the spend scope that funds it when its run's entry
/// spent under one (FIX 11496).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct JobLine {
    pub(super) run: String,
    #[serde(default)]
    pub(super) scope: Option<SpendScopeId>,
}

/// The program line: code mode's own meter, once the code host binds it,
/// the line of each program job this runtime submitted, and the scope run
/// of each job a spend scope funds.
#[derive(Default)]
pub(super) struct ProgramLine {
    meter: OnceLock<BudgetGuard>,
    /// The line of each program job whose row was not kept, by ticket, so
    /// the job still answers its run.
    submitted: Mutex<BTreeMap<String, JobLine>>,
    /// Each job held here that a spend scope funds, by ticket: the scope
    /// and the run on its own guard, booked once at the job's end.
    scoped: Mutex<BTreeMap<String, ScopedJob>>,
}

/// A job a spend scope funds (FIX 11496): the scope, and the run on a guard
/// of the scope's own that holds the job's permit.
struct ScopedJob {
    scope: SpendScopeId,
    run: RunAdmission,
}

impl MediaRuntime {
    /// The run kept job `ticket`'s `row` is taken up on after a restart: a
    /// fresh guard of the spend scope that funds it, when one does; the
    /// program line's, under its run's name, when a program's run submitted
    /// it; else the media meter's. Each bills the payer its submit bound. A
    /// program's job no scope funds is not taken up before the code host
    /// binds its line; it stays kept until then.
    pub(super) fn job_run(&self, ticket: &str, row: &JobRow) -> LlmResult<RunAdmission> {
        let Some(line) = &row.line else {
            // A kept job's row names no sources: a restart knows none.
            return self.media_run(row.payer.clone(), None);
        };
        // A job its run's spend scope funds is taken up on a fresh guard of
        // that scope's, booked there at its end (FIX 11496).
        if let Some(scope) = &line.scope {
            let run = self.scope_run(&line.run, scope, row.payer.clone())?;
            self.hold_scoped(ticket, scope.clone(), run.clone());
            return Ok(run);
        }
        let meter = self
            .program_line
            .meter
            .get()
            .cloned()
            .ok_or(FatalLlmError::InvalidRequest)?;
        Ok(funded_run(
            line.run.clone(),
            meter,
            self.host.clone(),
            Arc::clone(&self.receipts),
            row.payer.clone(),
        ))
    }

    /// Binds the program line's meter, once, and takes up on it every kept
    /// job a program's run submitted, so new calls cannot spend what those
    /// jobs will owe. A second bind keeps the first.
    fn bind_program_line(&self, meter: BudgetGuard) {
        if self.program_line.meter.set(meter).is_ok() {
            self.take_up_kept();
        }
    }

    /// Notes that job `ticket`, whose row was not kept, was submitted on
    /// `line`.
    pub(super) fn submitted_on(&self, ticket: &str, line: JobLine) {
        self.lock_submitted().insert(ticket.to_owned(), line);
    }

    /// Whether job `ticket` is a program's job whose row was not kept.
    pub(super) fn unkept_program_job(&self, ticket: &str) -> bool {
        self.lock_submitted().contains_key(ticket)
    }

    /// Whether job `id` was submitted on run `run`'s line: as its kept row
    /// names it, erased or not, or as its submit noted it here when its row
    /// was not kept.
    fn on_line(&self, id: &str, run: &str) -> bool {
        let line = match self.store.as_ref().and_then(|store| store.get(id)) {
            Some(KeptJob::Row(row)) => row.line,
            Some(KeptJob::Erased) => None,
            None => self.lock_submitted().get(id).cloned(),
        };
        line.is_some_and(|line| line.run == run)
    }

    /// [`Self::poll`] for a run that is not the owner's: a job its own run
    /// submitted on its line. Any other job is no job of this run's.
    pub(crate) async fn poll_on_line(
        &self,
        run: &RunAdmission,
        id: &str,
    ) -> LlmResult<MediaJobState> {
        if !self.on_line(id, run.run()) {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        self.poll(id).await
    }

    /// [`Self::cancel`] for a run that is not the owner's, as
    /// [`Self::poll_on_line`] reaches a job.
    pub(crate) async fn cancel_on_line(&self, run: &RunAdmission, id: &str) -> LlmResult<()> {
        if !self.on_line(id, run.run()) {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        self.cancel(id).await?;
        self.lock_submitted().remove(id);
        Ok(())
    }

    fn lock_submitted(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, JobLine>> {
        self.program_line
            .submitted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// [`Self::submit_run_admitted`] for a job a pumped run's entry funds
    /// from `scope`, its attempt's spend scope (FIX 11496). The job runs on
    /// a guard of the scope's own, not on `line`, the entry's meter, which
    /// the entry books on the scope when it ends: a job that outlives its
    /// entry still reaches the scope. What the job's guard used is booked on
    /// the scope once, as an entry's meter is (`record_guard_spend`), when
    /// the job ends, is stopped, or its submit fails. Its row keeps the
    /// scope, so a restart takes it up on a fresh guard of it. A runtime
    /// that keeps no jobs reads no scope: the job runs on `line`, as before.
    pub(crate) async fn submit_scoped(
        &self,
        line: &RunAdmission,
        scope: SpendScopeId,
        request: MediaRequest,
        actor: Option<EntityId>,
        replay: Option<MediaReplayKey>,
    ) -> LlmResult<MediaTicket> {
        if self.store.is_none() {
            return self
                .submit_run_admitted(line, None, request, actor, replay)
                .await;
        }
        let run = self.scope_run(line.run(), &scope, line.payer().cloned())?;
        let submitted = self
            .submit_run_admitted(&run, Some(scope.clone()), request, actor, replay)
            .await;
        match &submitted {
            // A repeat under its step key answered the first's ticket and
            // reserved nothing here: the first's guard holds the job.
            Ok(ticket) => {
                let read = run.read();
                if read.reserved_units > 0 || read.used_units > 0 {
                    self.hold_scoped(&ticket.job, scope, run);
                }
            }
            Err(_) => self.book(&scope, &run),
        }
        submitted
    }

    /// Books job `id`'s spend on the scope that funds it, once: the job
    /// ended, was stopped, or this runtime lets it go (FIX 11496). A job no
    /// scope funds books nothing.
    pub(super) fn book_job_scope(&self, id: &str) {
        let job = self.lock_scoped().remove(id);
        if let Some(job) = job {
            self.book(&job.scope, &job.run);
        }
    }

    /// A run under `run`'s name on a guard of `scope`'s own, billed to
    /// `payer`: what the scope may still spend bounds it (FIX 11496).
    fn scope_run(
        &self,
        run: &str,
        scope: &SpendScopeId,
        payer: Option<PayerPerson>,
    ) -> LlmResult<RunAdmission> {
        let store = self.store.as_ref().ok_or(FatalLlmError::InvalidRequest)?;
        let guard = AgentDispatcher::new(store.vault())
            .guard_for_scope(scope)
            .map_err(|_| FatalLlmError::InvalidRequest)?;
        Ok(funded_run(
            run.to_owned(),
            guard,
            self.host.clone(),
            Arc::clone(&self.receipts),
            payer,
        ))
    }

    /// Holds `run`, the scope run of job `ticket`, for its booking. A run
    /// it replaces is booked first, so no guard's spend is lost.
    fn hold_scoped(&self, ticket: &str, scope: SpendScopeId, run: RunAdmission) {
        let replaced = self
            .lock_scoped()
            .insert(ticket.to_owned(), ScopedJob { scope, run });
        if let Some(replaced) = replaced {
            self.book(&replaced.scope, &replaced.run);
        }
    }

    /// Books on `scope` what `run`'s own guard used, once, as an entry's
    /// meter is booked (FIX 11496). A booking the vault refuses is logged.
    fn book(&self, scope: &SpendScopeId, run: &RunAdmission) {
        let Some(store) = &self.store else {
            return;
        };
        if let Err(error) =
            AgentDispatcher::new(store.vault()).record_guard_spend(scope, run.read().used_units)
        {
            tracing::error!(%error, "a media job's spend was not booked on its scope");
        }
    }

    fn lock_scoped(&self) -> MutexGuard<'_, BTreeMap<String, ScopedJob>> {
        self.program_line
            .scoped
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl crate::models::ModelRuntime {
    /// Binds the program line (FIX 780, FIX 6083): `meter`, code mode's own,
    /// which every unscoped program's steps spend on, and its media calls
    /// with them. A kept job a program's run submitted is taken up on it
    /// again after a restart.
    pub fn bind_program_media_line(&self, meter: BudgetGuard) {
        self.media.bind_program_line(meter);
    }
}
