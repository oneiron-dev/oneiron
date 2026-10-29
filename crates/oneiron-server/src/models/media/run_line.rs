//! A program's media jobs on its run's line (FIX 780, FIX 6083). A code-mode
//! run, or an owner's own program, submits its `ai.video` job on the line its
//! steps spend on: code mode's own meter, under the run's name. The job's
//! permit is held on that line until the job ends, and its end, its cancel
//! and its take-up after a restart all settle there, never on the media
//! meter, so the job is reserved and paid for once. Its row names the run, so
//! a restart takes it up again on that line once the code host binds it. A
//! run that is not the owner's reaches only the jobs its own run submitted.
//! A job a pumped run's entry funds from its attempt's spend scope is
//! admitted on a guard of that scope's own from its submit, so its entry's
//! meter never carries it, and what that guard used is booked on the scope
//! as an entry's meter is (FIX 11496, L06-A 07:17): what its walk's settled
//! rungs charged before its row is kept, and the rest when its permit is
//! taken and settled with a charge, before its end is written. A permit
//! handed off, a paid end or one already taken books nothing.
//! Entry: `MediaRuntime::submit_run_admitted` (calls.rs), `submit_scoped`,
//! `poll_on_line`.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use oneiron::agent_dispatch::{AgentDispatcher, SpendScopeId};
use oneiron::llm::media::{MediaJobState, MediaReplayKey, MediaRequest};
use oneiron::llm::run_admission::{PayerPerson, RunAdmission};
use oneiron::{BudgetGuard, EntityId};
use serde::{Deserialize, Serialize};

use super::{
    FatalLlmError, HeldJob, JobRow, JobStore, KeptJob, LlmResult, MediaRuntime, MediaTicket,
    funded_run,
};

/// The run line a program's job was submitted on: its run's name on the
/// program line, and the spend scope that funds it when its run's entry
/// spent under one (FIX 11496).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct JobLine {
    pub(super) run: String,
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
    /// and the run on its own guard, booked when its permit settles.
    scoped: Mutex<BTreeMap<String, ScopedJob>>,
}

/// A job a spend scope funds (FIX 11496): the scope, the run on a guard of
/// the scope's own that holds the job's permit, and what of that guard's
/// use the scope already holds.
struct ScopedJob {
    scope: SpendScopeId,
    run: RunAdmission,
    booked: u64,
}

impl HeldJob {
    /// Whether the job's permit is still held and its end not paid yet:
    /// the settle that takes it charges its line, and the scope that funds
    /// the job books that charge (FIX 11496). A handed-off or paid end
    /// charges nothing, and books nothing.
    pub(super) fn charges(&self) -> bool {
        self.permit.is_some() && !self.paid
    }
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
    /// from `scope`, its metered attempt's spend scope (FIX 11496, L06-A
    /// 07:17). The job is admitted on a guard of the scope's own, under
    /// `line`'s run name and payer, never on `line`, the entry's meter, which
    /// the entry books on the scope when it ends: so a job that ends before
    /// or after its entry is booked once, whole. Its row keeps the scope, so
    /// a restart takes it up on a fresh guard of it. A runtime that keeps no
    /// jobs has no scope to read: such a submit is its caller's bug, and an
    /// error that names it.
    pub(crate) async fn submit_scoped(
        &self,
        line: &RunAdmission,
        scope: SpendScopeId,
        request: MediaRequest,
        actor: Option<EntityId>,
        replay: Option<MediaReplayKey>,
    ) -> LlmResult<MediaTicket> {
        let run = self.scope_run(line.run(), &scope, line.payer().cloned())?;
        self.submit_run_admitted(&run, Some(scope), request, actor, replay)
            .await
    }

    /// The store a job a spend scope funds needs, for its scope's guard and
    /// its booking (FIX 11496). A runtime that keeps no jobs answers its
    /// caller's bug, by name, never a silent unscoped job.
    pub(super) fn scoped_store(&self) -> LlmResult<&JobStore> {
        self.store.as_ref().ok_or_else(|| {
            tracing::error!("a scoped media job was submitted on a runtime that keeps no jobs");
            FatalLlmError::InvalidRequestDetail {
                message: "a scoped media job needs a runtime that keeps its jobs (FIX 11496)"
                    .to_owned(),
            }
            .into()
        })
    }

    /// Books job `id`'s spend on the scope that funds it, once, right after
    /// its permit was taken and settled with a charge, and before its end
    /// or its delete is written (FIX 11496): the guard's use past what its
    /// submit booked. A job no scope funds books nothing.
    pub(crate) fn book_job_scope(&self, id: &str) {
        let job = self.lock_scoped().remove(id);
        if let Some(job) = job {
            self.book(&job.scope, &job.run, job.booked);
        }
    }

    /// Books on `scope`, when one funds the job, what its failed submit's
    /// settled rungs charged `run`, the job's own guard (FIX 11496).
    pub(super) fn book_failed_submit(&self, scope: Option<&SpendScopeId>, run: &RunAdmission) {
        if let Some(scope) = scope {
            self.book(scope, run, 0);
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
        let store = self.scoped_store()?;
        let guard = AgentDispatcher::new(store.vault())
            .guard_for_scope(scope)
            .map_err(|error| {
                tracing::error!(%error, %scope, "a media job's scope guard was not read");
                FatalLlmError::InvalidRequest
            })?;
        Ok(funded_run(
            run.to_owned(),
            guard,
            self.host.clone(),
            Arc::clone(&self.receipts),
            payer,
        ))
    }

    /// Holds `run`, job `ticket`'s run on a guard of `scope`'s own, for the
    /// booking its permit's settle makes, and books now what its walk's
    /// settled rungs already charged it, before its row is kept (FIX
    /// 11496). A taken-up job's fresh guard has charged nothing yet.
    pub(super) fn hold_scoped(&self, ticket: &str, scope: SpendScopeId, run: RunAdmission) {
        let booked = self.book(&scope, &run, 0);
        self.lock_scoped()
            .insert(ticket.to_owned(), ScopedJob { scope, run, booked });
    }

    /// Books on `scope` what `run`'s own guard used past `booked`, what the
    /// scope already holds of it, as an entry's meter is booked (FIX
    /// 11496), and answers what the scope holds now. A booking the vault
    /// refuses is logged, never a refusal.
    fn book(&self, scope: &SpendScopeId, run: &RunAdmission, booked: u64) -> u64 {
        let used = run.read().used_units;
        let part = used.saturating_sub(booked);
        let Some(store) = self.store.as_ref().filter(|_| part > 0) else {
            return booked;
        };
        match AgentDispatcher::new(store.vault()).record_guard_spend(scope, part) {
            Ok(_) => used,
            Err(error) => {
                tracing::error!(%error, %scope, "a media job's spend did not reach its scope");
                booked
            }
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
