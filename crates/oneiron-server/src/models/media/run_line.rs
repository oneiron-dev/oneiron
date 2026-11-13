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
//! rungs charged before its row is kept, and the rest, once its permit is
//! taken and settled, with its end. A permit handed off, a paid end or one
//! already taken books nothing.
//! Each booking stages its part on the scope, then drains the scope
//! ([MEDIA-JOB-SPEND-LOST-ON-PROCESS-DEATH]), as a live lease's look does
//! (`AgentDispatcher::drain_lease_spend`; the server drains every scope at
//! each lifecycle tick, its start included). A job's end stages its part in
//! the commit that writes its end row, its held end or its delete
//! (`JobStore::update_staged`, S7299-P1), so a restart either finds the end
//! written and takes no job up, or finds the job running with no stage of
//! its end, and its take-up's fresh guard pays that end. A booking with no
//! row of a running job behind it, the submit's settled rungs, a failed
//! send's or an unkept job's, stages in a commit of its own. A process that
//! dies after a stage and before its drain loses none of it: the next drain
//! books it.
//! Entry: `MediaRuntime::submit_run_admitted` (calls.rs), `submit_scoped`,
//! `poll_on_line`.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use oneiron::agent_dispatch::{AgentDispatcher, SpendScopeId};
use oneiron::llm::media::{MediaJobState, MediaReplayKey, MediaRequest};
use oneiron::llm::run_admission::{PayerPerson, RunAdmission};
use oneiron::{BudgetGuard, EntityId, Vault};
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
/// the scope's own that holds the job's permit, and the ledger of what of
/// that guard's use the scope already holds.
struct ScopedJob {
    scope: SpendScopeId,
    run: RunAdmission,
    ledger: JobSpendLedger,
}

/// What of one scoped job's guard use is durable on the scope that funds
/// it, booked there or staged, and the key of the job's staged-spend row
/// ([MEDIA-JOB-SPEND-LOST-ON-PROCESS-DEATH]). A part is counted only once
/// its stage committed.
pub(crate) struct JobSpendLedger {
    /// The key of this job's staged-spend row on its scope.
    id: EntityId,
    /// How much of the guard's use is durable on the scope.
    staged: u64,
}

impl JobSpendLedger {
    pub(crate) fn new() -> Self {
        Self {
            id: EntityId::now(),
            staged: 0,
        }
    }

    /// Books on `scope` what the job's guard `used` past what is durable
    /// there: stages that part in its own commit, then drains the scope. A
    /// stage the vault refuses is logged and leaves the part to the job's
    /// next booking; a drain that fails is logged, and what was staged books
    /// at the scope's next drain. Never a refusal.
    pub(crate) fn book(&mut self, vault: &Vault, scope: &SpendScopeId, used: u64) {
        let dispatcher = AgentDispatcher::new(vault);
        match self.stage(&dispatcher, scope, used) {
            Ok(false) => {}
            Ok(true) => {
                if let Err(error) = dispatcher.drain_lease_spend(scope) {
                    tracing::warn!(
                        %error,
                        %scope,
                        "a media job's staged spend waits for its scope's next drain"
                    );
                }
            }
            Err(error) => {
                tracing::error!(%error, %scope, "a media job's spend was not staged on its scope");
            }
        }
    }

    /// A booking's first commit alone, the stage, for the integration test
    /// doors: a job whose process dies right after it.
    #[cfg(oneiron_test_support)]
    pub(crate) fn stage_only(
        &mut self,
        vault: &Vault,
        scope: &SpendScopeId,
        used: u64,
    ) -> oneiron::Result<()> {
        self.stage(&AgentDispatcher::new(vault), scope, used)
            .map(|_| ())
    }

    /// Stages on `scope` what the guard `used` past what is staged, in its
    /// own commit, and only then counts it staged. Answers whether a part
    /// was staged.
    fn stage(
        &mut self,
        dispatcher: &AgentDispatcher<'_>,
        scope: &SpendScopeId,
        used: u64,
    ) -> oneiron::Result<bool> {
        let part = used.saturating_sub(self.staged);
        if part == 0 {
            return Ok(false);
        }
        dispatcher.stage_lease_spend(scope, self.id, part)?;
        self.staged = used;
        Ok(true)
    }
}

/// The part of one scoped job's guard use its scope does not hold yet, for
/// the commit that writes the job's end, held end or delete to stage
/// (S7299-P1): its scope, its ledger's key there, and the units.
pub(super) struct ScopeStage {
    scope: SpendScopeId,
    lease: EntityId,
    units: u64,
}

impl ScopeStage {
    /// Stages the part on its scope in `txn`, the job's end's own write.
    pub(super) fn stage_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
    ) -> oneiron::Result<()> {
        AgentDispatcher::new(vault).stage_lease_spend_in_txn(
            txn,
            &self.scope,
            self.lease,
            self.units,
        )
    }
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
                code: None,
            }
            .into()
        })
    }

    /// Books job `id`'s spend on the scope that funds it, once, in commits
    /// of its own (FIX 11496): the guard's use past what its ledger holds.
    /// Only for a job no restart takes up as running: one whose row was
    /// never kept or an erase took, or whose send failed and left its row
    /// unsent for a fresh guard's resend. A job no scope funds books
    /// nothing.
    pub(crate) fn book_job_scope(&self, id: &str) {
        let job = self.lock_scoped().remove(id);
        if let Some(mut job) = job {
            self.book(&job.scope, &job.run, &mut job.ledger);
        }
    }

    /// What job `id`'s scope does not hold yet of its guard's use, for the
    /// commit that writes the job's end, held end or delete to stage
    /// (S7299-P1); `None` for a job no scope funds. The job stays held here
    /// until such a commit is durable ([`Self::end_committed`]): an end
    /// whose write the vault refused stages its part in the next write of
    /// it, or, when the process dies first, leaves the end to its take-up.
    /// Its caller holds the jobs lock from this snapshot to
    /// [`Self::end_committed`], so no two ends of a job stage one part
    /// (S7299 review round 3 P1).
    pub(super) fn end_stage(&self, id: &str) -> Option<ScopeStage> {
        let scoped = self.lock_scoped();
        let job = scoped.get(id)?;
        Some(ScopeStage {
            scope: job.scope.clone(),
            lease: job.ledger.id,
            units: job.run.read().used_units.saturating_sub(job.ledger.staged),
        })
    }

    /// The commit that carried `stage`, job `id`'s end, is durable: the job
    /// goes from here, and answers the scope to drain, when a part was
    /// staged.
    pub(super) fn end_committed(
        &self,
        id: &str,
        stage: Option<ScopeStage>,
    ) -> Option<SpendScopeId> {
        let stage = stage?;
        let mut scoped = self.lock_scoped();
        if scoped
            .get(id)
            .is_some_and(|job| job.ledger.id == stage.lease)
        {
            scoped.remove(id);
        }
        (stage.units > 0).then_some(stage.scope)
    }

    /// Drains `scope`, when an end's commit staged a part on it: a drain
    /// that fails leaves the part to the scope's next drain.
    pub(super) fn drain_end_stage(&self, scope: Option<SpendScopeId>) {
        let (Some(scope), Some(store)) = (scope, self.store.as_ref()) else {
            return;
        };
        if let Err(error) = AgentDispatcher::new(store.vault()).drain_lease_spend(&scope) {
            tracing::warn!(
                %error,
                %scope,
                "a media job's staged end waits for its scope's next drain"
            );
        }
    }

    /// Books on `scope`, when one funds the job, what its failed submit's
    /// settled rungs charged `run`, the job's own guard (FIX 11496).
    pub(super) fn book_failed_submit(&self, scope: Option<&SpendScopeId>, run: &RunAdmission) {
        if let Some(scope) = scope {
            self.book(scope, run, &mut JobSpendLedger::new());
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
    /// 11496). A taken-up job's fresh guard has charged nothing yet. A run
    /// it replaces, a take-up whose permit settled as it failed, books what
    /// it charged past its booking first, so no guard's spend is lost.
    pub(super) fn hold_scoped(&self, ticket: &str, scope: SpendScopeId, run: RunAdmission) {
        let mut ledger = JobSpendLedger::new();
        self.book(&scope, &run, &mut ledger);
        let replaced = self
            .lock_scoped()
            .insert(ticket.to_owned(), ScopedJob { scope, run, ledger });
        if let Some(mut replaced) = replaced {
            self.book(&replaced.scope, &replaced.run, &mut replaced.ledger);
        }
    }

    /// Books on `scope` what `run`'s own guard used past what `ledger`
    /// holds durable there, as an entry's meter is booked (FIX 11496):
    /// staged first, then drained ([MEDIA-JOB-SPEND-LOST-ON-PROCESS-DEATH]).
    /// A booking the vault refuses is logged, never a refusal.
    fn book(&self, scope: &SpendScopeId, run: &RunAdmission, ledger: &mut JobSpendLedger) {
        if let Some(store) = self.store.as_ref() {
            ledger.book(store.vault(), scope, run.read().used_units);
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
