//! A program's media jobs on its run's line (FIX 780, FIX 6083). A code-mode
//! run, or an owner's own program, submits its `ai.video` job on the line its
//! steps spend on: code mode's own meter, under the run's name. The job's
//! permit is held on that line until the job ends, and its end, its cancel
//! and its take-up after a restart all settle there, never on the media
//! meter, so the job is reserved and paid for once. Its row names the run, so
//! a restart takes it up again on that line once the code host binds it. A
//! run that is not the owner's reaches only the jobs its own run submitted.
//! Entry: `MediaRuntime::submit_run_admitted` (calls.rs), `poll_on_line`.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use oneiron::BudgetGuard;
use oneiron::llm::media::MediaJobState;
use oneiron::llm::run_admission::RunAdmission;
use serde::{Deserialize, Serialize};

use super::{FatalLlmError, JobRow, KeptJob, LlmResult, MediaRuntime, funded_run};

/// The run line a program's job was submitted on: its run's name on the
/// program line.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct JobLine {
    pub(super) run: String,
}

/// The program line: code mode's own meter, once the code host binds it,
/// and the line of each program job this runtime submitted.
#[derive(Default)]
pub(super) struct ProgramLine {
    meter: OnceLock<BudgetGuard>,
    /// The line of each program job whose row was not kept, by ticket, so
    /// the job still answers its run.
    submitted: Mutex<BTreeMap<String, JobLine>>,
}

impl MediaRuntime {
    /// The run kept job `row` is taken up on after a restart: the program
    /// line's, under its run's name, when a program's run submitted it, else
    /// the media meter's. Each bills the payer its submit bound. A program's
    /// job is not taken up before the code host binds its line; it stays
    /// kept until then.
    pub(super) fn job_run(&self, row: &JobRow) -> LlmResult<RunAdmission> {
        let Some(line) = &row.line else {
            return self.media_run(row.payer.clone());
        };
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
