//! A kept job's end and its delete, in one order (FIX 9511, FIX 9513). A
//! poll that sees the job end writes that end under the job's own lock, and
//! a delete of a running job stops it under the same lock, so neither runs
//! inside the other. A job's end is written only over the row its submit
//! kept: once a delete dropped the row and its clips, in one write, a late
//! end writes nothing back and its poll finds no job. A delete goes ahead
//! only once the provider confirmed the stop: a stop that failed, or whose
//! outcome is unknown, leaves the job running here with its ticket, permit
//! and row, since it may still run and bill at its provider, and its caller
//! may poll it or delete it again. A job a spend scope funds stages what
//! its scope does not hold yet of its guard's use in the commit that writes
//! its end, its held end or its delete, and drains the scope after it
//! ([MEDIA-JOB-SPEND-LOST-ON-PROCESS-DEATH], S7299-P1): a restart never
//! takes up a job whose end is staged. The snapshot of that part, the commit
//! that stages it and the let-go of the job's ledger run under the lock
//! every poll and delete of the job takes (S7299 review round 3 P1): a
//! second end of the job, a poll that writes its refused end again or its
//! delete, finds the part staged and stages none of it.
//! Entry: `MediaRuntime::cancel_kept_job`.
use oneiron::agent_dispatch::SpendScopeId;

use super::run_line::ScopeStage;
use super::{FatalLlmError, Held, KeptJob, LlmResult, MediaJobState, MediaRuntime, erased_poll};

/// What writing a job's end came to.
pub(super) enum JobWrite {
    /// The row keeps its end now.
    Kept,
    /// An erase took the job first: nothing was written (KS-2B2).
    Erased,
    /// A delete dropped the job first: nothing was written back.
    Deleted,
}

impl MediaRuntime {
    /// Keeps job `id`'s end `state` in its row, the row and its clips in one
    /// write over the row already kept, and lets the job go from here. A
    /// held write of the job goes in place first (FIX 2963). An end the
    /// vault refuses, or a job whose row was never kept, stays held here
    /// with its end, for the next poll to answer and write again, and is
    /// held in the vault as the job's held write, so a restart neither polls
    /// an ended job on a fresh permit nor pays its end again. A
    /// job dropped meanwhile stays dropped: a delete's job is gone, and its
    /// poll finds no job. A job an erase took keeps nothing of its end,
    /// which goes from here unanswered: the answer is its erased end
    /// (KS-2B2). The scope that funds the job, when one does, stages its
    /// end's part in the commit that writes the end or the held end, and is
    /// drained after it (S7299-P1). Returns what the poll answers.
    /// Two polls of a job whose end the vault refused write it one after
    /// the other: the second stages nothing (S7299 review round 3 P1).
    pub(super) fn complete_kept_job(
        &self,
        id: &str,
        state: &MediaJobState,
    ) -> LlmResult<MediaJobState> {
        let (answer, staged) = self.write_kept_end(id, state);
        self.drain_end_stage(staged);
        answer
    }

    /// [`Self::complete_kept_job`]'s writes, up to its drain: what the poll
    /// answers, and the scope an end's commit staged a part on. An erased
    /// job, or one with no row anywhere, is taken up by no restart: its
    /// part books in commits of its own. An end whose writes the vault
    /// refused stages nothing: the job's next write of its end stages it,
    /// or a restart takes the job up and its fresh guard pays the end. The
    /// part's snapshot, its commit and the ledger's let-go hold the jobs
    /// lock, as [`Self::drop_kept_job`]'s do, so no other end of the job
    /// snapshots the part between them (S7299 review round 3 P1).
    pub(super) fn write_kept_end(
        &self,
        id: &str,
        state: &MediaJobState,
    ) -> (LlmResult<MediaJobState>, Option<SpendScopeId>) {
        let mut jobs = self.lock_jobs();
        let stage = self.end_stage(id);
        #[cfg(oneiron_test_support)]
        super::scoped_job_door::end_snapshot_taken(id);
        let mut committed = false;
        let written =
            self.store
                .as_ref()
                .map_or(Ok(JobWrite::Kept), |store| -> Result<JobWrite, String> {
                    store.flush(id);
                    let kept = store
                        .get(id)
                        .ok_or_else(|| "its row is not kept".to_owned())?;
                    let Some(mut row) = kept.live() else {
                        self.book_job_scope(id);
                        return Ok(JobWrite::Erased);
                    };
                    row.ended = Some(state.clone());
                    let written = store.update_staged(id, row, stage.as_ref())?;
                    committed = true;
                    Ok(written)
                });
        let answer = match written {
            Ok(JobWrite::Kept) => {
                jobs.remove(id);
                Ok(state.clone())
            }
            Ok(JobWrite::Erased) => {
                jobs.remove(id);
                Ok(erased_poll(id))
            }
            Ok(JobWrite::Deleted) => {
                jobs.remove(id);
                Err(FatalLlmError::InvalidRequest.into())
            }
            Err(error) => {
                tracing::error!(%error, ticket = id, "a media job's end is held, not kept");
                match self.hold_end(id, state, stage.as_ref()) {
                    EndHold::Held => committed = true,
                    EndHold::NoRow => self.book_job_scope(id),
                    EndHold::Refused => {}
                }
                if let Some(held) = jobs.get_mut(id)
                    && matches!(held, Held::Running(_))
                {
                    *held = Held::Unkept(state.clone());
                }
                Ok(state.clone())
            }
        };
        let staged = if committed {
            self.end_committed(id, stage)
        } else {
            None
        };
        drop(jobs);
        (answer, staged)
    }

    /// Holds job `id`'s end `state` as its held write (FIX 2963), over the
    /// row its own key keeps or, when that was never kept, its held submit,
    /// `stage` staged in the same commit. A job with neither keeps its end
    /// here only.
    fn hold_end(&self, id: &str, state: &MediaJobState, stage: Option<&ScopeStage>) -> EndHold {
        let Some(store) = &self.store else {
            return EndHold::NoRow;
        };
        let base = store
            .read(id, false)
            .and_then(KeptJob::live)
            .or_else(|| store.held_row(id));
        let Some(mut row) = base else {
            tracing::error!(
                ticket = id,
                "a media job's end is held here only: no row of it is kept"
            );
            return EndHold::NoRow;
        };
        row.ended = Some(state.clone());
        match store.hold_staged(id, row, stage) {
            Ok(()) => EndHold::Held,
            Err(error) => {
                tracing::error!(%error, ticket = id, "a media job's end is held here only");
                EndHold::Refused
            }
        }
    }

    /// Stops job `id` at its provider and drops it, here and in the vault.
    /// A running job is stopped first, under the lock its polls take; only
    /// a stop its provider confirmed settles its permit and lets it go. A
    /// stop that failed is the caller's error, and the job runs on here. A
    /// job that ended is only dropped.
    pub(super) async fn cancel_kept_job(&self, id: &str) -> LlmResult<()> {
        let job = match self.held(id)? {
            Held::Running(job) => job,
            // Nothing can stop it at its provider until its submit is
            // answered: the caller asks again (FIX 2248).
            Held::Submitting(_) => return Err(oneiron::RetryableLlmError::ServerError.into()),
            // Its provider's job cannot be reached: its row is let go.
            Held::Unsent(_) | Held::Unkept(_) | Held::Ended(_) => return self.drop_kept_job(id),
        };
        let mut held = job.lock().await;
        held.cancel().await?;
        // A confirmed stop settled its permit: what that charged reaches
        // the scope that funds it in the commit that drops its row (FIX
        // 11496, S7299-P1).
        self.drop_kept_job(id)
    }

    /// Drops job `id` from here and its row and clips from the vault, in
    /// one write, while no poll takes it up again; the scope that funds it,
    /// when one does, stages in that write what it does not hold yet of the
    /// job's guard use, and is drained after it (S7299-P1). The ledger goes
    /// before the jobs lock does, so a poll that writes the job's refused
    /// end again stages none of that part (S7299 review round 3 P1). A
    /// write the vault refuses drops and stages nothing: the job stays, and
    /// the caller hears it.
    fn drop_kept_job(&self, id: &str) -> LlmResult<()> {
        let mut jobs = self.lock_jobs();
        let stage = self.end_stage(id);
        if let Some(store) = &self.store
            && let Err(error) = store.delete_staged(id, stage.as_ref())
        {
            tracing::error!(%error, ticket = id, "a media job's row was not dropped; it is kept");
            return Err(oneiron::RetryableLlmError::ServerError.into());
        }
        jobs.remove(id);
        let staged = self.end_committed(id, stage);
        drop(jobs);
        self.drain_end_stage(staged);
        Ok(())
    }
}

/// What holding a job's end in the vault came to.
enum EndHold {
    /// The held end, and its stage, committed.
    Held,
    /// No row of the job is kept: no restart takes it up.
    NoRow,
    /// The vault refused the held end: nothing committed.
    Refused,
}
