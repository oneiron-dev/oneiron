//! A kept job's end and its delete, in one order (FIX 9511, FIX 9513). A
//! poll that sees the job end writes that end under the job's own lock, and
//! a delete of a running job stops it under the same lock, so neither runs
//! inside the other. A job's end is written only over the row its submit
//! kept: once a delete dropped the row and its clips, in one write, a late
//! end writes nothing back and its poll finds no job. A delete goes ahead
//! only once the provider confirmed the stop: a stop that failed, or whose
//! outcome is unknown, leaves the job running here with its ticket, permit
//! and row, since it may still run and bill at its provider, and its caller
//! may poll it or delete it again.
//! Entry: `MediaRuntime::cancel_kept_job`.
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
    /// (KS-2B2). Returns what the poll answers.
    pub(super) fn complete_kept_job(
        &self,
        id: &str,
        state: &MediaJobState,
    ) -> LlmResult<MediaJobState> {
        let written =
            self.store
                .as_ref()
                .map_or(Ok(JobWrite::Kept), |store| -> Result<JobWrite, String> {
                    store.flush(id);
                    let kept = store
                        .get(id)
                        .ok_or_else(|| "its row is not kept".to_owned())?;
                    let Some(mut row) = kept.live() else {
                        return Ok(JobWrite::Erased);
                    };
                    row.ended = Some(state.clone());
                    store.update(id, row)
                });
        let mut jobs = self.lock_jobs();
        match written {
            Ok(JobWrite::Kept) => {
                jobs.remove(id);
            }
            Ok(JobWrite::Erased) => {
                jobs.remove(id);
                return Ok(erased_poll(id));
            }
            Ok(JobWrite::Deleted) => {
                jobs.remove(id);
                return Err(FatalLlmError::InvalidRequest.into());
            }
            Err(error) => {
                tracing::error!(%error, ticket = id, "a media job's end is held, not kept");
                self.hold_end(id, state);
                if let Some(held) = jobs.get_mut(id)
                    && matches!(held, Held::Running(_))
                {
                    *held = Held::Unkept(state.clone());
                }
            }
        }
        Ok(state.clone())
    }

    /// Holds job `id`'s end `state` as its held write (FIX 2963), over the
    /// row its own key keeps or, when that was never kept, its held submit.
    /// A job with neither keeps its end here only.
    fn hold_end(&self, id: &str, state: &MediaJobState) {
        let Some(store) = &self.store else {
            return;
        };
        let base = store
            .read(id, false)
            .and_then(KeptJob::live)
            .or_else(|| store.held_row(id));
        let held = base.ok_or_else(|| "no row of it is kept".to_owned()).and_then(|mut row| {
            row.ended = Some(state.clone());
            store.hold(id, row)
        });
        if let Err(error) = held {
            tracing::error!(%error, ticket = id, "a media job's end is held here only");
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
        self.drop_kept_job(id)
    }

    /// Drops job `id` from here and its row and clips from the vault, in
    /// one write, while no poll takes it up again. A write the vault
    /// refuses drops nothing: the job stays, and the caller hears it.
    fn drop_kept_job(&self, id: &str) -> LlmResult<()> {
        let mut jobs = self.lock_jobs();
        if let Some(store) = &self.store
            && let Err(error) = store.delete(id)
        {
            tracing::error!(%error, ticket = id, "a media job's row was not dropped; it is kept");
            return Err(oneiron::RetryableLlmError::ServerError.into());
        }
        jobs.remove(id);
        Ok(())
    }
}
