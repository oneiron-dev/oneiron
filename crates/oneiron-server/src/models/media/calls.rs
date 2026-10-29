//! Media calls, public job operations and runtime cleanup.
//! Entry: MediaRuntime::run.
//! Types and private call/job helpers stay in the parent; this module owns the listed impls.

use super::{
    Arc, FatalLlmError, Held, JobLine, JobRow, JobStore, LlmResult, MediaAnswer, MediaJobState,
    MediaRequest, MediaResponse, MediaRuntime, MediaTicket, PayerPerson, RetryHint, RunAdmission,
    RungVoices, Vault, submit_stamps,
};

/// A runtime that keeps its jobs hands each running job's permit off as it
/// stops, charging nothing: the job runs on at its provider, and the runtime
/// that takes it up from its kept row pays its end, once. A program's job
/// whose row was not kept has no row to take it up from: it pays its
/// reservation on its run's line now (FIX 780, 6083). A job in a poll that
/// holds it is left to its own permit.
impl Drop for MediaRuntime {
    fn drop(&mut self) {
        if self.store.is_none() {
            return;
        }
        for (ticket, job) in self.lock_jobs().iter() {
            let Held::Running(job) = job else {
                continue;
            };
            let Ok(mut job) = job.try_lock() else {
                continue;
            };
            if self.unkept_program_job(ticket) {
                job.settle_failed();
                continue;
            }
            if let Some(permit) = job.permit.take()
                && let Err(denied) = permit.hand_off_media()
            {
                tracing::error!(%denied, "a kept media job's permit was not handed off");
            }
        }
    }
}

impl MediaRuntime {
    /// One call to its answer, on a run of its own on the media meter,
    /// billed to `payer` when a room pays for it (FIX 805); `None` is the
    /// vault owner's. Its permits carry `sources`, the rows the caller read
    /// the request from (FIX 11311), `None` when not known whole.
    pub async fn run(
        &self,
        request: MediaRequest,
        payer: Option<PayerPerson>,
        sources: Option<Vec<oneiron::EntityId>>,
    ) -> LlmResult<MediaResponse> {
        self.run_in(request, None, payer, sources).await
    }

    /// [`Self::run`] for a speech call in a banked voice (FIX 1746): it goes
    /// only to the rungs of its ladder that hold the voice, each in its own
    /// binding of it.
    pub(crate) async fn run_voiced(
        &self,
        request: MediaRequest,
        voices: &RungVoices,
        payer: Option<PayerPerson>,
        sources: Option<Vec<oneiron::EntityId>>,
    ) -> LlmResult<MediaResponse> {
        self.run_in(request, Some(voices), payer, sources).await
    }

    /// When `request` may be sent again if no offer answers it (FIX 3194):
    /// the offers that could serve it, in its voice, read again once the
    /// call failed. Taken before the call, which consumes the request.
    pub(crate) fn retry_hint(
        &self,
        request: &MediaRequest,
        voices: Option<&RungVoices>,
    ) -> RetryHint {
        self.ladder(request).map_or_else(
            |_| RetryHint {
                offers: Vec::new(),
                rests: None,
            },
            |ladder| ladder.media_retry(request, voices),
        )
    }

    /// One call to its answer on `run`, the line its caller admitted it on
    /// (FIX 3194): a pumped agent run's own, which it spends on as it does
    /// its other model calls, never the media meter.
    pub(crate) async fn run_admitted(
        &self,
        run: &RunAdmission,
        request: MediaRequest,
        voices: Option<&RungVoices>,
    ) -> LlmResult<MediaResponse> {
        if request.operation.is_job() {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let ladder = self.ladder(&request)?;
        match ladder.media(run, request, None, voices).await? {
            MediaAnswer::Done(response) => Ok(response),
            // Only a job operation is submitted.
            MediaAnswer::Job(mut job) => {
                job.settle_failed();
                Err(FatalLlmError::InvalidRequest.into())
            }
        }
    }

    /// Submits one job (`ai.video`), billed to `payer` as [`Self::run`]'s
    /// call is; its caller polls the ticket. The job is kept in the vault
    /// with its payer, so a restart loses neither, and a poll or a cancel
    /// never names a payer of its own. Its row is stamped with who owns its
    /// content: `actor`, the caller's entity when its credential names one,
    /// and its request's subject; never its payer (KS-2B2).
    pub async fn submit(
        &self,
        request: MediaRequest,
        payer: Option<PayerPerson>,
        actor: Option<oneiron::EntityId>,
        sources: Option<Vec<oneiron::EntityId>>,
    ) -> LlmResult<MediaTicket> {
        self.submit_replayed(request, payer, actor, sources, None)
            .await
    }

    /// [`Self::submit`] on `run`, the line its caller admitted it on (FIX
    /// 780, FIX 6083): a program's run's own. The job's permit is held on
    /// that line until the job ends, and its end, its cancel and its take-up
    /// after a restart settle there, never on the media meter. Its row keeps
    /// the run's name and payer, and is stamped as [`Self::submit`]'s is.
    pub(crate) async fn submit_run_admitted(
        &self,
        run: &RunAdmission,
        request: MediaRequest,
        actor: Option<oneiron::EntityId>,
    ) -> LlmResult<MediaTicket> {
        if !request.operation.is_job() {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let operation = request.operation;
        let stamps = submit_stamps(actor, &request);
        let sent = self.store.as_ref().map(|_| request.clone());
        let ladder = self.ladder(&request)?;
        // A media call's one deadline is its caller's (FIX 8134), as
        // `submit`'s walk.
        let deadline = crate::models::CallDeadline::Open;
        let walked = ladder.media_by(run, request, None, None, deadline);
        let MediaAnswer::Job(job) = walked.await? else {
            return Err(FatalLlmError::EmptyResponse.into());
        };
        let id = super::replay::fresh_ticket();
        let line = JobLine {
            run: run.run().to_owned(),
        };
        let ticket = MediaTicket {
            job: id.clone(),
            model: job.model.to_string(),
            operation,
        };
        let mut kept = self.store.is_some();
        if let (Some(store), Some(request)) = (&self.store, sent)
            && let Err(error) = store.put(
                &id,
                JobRow {
                    model: job.model.clone(),
                    operation,
                    provider_job: Some(job.provider_job.clone()),
                    request,
                    ended: None,
                    receipt: job.receipt.clone(),
                    payer: run.payer().cloned(),
                    stamps,
                    erased: false,
                    replay_until_s: None,
                    paid: false,
                    line: Some(line.clone()),
                },
            )
        {
            tracing::error!(%error, ticket = %id, "a media job was not kept: it runs held here");
            kept = false;
        }
        // A job whose row was not kept still answers its own run.
        if !kept {
            self.submitted_on(&id, line);
        }
        self.lock_jobs()
            .insert(id, Held::Running(Arc::new(tokio::sync::Mutex::new(job))));
        Ok(ticket)
    }

    /// Where job `id` stands. A job that ended keeps its end, and every poll
    /// answers it until its caller deletes the job; without a vault it is
    /// answered once. An end the vault refuses is held here and answered
    /// from here, and each poll writes it again; the job is never polled or
    /// paid for again. A job a restart left running is taken up again on a
    /// fresh permit, and nothing is sent again. A job an erase took answers
    /// its erased end: a running one is still polled and paid for, and its
    /// end is neither kept nor answered (KS-2B2).
    pub async fn poll(&self, id: &str) -> LlmResult<MediaJobState> {
        let job = match self.held(id)? {
            Held::Running(job) => job,
            // Its submit is still out (FIX 2248).
            Held::Submitting(_) => return Ok(MediaJobState::Queued),
            Held::Unsent(row) => return self.resubmit_kept(id, *row).await,
            Held::Unkept(state) => return self.complete_kept_job(id, &state),
            Held::Ended(state) => return Ok(state),
        };
        let mut held = job.lock().await;
        if held.permit.is_none() {
            // The poll this one waited behind saw the end.
            drop(held);
            return self.ended(id);
        }
        let state = held.poll().await;
        if let Ok(ended) = &state
            && ended.ended()
        {
            return self.complete_kept_job(id, ended);
        }
        state
    }

    /// Stops job `id` at its provider and drops it, its kept row and clips
    /// with it, once its provider confirmed the stop; a stop that failed
    /// keeps the job, to poll or stop again (FIX 9513). A job that ended is
    /// only dropped. A drop the vault refuses is an error, never a success.
    pub async fn cancel(&self, id: &str) -> LlmResult<()> {
        self.cancel_kept_job(id).await
    }
}

impl crate::models::ModelRuntime {
    /// This runtime with its `ai.video` jobs kept in `vault`, so a restart
    /// loses none and an ended job answers every poll (FIX-LIST 465), and
    /// its voice reference uploads checked against `vault`'s bank before
    /// each one (FIX 9517).
    #[must_use]
    pub fn with_media_vault(mut self, vault: Arc<Vault>) -> Self {
        self.media.voice_refs.bind(Arc::clone(&vault));
        self.media.store = Some(JobStore::new(vault));
        self
    }

    /// Takes up, once the runtime is whole, every kept `ai.video` job a
    /// restart left running: its permit is admitted again on the media meter
    /// at start, not at its next poll, so new calls cannot spend what the
    /// job will owe.
    pub fn take_up_kept_media_jobs(&self) {
        self.media.take_up_kept();
    }
}
