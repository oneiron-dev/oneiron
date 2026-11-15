//! Starting a chunk: the quote shown, reserved whole, written, then created
//! (CROSS-ARCH-0023 lifecycle 01-03, C2 01 and 05), and the customer's
//! cancel. The owner starts under their own proof; an agent starts under its
//! own Grant within the per-job maximum the owner set beside it (RULING
//! L10-31-STARTER = B), and resumes or cancels only a job it started.
use crate::consent::AuthenticatedOwner;
use crate::llm::run_admission::{
    CallOutcome, CheckpointRef, DeclaredMaximum, JobMaximum, MaximumShown, ResumeOffer,
    ResumeRefused, RunAdmission,
};
use crate::{EntityId, Vault};

use super::caller::refused;
use super::{
    GPU_JOBS, GpuChunk, GpuConnectorError, GpuEndReason, GpuJob, GpuJobActor, GpuJobAgent,
    GpuJobConnector, GpuJobError, GpuJobPermits, GpuJobQuote, GpuJobState, GpuJobVerb, GpuOffer,
    GpuOfferPin, seconds,
};

/// The job a start writes, or why its write refused.
type Written = Result<GpuJob, GpuJobError>;

impl<'a> From<&'a AuthenticatedOwner> for GpuJobActor<'a> {
    fn from(owner: &'a AuthenticatedOwner) -> Self {
        Self::Owner(owner)
    }
}

impl<'a> From<&'a GpuJobAgent> for GpuJobActor<'a> {
    fn from(agent: &'a GpuJobAgent) -> Self {
        Self::Agent(agent)
    }
}

impl Vault {
    /// `actor` starts a job on `quote`, or resumes the stopped job the quote
    /// names from `resume`, the offer its stop gave. The owner's pressing
    /// start on the quote is the showing of its maximum (C2 01); an agent's
    /// start fits the per-job maximum the owner set beside the Grant that
    /// admits it, and that setting is the showing. The whole quote is
    /// reserved before anything is written or created; a refusal leaves
    /// nothing behind. `admission` is the job's own run
    /// ([`GpuJob::admission_ref_of`] of `quote.job`). The quote a stop's
    /// notice offers stays good while that stop stands.
    ///
    /// # Errors
    ///
    /// [`GpuJobError::QuoteChanged`] or [`GpuJobError::QuoteExpired`]: quote
    /// again. [`GpuJobError::Denied`] when the reservation does not fit.
    /// [`GpuJobError::Resume`] for a resume its stop does not allow.
    /// [`GpuJobError::Caller`] for an agent past its Grant or its maximum.
    #[allow(clippy::too_many_arguments)]
    pub fn start_gpu_job<'a>(
        &self,
        actor: impl Into<GpuJobActor<'a>>,
        offer: &GpuOffer,
        quote: &GpuJobQuote,
        resume: Option<&ResumeOffer>,
        admission: &RunAdmission,
        permits: &GpuJobPermits,
        connector: &dyn GpuJobConnector,
        now_ms: u64,
    ) -> Result<GpuJob, GpuJobError> {
        let actor = actor.into();
        if let GpuJobActor::Owner(owner) = actor {
            owner.revalidate(self)?;
        }
        let current = self.gpu_job(&quote.job)?;
        let offered_by_stop = resume.is_some()
            && current.as_ref().and_then(|job| job.resume_quote.as_ref()) == Some(quote);
        if offered_by_stop {
            quote.check_terms(offer)?;
        } else {
            quote.check(offer, now_ms)?;
        }
        if admission.run() != GpuJob::admission_ref_of(&quote.job) {
            return Err(GpuJobError::AdmissionMismatch);
        }
        // Every refusal of the caller or the maximum comes before the
        // reservation.
        let (_, shown) = {
            let txn = self.store.env.read_txn()?;
            self.gpu_job_starter_in_txn(&txn, actor, current.as_ref(), quote, resume, now_ms)??
        };
        next_chunk(current, offer, quote, resume, shown, now_ms)?;
        let permit = admission
            .admit_paid(&offer.connector, quote.quantity)
            .map_err(GpuJobError::Denied)?;
        let written = self.with_write_txn_grouped(|txn| -> crate::Result<Written> {
            let current = GPU_JOBS.get(&self.store, txn, &quote.job)?;
            let (starter, shown) = match self.gpu_job_starter_in_txn(
                txn,
                actor,
                current.as_ref(),
                quote,
                resume,
                now_ms,
            )? {
                Ok(starter) => starter,
                Err(refused) => return Ok(Err(refused)),
            };
            let mut job = match next_chunk(current, offer, quote, resume, shown, now_ms) {
                Ok(job) => job,
                Err(refused) => return Ok(Err(refused)),
            };
            if job.started_by.is_none() && job.chunks.len() == 1 {
                job.started_by = Some(starter);
            }
            job.chunk_mut()?.permit = serde_json::to_value(permit.facts())
                .map_err(|_| crate::Error::InvariantViolation("gpu permit facts encode"))?;
            job.revision += 1;
            job.updated_at_ms = now_ms;
            GPU_JOBS.put(&self.store, txn, &job.id, &job)?;
            Ok(Ok(job))
        });
        let job = match written {
            Ok(Ok(job)) => job,
            Ok(Err(refused)) => {
                let _ = permit.settle_unsent();
                return Err(refused);
            }
            Err(error) => {
                let _ = permit.settle_unsent();
                return Err(error.into());
            }
        };
        if let Err(denied) = admission.dispatch_paid(permit.lease(), &offer.connector) {
            let _ = permit.settle_unsent();
            self.hold_gpu_job(job, denied.to_string(), now_ms)?;
            return Err(GpuJobError::Denied(denied));
        }
        permits.hold(job.id, permit);
        self.create_gpu_chunk(job, permits, connector, now_ms)
    }

    /// Who starts this chunk and when its maximum was shown: the owner, now;
    /// or an agent the Grant picked for `vault.gpu.jobs.start` admits now,
    /// when the job's total maximum after the chunk fits the maximum the
    /// owner set beside that Grant, at that setting. An agent resumes only a
    /// job it started.
    fn gpu_job_starter_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        actor: GpuJobActor<'_>,
        current: Option<&GpuJob>,
        quote: &GpuJobQuote,
        resume: Option<&ResumeOffer>,
        now_ms: u64,
    ) -> crate::Result<Result<(EntityId, MaximumShown), GpuJobError>> {
        let agent = match actor {
            GpuJobActor::Owner(owner) => {
                let owner = owner.revalidate_in_txn(self, txn)?;
                return Ok(Ok((owner, MaximumShown { at_ms: now_ms })));
            }
            GpuJobActor::Agent(agent) => agent,
        };
        let verb = GpuJobVerb::Start;
        let grant = match agent.grant_in_txn(self, txn, verb) {
            Ok(grant) => grant,
            Err(refusal) => return Ok(Err(GpuJobError::Caller(refusal))),
        };
        if resume.is_some() && current.is_some_and(|job| job.started_by != Some(agent.actor())) {
            return Ok(Err(GpuJobError::Caller(refused(
                verb,
                "an agent resumes only a GPU job it started",
            ))));
        }
        let Some(allowance) = self.gpu_job_allowance_in_txn(txn, &grant)? else {
            return Ok(Err(GpuJobError::Caller(refused(
                verb,
                &format!(
                    "the owner set no GPU job maximum beside the Grant {} that admits this \
                     agent to start; vault.gpu.jobs.allow sets one",
                    grant.to_hex()
                ),
            ))));
        };
        let total_secs = current
            .filter(|_| resume.is_some())
            .map_or(0, |job| job.maximum.used_units())
            .saturating_add(quote.maximum_secs);
        if total_secs > allowance.maximum_secs {
            return Ok(Err(GpuJobError::Caller(refused(
                verb,
                &format!(
                    "the job's maximum of {total_secs} seconds is over the {} seconds the owner \
                     set beside its Grant",
                    allowance.maximum_secs
                ),
            ))));
        }
        Ok(Ok((
            agent.actor(),
            MaximumShown {
                at_ms: allowance.set_at_ms,
            },
        )))
    }

    /// `actor` cancels a job: a live chunk is terminated and settles its
    /// billed time; a stopped job gives up its resume. The customer's own
    /// end needs none of the conditions of a stop at the maximum. An agent
    /// cancels only a job it started, under a Grant that names the verb.
    ///
    /// # Errors
    ///
    /// [`GpuJobError::Ended`] for a job that already ended;
    /// [`GpuJobError::Caller`] for an agent the act does not admit.
    pub fn cancel_gpu_job<'a>(
        &self,
        actor: impl Into<GpuJobActor<'a>>,
        id: &EntityId,
        permits: &GpuJobPermits,
        connector: &dyn GpuJobConnector,
        now_ms: u64,
    ) -> Result<GpuJob, GpuJobError> {
        let actor = actor.into();
        if let GpuJobActor::Owner(owner) = actor {
            owner.revalidate(self)?;
        }
        let written = self.with_write_txn_grouped(|txn| -> crate::Result<Written> {
            let Some(mut job) = GPU_JOBS.get(&self.store, txn, id)? else {
                return Ok(Err(GpuJobError::NotFound));
            };
            match actor {
                GpuJobActor::Owner(owner) => {
                    owner.revalidate_in_txn(self, txn)?;
                }
                GpuJobActor::Agent(agent) => {
                    let verb = GpuJobVerb::Cancel;
                    if let Err(refusal) = agent.grant_in_txn(self, txn, verb) {
                        return Ok(Err(GpuJobError::Caller(refusal)));
                    }
                    if job.started_by != Some(agent.actor()) {
                        return Ok(Err(GpuJobError::Caller(refused(
                            verb,
                            "an agent cancels only a GPU job it started",
                        ))));
                    }
                }
            }
            job.state = match job.state {
                GpuJobState::Reserved | GpuJobState::Running => GpuJobState::Ending {
                    reason: GpuEndReason::Cancelled,
                },
                GpuJobState::Stopped => {
                    // The cancel gives up the stop's resume.
                    job.stop = None;
                    job.resume_quote = None;
                    GpuJobState::Ended {
                        reason: GpuEndReason::Cancelled,
                    }
                }
                GpuJobState::Ending { .. } => return Ok(Ok(job)),
                GpuJobState::Ended { .. } | GpuJobState::Held { .. } => {
                    return Ok(Err(GpuJobError::Ended));
                }
            };
            self.put_gpu_job_in_txn(txn, &mut job, now_ms)?;
            Ok(Ok(job))
        })??;
        if !matches!(written.state, GpuJobState::Ending { .. }) {
            return Ok(written);
        }
        self.end_gpu_chunk(written, permits, connector, now_ms)
            .map(|(job, _)| job)
    }

    /// Asks the provider for the chunk's resource under its key, or finds the
    /// one an unanswered create made: a create that did not answer is never
    /// made again blind (`#gpu-uncertain` 01). A refusal before any resource
    /// existed bills nothing and holds the job with its reason.
    pub(super) fn create_gpu_chunk(
        &self,
        mut job: GpuJob,
        permits: &GpuJobPermits,
        connector: &dyn GpuJobConnector,
        now_ms: u64,
    ) -> Result<GpuJob, GpuJobError> {
        let spec = job.spec()?;
        let key = job.chunk_mut()?.idempotency_key.clone();
        let created = match connector.create(&key, &spec) {
            Ok(resource) => Some(resource),
            Err(GpuConnectorError::Refused { reason }) => {
                if let Some(permit) = permits.take(&job.id) {
                    let _ = permit.settle(CallOutcome::Used(0));
                }
                return self.hold_gpu_job(job, reason, now_ms);
            }
            Err(GpuConnectorError::Timeout | GpuConnectorError::Unavailable { .. }) => {
                connector.find(&key).ok().flatten()
            }
        };
        let chunk = job.chunk_mut()?;
        chunk.dispatched = true;
        if let Some(resource) = created {
            chunk.resource = Some(resource);
            job.state = GpuJobState::Running;
        }
        if !self.with_write_txn_grouped(|txn| self.put_gpu_job_in_txn(txn, &mut job, now_ms))? {
            // Another write came first (a cancel): the stored row stands, and
            // the chunk's end finds a resource this create made by its key.
            return self.load_gpu_job(&job.id);
        }
        Ok(job)
    }

    /// Holds a job whose chunk never reached its provider.
    fn hold_gpu_job(
        &self,
        mut job: GpuJob,
        reason: String,
        now_ms: u64,
    ) -> Result<GpuJob, GpuJobError> {
        job.state = GpuJobState::Held { reason };
        if !self.with_write_txn_grouped(|txn| self.put_gpu_job_in_txn(txn, &mut job, now_ms))? {
            return self.load_gpu_job(&job.id);
        }
        Ok(job)
    }
}

/// The job with `quote`'s chunk added: a new job under the maximum it shows,
/// or the stopped job resumed from its checkpoint under its run time so far
/// plus the quote's maximum. It checks; the caller writes.
fn next_chunk(
    current: Option<GpuJob>,
    offer: &GpuOffer,
    quote: &GpuJobQuote,
    resume: Option<&ResumeOffer>,
    shown: MaximumShown,
    now_ms: u64,
) -> Result<GpuJob, GpuJobError> {
    let (mut job, checkpoint_from) = match (current, resume) {
        (None, None) => {
            let maximum = JobMaximum::start(
                quote.job.to_hex(),
                DeclaredMaximum {
                    units: quote.maximum_secs,
                    unit: seconds(),
                },
                Some(shown),
            )
            .map_err(GpuJobError::Start)?;
            let job = GpuJob {
                id: quote.job,
                started_by: None,
                offer: GpuOfferPin {
                    name: offer.name.clone(),
                    class: offer.class.clone(),
                    provider: offer.provider.clone(),
                    region: offer.region.clone(),
                    price_shape: offer.price_shape,
                },
                job_type: quote.job_type.clone(),
                image: quote.image.clone(),
                maximum,
                chunks: Vec::new(),
                state: GpuJobState::Reserved,
                stop: None,
                resume_quote: None,
                overrun_reported: false,
                created_at_ms: now_ms,
                updated_at_ms: now_ms,
                revision: 0,
            };
            (job, None::<CheckpointRef>)
        }
        (Some(_), None) => return Err(GpuJobError::QuoteUsed),
        (None, Some(_)) => return Err(GpuJobError::NotFound),
        (Some(mut job), Some(resume)) => {
            if job.state != GpuJobState::Stopped {
                return Err(GpuJobError::Resume(ResumeRefused::NotStopped));
            }
            let total = DeclaredMaximum {
                units: job.maximum.used_units().saturating_add(quote.maximum_secs),
                unit: seconds(),
            };
            let checkpoint = job
                .maximum
                .resume(resume, total, Some(shown))
                .map_err(GpuJobError::Resume)?;
            job.stop = None;
            job.resume_quote = None;
            job.overrun_reported = false;
            (job, Some(checkpoint))
        }
    };
    let index = job.chunks.len();
    job.chunks.push(GpuChunk {
        idempotency_key: format!("{}:{index}", job.id.to_hex()),
        quote: quote.clone(),
        base_used_secs: job.maximum.used_units(),
        checkpoint_from,
        permit: serde_json::Value::Null,
        dispatched: false,
        resource: None,
        used_secs: 0,
        signalled_percents: Vec::new(),
        newest_checkpoint: None,
        billed_secs: None,
        settled_units: None,
        unbilled_secs: 0,
        admission_lost: false,
    });
    job.state = GpuJobState::Reserved;
    Ok(job)
}
