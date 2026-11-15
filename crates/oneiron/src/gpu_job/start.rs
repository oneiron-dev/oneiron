//! Starting a chunk: the quote shown, reserved whole, written, then created
//! (CROSS-ARCH-0023 lifecycle 01-03, C2 01 and 05), and the customer's
//! cancel.
use crate::consent::AuthenticatedOwner;
use crate::llm::run_admission::{
    CallOutcome, CheckpointRef, DeclaredMaximum, JobMaximum, MaximumShown, ResumeOffer,
    ResumeRefused, RunAdmission,
};
use crate::{EntityId, Vault};

use super::{
    GPU_JOBS, GpuChunk, GpuConnectorError, GpuEndReason, GpuJob, GpuJobConnector, GpuJobError,
    GpuJobPermits, GpuJobQuote, GpuJobState, GpuOffer, GpuOfferPin, seconds,
};

/// The job a start writes, or why its write refused.
type Written = Result<GpuJob, GpuJobError>;

impl Vault {
    /// The owner starts a job on `quote`, or resumes the stopped job the quote
    /// names from `resume`, the offer its stop gave. Pressing start on the
    /// quote is the showing of its maximum (C2 01). The whole quote is
    /// reserved before anything is written or created; a refusal leaves
    /// nothing behind. `admission` is the job's own run
    /// ([`GpuJob::admission_ref_of`] of `quote.job`).
    ///
    /// # Errors
    ///
    /// [`GpuJobError::QuoteChanged`] or [`GpuJobError::QuoteExpired`]: quote
    /// again. [`GpuJobError::Denied`] when the reservation does not fit.
    /// [`GpuJobError::Resume`] for a resume its stop does not allow.
    #[allow(clippy::too_many_arguments)]
    pub fn start_gpu_job(
        &self,
        owner: &AuthenticatedOwner,
        offer: &GpuOffer,
        quote: &GpuJobQuote,
        resume: Option<&ResumeOffer>,
        admission: &RunAdmission,
        permits: &GpuJobPermits,
        connector: &dyn GpuJobConnector,
        now_ms: u64,
    ) -> Result<GpuJob, GpuJobError> {
        owner.revalidate(self)?;
        quote.check(offer, now_ms)?;
        if admission.run() != GpuJob::admission_ref_of(&quote.job) {
            return Err(GpuJobError::AdmissionMismatch);
        }
        let shown = MaximumShown { at_ms: now_ms };
        // Every refusal of the maximum comes before the reservation.
        let current = self.gpu_job(&quote.job)?;
        next_chunk(current, offer, quote, resume, shown, now_ms)?;
        let permit = admission
            .admit_paid(&offer.connector, quote.quantity)
            .map_err(GpuJobError::Denied)?;
        let written = self.with_write_txn_grouped(|txn| -> crate::Result<Written> {
            let actor = owner.revalidate_in_txn(self, txn)?;
            let current = GPU_JOBS.get(&self.store, txn, &quote.job)?;
            let mut job = match next_chunk(current, offer, quote, resume, shown, now_ms) {
                Ok(job) => job,
                Err(refused) => return Ok(Err(refused)),
            };
            if job.started_by.is_none() && job.chunks.len() == 1 {
                job.started_by = Some(actor);
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

    /// The owner cancels their job: a live chunk is terminated and settles
    /// its billed time; a stopped job gives up its resume. The customer's own
    /// end needs none of the conditions of a stop at the maximum.
    ///
    /// # Errors
    ///
    /// [`GpuJobError::Ended`] for a job that already ended.
    pub fn cancel_gpu_job(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        permits: &GpuJobPermits,
        connector: &dyn GpuJobConnector,
        now_ms: u64,
    ) -> Result<GpuJob, GpuJobError> {
        owner.revalidate(self)?;
        let written = self.with_write_txn_grouped(|txn| -> crate::Result<Written> {
            owner.revalidate_in_txn(self, txn)?;
            let Some(mut job) = GPU_JOBS.get(&self.store, txn, id)? else {
                return Ok(Err(GpuJobError::NotFound));
            };
            job.state = match job.state {
                GpuJobState::Reserved | GpuJobState::Running => GpuJobState::Ending {
                    reason: GpuEndReason::Cancelled,
                },
                GpuJobState::Stopped => GpuJobState::Ended {
                    reason: GpuEndReason::Cancelled,
                },
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
        self.with_write_txn_grouped(|txn| self.put_gpu_job_in_txn(txn, &mut job, now_ms))?;
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
        self.with_write_txn_grouped(|txn| self.put_gpu_job_in_txn(txn, &mut job, now_ms))?;
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
