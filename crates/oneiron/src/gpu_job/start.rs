//! Starting a chunk: the quote shown, reserved whole, written, then created
//! (CROSS-ARCH-0023 lifecycle 01-03, C2 01 and 05), and the customer's
//! cancel. The owner starts under their own proof; an agent starts under its
//! own Grant within the per-job maximum the owner set beside it (RULING
//! L10-31-STARTER = B), and resumes or cancels only a job it started.
use crate::gpu_line::{ClaimKey, UnitEndReport, settle_unit_in_txn};
use crate::job_dispatch::{DispatchClose, DispatchPhase};
use crate::llm::run_admission::{
    CallOutcome, CheckpointRef, DeclaredMaximum, JobMaximum, MaximumShown, ResumeOffer,
    ResumeRefused, RunAdmission,
};
use crate::{EntityId, Vault};

use super::caller::refused;
use super::{
    GPU_JOBS, GpuChunk, GpuConnectorError, GpuEndReason, GpuJob, GpuJobActor, GpuJobConnector,
    GpuJobError, GpuJobPermits, GpuJobQuote, GpuJobState, GpuJobVerb, GpuOffer, GpuOfferPin,
    GpuResourceRef, GpuTermination, seconds,
};

/// The job a start writes, or why its write refused.
type Written = Result<GpuJob, GpuJobError>;

/// What a start or a resume of a GPU job asks: who presses it, the offer and
/// the quote it starts on, the offer a stop gave when it resumes from that
/// stop, and the job's own run ([`GpuJob::admission_ref_of`] of
/// `quote.job`).
#[derive(Debug, Clone, Copy)]
pub struct GpuJobStart<'a> {
    pub actor: GpuJobActor<'a>,
    pub offer: &'a GpuOffer,
    pub quote: &'a GpuJobQuote,
    pub resume: Option<&'a ResumeOffer>,
    pub admission: &'a RunAdmission,
}

impl Vault {
    /// `start.actor` starts a job on `start.quote`, or resumes the stopped
    /// job the quote names from `start.resume`, the offer its stop gave. The
    /// owner's pressing start on the quote is the showing of its maximum (C2
    /// 01); an agent's start fits the per-job maximum the owner set beside the
    /// Grant that admits it, and that setting is the showing. The whole quote
    /// is reserved before anything is written or created; a refusal leaves
    /// nothing behind. The quote a stop's notice offers stays good while that
    /// stop stands.
    ///
    /// # Errors
    ///
    /// [`GpuJobError::QuoteChanged`] or [`GpuJobError::QuoteExpired`]: quote
    /// again. [`GpuJobError::Denied`] when the reservation does not fit.
    /// [`GpuJobError::Resume`] for a resume its stop does not allow.
    /// [`GpuJobError::Caller`] for an agent past its Grant or its maximum.
    /// [`GpuJobError::LineManaged`] on an offer a GPU line names: a job
    /// starts there only through its unit claim
    /// ([`Self::start_claimed_gpu_job`]).
    pub fn start_gpu_job(
        &self,
        start: GpuJobStart<'_>,
        permits: &GpuJobPermits,
        connector: &dyn GpuJobConnector,
        now_ms: u64,
    ) -> Result<GpuJob, GpuJobError> {
        let GpuJobStart {
            actor,
            offer,
            quote,
            resume,
            admission,
        } = start;
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
        // Every refusal of the start gate, the caller or the maximum comes
        // before the reservation.
        let (_, shown) = {
            let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
            self.plain_start_gate_in_txn(&txn, offer, resume)??;
            self.gpu_job_starter_in_txn(&txn, actor, current.as_ref(), quote, resume, now_ms)??
        };
        next_chunk(current, offer, quote, resume, shown, now_ms)?;
        let permit = admission
            .admit_paid(&offer.connector, quote.quantity)
            .map_err(GpuJobError::Denied)?;
        let written = self.with_write_txn_grouped(|txn| -> crate::Result<Written> {
            if let Err(refused) = self.plain_start_gate_in_txn(txn, offer, resume)? {
                return Ok(Err(refused));
            }
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
            if let GpuJobActor::Order(attempt) = actor
                && let Err(refused) =
                    self.record_order_attempt_in_txn(txn, attempt, &job.id, now_ms)?
            {
                return Ok(Err(GpuJobError::Order(refused)));
            }
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
        let mut job = match written {
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
        permits.hold(job.id, job.chunk_mut()?.idempotency_key.clone(), permit);
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
            GpuJobActor::Order(attempt) => {
                return self.order_job_starter_in_txn(txn, attempt, quote, resume, now_ms);
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

    /// Who starts an attempt the work-order loop makes, and when its maximum
    /// was shown (pass 34, 1.1): the order's requester as the order's own
    /// check finds it in `txn`. The owner's order is his showing; an agent's
    /// attempt fits the per-job maximum the owner set beside the Grant that
    /// named `vault.jobs.order`. An order never resumes a stopped job: a
    /// retry is a new attempt under a new job id.
    fn order_job_starter_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        attempt: &crate::work_order::OrderAttemptRef,
        quote: &GpuJobQuote,
        resume: Option<&ResumeOffer>,
        now_ms: u64,
    ) -> crate::Result<Result<(EntityId, MaximumShown), GpuJobError>> {
        use crate::work_order::{AttemptRefused, Blocker, OrderStarter};
        if resume.is_some() {
            return Ok(Err(GpuJobError::Order(AttemptRefused::OrderChanged)));
        }
        match self.order_starter_in_txn(txn, attempt, &quote.job, now_ms)? {
            Err(refused) => Ok(Err(GpuJobError::Order(refused))),
            Ok(OrderStarter::Owner {
                owner,
                ordered_at_ms,
            }) => Ok(Ok((
                owner,
                MaximumShown {
                    at_ms: ordered_at_ms,
                },
            ))),
            Ok(OrderStarter::Agent { actor, grant }) => {
                let allowance = self.gpu_job_allowance_in_txn(txn, &grant)?;
                match allowance {
                    Some(allowance) if quote.maximum_secs <= allowance.maximum_secs => Ok(Ok((
                        actor,
                        MaximumShown {
                            at_ms: allowance.set_at_ms,
                        },
                    ))),
                    allowance => Ok(Err(GpuJobError::Order(AttemptRefused::Blocked(
                        Blocker::AllowanceExceeded {
                            maximum_secs: allowance.map_or(0, |allowance| allowance.maximum_secs),
                        },
                    )))),
                }
            }
        }
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
    pub fn cancel_gpu_job(
        &self,
        actor: GpuJobActor<'_>,
        id: &EntityId,
        permits: &GpuJobPermits,
        connector: &dyn GpuJobConnector,
        now_ms: u64,
    ) -> Result<GpuJob, GpuJobError> {
        if let GpuJobActor::Owner(owner) = actor {
            owner.revalidate(self)?;
        }
        self.cancel_gpu_job_for(CancelFor::Actor(actor), id, permits, connector, now_ms)
    }

    /// The cancel of [`Self::cancel_gpu_job`], for `by`. An agent's generic
    /// cancel of a unit's job is refused: `vault.arms.units.cancel` ends it
    /// (design pass 32 r2, 5.3).
    pub(super) fn cancel_gpu_job_for(
        &self,
        by: CancelFor<'_>,
        id: &EntityId,
        permits: &GpuJobPermits,
        connector: &dyn GpuJobConnector,
        now_ms: u64,
    ) -> Result<GpuJob, GpuJobError> {
        let written = self.with_write_txn_grouped(|txn| -> crate::Result<Written> {
            let Some(mut job) = GPU_JOBS.get(&self.store, txn, id)? else {
                return Ok(Err(GpuJobError::NotFound));
            };
            match by {
                CancelFor::Actor(GpuJobActor::Owner(owner)) => {
                    owner.revalidate_in_txn(self, txn)?;
                }
                CancelFor::Actor(GpuJobActor::Order(attempt)) => {
                    if !self.order_stop_reaches_in_txn(txn, attempt, id)? {
                        return Ok(Err(GpuJobError::Order(
                            crate::work_order::AttemptRefused::OrderChanged,
                        )));
                    }
                }
                CancelFor::Actor(GpuJobActor::Agent(agent)) => {
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
                    if job.claim.is_some() {
                        return Ok(Err(GpuJobError::Caller(refused(
                            verb,
                            "a unit's job is cancelled with vault.arms.units.cancel",
                        ))));
                    }
                }
                CancelFor::Unit(claim) => {
                    if job.claim.as_ref() != Some(claim) {
                        return Ok(Err(GpuJobError::NotFound));
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
        // A host that holds no permit for the live chunk (it restarted since
        // the chunk began) leaves it ending: its next step admits the chunk
        // again and the new permit pays the end, as for any chunk it takes up.
        // A chunk whose admission was lost ends now, unpaid, as its step would.
        // A unit's job holds no permit (its claim is its hold): it ends now.
        let taken_up_by_a_step = written.claim.is_none()
            && written.chunk().is_some_and(|chunk| {
                !chunk.admission_lost && !permits.holds_chunk(&written.id, &chunk.idempotency_key)
            });
        if taken_up_by_a_step {
            return Ok(written);
        }
        self.end_gpu_chunk(written, permits, connector, now_ms)
            .map(|(job, _)| job)
    }

    /// Asks the provider for the chunk's resource under its key, or finds the
    /// one an unanswered create made: a create that did not answer is never
    /// made again blind (`#gpu-uncertain` 01). A refusal before any resource existed
    /// bills nothing. A signed node refusal ends the job; any other refusal holds it.
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
                if let Some(permit) = permits.take_for_chunk(&job.id, &key) {
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
        if let Some(resource) = &created {
            chunk.resource = Some(resource.clone());
            job.state = GpuJobState::Running;
        }
        if !self.with_write_txn_grouped(|txn| self.put_gpu_job_in_txn(txn, &mut job, now_ms))? {
            return self
                .stored_after_lost_write(&job.id, &key, created, permits, connector, now_ms);
        }
        Ok(job)
    }

    /// The stored row, after this host's write over the chunk under `key`
    /// of `id` lost to another one (a cancel, an erase), as
    /// [`Self::stored_after_lost_step`] reads it. A resource this host made
    /// or found under `key` is terminated unless that row still steps it: an
    /// end that found nothing has settled the chunk already, and no later
    /// step would end it. A termination the provider does not confirm at
    /// once leaves the resource on the row, and the host's step asks again
    /// until it does.
    pub(super) fn stored_after_lost_write(
        &self,
        id: &EntityId,
        key: &str,
        resource: Option<GpuResourceRef>,
        permits: &GpuJobPermits,
        connector: &dyn GpuJobConnector,
        now_ms: u64,
    ) -> Result<GpuJob, GpuJobError> {
        let mut stored = self.stored_after_lost_step(id, key, permits)?;
        let Some(resource) = resource.filter(|resource| !steps_resource(&stored, key, resource))
        else {
            return Ok(stored);
        };
        if let Ok(GpuTermination::Confirmed { .. }) = connector.terminate(&resource) {
            return Ok(stored);
        }
        while !stored.orphaned_resources.contains(&resource)
            && !steps_resource(&stored, key, &resource)
        {
            stored.orphaned_resources.push(resource.clone());
            if self
                .with_write_txn_grouped(|txn| self.put_gpu_job_in_txn(txn, &mut stored, now_ms))?
            {
                break;
            }
            stored = self.load_gpu_job(id)?;
        }
        Ok(stored)
    }

    /// The stored row, after a step's write over the chunk under `key` of
    /// `id` lost to another write. When that row ended the chunk with no
    /// settlement, the permit this host holds for the chunk pays nothing: no
    /// step settles it any more, and it would hold the reservation until the
    /// host stops. An end that settled the chunk takes its own permit.
    pub(super) fn stored_after_lost_step(
        &self,
        id: &EntityId,
        key: &str,
        permits: &GpuJobPermits,
    ) -> Result<GpuJob, GpuJobError> {
        let stored = self.load_gpu_job(id)?;
        if ended_unsettled(&stored, key)
            && let Some(permit) = permits.take_for_chunk(id, key)
        {
            let _ = permit.settle(CallOutcome::Used(0));
        }
        Ok(stored)
    }

    /// Asks the termination of each resource a lost write left on `job`, and
    /// drops those whose provider confirmed it; the others wait for the next
    /// step.
    pub(super) fn terminate_orphaned_resources(
        &self,
        mut job: GpuJob,
        connector: &dyn GpuJobConnector,
        now_ms: u64,
    ) -> Result<GpuJob, GpuJobError> {
        let before = job.orphaned_resources.len();
        job.orphaned_resources.retain(|resource| {
            !matches!(
                connector.terminate(resource),
                Ok(GpuTermination::Confirmed { .. })
            )
        });
        if job.orphaned_resources.len() == before
            || self.with_write_txn_grouped(|txn| self.put_gpu_job_in_txn(txn, &mut job, now_ms))?
        {
            return Ok(job);
        }
        // Another write came first: the next step asks again.
        self.load_gpu_job(&job.id)
    }

    /// Records a refusal before any resource existed. A signed node refusal ends the job
    /// as `NeverStarted`; any other refusal holds it. A unit's job ends its claim
    /// `Released(reason)` in the same write: nothing ran, so the claim's draws return once
    /// (design pass 32 r2, 7.3).
    fn hold_gpu_job(
        &self,
        mut job: GpuJob,
        reason: String,
        now_ms: u64,
    ) -> Result<GpuJob, GpuJobError> {
        let refused = UnitEndReport::Refused {
            reason: reason.clone(),
        };
        let written = self.with_write_txn_grouped(|txn| -> crate::Result<bool> {
            let key = &job.chunk_mut()?.idempotency_key;
            let node_refused = self.job_dispatch_in_txn(txn, key)?.is_some_and(|row| {
                row.phase == DispatchPhase::Closed
                    && matches!(row.closed, Some(DispatchClose::NodeRefused { .. }))
            });
            job.state = if node_refused {
                GpuJobState::Ended {
                    reason: GpuEndReason::NeverStarted,
                }
            } else {
                GpuJobState::Held { reason }
            };
            if !self.put_gpu_job_in_txn(txn, &mut job, now_ms)? {
                return Ok(false);
            }
            if let Some(claim) = &job.claim {
                // A claim that already ended keeps its terminal.
                let _ = settle_unit_in_txn(self, txn, claim, &job.id, &refused, now_ms)?;
            }
            Ok(true)
        })?;
        if !written {
            return self.load_gpu_job(&job.id);
        }
        Ok(job)
    }
}

/// Whether `job`'s stored row still steps the resource made under `key`: its
/// current chunk is that key's and names the resource, or is reserved, so the
/// next step finds the resource by its key.
fn steps_resource(job: &GpuJob, key: &str, resource: &GpuResourceRef) -> bool {
    job.chunk()
        .filter(|chunk| chunk.idempotency_key == key)
        .is_some_and(|chunk| {
            chunk.resource.as_ref() == Some(resource) || job.state == GpuJobState::Reserved
        })
}

/// Whether `job`'s stored row no longer runs the chunk under `key` and
/// records no settlement for it.
fn ended_unsettled(job: &GpuJob, key: &str) -> bool {
    let runs = job.state.is_live()
        && job
            .chunk()
            .is_some_and(|chunk| chunk.idempotency_key == key);
    !runs
        && job
            .chunks
            .iter()
            .find(|chunk| chunk.idempotency_key == key)
            .is_none_or(|chunk| chunk.settled_units.is_none())
}

/// Who a cancel runs for: a caller of `vault.gpu.jobs.cancel`, or the unit
/// door, which judged the line role and the reserver itself and cancels only
/// the job of the claim it names.
#[derive(Debug, Clone, Copy)]
pub(super) enum CancelFor<'a> {
    Actor(GpuJobActor<'a>),
    Unit(&'a ClaimKey),
}

/// The job with `quote`'s chunk added: a new job under the maximum it shows,
/// or the stopped job resumed from its checkpoint under its run time so far
/// plus the quote's maximum. It checks; the caller writes.
pub(super) fn next_chunk(
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
                orphaned_resources: Vec::new(),
                claim: None,
                backend: None,
            };
            (job, None::<CheckpointRef>)
        }
        (Some(_), None) => return Err(GpuJobError::QuoteUsed),
        (None, Some(_)) => return Err(GpuJobError::NotFound),
        (Some(mut job), Some(resume)) => {
            if job.state != GpuJobState::Stopped {
                return Err(GpuJobError::Resume(ResumeRefused::NotStopped));
            }
            // The resumed chunk runs where the job ran: the host's steps and
            // the cancel reach the job's resource through its pinned offer.
            if offer.name != job.offer.name
                || quote.job_type != job.job_type
                || quote.image != job.image
            {
                return Err(GpuJobError::ResumeTermsChanged);
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
    // The chunk runs on the backend the offer names now; the host's steps and
    // cancel reach it through the row from here on.
    job.backend = offer.backend().map(str::to_owned);
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
