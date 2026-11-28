//! A session's renewal on the host's step (pass 34, 9.3; row W1). A job whose first quote's offer
//! renews at the maximum runs as one run on its machine, paid chunk by chunk: once the current
//! chunk's run time reaches its maximum less `jobs.sessions.renew_lead_secs`, the step quotes the
//! next chunk on the same offer, admits it under its own permit, writes it, and only then sends
//! it. When the admission or the provider refuses, nothing more is sent and the run ends at the
//! end of the chunk paid. Once the provider proves the run passed the current chunk's end, that
//! chunk's slice settles alone, with no termination, and the next chunk runs. C2's checkpoints,
//! warning and stop never apply to a session.
use crate::Vault;
use crate::llm::run_admission::{CallOutcome, DeclaredMaximum, PaidConnector, RunAdmission};

use super::{
    GpuChunk, GpuConnectorError, GpuJob, GpuJobConnector, GpuJobError, GpuJobPermits, GpuJobQuote,
    GpuJobState, GpuJobStepReport, GpuOffer, GpuTermination, seconds,
};

/// The default of `jobs.sessions.renew_lead_secs`: five minutes of the chunk's run time.
pub const SESSION_RENEW_LEAD_DEFAULT_SECS: u64 = 300;

/// What a host gives its step to renew sessions (row W1). A step without it renews nothing, so
/// a session ends at the end of its paid chunk.
#[derive(Clone, Copy)]
pub struct GpuJobRenewal<'a> {
    /// The least renewal lead, in milliseconds, that still reaches the machine before the
    /// chunk's cutoff: the host's step, its send timeout, the node's stop grace and its renewal
    /// margin. A `jobs.sessions.renew_lead_secs` at or below it renews nothing.
    pub lead_floor_ms: u64,
    /// The admission of one chunk's own quote: each chunk is paid by its own permit, at the price
    /// its quote froze.
    pub admission: &'a dyn Fn(&GpuJobQuote) -> RunAdmission,
}

impl std::fmt::Debug for GpuJobRenewal<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GpuJobRenewal")
            .field("lead_floor_ms", &self.lead_floor_ms)
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Renews a running session whose current chunk's run time reached its maximum less the lead:
    /// quotes the next chunk on `offer` with the current chunk's request and maximum, admits it
    /// under its own permit, writes it, then sends it. A next chunk written but not answered is
    /// sent again under its key. A refusal of the admission sends nothing, and the step asks
    /// again at its next step, until the chunk ends.
    pub(super) fn renew_gpu_session(
        &self,
        job: GpuJob,
        offer: &GpuOffer,
        renewal: &GpuJobRenewal<'_>,
        permits: &GpuJobPermits,
        connector: &dyn GpuJobConnector,
        now_ms: u64,
    ) -> Result<GpuJob, GpuJobError> {
        // A unit's job holds no permit: its claim is its hold, and a claim per chunk is not
        // built yet (FIX row W1-SESSION-LINE-CLAIM), so it renews nothing and ends at its chunk.
        if job.state != GpuJobState::Running || !job.renews() || job.claim.is_some() {
            return Ok(job);
        }
        if let Some(next) = &job.renewal {
            if next.billed_secs.is_some() {
                return Ok(job);
            }
            // A next chunk this host holds no permit for (its admission was lost at a restart)
            // is never sent again. It closes at zero only when its provider holds nothing under
            // its key, so it was never sent; one that may have gone out ends with the run.
            if !permits.holds_chunk(&job.id, &next.idempotency_key) {
                if next.dispatched || connector.find(&next.idempotency_key)?.is_some() {
                    return Ok(job);
                }
                return self.close_gpu_renewal(job, permits, now_ms);
            }
            let Some(resource) = next.resource.clone() else {
                return self.send_gpu_renewal(job, permits, connector, now_ms);
            };
            // Read at each step, so a provider whose send got no answer sends the same chunk
            // again inside its window. A refusal is the provider's word that this chunk ended
            // before the run reached it (it refused the renewal on a send whose answer was lost,
            // or the run ended first): it never runs, so it settles zero now and its hold
            // returns before the current chunk ends. Anything else is the current chunk's to
            // tell: that chunk's end, or the run's passage into this one.
            if let Err(GpuConnectorError::Refused { reason }) = connector.status(&resource) {
                tracing::info!(job = %job.id.to_hex(), %reason, "gpu session: the provider ended the next chunk before the run reached it; it settles zero");
                return self.close_gpu_renewal(job, permits, now_ms);
            }
            return Ok(job);
        }
        let Some(active) = job.chunk() else {
            return Ok(job);
        };
        let lead_secs = match self.gpu_session_renew_lead_secs() {
            Ok(secs) => secs,
            Err(error) => {
                tracing::warn!(job = %job.id.to_hex(), %error, "gpu session: jobs.sessions.renew_lead_secs not read; no renewal this step");
                return Ok(job);
            }
        };
        if lead_secs.saturating_mul(1000) <= renewal.lead_floor_ms {
            tracing::warn!(
                job = %job.id.to_hex(),
                lead_secs,
                floor_ms = renewal.lead_floor_ms,
                "gpu session: jobs.sessions.renew_lead_secs is at or below the host's floor; the session ends at the end of its chunk"
            );
            return Ok(job);
        }
        // The provider must have reported run time first: a renewal of a run that has not
        // launched yet (a chunk shorter than the lead, still staging) is refused for good, and
        // the session could then never renew.
        if active.used_secs == 0
            || active.used_secs.saturating_add(lead_secs) < active.quote.maximum_secs
        {
            return Ok(job);
        }
        let quote = match offer.quote_for(
            job.id,
            &active.quote.request(),
            active.quote.maximum_secs,
            now_ms,
        ) {
            Ok(quote) => quote,
            Err(error) => {
                tracing::warn!(job = %job.id.to_hex(), %error, "gpu session: the next chunk could not be quoted; no renewal this step");
                return Ok(job);
            }
        };
        let continues = job
            .run_key()
            .ok_or(crate::Error::InvariantViolation("a GPU job holds a chunk"))?
            .to_owned();
        let admission = (renewal.admission)(&quote);
        if admission.run() != job.admission_ref() {
            return Err(GpuJobError::AdmissionMismatch);
        }
        let permit = match admission.admit_paid(&offer.connector, quote.quantity) {
            Ok(permit) => permit,
            Err(denied) => {
                tracing::info!(job = %job.id.to_hex(), %denied, "gpu session: the next chunk is not admitted; the session ends at the end of its chunk unless a later step admits it");
                return Ok(job);
            }
        };
        if let Err(denied) = admission.dispatch_paid(permit.lease(), &offer.connector) {
            let _ = permit.settle_unsent();
            tracing::info!(job = %job.id.to_hex(), %denied, "gpu session: the next chunk's dispatch check refused");
            return Ok(job);
        }
        let facts = match serde_json::to_value(permit.facts()) {
            Ok(facts) => facts,
            Err(_) => {
                let _ = permit.settle_unsent();
                return Err(crate::Error::InvariantViolation("gpu permit facts encode").into());
            }
        };
        let mut job = job;
        let key = format!("{}:{}", job.id.to_hex(), job.chunks.len());
        job.renewal = Some(GpuChunk {
            idempotency_key: key.clone(),
            quote,
            // Set when the run reaches it, from its predecessor's confirmed run time.
            base_used_secs: 0,
            checkpoint_from: None,
            permit: facts,
            dispatched: false,
            resource: None,
            used_secs: 0,
            signalled_percents: Vec::new(),
            newest_checkpoint: None,
            billed_secs: None,
            settled_units: None,
            unbilled_secs: 0,
            admission_lost: false,
            continues: Some(continues),
        });
        match self.with_write_txn_grouped(|txn| self.put_gpu_job_in_txn(txn, &mut job, now_ms)) {
            Ok(true) => {}
            Ok(false) => {
                let _ = permit.settle_unsent();
                return self.load_gpu_job(&job.id);
            }
            Err(error) => {
                let _ = permit.settle_unsent();
                return Err(error.into());
            }
        }
        permits.hold(job.id, key, permit);
        self.send_gpu_renewal(job, permits, connector, now_ms)
    }

    /// Sends the session's written next chunk under its key. A refusal settles it at zero under
    /// its permit and keeps it on the job, so no other renewal follows: the run ends at the end of
    /// the chunk paid. An unanswered send is looked up by its key, and sent again at the next step
    /// when nothing answers for it.
    fn send_gpu_renewal(
        &self,
        mut job: GpuJob,
        permits: &GpuJobPermits,
        connector: &dyn GpuJobConnector,
        now_ms: u64,
    ) -> Result<GpuJob, GpuJobError> {
        let spec = job.renewal_spec()?;
        let next = job
            .renewal
            .as_mut()
            .ok_or(crate::Error::InvariantViolation(
                "a GPU session holds its next chunk",
            ))?;
        let key = next.idempotency_key.clone();
        let continues = next
            .continues
            .clone()
            .ok_or(crate::Error::InvariantViolation(
                "a GPU session's next chunk names the run it continues",
            ))?;
        let sent = match connector.renew(&key, &continues, &spec) {
            Ok(resource) => Some(resource),
            Err(GpuConnectorError::Refused { reason }) => {
                tracing::info!(job = %job.id.to_hex(), key = %key, %reason, "gpu session: the provider refused the next chunk; the session ends at the end of its chunk");
                return self.close_gpu_renewal(job, permits, now_ms);
            }
            Err(GpuConnectorError::Timeout | GpuConnectorError::Unavailable { .. }) => {
                connector.find(&key).ok().flatten()
            }
        };
        next.dispatched = true;
        if let Some(resource) = &sent {
            next.resource = Some(resource.clone());
        }
        if !self.with_write_txn_grouped(|txn| self.put_gpu_job_in_txn(txn, &mut job, now_ms))? {
            return self.stored_after_lost_write(&job.id, &key, sent, permits, connector, now_ms);
        }
        Ok(job)
    }

    /// Ends the session's open next chunk with nothing run: it bills zero, settles its permit at
    /// zero after the write, and stays on the job, so no other renewal follows it and the run
    /// ends at the end of the chunk paid.
    fn close_gpu_renewal(
        &self,
        mut job: GpuJob,
        permits: &GpuJobPermits,
        now_ms: u64,
    ) -> Result<GpuJob, GpuJobError> {
        let id = job.id;
        let next = job
            .renewal
            .as_mut()
            .ok_or(crate::Error::InvariantViolation(
                "a GPU session holds its next chunk",
            ))?;
        let key = next.idempotency_key.clone();
        let paid = permits.holds_chunk(&id, &key);
        let _ = bill_chunk(next, Some(0), paid, false);
        if !self.with_write_txn_grouped(|txn| self.put_gpu_job_in_txn(txn, &mut job, now_ms))? {
            return self.stored_after_lost_step(&id, &key, permits);
        }
        if let Some(permit) = permits.take_for_chunk(&id, &key) {
            let _ = permit.settle(CallOutcome::Used(0));
        }
        Ok(job)
    }

    /// The current chunk of a session whose run passed its paid end: settles that chunk's slice
    /// at `billed_secs`, as its provider confirmed it, and makes the session's next chunk the one
    /// running now, in one write; then that chunk's permit alone settles. Nothing is terminated:
    /// the run goes on. An ending job stays ending, so its next step ends the chunk running now.
    ///
    /// # Errors
    ///
    /// An invariant violation when the job holds no next chunk: the provider's run went on under
    /// a chunk this job never sent. Nothing is written.
    pub(super) fn pass_gpu_slice(
        &self,
        mut job: GpuJob,
        used_secs: Option<u64>,
        billed_secs: u64,
        permits: &GpuJobPermits,
        connector: &dyn GpuJobConnector,
        now_ms: u64,
    ) -> Result<(GpuJob, GpuJobStepReport), GpuJobError> {
        let id = job.id;
        let mut next = job.renewal.take().ok_or(crate::Error::InvariantViolation(
            "a GPU session's run went on under a chunk the job does not hold",
        ))?;
        // The run reached a next chunk this job had closed (a restart that could not admit it
        // again, after its send had gone out): it runs on unpaid, as any chunk whose admission
        // was lost, and its permit, if any, settled already.
        if next.billed_secs.is_some() {
            tracing::warn!(job = %id.to_hex(), key = %next.idempotency_key, "gpu session: the run passed into a next chunk the job had closed; it runs unpaid");
            next.billed_secs = None;
            next.settled_units = None;
            next.unbilled_secs = 0;
            next.admission_lost = true;
        }
        if next.resource.is_none() {
            next.resource = connector.find(&next.idempotency_key)?;
            next.dispatched = true;
        }
        if next.resource.is_none() {
            return Err(crate::Error::InvariantViolation(
                "a GPU session's next chunk names its resource",
            )
            .into());
        }
        let chunk = job.chunk_mut()?;
        let key = chunk.idempotency_key.clone();
        // The slice ran at least what it bills, also when a stop met it with no reading.
        chunk.used_secs = chunk.used_secs.max(used_secs.unwrap_or(0)).max(billed_secs);
        let paid = permits.holds_chunk(&id, &key);
        let charged_secs = bill_chunk(chunk, Some(billed_secs), paid, false);
        let settled_units = chunk.settled_units;
        let base = chunk.base_used_secs.saturating_add(chunk.used_secs);
        next.base_used_secs = base;
        let _ = job.maximum.add_session_chunk(&DeclaredMaximum {
            units: next.quote.maximum_secs,
            unit: seconds(),
        });
        job.maximum.record_session_usage(base);
        job.chunks.push(next);
        if !matches!(job.state, GpuJobState::Ending { .. }) {
            job.state = GpuJobState::Running;
        }
        if !self.with_write_txn_grouped(|txn| self.put_gpu_job_in_txn(txn, &mut job, now_ms))? {
            let stored = self.stored_after_lost_step(&id, &key, permits)?;
            let report = GpuJobStepReport::of(&stored);
            return Ok((stored, report));
        }
        if let Some(permit) = permits.take_for_chunk(&id, &key) {
            let _ = permit.settle(CallOutcome::Used(charged_secs));
        }
        let mut report = GpuJobStepReport::of(&job);
        report.settled_units = settled_units;
        Ok((job, report))
    }
}

/// Admits a session's open next chunk again when this host holds no permit for it, after a
/// restart, at its own quote's price, as [`super::step`] takes up the current chunk. Returns
/// whether the record changed. With its offer withdrawn (`None`), nothing binds a new permit:
/// the chunk's admission is lost, so it is never sent.
pub(super) fn take_up_gpu_renewal(
    job: &mut GpuJob,
    offer: Option<&GpuOffer>,
    renewal: &GpuJobRenewal<'_>,
    permits: &GpuJobPermits,
) -> bool {
    if job.claim.is_some() {
        return false;
    }
    let id = job.id;
    let admission_ref = job.admission_ref();
    let Some(next) = job
        .renewal
        .as_mut()
        .filter(|next| next.billed_secs.is_none())
    else {
        return false;
    };
    let key = next.idempotency_key.clone();
    if next.admission_lost || permits.holds_chunk(&id, &key) {
        return false;
    }
    let Some(offer) = offer else {
        next.admission_lost = true;
        return true;
    };
    let admission = (renewal.admission)(&next.quote);
    let binding = PaidConnector {
        unit_cost: next.quote.unit_cost,
        cost_unit: next.quote.unit.clone(),
        ..offer.connector.clone()
    };
    let admitted = (admission.run() == admission_ref)
        .then(|| admission.admit_paid(&binding, next.quote.quantity).ok())
        .flatten();
    let Some(permit) = admitted else {
        next.admission_lost = true;
        return true;
    };
    if admission.dispatch_paid(permit.lease(), &binding).is_err() {
        let _ = permit.settle_unsent();
        next.admission_lost = true;
        return true;
    }
    permits.hold(id, key, permit);
    false
}

/// Ends a session's open next chunk with its run (row W1): the current chunk's termination
/// confirmed a real end, so the run ended inside it and never reached the next chunk, which bills
/// nothing. Its provider is told once, so it closes the chunk; an answer that bills it is taken,
/// any other answer (none, pending, an error) bills zero, so the job's end never waits on it.
/// Answers the chunk's key and the seconds charged, or `None` when no next chunk is open.
pub(super) fn drain_gpu_renewal(
    job: &mut GpuJob,
    permits: &GpuJobPermits,
    connector: &dyn GpuJobConnector,
) -> Option<(String, u64)> {
    let id = job.id;
    let next = job
        .renewal
        .as_mut()
        .filter(|next| next.billed_secs.is_none())?;
    let resource = next
        .resource
        .clone()
        .or_else(|| connector.find(&next.idempotency_key).ok().flatten());
    let billed_secs = resource
        .as_ref()
        .and_then(|resource| match connector.terminate(resource) {
            Ok(
                GpuTermination::Confirmed { billed_secs }
                | GpuTermination::Continued { billed_secs, .. },
            ) => Some(billed_secs),
            Ok(GpuTermination::Pending) | Err(_) => None,
        })
        .unwrap_or(0);
    next.resource = resource;
    let key = next.idempotency_key.clone();
    let paid = permits.holds_chunk(&id, &key);
    let charged_secs = bill_chunk(next, Some(billed_secs), paid, false);
    Some((key, charged_secs))
}

/// Bills `chunk` its provider's `billed_secs` plus its overhead, never above its quote, and
/// records the settlement when this host holds the chunk's permit (`paid`). A session's
/// continuing chunk adds no overhead: it started nothing, and its run's first chunk carries the
/// run's startup, teardown and rounding. A key that never started (`never_ran`) bills zero,
/// overhead included (JOB-SETTLES-ON-LAUNCH-REFUSED, LE-2 = A). Answers the seconds charged.
pub(super) fn bill_chunk(
    chunk: &mut GpuChunk,
    billed_secs: Option<u64>,
    paid: bool,
    never_ran: bool,
) -> u64 {
    let overhead_secs = if chunk.continues.is_some() {
        0
    } else {
        chunk.quote.overhead_secs
    };
    let billed_with_overhead = if never_ran {
        0
    } else {
        billed_secs.map_or(0, |secs| secs.saturating_add(overhead_secs))
    };
    let charged_secs = billed_with_overhead.min(chunk.quote.quantity);
    chunk.billed_secs = billed_secs;
    chunk.unbilled_secs = billed_with_overhead - charged_secs;
    if paid {
        chunk.settled_units = Some(charged_secs.saturating_mul(chunk.quote.unit_cost));
    }
    charged_secs
}
