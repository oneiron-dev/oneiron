//! The host's step over one live job: one bounded round of provider calls,
//! then one write (CROSS-ARCH-0023 lifecycle 04-05, C2 02-04).
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::llm::run_admission::{CallOutcome, JobSignal, PaidConnector, RunAdmission, StopRefused};
use crate::{EntityId, Vault};

use super::renew::{RenewalDrain, bill_chunk, drain_gpu_renewal, take_up_gpu_renewal};
use super::{
    GPU_JOB_STOPPED_PRODUCER, GPU_JOB_WARNING_PRODUCER, GpuEndReason, GpuJob, GpuJobConnector,
    GpuJobError, GpuJobPermits, GpuJobRenewal, GpuJobSignal, GpuJobState, GpuJobStepReport,
    GpuOffer, GpuOverrun, GpuResourceStatus, GpuTermination,
};

impl Vault {
    /// Steps one job, as the host's worker does every few seconds: a reserved
    /// chunk is looked up, then created; a running chunk reports its run time,
    /// and the job is told to checkpoint at 50, 80 and 95 percent, the
    /// customer warned at 95, and the job stopped at its maximum after a
    /// checkpoint taken after that warning; an ending chunk is terminated
    /// until its provider confirms, then settled. A chunk this host holds no
    /// permit for, after a restart, is admitted again at its quote's price
    /// and pays its own end; if that no longer fits, it runs on unpaid and
    /// says so (`admission_lost`), since a running chunk is never cut for
    /// money (`#gpu-chunks`). `offer` is the offer the job was quoted on, and
    /// `admission` the job's own run. A resource a lost write left on the job
    /// is asked to terminate first, live chunk or not.
    ///
    /// # Errors
    ///
    /// [`GpuJobError::Connector`] when the provider did not answer; nothing
    /// of this step's chunk was written, and the next step asks again.
    pub fn gpu_job_step(
        &self,
        id: &EntityId,
        offer: &GpuOffer,
        admission: &RunAdmission,
        permits: &GpuJobPermits,
        connector: &dyn GpuJobConnector,
        now_ms: u64,
    ) -> Result<GpuJobStepReport, GpuJobError> {
        self.gpu_job_step_with_renewal(id, offer, admission, permits, connector, None, now_ms)
    }

    /// [`Self::gpu_job_step`], with what the host gives a session's renewal (row W1): a running
    /// session whose chunk's run time reaches its maximum less `jobs.sessions.renew_lead_secs`
    /// sends its next paid chunk, and a chunk whose slice the run passed settles alone while the
    /// next one runs. With `renewal` `None`, a session renews nothing and ends at the end of its
    /// chunk. A session never takes C2's checkpoints, warning or stop.
    ///
    /// # Errors
    ///
    /// As [`Self::gpu_job_step`].
    pub fn gpu_job_step_with_renewal(
        &self,
        id: &EntityId,
        offer: &GpuOffer,
        admission: &RunAdmission,
        permits: &GpuJobPermits,
        connector: &dyn GpuJobConnector,
        renewal: Option<&GpuJobRenewal<'_>>,
        now_ms: u64,
    ) -> Result<GpuJobStepReport, GpuJobError> {
        let mut job = self.load_gpu_job(id)?;
        if !job.orphaned_resources.is_empty() {
            job = self.terminate_orphaned_resources(job, connector, now_ms)?;
        }
        if !job.state.is_live() {
            return Ok(GpuJobStepReport::of(&job));
        }
        if admission.run() != job.admission_ref() {
            return Err(GpuJobError::AdmissionMismatch);
        }
        let mut taken_up = take_up_gpu_chunk(&mut job, offer, admission, permits)?;
        if let Some(renewal) = renewal {
            taken_up |= take_up_gpu_renewal(&mut job, offer, renewal, permits);
        }
        match job.state {
            GpuJobState::Reserved => {
                let key = job.chunk_mut()?.idempotency_key.clone();
                match connector.find(&key)? {
                    Some(resource) => {
                        job.chunk_mut()?.resource = Some(resource.clone());
                        job.state = GpuJobState::Running;
                        if !self.with_write_txn_grouped(|txn| {
                            self.put_gpu_job_in_txn(txn, &mut job, now_ms)
                        })? {
                            let stored = self.stored_after_lost_write(
                                &job.id,
                                &key,
                                Some(resource),
                                permits,
                                connector,
                                now_ms,
                            )?;
                            return Ok(GpuJobStepReport::of(&stored));
                        }
                        Ok(GpuJobStepReport::of(&job))
                    }
                    None => self
                        .create_gpu_chunk(job, permits, connector, now_ms)
                        .map(|job| GpuJobStepReport::of(&job)),
                }
            }
            GpuJobState::Running => {
                self.observe_gpu_chunk(job, offer, taken_up, permits, connector, renewal, now_ms)
            }
            _ => self
                .end_gpu_chunk(job, permits, connector, now_ms)
                .map(|(_, report)| report),
        }
    }

    /// Reads a running chunk's status and acts on what its usage crossed. A session records its
    /// usage alone, renews once its chunk nears its maximum, and moves to its next chunk once its
    /// provider proves the run passed this one's end.
    #[allow(clippy::too_many_arguments)]
    fn observe_gpu_chunk(
        &self,
        mut job: GpuJob,
        offer: &GpuOffer,
        taken_up: bool,
        permits: &GpuJobPermits,
        connector: &dyn GpuJobConnector,
        renewal: Option<&GpuJobRenewal<'_>>,
        now_ms: u64,
    ) -> Result<GpuJobStepReport, GpuJobError> {
        let resource =
            job.chunk_mut()?
                .resource
                .clone()
                .ok_or(crate::Error::InvariantViolation(
                    "a running GPU chunk names its resource",
                ))?;
        let mut signals = Vec::new();
        let mut overrun = None;
        let mut warned = false;
        match connector.status(&resource)? {
            GpuResourceStatus::Pending => {
                if !taken_up {
                    return Ok(GpuJobStepReport::of(&job));
                }
            }
            // A session's run ends at the cutoff of its last paid chunk: no checkpoint, warning
            // or stop of C2 applies (pass 34, 9.3).
            GpuResourceStatus::Running { used_secs, .. } if job.renews() => {
                let chunk = job.chunk_mut()?;
                chunk.used_secs = chunk.used_secs.max(used_secs);
                let total = chunk.base_used_secs.saturating_add(chunk.used_secs);
                job.maximum.record_session_usage(total);
            }
            GpuResourceStatus::Continued {
                used_secs,
                billed_secs,
            } => {
                return self
                    .pass_gpu_slice(
                        job,
                        Some(used_secs),
                        billed_secs,
                        permits,
                        connector,
                        now_ms,
                    )
                    .map(|(_, report)| report);
            }
            GpuResourceStatus::Running {
                used_secs,
                checkpoint,
            } => {
                let chunk = job.chunk_mut()?;
                chunk.used_secs = chunk.used_secs.max(used_secs);
                let total = chunk.base_used_secs.saturating_add(chunk.used_secs);
                // The provider reports the newest checkpoint at every status:
                // only one not seen before is new.
                let fresh =
                    checkpoint.filter(|seen| chunk.newest_checkpoint.as_ref() != Some(seen));
                if let Some(seen) = &fresh {
                    chunk.newest_checkpoint = Some(seen.clone());
                }
                signals = job.maximum.record_usage(total);
                // Counted before this step confirms the warning: a checkpoint
                // first seen with the warning was taken before it reached the
                // customer, and never counts for the stop (C2 03).
                if let Some(seen) = fresh {
                    job.maximum.checkpoint(seen);
                }
                for signal in &signals {
                    match signal {
                        JobSignal::CheckpointDue { percent } => {
                            connector.signal(
                                &resource,
                                GpuJobSignal::CheckpointDue { percent: *percent },
                            )?;
                            job.chunk_mut()?.signalled_percents.push(*percent);
                        }
                        JobSignal::Warning95 { .. } => warned = true,
                        JobSignal::AtMaximum => {}
                    }
                }
                // The warning has reached the customer when its notice
                // commits in their inbox, in this step's own write (RULING
                // L10-31-WARNING-DELIVERED = A).
                if warned {
                    let _ = job.maximum.confirm_warning();
                }
                if signals.contains(&JobSignal::AtMaximum) {
                    match job.maximum.stop_at_maximum() {
                        Ok(stop) => {
                            job.stop = Some(stop);
                            // The notice's one tap (C2 05): one more chunk of
                            // the job's first maximum, priced now.
                            let resume_quote = job.chunks.first().and_then(|first| {
                                offer
                                    .quote_for(
                                        job.id,
                                        &first.quote.request(),
                                        first.quote.maximum_secs,
                                        now_ms,
                                    )
                                    .ok()
                            });
                            job.resume_quote = resume_quote;
                            job.state = GpuJobState::Ending {
                                reason: GpuEndReason::AtMaximum,
                            };
                        }
                        // No stop without a checkpoint: the job runs on and
                        // is asked again each step (RULING
                        // L10-31-NO-CHECKPOINT = A).
                        Err(StopRefused::NoCheckpoint) => {
                            connector.signal(&resource, GpuJobSignal::CheckpointBeforeStop)?;
                        }
                        Err(_) => {}
                    }
                }
                overrun = report_overrun(&mut job, total);
            }
            GpuResourceStatus::Exited { used_secs } => {
                let chunk = job.chunk_mut()?;
                chunk.used_secs = chunk.used_secs.max(used_secs);
                let total = chunk.base_used_secs.saturating_add(chunk.used_secs);
                if job.renews() {
                    job.maximum.record_session_usage(total);
                } else {
                    let _ = job.maximum.record_usage(total);
                }
                job.state = GpuJobState::Ending {
                    reason: GpuEndReason::Exited,
                };
            }
            GpuResourceStatus::Gone => {
                job.state = GpuJobState::Ending {
                    reason: GpuEndReason::Gone,
                };
            }
        }
        let notices = self.with_write_txn_grouped(|txn| {
            if !self.put_gpu_job_in_txn(txn, &mut job, now_ms)? {
                return Ok(None);
            }
            if !warned {
                return Ok(Some(Vec::new()));
            }
            let maximum = job.maximum.maximum().units;
            let detail = format!(
                "used {} of its maximum {maximum} seconds",
                job.maximum.used_units()
            );
            self.notify_gpu_job_in_txn(
                txn,
                &job,
                NotificationKind::GpuJobWarning,
                GPU_JOB_WARNING_PRODUCER,
                detail,
            )
            .map(Some)
        })?;
        let Some(notices) = notices else {
            // Another write came first: this step's view is stale.
            let key = job.chunk_mut()?.idempotency_key.clone();
            let stored = self.stored_after_lost_step(&job.id, &key, permits)?;
            return Ok(GpuJobStepReport::of(&stored));
        };
        let mut report = if matches!(job.state, GpuJobState::Ending { .. }) {
            self.end_gpu_chunk(job, permits, connector, now_ms)?.1
        } else if let Some(renewal) = renewal.filter(|_| job.renews()) {
            let job = self.renew_gpu_session(job, offer, renewal, permits, connector, now_ms)?;
            GpuJobStepReport::of(&job)
        } else {
            GpuJobStepReport::of(&job)
        };
        report.signals = signals;
        report.notices = notices.into_iter().chain(report.notices).collect();
        report.overrun = overrun;
        Ok(report)
    }

    /// Terminates an ending chunk until its provider confirms, then settles
    /// its billed time plus overhead, never above its quote; the rest of the
    /// reservation goes back (lifecycle 05-06). A stop at the maximum then
    /// writes the add-funds notice, whose resume is the next chunk (C2 04,
    /// 05).
    pub(super) fn end_gpu_chunk(
        &self,
        mut job: GpuJob,
        permits: &GpuJobPermits,
        connector: &dyn GpuJobConnector,
        now_ms: u64,
    ) -> Result<(GpuJob, GpuJobStepReport), GpuJobError> {
        let GpuJobState::Ending { reason } = job.state else {
            let report = GpuJobStepReport::of(&job);
            return Ok((job, report));
        };
        let chunk = job.chunk_mut()?;
        let key = chunk.idempotency_key.clone();
        let resource = match chunk.resource.clone() {
            Some(resource) => Some(resource),
            None => connector.find(&key)?,
        };
        let billed_secs = match &resource {
            // No resource was ever made: nothing ran and nothing is billed.
            None => None,
            Some(resource) => match connector.terminate(resource)? {
                GpuTermination::Pending => {
                    let report = GpuJobStepReport::of(&job);
                    return Ok((job, report));
                }
                GpuTermination::Confirmed { billed_secs } => Some(billed_secs),
                // A session's run passed this chunk's end before the stop reached it: the slice
                // settles, the next chunk runs, and the job's next step ends that one.
                GpuTermination::Continued { billed_secs } => {
                    return self.pass_gpu_slice(job, None, billed_secs, permits, connector, now_ms);
                }
            },
        };
        // The run ended in this chunk: a session's next chunk ends with it, before the job does.
        let drained = match drain_gpu_renewal(&mut job, permits, connector)? {
            RenewalDrain::Pending => {
                let report = GpuJobStepReport::of(&job);
                return Ok((job, report));
            }
            RenewalDrain::Nothing => None,
            RenewalDrain::Ended { key, charged_secs } => Some((key, charged_secs)),
        };
        let paid = permits.holds_chunk(&job.id, &key);
        let chunk = job.chunk_mut()?;
        chunk.resource = resource;
        let charged_secs = bill_chunk(chunk, billed_secs, paid);
        let settled_units = chunk.settled_units;
        job.state = if reason == GpuEndReason::AtMaximum {
            GpuJobState::Stopped
        } else {
            GpuJobState::Ended { reason }
        };
        let notices = self.with_write_txn_grouped(|txn| {
            if !self.put_gpu_job_in_txn(txn, &mut job, now_ms)? {
                return Ok(None);
            }
            let Some(stop) = job
                .stop
                .as_ref()
                .filter(|_| reason == GpuEndReason::AtMaximum)
            else {
                return Ok(Some(Vec::new()));
            };
            let detail = format!(
                "stopped at its maximum after {} of {} seconds; add funds and resume from \
                 checkpoint {}",
                stop.notice.used_units, stop.notice.maximum.units, stop.notice.checkpoint.0
            );
            self.notify_gpu_job_in_txn(
                txn,
                &job,
                NotificationKind::Ask,
                GPU_JOB_STOPPED_PRODUCER,
                detail,
            )
            .map(Some)
        })?;
        let Some(notices) = notices else {
            if let Some((renewal_key, _)) = &drained {
                self.stored_after_lost_step(&job.id, renewal_key, permits)?;
            }
            let current = self.stored_after_lost_step(&job.id, &key, permits)?;
            let report = GpuJobStepReport::of(&current);
            return Ok((current, report));
        };
        #[cfg(oneiron_test_support)]
        crate::test_doors::gpu_job::pass_end_commit_gate(permits, &job.id);
        // Settled after the write, so a settled chunk is never admitted again;
        // only this chunk's permit: a resume may already hold the next one's.
        if let Some(permit) = permits.take_for_chunk(&job.id, &key) {
            let _ = permit.settle(CallOutcome::Used(charged_secs));
        }
        if let Some((renewal_key, renewal_secs)) = drained
            && let Some(permit) = permits.take_for_chunk(&job.id, &renewal_key)
        {
            let _ = permit.settle(CallOutcome::Used(renewal_secs));
        }
        let mut report = GpuJobStepReport::of(&job);
        report.notices = notices;
        report.settled_units = settled_units;
        Ok((job, report))
    }

    /// Writes one notice about `job` to each of the vault's Owners, the
    /// customer (or, in a vault with none, to the job's starter).
    fn notify_gpu_job_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        job: &GpuJob,
        kind: NotificationKind,
        producer: &str,
        detail: String,
    ) -> crate::Result<Vec<EntityId>> {
        let owners = crate::policy_model::owners_in_txn(self, txn)?;
        let recipients: Vec<Option<EntityId>> = if owners.is_empty() {
            vec![job.started_by]
        } else {
            owners.into_iter().map(Some).collect()
        };
        let created_at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
        let event_prefix = super::notice_event_prefix(&job.id, job.chunks.len().saturating_sub(1));
        let mut ids = Vec::with_capacity(recipients.len());
        for recipient in recipients {
            let to = recipient.map_or_else(|| "all".to_owned(), |id| id.to_hex());
            ids.push(self.record_notification_in_txn(
                txn,
                &NotificationEvent {
                    kind,
                    source: NotificationSource {
                        producer: producer.to_owned(),
                        event: format!("{event_prefix}{to}"),
                        result: Some(job.id.to_hex()),
                        detail: Some(detail.clone()),
                        ..NotificationSource::default()
                    },
                    subject_refs: Vec::new(),
                    recipient,
                    created_at,
                    origin_conversation: None,
                },
            )?);
        }
        Ok(ids)
    }
}

/// Admits a live chunk again when this host holds no permit for it, after a
/// restart: at its quote's price and unit, which froze at the quote, for its
/// whole quote, as the kept permit before it held. Returns whether the record
/// changed.
fn take_up_gpu_chunk(
    job: &mut GpuJob,
    offer: &GpuOffer,
    admission: &RunAdmission,
    permits: &GpuJobPermits,
) -> crate::Result<bool> {
    let id = job.id;
    let chunk = job.chunk_mut()?;
    let key = chunk.idempotency_key.clone();
    if chunk.admission_lost || permits.holds_chunk(&id, &key) {
        return Ok(false);
    }
    let binding = PaidConnector {
        unit_cost: chunk.quote.unit_cost,
        cost_unit: chunk.quote.unit.clone(),
        ..offer.connector.clone()
    };
    let Ok(permit) = admission.admit_paid(&binding, chunk.quote.quantity) else {
        chunk.admission_lost = true;
        return Ok(true);
    };
    if admission.dispatch_paid(permit.lease(), &binding).is_err() {
        let _ = permit.settle_unsent();
        chunk.admission_lost = true;
        return Ok(true);
    }
    permits.hold(id, key, permit);
    Ok(false)
}

/// The run time past the maximum, once it passes 10 percent with no stop:
/// our cost, for operations (NOTE on L10-31-NO-CHECKPOINT: the notice carries
/// the money).
fn report_overrun(job: &mut GpuJob, total_secs: u64) -> Option<GpuOverrun> {
    if job.overrun_reported || job.maximum.is_stopped() {
        return None;
    }
    let maximum = job.maximum.maximum().units;
    let secs = total_secs.checked_sub(maximum)?;
    if u128::from(secs) * 10 <= u128::from(maximum) {
        return None;
    }
    job.overrun_reported = true;
    let chunk = job.chunk()?;
    Some(GpuOverrun {
        secs,
        units: secs.saturating_mul(chunk.quote.unit_cost),
        unit: chunk.quote.unit.clone(),
    })
}
