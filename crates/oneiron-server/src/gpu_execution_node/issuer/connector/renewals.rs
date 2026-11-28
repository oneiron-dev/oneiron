//! A session's renewal on the issuer (pass 34, 9.3; row W1): the continuing submit of a
//! session's next paid chunk, bound to the run's first key, and the session's write-off bound.
use oneiron::EntityId;
use oneiron::gpu_job::{
    GpuConnectorError, GpuJob, GpuJobEnd, GpuJobSpec, GpuJobTerminal, GpuResourceRef,
};
use oneiron::job_dispatch::{
    DispatchAsk, DispatchClose, DispatchPhase, DispatchRefusal, JobDispatch,
};

use super::{
    Sent, VaultMachineConnector, call_error, decode, encode, hold_of, job_answer_label, refused,
    store, unavailable,
};
use crate::gpu_execution_node::issuer::NOT_AVAILABLE_TO_THIS_CALLER;
use crate::gpu_execution_node::wire::{
    JobAnswer, JobEnd, JobRequest, JobState, JobSubmit, SignedJobReceipt, SignedJobSubmit, Starter,
    TemplateKind,
};

impl VaultMachineConnector {
    /// `renew` under the key's lock (row W1): the session's next paid chunk under `key`, a
    /// submit that continues the run the job's first key `continues` started. It binds to that
    /// key's dispatch: its machine, pin, slot and signed starter; no Grant is chosen anew. Before
    /// the row is written it checks the pause, the machine's guard, the live recheck of that
    /// starter, the Grant's per-job maximum over every chunk of the run, and the node's offer of
    /// the pin's template as a session's. The row holds the signed submit before any network
    /// call, and the submit goes out with no reserve.
    pub(super) fn renew_key(
        &self,
        key: &str,
        continues: &str,
        spec: &GpuJobSpec,
    ) -> Result<GpuResourceRef, GpuConnectorError> {
        if let Some(row) = self.vault().job_dispatch(key).map_err(store)? {
            return Ok(GpuResourceRef(row.resource()));
        }
        let job = EntityId::from_hex(&spec.job).map_err(|_| refused("job_id_invalid"))?;
        let first = self
            .vault()
            .job_dispatch(continues)
            .map_err(store)?
            .filter(|first| first.job == job)
            .ok_or_else(|| refused("continues_unknown"))?;
        let first_submit = decode::<SignedJobSubmit>(&first.submit)?.submit;
        if first_submit.continues.is_some() {
            return Err(refused("continues_not_a_first_key"));
        }
        if let Some(refusal) =
            self.renewal_refusal(&job, first.machine, &first_submit, spec.maximum_secs)?
        {
            return Err(refused(refusal));
        }
        let Some(starter) = self.starter_of(&first, &first_submit)? else {
            return Err(refused(DispatchRefusal::StarterLapsed.code()));
        };
        let now = self.now_ms();
        let ask = DispatchAsk {
            starter,
            workload: &first.workload,
            node: first.machine,
            maximum_secs: spec.maximum_secs,
        };
        let pin = self
            .vault()
            .dispatch_recheck(&ask, now, self.horizon_ms())
            .map_err(store)?
            .map_err(|refusal| refused(refusal.code()))?;
        if pin != first_submit.pin {
            return Err(refused("pin_changed"));
        }
        self.session_template_offered(first.machine, &first_submit)?;
        let not_after_ms =
            now.saturating_add(self.parts.settings.submit_window_secs.saturating_mul(1000));
        let submit = JobSubmit {
            key: key.to_owned(),
            job,
            chunk: spec.chunk,
            pin,
            slot: first_submit.slot.clone(),
            maximum_secs: spec.maximum_secs,
            issued_at_ms: now,
            not_after_ms,
            issuer: self.parts.issuer,
            starter: first_submit.starter,
            hold: hold_of(key),
            authority_heads: self.vault().authority_main_log_heads().map_err(store)?,
            continues: Some(continues.to_owned()),
        };
        let signed = SignedJobSubmit::sign(submit, self.parts.signer.as_ref())
            .map_err(|error| refused(format!("issuer_cannot_sign: {error}")))?;
        // A continuing key stays `Reserving` until the node's receipt proves it: no reserve is
        // ever sent for it, so the phase alone never claims the node journaled it.
        let row = self
            .vault()
            .insert_job_dispatch(JobDispatch {
                key: key.to_owned(),
                job,
                chunk: spec.chunk,
                workload: first.workload.clone(),
                machine: first.machine,
                submit: encode(&signed)?,
                issued_at_ms: now,
                not_after_ms,
                phase: DispatchPhase::Reserving,
                held: None,
                sent_boot: None,
                closed: None,
                history_lost_at_ms: None,
            })
            .map_err(store)?;
        let resource = GpuResourceRef(row.resource());
        self.reconciled
            .ensure(
                row.machine,
                self.vault(),
                self.parts.client.as_ref(),
                self.parts.orphans.as_ref(),
            )
            .map_err(|error| unavailable(format!("reconcile: {error}")))?;
        let receipt = match self.send_submit(&row, &signed)? {
            Sent::Receipt(receipt) => receipt,
            // A terminate closed the key before the submit: its status reads the key.
            Sent::Withheld => return Ok(resource),
            // Busy, or no answer: the step's read of this key sends the same bytes again inside
            // its window.
            Sent::NoReceipt(why) => {
                tracing::info!(node = %row.machine.to_hex(), key, why = %why, "vault_machine: a session's next chunk got no receipt yet");
                return Ok(resource);
            }
            Sent::NoAnswer(_) => return Ok(resource),
        };
        if let (JobState::Ended, Some(JobEnd::Refused { reason })) = (receipt.state, &receipt.end) {
            tracing::info!(
                node = %row.machine.to_hex(),
                key,
                reason = %reason,
                "vault_machine: the node refused a session's next chunk"
            );
            let reason = reason.clone();
            self.update(key, |row| {
                row.phase = DispatchPhase::Closed;
                row.closed
                    .get_or_insert(DispatchClose::NodeRefused { reason });
            })?;
            return Err(refused(NOT_AVAILABLE_TO_THIS_CALLER));
        }
        Ok(resource)
    }

    /// The issuer's own controls on a session's next chunk (row W1), before its first send and
    /// before every send again: the pause, the machine's guard, the job still live with its
    /// current chunk not written off (door 10 closes that chunk's dispatch before it reads the
    /// next key as never dispatched, so the run ends at its paid cutoff), and a Grant's per-job
    /// maximum, which holds over every chunk of the run as it holds over a resume (the paid
    /// maximum so far plus `maximum_secs` must fit it). Answers the refusal's code, or `None` to
    /// go on.
    pub(super) fn renewal_refusal(
        &self,
        job: &EntityId,
        machine: EntityId,
        submit: &JobSubmit,
        maximum_secs: u64,
    ) -> Result<Option<String>, GpuConnectorError> {
        if self.parts.settings.paused {
            return Ok(Some("dispatch_paused".to_owned()));
        }
        if let Some(refusal) = super::super::guard::machine_job_guard_refusal(self.vault(), machine)
        {
            return Ok(Some(refusal.into()));
        }
        let Some(stored) = self.vault().gpu_job(job).map_err(store)? else {
            return Ok(Some("job_missing".to_owned()));
        };
        if !stored.state.is_live() {
            return Ok(Some("job_ended".to_owned()));
        }
        if let Some(current) = stored.chunk()
            && self
                .vault()
                .job_dispatch(&current.idempotency_key)
                .map_err(store)?
                .is_some_and(|row| matches!(row.closed, Some(DispatchClose::WrittenOff { .. })))
        {
            return Ok(Some("written_off".to_owned()));
        }
        let Starter::Grant { grant } = submit.starter else {
            return Ok(None);
        };
        let Some(allowance) = self.vault().gpu_job_allowance(&grant).map_err(store)? else {
            return Ok(Some("allowance_missing".to_owned()));
        };
        let paid_secs = stored.maximum.maximum().units;
        if paid_secs.saturating_add(maximum_secs) > allowance.maximum_secs {
            return Ok(Some("allowance_exceeded".to_owned()));
        }
        Ok(None)
    }

    /// The node must offer the first key's template, by name and digest, as a session's
    /// template, and take work now: a node that predates sessions, a job's template, a pause or
    /// a drain renews nothing. The node checks all of it again itself.
    fn session_template_offered(
        &self,
        machine: EntityId,
        first: &JobSubmit,
    ) -> Result<(), GpuConnectorError> {
        let answer = self
            .parts
            .client
            .job(machine, &JobRequest::Node)
            .map_err(call_error)?;
        let JobAnswer::Node(node) = answer else {
            return Err(unavailable(job_answer_label(&answer)));
        };
        if !node.enabled || node.paused.is_some() || node.drained.is_some() {
            return Err(refused("node_takes_no_work"));
        }
        let offered = node.templates.iter().any(|template| {
            template.name == first.pin.template
                && template.digest == first.pin.template_digest
                && template.kind == TemplateKind::Session
        });
        if !offered {
            return Err(refused("template_not_a_session"));
        }
        Ok(())
    }

    /// The typed terminal of a session's slice that the run passed (row W1), if the key holds
    /// one.
    pub(super) fn continued_terminal(
        &self,
        key: &str,
    ) -> Result<Option<GpuJobTerminal>, GpuConnectorError> {
        Ok(self
            .vault()
            .job_observation(key)
            .map_err(store)?
            .and_then(|observation| observation.terminal)
            .filter(|terminal| terminal.end == GpuJobEnd::Continued))
    }

    /// The latest cutoff a session's run can reach (row W1); `None` for a job that does not
    /// renew, whose chunk's own submit bounds it. The run launched by its latest launch time,
    /// and ends by then plus the maximum of every chunk of the run, the open next one included.
    /// Its latest launch is the later of two bounds. The first key's `not_after`: the node
    /// accepts the submit by then, and the write-off wait covers its staging, as for a job. And
    /// the first renewal's `not_after`, which the node enforces on its own: it takes a renewal
    /// only for a run it launched, and only by the renewal's `not_after`, so a run that staged
    /// past its first key's window and renewed is still bounded. The cutoff is never before any
    /// key's own `not_after` plus its maximum, a job's bound for that key.
    pub(super) fn session_run_cutoff_ms(
        &self,
        job: &GpuJob,
    ) -> Result<Option<u64>, GpuConnectorError> {
        if !job.renews() {
            return Ok(None);
        }
        let mut launch_by_ms = None::<u64>;
        let mut key_cutoff_ms = 0_u64;
        for (index, chunk) in job.chunks.iter().chain(job.renewal.as_ref()).enumerate() {
            let Some(row) = self
                .vault()
                .job_dispatch(&chunk.idempotency_key)
                .map_err(store)?
            else {
                // The run's first key unknown: no bound of the run (FIX W1-WRITE-OFF-RUN-UNKNOWN).
                // A next chunk with no row was never sent, so no node took it; its maximum still
                // counts below.
                if index == 0 {
                    return Ok(None);
                }
                continue;
            };
            let submit = decode::<SignedJobSubmit>(&row.submit)?.submit;
            // Index 0 is the first key, index 1 the run's first renewal.
            if index <= 1 {
                launch_by_ms = Some(launch_by_ms.map_or(submit.not_after_ms, |launch_by_ms| {
                    launch_by_ms.max(submit.not_after_ms)
                }));
            }
            key_cutoff_ms = key_cutoff_ms.max(
                submit
                    .not_after_ms
                    .saturating_add(submit.maximum_secs.saturating_mul(1_000)),
            );
        }
        let Some(launch_by_ms) = launch_by_ms else {
            return Ok(None);
        };
        let maximum_secs = job
            .chunks
            .iter()
            .chain(job.renewal.as_ref())
            .fold(0_u64, |total, chunk| {
                total.saturating_add(chunk.quote.maximum_secs)
            });
        Ok(Some(
            launch_by_ms
                .saturating_add(maximum_secs.saturating_mul(1_000))
                .max(key_cutoff_ms),
        ))
    }

    /// Door 10 for `job` (pass 33, 8.5; row W1): its current chunk's dispatch closes as written
    /// off, with a session's open next chunk's, as `GpuJobConnector::write_off` on the
    /// connector says. A next chunk whose end the node signed as never started (it refused the
    /// renewal, or the run ended before it) has nothing to wait for: it closes for good, and the
    /// door's own write settles it at zero, the value a key that never started bills (LE-2 = A;
    /// ANSWER W1-DOOR10-NEVER-STARTED-RENEWAL = A). The current chunk still waits for the run's
    /// bound. Every refusal comes before anything closes.
    pub(super) fn write_off_job(&self, job: &GpuJob, now_ms: u64) -> Result<(), GpuConnectorError> {
        let chunk = job.chunk().ok_or_else(|| refused("write_off_no_chunk"))?;
        let key = chunk.idempotency_key.as_str();
        let next_key = job
            .renewal
            .as_ref()
            .filter(|next| next.billed_secs.is_none())
            .map(|next| next.idempotency_key.as_str());
        if let Some(next_key) = next_key {
            self.keys
                .with(next_key, || self.renewal_end(job, next_key))?;
        }
        let run_cutoff_ms = self.session_run_cutoff_ms(job)?;
        self.keys
            .with(key, || self.write_off_key(key, run_cutoff_ms, now_ms))?;
        let Some(next_key) = next_key else {
            return Ok(());
        };
        // Read again under the next chunk's lock: a send of it that came after the first read
        // is bounded by its own window too.
        match self.keys.with(next_key, || {
            if self.renewal_end(job, next_key)? == RenewalEnd::NeverStarted {
                return self.close_never_started(next_key, now_ms);
            }
            let run_cutoff_ms = self.session_run_cutoff_ms(job)?;
            self.write_off_key(next_key, run_cutoff_ms, now_ms)
        }) {
            // Never sent: with the current chunk written off, its send refuses, so it never is.
            Err(GpuConnectorError::Refused { reason })
                if reason == "write_off_never_dispatched" =>
            {
                Ok(())
            }
            other => other,
        }
    }

    /// What door 10 may do with a session's open next chunk `key` (row W1), under its lock.
    /// `Open` when the issuer holds no terminal receipt of it: it is written off under the run's
    /// bound, or was never sent. `NeverStarted` when the issuer holds the node's signed end
    /// saying the chunk never started, checked again before door 10 trusts it (ANSWER
    /// W1-DOOR10-NEVER-STARTED-RENEWAL = A, 1): its signature, that it names this key, the
    /// dispatch row's node and this issuer, and that the row is this job's and continues this
    /// session. An end saying the chunk ran refuses `end_confirmed`, so the step bills it; a
    /// check that fails refuses with its name.
    fn renewal_end(&self, job: &GpuJob, key: &str) -> Result<RenewalEnd, GpuConnectorError> {
        let Some(row) = self.vault().job_dispatch(key).map_err(store)? else {
            return Ok(RenewalEnd::Open);
        };
        let Some(observation) = self.vault().job_observation(key).map_err(store)? else {
            return Ok(RenewalEnd::Open);
        };
        let signed = decode::<SignedJobReceipt>(&observation.receipt)?;
        if signed.receipt.state != JobState::Ended {
            return Ok(RenewalEnd::Open);
        }
        if signed.receipt.started || signed.receipt.end == Some(JobEnd::Continued) {
            return Err(refused("end_confirmed"));
        }
        if signed.verify(self.parts.signer.as_ref()).is_err() {
            return Err(refused("end_unverified: receipt_signature_invalid"));
        }
        let receipt = &signed.receipt;
        if receipt.key != key
            || receipt.machine != row.machine
            || receipt.issuer != self.parts.issuer
        {
            return Err(refused("end_unverified: receipt_names_another_chunk"));
        }
        let submit = decode::<SignedJobSubmit>(&row.submit)?.submit;
        if row.job != job.id || submit.job != job.id || submit.continues.as_deref() != job.run_key()
        {
            return Err(refused("end_unverified: chunk_of_another_session"));
        }
        Ok(RenewalEnd::NeverStarted)
    }

    /// Closes a session's next chunk whose signed end says it never started, for good, so
    /// nothing is sent for its key again. A row its node's refusal closed already is left as it
    /// is, so a repeat writes nothing.
    fn close_never_started(&self, key: &str, now_ms: u64) -> Result<(), GpuConnectorError> {
        let Some(row) = self.vault().job_dispatch(key).map_err(store)? else {
            return Ok(());
        };
        if row.phase == DispatchPhase::Closed && row.closed.is_some() {
            return Ok(());
        }
        self.update(key, |row| {
            row.phase = DispatchPhase::Closed;
            row.closed.get_or_insert(DispatchClose::WrittenOff {
                at_ms: now_ms,
                late_receipt: None,
            });
        })?;
        Ok(())
    }
}

/// Door 10's reading of a session's open next chunk (row W1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RenewalEnd {
    /// The issuer holds no terminal receipt of it.
    Open,
    /// The node's checked, signed end says it never started.
    NeverStarted,
}
