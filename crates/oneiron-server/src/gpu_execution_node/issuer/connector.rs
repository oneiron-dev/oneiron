//! [`VaultMachineConnector`]: the GPU job backend `vault_machine`, which runs a chunk of a job
//! on one of the vault's own machines (pass 33 section 8.2).
//!
//! - `create` writes the dispatch row with the signed submit before any network call, checks
//!   again live, reconciles the node if it has not since this issuer started, reserves (the
//!   node's `Held` receipt is stored) and submits.
//! - `find` answers from the dispatch row alone: a key with no row was never sent anywhere.
//! - `status` asks the node for the key's receipt and follows the table of 8.2. Every reserve
//!   or submit it sends again repeats the live recheck first, goes only to a reconciled node,
//!   and repeats the bytes first signed. At every step it also checks for a revoke (section 9):
//!   a revoke closes the key with a stop; an expiry does not.
//! - `terminate` marks the key closing, sends a stop, and confirms once the node's terminal
//!   receipt shows the unit empty, billed by [`super::billing`].
use std::sync::Arc;

use oneiron::gpu_job::{
    GpuConnectorError, GpuJob, GpuJobConnector, GpuJobNodeView, GpuJobSignal, GpuJobSpec,
    GpuResourceRef, GpuResourceStatus, GpuTermination,
};
use oneiron::job_dispatch::{
    DispatchAsk, DispatchClose, DispatchPhase, DispatchRefusal, JobDispatch, JobObservation,
};
use oneiron::job_workload::WorkloadStarter;
use oneiron::machine_signature::MachineSignatures;
use oneiron::{EntityId, Vault};
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::billing::{billing, bracket, terminal};
use super::clock::IssuerClock;
use super::node_client::{JobNodeClient, NodeCallError};
use super::reconcile::{OrphanKeys, Reconciled};
use super::{job_answer_kind, job_refusal_code, status_answer_kind, vault_machine_inputs};
use crate::config::gpu_jobs::VaultMachineSettings;
use crate::gpu_execution_node::wire::{
    HoldRef, JobAnswer, JobEnd, JobReceipt, JobRequest, JobReserve, JobState, JobStatusAnswer,
    JobStatusRequest, JobSubmit, SignedJobReceipt, SignedJobSubmit, Starter,
};

/// What a [`VaultMachineConnector`] is built from.
pub struct VaultMachineParts {
    pub vault: Arc<Vault>,
    /// This install's MACHINE: the issuer the submits name.
    pub issuer: EntityId,
    pub client: Arc<dyn JobNodeClient>,
    pub signer: Arc<dyn MachineSignatures>,
    pub clock: Arc<dyn IssuerClock>,
    pub orphans: Arc<dyn OrphanKeys>,
    pub settings: VaultMachineSettings,
}

/// The `vault_machine` GPU job backend on the issuer.
pub struct VaultMachineConnector {
    parts: VaultMachineParts,
    reconciled: Reconciled,
}

/// What a reserve or a submit brought back.
enum Sent {
    /// The node's receipt of the key, verified and stored.
    Receipt(JobReceipt),
    /// An answer with no receipt: busy, a refusal before any journal, or another answer.
    NoReceipt(String),
    /// No answer arrived: the request may have reached the node.
    NoAnswer(GpuConnectorError),
}

/// Whether a reserve or a submit may go out now.
enum Gate {
    Go,
    /// It may not: what `status` answers instead.
    Answer(GpuResourceStatus),
}

/// A receipt that passed its checks, with the bytes it arrived as.
struct Admitted {
    receipt: JobReceipt,
    bytes: Vec<u8>,
}

impl VaultMachineConnector {
    #[must_use]
    pub fn new(parts: VaultMachineParts) -> Self {
        Self {
            parts,
            reconciled: Reconciled::default(),
        }
    }

    /// The quote check of door 6: a `vault_machine` quote names its machine in
    /// `inputs.machine`. The same signature as the connector trait's quote check, which
    /// OPUS-LE-FLEET's M2-C adds; the trait method answers with this.
    ///
    /// # Errors
    ///
    /// `machine_missing`, `device_id_invalid` or `model_invalid`.
    pub fn check_inputs(&self, _job_type: &str, inputs: &serde_json::Value) -> Result<(), String> {
        vault_machine_inputs(inputs)
            .map(|_| ())
            .map_err(str::to_owned)
    }

    fn vault(&self) -> &Vault {
        &self.parts.vault
    }

    fn now_ms(&self) -> u64 {
        self.parts.clock.now_ms()
    }

    fn horizon_ms(&self) -> u64 {
        self.parts
            .settings
            .recheck_horizon_secs
            .saturating_mul(1000)
    }

    /// The dispatch row a resource names.
    fn dispatch_of(&self, resource: &GpuResourceRef) -> Result<JobDispatch, GpuConnectorError> {
        let (machine, key) = resource
            .0
            .split_once('#')
            .and_then(|(machine, key)| Some((EntityId::from_hex(machine).ok()?, key)))
            .ok_or_else(|| unavailable("resource_invalid"))?;
        let row = self
            .vault()
            .job_dispatch(key)
            .map_err(store)?
            .ok_or_else(|| unavailable("no_dispatch_row"))?;
        if row.machine != machine {
            return Err(unavailable("resource_names_another_machine"));
        }
        Ok(row)
    }

    /// The starter a submit names: its Grant, or the owner who started the job.
    fn starter_of(
        &self,
        row: &JobDispatch,
        submit: &JobSubmit,
    ) -> Result<Option<WorkloadStarter>, GpuConnectorError> {
        Ok(match submit.starter {
            Starter::Grant { grant } => Some(WorkloadStarter::Grant(grant)),
            Starter::Owner => self
                .vault()
                .gpu_job(&row.job)
                .map_err(store)?
                .and_then(|job| job.started_by)
                .map(WorkloadStarter::Owner),
        })
    }

    /// The live recheck before a reserve or submit goes out again (8.2, step 2).
    fn recheck(
        &self,
        row: &JobDispatch,
        submit: &JobSubmit,
    ) -> Result<Result<(), DispatchRefusal>, GpuConnectorError> {
        let Some(starter) = self.starter_of(row, submit)? else {
            return Ok(Err(DispatchRefusal::StarterLapsed));
        };
        let ask = dispatch_ask(row, submit, starter);
        Ok(self
            .vault()
            .dispatch_recheck(&ask, self.now_ms(), self.horizon_ms())
            .map_err(store)?
            .map(|_| ()))
    }

    /// The revoke check at a step (section 9): `Some` only for a revoke.
    fn revoked(
        &self,
        row: &JobDispatch,
        submit: &JobSubmit,
    ) -> Result<Option<DispatchRefusal>, GpuConnectorError> {
        let Some(starter) = self.starter_of(row, submit)? else {
            return Ok(Some(DispatchRefusal::StarterLapsed));
        };
        let ask = dispatch_ask(row, submit, starter);
        self.vault()
            .dispatch_revoked(&ask, self.now_ms())
            .map_err(store)
    }

    /// Changes the dispatch row in one durable write and answers it as written.
    fn update(
        &self,
        key: &str,
        change: impl FnOnce(&mut JobDispatch),
    ) -> Result<JobDispatch, GpuConnectorError> {
        self.vault()
            .update_job_dispatch(key, change)
            .map_err(store)?
            .ok_or_else(|| unavailable("no_dispatch_row"))
    }

    /// Marks the key closing for `why`, unless an earlier reason closed it.
    fn close(&self, key: &str, why: DispatchClose) -> Result<JobDispatch, GpuConnectorError> {
        self.update(key, |row| {
            if row.phase < DispatchPhase::Closing {
                row.phase = DispatchPhase::Closing;
            }
            row.closed.get_or_insert(why);
        })
    }

    fn mark_history_lost(&self, key: &str) -> Result<(), GpuConnectorError> {
        let now = self.now_ms();
        self.update(key, |row| {
            row.history_lost_at_ms.get_or_insert(now);
        })
        .map(|_| ())
    }

    /// Checks a receipt of `row`'s key and stores it when it is the newest: it must carry the
    /// node's signature, name this key, this node and this issuer, and never go back in the
    /// journal it came from. A receipt older than one the issuer holds, or from another journal
    /// than the one that held the reserve, means the node's history is lost: nothing is sent
    /// again.
    fn admit(
        &self,
        row: &JobDispatch,
        signed: SignedJobReceipt,
    ) -> Result<Admitted, GpuConnectorError> {
        signed
            .verify(self.parts.signer.as_ref())
            .map_err(|_| unavailable("receipt_signature_invalid"))?;
        let receipt = &signed.receipt;
        if receipt.key != row.key
            || receipt.machine != row.machine
            || receipt.issuer != self.parts.issuer
        {
            return Err(unavailable("receipt_names_another_key"));
        }
        let held_epoch = row
            .held
            .as_deref()
            .map(decode::<SignedJobReceipt>)
            .transpose()?
            .map(|held| held.receipt.epoch);
        let stored = self.vault().job_observation(&row.key).map_err(store)?;
        let went_back = stored
            .as_ref()
            .is_some_and(|stored| stored.epoch == receipt.epoch && receipt.seq < stored.seq);
        if went_back || held_epoch.is_some_and(|epoch| epoch != receipt.epoch) {
            self.mark_history_lost(&row.key)?;
            return Err(unavailable("history_lost"));
        }
        let bytes = encode(&signed)?;
        let newer = stored
            .as_ref()
            .is_none_or(|stored| stored.epoch != receipt.epoch || receipt.seq > stored.seq);
        if newer {
            let end_seen = stored
                .as_ref()
                .and_then(|stored| stored.end_seen.clone())
                .or_else(|| {
                    (receipt.state == JobState::Ended).then(|| self.parts.clock.boot_mark())
                });
            let observation = JobObservation {
                key: row.key.clone(),
                machine: row.machine,
                device_id: receipt.device_id.clone(),
                receipt: bytes.clone(),
                epoch: receipt.epoch.clone(),
                seq: receipt.seq,
                last_measured_secs: receipt
                    .measured_secs
                    .or_else(|| stored.as_ref().and_then(|stored| stored.last_measured_secs)),
                observed_at_ms: self.now_ms(),
                end_seen,
                meter: stored.as_ref().and_then(|stored| stored.meter),
                terminal: stored.and_then(|stored| stored.terminal),
            };
            self.vault()
                .put_job_observation(&observation)
                .map_err(store)?;
        }
        Ok(Admitted {
            receipt: signed.receipt,
            bytes,
        })
    }

    /// The reserve of `submit`'s key. A `Held` receipt is stored on the row.
    fn send_reserve(
        &self,
        row: &JobDispatch,
        submit: &JobSubmit,
    ) -> Result<Sent, GpuConnectorError> {
        let reserve = JobRequest::Reserve(JobReserve {
            key: submit.key.clone(),
            pin: submit.pin.clone(),
            slot: submit.slot.clone(),
            issuer: submit.issuer,
            starter: submit.starter,
            issued_at_ms: submit.issued_at_ms,
            not_after_ms: submit.not_after_ms,
        });
        let answer = self.parts.client.job(row.machine, &reserve);
        let answer = match answer {
            Ok(answer) => answer,
            Err(error) => return Ok(Sent::NoAnswer(call_error(error))),
        };
        let JobAnswer::Receipt(signed) = answer else {
            return Ok(Sent::NoReceipt(job_answer_label(&answer)));
        };
        let admitted = self.admit(row, signed)?;
        if admitted.receipt.state == JobState::Held && row.held.is_none() {
            let held = admitted.bytes.clone();
            self.update(&row.key, |row| {
                row.held.get_or_insert(held);
                if row.phase < DispatchPhase::Reserved {
                    row.phase = DispatchPhase::Reserved;
                }
            })?;
        }
        Ok(Sent::Receipt(admitted.receipt))
    }

    /// The stored signed submit, sent again as first signed. The first send marks the start of
    /// the issuer's bracket before it goes out.
    fn send_submit(
        &self,
        row: &JobDispatch,
        signed: &SignedJobSubmit,
    ) -> Result<Sent, GpuConnectorError> {
        if row.sent_boot.is_none() {
            let mark = self.parts.clock.boot_mark();
            self.update(&row.key, |row| {
                row.sent_boot.get_or_insert(mark);
            })?;
        }
        let answer = self
            .parts
            .client
            .job(row.machine, &JobRequest::Submit(signed.clone()));
        let answer = match answer {
            Ok(answer) => answer,
            Err(error) => return Ok(Sent::NoAnswer(call_error(error))),
        };
        let JobAnswer::Receipt(receipt) = answer else {
            return Ok(Sent::NoReceipt(job_answer_label(&answer)));
        };
        let admitted = self.admit(row, receipt)?;
        if !matches!(admitted.receipt.state, JobState::Held | JobState::Ended) {
            self.update(&row.key, |row| {
                if row.phase < DispatchPhase::Submitted {
                    row.phase = DispatchPhase::Submitted;
                }
            })?;
        }
        Ok(Sent::Receipt(admitted.receipt))
    }

    /// The three rules before a reserve or submit goes out again: the live recheck (a no closes
    /// the key with a stop), and the node's reconcile (none yet: the job waits).
    fn gate(&self, row: &JobDispatch, submit: &JobSubmit) -> Result<Gate, GpuConnectorError> {
        if let Err(refusal) = self.recheck(row, submit)? {
            let closed = self.close(
                &row.key,
                DispatchClose::RefusedBeforeSend {
                    code: refusal.code().to_owned(),
                },
            )?;
            return Ok(Gate::Answer(self.stop_and_read(&closed)?));
        }
        if let Err(error) = self.reconciled.ensure(
            row.machine,
            self.vault(),
            self.parts.client.as_ref(),
            self.parts.orphans.as_ref(),
        ) {
            tracing::info!(node = %row.machine.to_hex(), error = %error, "vault_machine: the node is not reconciled yet");
            return Ok(Gate::Answer(GpuResourceStatus::Pending));
        }
        Ok(Gate::Go)
    }

    /// Sends a stop for a key the issuer closed, and answers what the node's receipt says.
    fn stop_and_read(&self, row: &JobDispatch) -> Result<GpuResourceStatus, GpuConnectorError> {
        Ok(match self.stop(row)? {
            Some(receipt) => receipt_status(&receipt),
            None => GpuResourceStatus::Pending,
        })
    }

    /// One stop of the key: the node's receipt when it answered with one. An absent key after a
    /// `Held` receipt, and a lost history, are marked.
    fn stop(&self, row: &JobDispatch) -> Result<Option<JobReceipt>, GpuConnectorError> {
        let answer = self
            .parts
            .client
            .job_status(
                row.machine,
                &JobStatusRequest::Stop {
                    key: row.key.clone(),
                },
            )
            .map_err(call_error)?;
        match answer {
            JobStatusAnswer::Known(signed) => Ok(Some(self.admit(row, signed)?.receipt)),
            JobStatusAnswer::Absent { .. } if row.held.is_some() => {
                self.mark_history_lost(&row.key)?;
                Ok(None)
            }
            JobStatusAnswer::HistoryLost => {
                self.mark_history_lost(&row.key)?;
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    /// `status` when the node does not hold the key.
    fn status_absent(
        &self,
        row: &JobDispatch,
        signed: &SignedJobSubmit,
    ) -> Result<GpuResourceStatus, GpuConnectorError> {
        if row.held.is_some() || row.phase >= DispatchPhase::Reserved {
            self.mark_history_lost(&row.key)?;
            return Err(unavailable("history_lost"));
        }
        if self.now_ms() >= row.not_after_ms {
            // Row R4, 7.9: the machine's journal never took the reserve in its whole window.
            super::guard::count_outcome(
                self.vault(),
                row.machine,
                &oneiron::job_dispatch::machine_records::MachineJobOutcome::MachineFailure {
                    why: "reserve_never_arrived".to_owned(),
                },
                self.now_ms(),
            );
            let closed = self.close(&row.key, DispatchClose::StartWindowPassed)?;
            return self.stop_and_read(&closed);
        }
        if let Gate::Answer(status) = self.gate(row, &signed.submit)? {
            return Ok(status);
        }
        Ok(match self.send_reserve(row, &signed.submit)? {
            Sent::Receipt(receipt) if receipt.state == JobState::Ended => receipt_status(&receipt),
            Sent::Receipt(_) | Sent::NoReceipt(_) | Sent::NoAnswer(_) => GpuResourceStatus::Pending,
        })
    }

    /// `status` on the key's newest receipt.
    fn status_known(
        &self,
        row: JobDispatch,
        signed: &SignedJobSubmit,
        admitted: Admitted,
    ) -> Result<GpuResourceStatus, GpuConnectorError> {
        let receipt = admitted.receipt;
        match receipt.state {
            JobState::Held => {
                let row = if row.held.is_none() {
                    self.update(&row.key, |row| {
                        row.held.get_or_insert(admitted.bytes);
                        if row.phase < DispatchPhase::Reserved {
                            row.phase = DispatchPhase::Reserved;
                        }
                    })?
                } else {
                    row
                };
                if self.now_ms() >= row.not_after_ms {
                    let closed = self.close(&row.key, DispatchClose::StartWindowPassed)?;
                    return self.stop_and_read(&closed);
                }
                if let Gate::Answer(status) = self.gate(&row, &signed.submit)? {
                    return Ok(status);
                }
                Ok(match self.send_submit(&row, signed)? {
                    Sent::Receipt(receipt) => receipt_status(&receipt),
                    Sent::NoReceipt(_) | Sent::NoAnswer(_) => GpuResourceStatus::Pending,
                })
            }
            JobState::Accepted | JobState::Staging | JobState::Launching => {
                if row.phase < DispatchPhase::Submitted {
                    self.update(&row.key, |row| {
                        if row.phase < DispatchPhase::Submitted {
                            row.phase = DispatchPhase::Submitted;
                        }
                    })?;
                }
                Ok(GpuResourceStatus::Pending)
            }
            JobState::Running | JobState::Ending | JobState::Ended => Ok(receipt_status(&receipt)),
        }
    }

    /// The terminal receipt the issuer already holds for the key, if any.
    fn stored_terminal(&self, key: &str) -> Result<Option<JobReceipt>, GpuConnectorError> {
        let Some(observation) = self.vault().job_observation(key).map_err(store)? else {
            return Ok(None);
        };
        let held = decode::<SignedJobReceipt>(&observation.receipt)?.receipt;
        Ok((held.state == JobState::Ended).then_some(held))
    }

    /// Confirms the key's end on its terminal receipt: bills it, stores the meter and the typed
    /// terminal beside the receipt, and closes the dispatch for good.
    fn confirm(
        &self,
        row: &JobDispatch,
        submit: &JobSubmit,
        ended: &JobReceipt,
    ) -> Result<GpuTermination, GpuConnectorError> {
        let mut observation = self
            .vault()
            .job_observation(&row.key)
            .map_err(store)?
            .ok_or_else(|| unavailable("no_observation"))?;
        let end_seen = observation
            .end_seen
            .clone()
            .unwrap_or_else(|| self.parts.clock.boot_mark());
        let bracket = row.sent_boot.as_ref().map(|sent| bracket(sent, &end_seen));
        let billing = billing(ended, submit.maximum_secs, bracket);
        // Row R4, 7.9: the end counts for the machine's guard on the issuer, once: the dispatch
        // closes below and a closed key confirms from its stored terminal.
        match self.vault().machine_job_settings(row.machine) {
            Ok(settings) => super::guard::count_outcome(
                self.vault(),
                row.machine,
                &super::guard::machine_job_outcome(ended, &billing.meter, settings.fast_exit_secs),
                self.now_ms(),
            ),
            Err(error) => {
                tracing::warn!(machine = %row.machine.to_hex(), %error, "vault_machine: the job guard's settings not read; this end is not counted");
            }
        }
        let revoked = matches!(row.closed, Some(DispatchClose::Revoked { .. }));
        let typed = terminal(
            ended,
            billing,
            revoked,
            observation.last_measured_secs.unwrap_or(0),
        );
        observation.end_seen = Some(end_seen);
        observation.meter = Some(billing.meter);
        observation.terminal = Some(typed);
        self.vault()
            .put_job_observation(&observation)
            .map_err(store)?;
        self.update(&row.key, |row| row.phase = DispatchPhase::Closed)?;
        Ok(GpuTermination::Confirmed {
            billed_secs: billing.billed_secs,
        })
    }
}

impl GpuJobConnector for VaultMachineConnector {
    fn create(&self, key: &str, spec: &GpuJobSpec) -> Result<GpuResourceRef, GpuConnectorError> {
        let inputs = vault_machine_inputs(&spec.inputs).map_err(refused)?;
        if let Some(row) = self.vault().job_dispatch(key).map_err(store)? {
            return Ok(GpuResourceRef(row.resource()));
        }
        if self.parts.settings.paused {
            return Err(refused("dispatch_paused"));
        }
        // Row R4, 7.9: a machine the issuer drained takes no new dispatch until door 12 clears
        // it. Nothing is written or sent.
        if let Some(refusal) =
            super::guard::machine_job_guard_refusal(self.vault(), inputs.machine).map_err(store)?
        {
            return Err(refused(refusal));
        }
        let job = EntityId::from_hex(&spec.job).map_err(|_| refused("job_id_invalid"))?;
        let started_by = self
            .vault()
            .gpu_job(&job)
            .map_err(store)?
            .ok_or_else(|| refused("job_missing"))?
            .started_by;
        let starter = match started_by {
            Some(by) => self.vault().dispatch_starter(by).map_err(store)?,
            None => None,
        }
        .ok_or_else(|| refused(DispatchRefusal::StarterLapsed.code()))?;
        let now = self.now_ms();
        let ask = DispatchAsk {
            starter,
            workload: &spec.image,
            node: inputs.machine,
            maximum_secs: spec.maximum_secs,
        };
        let pin = self
            .vault()
            .dispatch_recheck(&ask, now, self.horizon_ms())
            .map_err(store)?
            .map_err(|refusal| refused(refusal.code()))?;
        let not_after_ms =
            now.saturating_add(self.parts.settings.submit_window_secs.saturating_mul(1000));
        let submit = JobSubmit {
            key: key.to_owned(),
            job,
            chunk: spec.chunk,
            pin,
            slot: inputs.slot(),
            maximum_secs: spec.maximum_secs,
            issued_at_ms: now,
            not_after_ms,
            issuer: self.parts.issuer,
            starter: wire_starter(starter),
            hold: hold_of(key),
            authority_heads: self.vault().authority_main_log_heads().map_err(store)?,
        };
        let signed = SignedJobSubmit::sign(submit, self.parts.signer.as_ref())
            .map_err(|error| refused(format!("issuer_cannot_sign: {error}")))?;
        let row = self
            .vault()
            .insert_job_dispatch(JobDispatch {
                key: key.to_owned(),
                job,
                chunk: spec.chunk,
                workload: spec.image.clone(),
                machine: inputs.machine,
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
        let receipt = match self.send_reserve(&row, &signed.submit)? {
            Sent::Receipt(receipt) => receipt,
            Sent::NoReceipt(why) => return Err(unavailable(why)),
            Sent::NoAnswer(error) => return Err(error),
        };
        let receipt = match receipt.state {
            JobState::Held => {
                let row = self
                    .vault()
                    .job_dispatch(key)
                    .map_err(store)?
                    .unwrap_or(row);
                match self.send_submit(&row, &signed)? {
                    Sent::Receipt(receipt) => receipt,
                    Sent::NoReceipt(why) => return Err(unavailable(why)),
                    Sent::NoAnswer(error) => return Err(error),
                }
            }
            _ => receipt,
        };
        if let (JobState::Ended, Some(JobEnd::Refused { reason })) = (receipt.state, &receipt.end) {
            let reason = reason.clone();
            self.update(key, |row| {
                row.phase = DispatchPhase::Closed;
                row.closed.get_or_insert(DispatchClose::NodeRefused {
                    reason: reason.clone(),
                });
            })?;
            return Err(refused(reason));
        }
        Ok(resource)
    }

    fn find(&self, key: &str) -> Result<Option<GpuResourceRef>, GpuConnectorError> {
        Ok(self
            .vault()
            .job_dispatch(key)
            .map_err(store)?
            .map(|row| GpuResourceRef(row.resource())))
    }

    fn status(&self, resource: &GpuResourceRef) -> Result<GpuResourceStatus, GpuConnectorError> {
        let row = self.dispatch_of(resource)?;
        if row.history_lost_at_ms.is_some() {
            return Err(unavailable("history_lost"));
        }
        if row.phase >= DispatchPhase::Closing {
            return self.stop_and_read(&row);
        }
        let signed = decode::<SignedJobSubmit>(&row.submit)?;
        if let Some(refusal) = self.revoked(&row, &signed.submit)? {
            let closed = self.close(
                &row.key,
                DispatchClose::Revoked {
                    code: refusal.code().to_owned(),
                },
            )?;
            return self.stop_and_read(&closed);
        }
        let answer = self
            .parts
            .client
            .job_status(
                row.machine,
                &JobStatusRequest::Status {
                    key: row.key.clone(),
                },
            )
            .map_err(call_error)?;
        match answer {
            JobStatusAnswer::Known(receipt) => {
                let admitted = self.admit(&row, receipt)?;
                self.status_known(row, &signed, admitted)
            }
            JobStatusAnswer::Absent { .. } => self.status_absent(&row, &signed),
            JobStatusAnswer::HistoryLost => {
                self.mark_history_lost(&row.key)?;
                Err(unavailable("history_lost"))
            }
            other => Err(unavailable(status_answer_label(&other))),
        }
    }

    fn signal(
        &self,
        resource: &GpuResourceRef,
        signal: GpuJobSignal,
    ) -> Result<(), GpuConnectorError> {
        let row = self.dispatch_of(resource)?;
        let signal = match signal {
            GpuJobSignal::CheckpointDue { percent } => format!("checkpoint_due_{percent}"),
            GpuJobSignal::CheckpointBeforeStop => "checkpoint_before_stop".to_owned(),
        };
        match self
            .parts
            .client
            .job_status(
                row.machine,
                &JobStatusRequest::Signal {
                    key: row.key,
                    signal,
                },
            )
            .map_err(call_error)?
        {
            JobStatusAnswer::Acknowledged | JobStatusAnswer::Known(_) => Ok(()),
            other => Err(unavailable(status_answer_label(&other))),
        }
    }

    fn terminate(&self, resource: &GpuResourceRef) -> Result<GpuTermination, GpuConnectorError> {
        let row = self.dispatch_of(resource)?;
        let signed = decode::<SignedJobSubmit>(&row.submit)?;
        if row.phase == DispatchPhase::Closed
            && let Some(terminal) = self
                .vault()
                .job_observation(&row.key)
                .map_err(store)?
                .and_then(|observation| observation.terminal)
        {
            return Ok(GpuTermination::Confirmed {
                billed_secs: terminal.billed_secs,
            });
        }
        let row = self.close(&row.key, DispatchClose::Ended)?;
        let answered = match self.stop(&row) {
            Ok(Some(receipt)) if receipt.state == JobState::Ended => Some(receipt),
            Ok(Some(_)) => return Ok(GpuTermination::Pending),
            Ok(None) | Err(_) => None,
        };
        let ended = match answered {
            Some(receipt) => receipt,
            None => self
                .stored_terminal(&row.key)?
                .ok_or_else(|| unavailable("stop_not_confirmed"))?,
        };
        let row = self
            .vault()
            .job_dispatch(&row.key)
            .map_err(store)?
            .unwrap_or(row);
        self.confirm(&row, &signed.submit, &ended)
    }

    fn node_view(&self, job: &GpuJob, now_ms: u64, step_ms: u64) -> Option<GpuJobNodeView> {
        super::view::node_view(self.vault(), job, now_ms, step_ms)
    }
}

/// What a receipt says to the engine (the table of 8.2).
fn receipt_status(receipt: &JobReceipt) -> GpuResourceStatus {
    match receipt.state {
        JobState::Held | JobState::Accepted | JobState::Staging | JobState::Launching => {
            GpuResourceStatus::Pending
        }
        JobState::Running | JobState::Ending => GpuResourceStatus::Running {
            used_secs: receipt.measured_secs.unwrap_or(0),
            checkpoint: None,
        },
        JobState::Ended => match receipt.end {
            Some(JobEnd::Lost { .. }) => GpuResourceStatus::Gone,
            _ if !receipt.started => GpuResourceStatus::Exited { used_secs: 0 },
            _ => GpuResourceStatus::Exited {
                used_secs: receipt.measured_secs.unwrap_or(0),
            },
        },
    }
}

fn dispatch_ask<'a>(
    row: &'a JobDispatch,
    submit: &JobSubmit,
    starter: WorkloadStarter,
) -> DispatchAsk<'a> {
    DispatchAsk {
        starter,
        workload: &row.workload,
        node: row.machine,
        maximum_secs: submit.maximum_secs,
    }
}

fn wire_starter(starter: WorkloadStarter) -> Starter {
    match starter {
        WorkloadStarter::Owner(_) => Starter::Owner,
        WorkloadStarter::Grant(grant) => Starter::Grant { grant },
    }
}

/// The hold a chunk's submit names: the reservation is the chunk's own key. Its allocation
/// generation is 0 until allocation generations land (OPUS-WALLET-ALLOC, M2-I2), which replaces
/// this one read.
fn hold_of(key: &str) -> HoldRef {
    HoldRef {
        reservation: key.to_owned(),
        generation: 0,
    }
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, GpuConnectorError> {
    oneiron_organ_protocol::to_vec(value).map_err(|error| unavailable(format!("encode: {error}")))
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, GpuConnectorError> {
    oneiron_organ_protocol::from_slice(bytes)
        .map_err(|error| unavailable(format!("decode: {error}")))
}

fn job_answer_label(answer: &JobAnswer) -> String {
    match answer {
        JobAnswer::Refused(refusal) => job_refusal_code(refusal).to_owned(),
        other => job_answer_kind(other).to_owned(),
    }
}

fn status_answer_label(answer: &JobStatusAnswer) -> String {
    match answer {
        JobStatusAnswer::Refused(refusal) => job_refusal_code(refusal).to_owned(),
        other => status_answer_kind(other).to_owned(),
    }
}

fn store(error: impl std::fmt::Display) -> GpuConnectorError {
    unavailable(format!("the issuer's store: {error}"))
}

fn refused(reason: impl Into<String>) -> GpuConnectorError {
    GpuConnectorError::Refused {
        reason: reason.into(),
    }
}

fn unavailable(reason: impl Into<String>) -> GpuConnectorError {
    GpuConnectorError::Unavailable {
        reason: reason.into(),
    }
}

fn call_error(error: NodeCallError) -> GpuConnectorError {
    match error {
        NodeCallError::Timeout => GpuConnectorError::Timeout,
        NodeCallError::Unreachable { reason } => unavailable(reason),
    }
}
