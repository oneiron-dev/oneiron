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
//! - `renew` (row W1) sends a session's next paid chunk: a submit that continues the run of the
//!   job's first key, on that key's machine, pin, slot and signed starter, after the live recheck,
//!   the Grant's per-job maximum over every chunk of the run, and the node's offer of the pin's
//!   template as a session's. No reserve: the chunk holds no disk or device of its own. A slice
//!   the run passed confirms and bills on its own receipt, with no stop.
//!
//! The calls of one key run one after another in this process: a create, a status, a signal
//! and a terminate of a key never interleave, so a close never crosses a send of the key, and
//! two receipts of the key are never judged at once. Every reserve and submit reads the row
//! again before it goes out and sends nothing once the key is closing ([`sends`]). A receipt is
//! judged and stored in the same write as the row's `Held` mark ([`receipts`]).
mod receipts;
mod renewals;
mod sends;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use oneiron::gpu_job::{
    GpuConnectorError, GpuJob, GpuJobConnector, GpuJobEnd, GpuJobNodeView, GpuJobSignal,
    GpuJobSpec, GpuResourceRef, GpuResourceStatus, GpuTermination,
};
use oneiron::job_dispatch::{
    DispatchAsk, DispatchClose, DispatchPhase, DispatchRefusal, JobDispatch,
};
use oneiron::job_workload::WorkloadStarter;
use oneiron::machine_signature::MachineSignatures;
use oneiron::{EntityId, Vault};
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::clock::IssuerClock;
use super::node_client::{JobNodeClient, NodeCallError};
use super::reconcile::{OrphanKeys, Reconciled};
use super::{
    NOT_AVAILABLE_TO_THIS_CALLER, job_answer_kind, job_refusal_code, status_answer_kind,
    vault_machine_inputs,
};
use crate::config::gpu_jobs::VaultMachineSettings;
use crate::gpu_execution_node::wire::{
    HoldRef, JobAnswer, JobEnd, JobReceipt, JobState, JobStatusAnswer, JobStatusRequest, JobSubmit,
    SignedJobSubmit, Starter,
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
    keys: KeyLocks,
}

/// What a reserve or a submit brought back.
enum Sent {
    /// The node's receipt of the key, verified and stored.
    Receipt(JobReceipt),
    /// An answer with no receipt: busy, a refusal before any journal, or another answer.
    NoReceipt(String),
    /// No answer arrived: the request may have reached the node.
    NoAnswer(GpuConnectorError),
    /// The issuer closed the key, or found its history lost, before the request went out:
    /// nothing was sent.
    Withheld,
}

/// Whether a reserve or a submit may go out now.
enum Gate {
    Go,
    /// It may not: what `status` answers instead.
    Answer(GpuResourceStatus),
}

/// One lock for each key this process is working on: the calls of a key run one after another.
/// A key's lock is forgotten once no call holds or waits on it.
#[derive(Default)]
struct KeyLocks {
    held: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl KeyLocks {
    /// Runs `work` while this process holds the lock of `key`.
    fn with<T>(&self, key: &str, work: impl FnOnce() -> T) -> T {
        let lock = Arc::clone(
            self.held
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(key.to_owned())
                .or_default(),
        );
        let answer = {
            let _key = lock.lock().unwrap_or_else(PoisonError::into_inner);
            work()
        };
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        // The table and this call are the only holders: no other call waits on the key.
        if Arc::strong_count(&lock) == 2 {
            held.remove(key);
        }
        answer
    }
}

impl VaultMachineConnector {
    #[must_use]
    pub fn new(parts: VaultMachineParts) -> Self {
        Self {
            parts,
            reconciled: Reconciled::default(),
            keys: KeyLocks::default(),
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
        let (machine, key) = resource_parts(resource)?;
        let row = self.current(key)?;
        if row.machine != machine {
            return Err(unavailable("resource_names_another_machine"));
        }
        Ok(row)
    }

    /// The dispatch row of `key` as it stands now.
    fn current(&self, key: &str) -> Result<JobDispatch, GpuConnectorError> {
        self.vault()
            .job_dispatch(key)
            .map_err(store)?
            .ok_or_else(|| unavailable("no_dispatch_row"))
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

    /// `create` under the key's lock.
    fn create_key(
        &self,
        key: &str,
        spec: &GpuJobSpec,
    ) -> Result<GpuResourceRef, GpuConnectorError> {
        let inputs = vault_machine_inputs(&spec.inputs).map_err(refused)?;
        if let Some(row) = self.vault().job_dispatch(key).map_err(store)? {
            return Ok(GpuResourceRef(row.resource()));
        }
        if self.parts.settings.paused {
            return Err(refused("dispatch_paused"));
        }
        // Row R4, 7.9: a machine the issuer drained takes no new dispatch until door 12 clears
        // it. Nothing is written or sent.
        if let Some(refusal) = super::guard::machine_job_guard_refusal(self.vault(), inputs.machine)
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
        // A result binds only rows its starter may read: once the starter lapses, the result
        // lands through the owner's lane, which reads every row (RESULT-LANDING-LAPSED-STARTER
        // = A). Nothing is written or sent.
        if let (Some(binding), Some(by)) = (&inputs.result, started_by)
            && !self
                .vault()
                .gpu_job_result_binding_readable(by, binding)
                .map_err(store)?
        {
            return Err(refused("result_binding_unreadable"));
        }
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
            continues: None,
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
            Sent::Withheld => return Ok(resource),
            Sent::NoReceipt(why) => return Err(unavailable(why)),
            Sent::NoAnswer(error) => return Err(error),
        };
        let receipt = match receipt.state {
            JobState::Held => match self.send_submit(&row, &signed)? {
                Sent::Receipt(receipt) => receipt,
                // A terminate closed the key after the reserve: its status stops the key.
                Sent::Withheld => return Ok(resource),
                Sent::NoReceipt(why) => return Err(unavailable(why)),
                Sent::NoAnswer(error) => return Err(error),
            },
            _ => receipt,
        };
        if let (JobState::Ended, Some(JobEnd::Refused { reason })) = (receipt.state, &receipt.end) {
            tracing::info!(
                node = %row.machine.to_hex(),
                key,
                reason = %reason,
                "vault_machine: the node refused the key"
            );
            let reason = reason.clone();
            self.update(key, |row| {
                row.phase = DispatchPhase::Closed;
                row.closed
                    .get_or_insert(DispatchClose::NodeRefused { reason });
            })?;
            // The node's reason names the machine and what it said, which door 7 shows only a
            // caller who may read `vault.machines.execution.get` (section 6). The job's reason
            // is the code any caller may see; the dispatch row keeps the node's own.
            return Err(refused(NOT_AVAILABLE_TO_THIS_CALLER));
        }
        Ok(resource)
    }

    /// `status` under the key's lock.
    fn status_key(
        &self,
        resource: &GpuResourceRef,
    ) -> Result<GpuResourceStatus, GpuConnectorError> {
        let row = self.dispatch_of(resource)?;
        // Row R4, door 10: a written-off key is never asked or settled again.
        if matches!(row.closed, Some(DispatchClose::WrittenOff { .. })) {
            return Err(unavailable("written_off"));
        }
        if row.history_lost_at_ms.is_some() {
            return Err(unavailable("history_lost"));
        }
        // A session's slice the run passed (row W1) is confirmed for good: it is read again
        // from its terminal, and never stopped, since the run goes on under the next chunk.
        if let Some(terminal) = self.continued_terminal(&row.key)? {
            return Ok(GpuResourceStatus::Continued {
                used_secs: terminal.measured_secs.unwrap_or(0),
                billed_secs: terminal.billed_secs,
            });
        }
        let signed = decode::<SignedJobSubmit>(&row.submit)?;
        if row.phase >= DispatchPhase::Closing {
            // A session's next chunk that closed before any send could reach the node (its
            // window, a refused recheck, the node's refusal) is only read: a stop of a chunk the
            // run has not reached would end the run inside the chunk paid (row W1).
            let read_only = signed.submit.continues.is_some()
                && !matches!(
                    row.closed,
                    Some(DispatchClose::Revoked { .. } | DispatchClose::Ended)
                );
            if read_only {
                // A revoke still stops it: it may be the slice the run is in by now.
                if self.revoked(&row, &signed.submit)?.is_some() {
                    return self.stop_and_read(&row);
                }
                return self.read_closed_renewal(&row, &signed);
            }
            return self.stop_and_read(&row);
        }
        if let Some(refusal) = self.revoked(&row, &signed.submit)? {
            // A key the node had already ended when the issuer saw the revoke keeps its end and
            // its result: the revoke stops only work the node has not ended (a stop at the box
            // ends a job `Stopped` too, which is not the revoke's).
            if let Some(ended) = self.ended_at_node(&row) {
                return self.status_known(&row, &signed, &ended);
            }
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
                let receipt = self.admit(&row, receipt)?;
                self.status_known(&row, &signed, &receipt)
            }
            JobStatusAnswer::Absent { .. } => self.status_absent(&row, &signed),
            JobStatusAnswer::HistoryLost => {
                self.mark_history_lost(&row.key)?;
                Err(unavailable("history_lost"))
            }
            other => Err(unavailable(status_answer_label(&other))),
        }
    }

    /// `signal` under the key's lock.
    fn signal_key(
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

    /// `terminate` under the key's lock.
    fn terminate_key(
        &self,
        resource: &GpuResourceRef,
    ) -> Result<GpuTermination, GpuConnectorError> {
        let row = self.dispatch_of(resource)?;
        if matches!(row.closed, Some(DispatchClose::WrittenOff { .. })) {
            return Err(unavailable("written_off"));
        }
        let signed = decode::<SignedJobSubmit>(&row.submit)?;
        if row.phase == DispatchPhase::Closed
            && let Some(terminal) = self
                .vault()
                .job_observation(&row.key)
                .map_err(store)?
                .and_then(|observation| observation.terminal)
        {
            let billed_secs = terminal.billed_secs;
            if terminal.end == GpuJobEnd::Continued {
                return Ok(GpuTermination::Continued {
                    used_secs: terminal.measured_secs.unwrap_or(billed_secs),
                    billed_secs,
                });
            }
            return Ok(GpuTermination::Confirmed { billed_secs });
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
        self.confirm(&row.key, &signed.submit, &ended)
    }
}

impl GpuJobConnector for VaultMachineConnector {
    fn create(&self, key: &str, spec: &GpuJobSpec) -> Result<GpuResourceRef, GpuConnectorError> {
        self.keys.with(key, || self.create_key(key, spec))
    }

    fn find(&self, key: &str) -> Result<Option<GpuResourceRef>, GpuConnectorError> {
        Ok(self
            .vault()
            .job_dispatch(key)
            .map_err(store)?
            .map(|row| GpuResourceRef(row.resource())))
    }

    fn status(&self, resource: &GpuResourceRef) -> Result<GpuResourceStatus, GpuConnectorError> {
        let (_, key) = resource_parts(resource)?;
        self.keys.with(key, || self.status_key(resource))
    }

    fn signal(
        &self,
        resource: &GpuResourceRef,
        signal: GpuJobSignal,
    ) -> Result<(), GpuConnectorError> {
        let (_, key) = resource_parts(resource)?;
        self.keys.with(key, || self.signal_key(resource, signal))
    }

    fn terminate(&self, resource: &GpuResourceRef) -> Result<GpuTermination, GpuConnectorError> {
        let (_, key) = resource_parts(resource)?;
        self.keys.with(key, || self.terminate_key(resource))
    }

    fn renew(
        &self,
        key: &str,
        continues: &str,
        spec: &GpuJobSpec,
    ) -> Result<GpuResourceRef, GpuConnectorError> {
        self.keys.with(key, || self.renew_key(key, continues, spec))
    }

    fn node_view(&self, job: &GpuJob, now_ms: u64, step_ms: u64) -> Option<GpuJobNodeView> {
        super::view::node_view(self.vault(), job, now_ms, step_ms)
    }

    /// Door 10 (pass 33, 8.5): closes the chunk's dispatch as written off, for good, under the
    /// key's lock. Refused for a key whose terminal receipt the issuer holds (its step settles
    /// it), and before the node's latest cutoff (the submit's `not_after` plus its maximum) and
    /// `jobs.write_off.wait_secs` have passed, so any launch from this dispatch has met its
    /// cutoff. A session's run (row W1) is bounded by its latest launch (its first key's
    /// `not_after`, or its first renewal's, whichever is later) plus every chunk's maximum, the
    /// open next one's too, and never before any key's own bound; that next chunk's dispatch
    /// closes with it:
    /// one never dispatched stays so (its send refuses once the current chunk is written off),
    /// one whose end the node signed as never started closes and settles zero, and one whose end
    /// says it ran refuses the door before anything closes, so the step settles it. A repeat
    /// answers `Ok`.
    fn write_off(&self, job: &GpuJob, now_ms: u64) -> Result<(), GpuConnectorError> {
        self.write_off_job(job, now_ms)
    }

    /// Row R4: the live orphans are asked to stop again, and the owed results returned.
    fn housekeeping(&self) {
        self.parts.orphans.follow_live();
        let returns = self.result_returns();
        for key in returns.owed_keys() {
            self.keys.with(&key, || returns.follow_owed_return(&key));
        }
    }
}

impl VaultMachineConnector {
    /// The returned result's parts, from this connector's.
    fn result_returns(&self) -> super::returns::ResultReturns {
        super::returns::ResultReturns {
            vault: Arc::clone(&self.parts.vault),
            issuer: self.parts.issuer,
            client: Arc::clone(&self.parts.client),
            signer: Arc::clone(&self.parts.signer),
            clock: Arc::clone(&self.parts.clock),
        }
    }

    /// `write_off` under the key's lock.
    fn write_off_key(
        &self,
        key: &str,
        run_cutoff_ms: Option<u64>,
        now_ms: u64,
    ) -> Result<(), GpuConnectorError> {
        let Some(row) = self.vault().job_dispatch(key).map_err(store)? else {
            return Err(refused("write_off_never_dispatched"));
        };
        if matches!(row.closed, Some(DispatchClose::WrittenOff { .. })) {
            return Ok(());
        }
        if self.stored_terminal(&row.key)?.is_some() {
            return Err(refused("end_confirmed"));
        }
        let submit = decode::<SignedJobSubmit>(&row.submit)?.submit;
        let wait_secs = self
            .vault()
            .machine_job_settings(row.machine)
            .map_err(store)?
            .write_off_wait_secs;
        let earliest_ms = run_cutoff_ms
            .unwrap_or_else(|| {
                submit
                    .not_after_ms
                    .saturating_add(submit.maximum_secs.saturating_mul(1_000))
            })
            .saturating_add(wait_secs.saturating_mul(1_000));
        if now_ms < earliest_ms {
            return Err(refused("write_off_too_early"));
        }
        self.update(&row.key, |row| {
            row.phase = DispatchPhase::Closed;
            row.closed = Some(DispatchClose::WrittenOff {
                at_ms: now_ms,
                late_receipt: None,
            });
        })?;
        Ok(())
    }
}

/// The machine and the key a resource names: `<machine hex>#<key>`.
fn resource_parts(resource: &GpuResourceRef) -> Result<(EntityId, &str), GpuConnectorError> {
    resource
        .0
        .split_once('#')
        .and_then(|(machine, key)| Some((EntityId::from_hex(machine).ok()?, key)))
        .ok_or_else(|| unavailable("resource_invalid"))
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
            // A session's slice the run passed (row W1) is no end: `ended_or_status` confirms
            // and bills it; any other read of it answers that the run goes on.
            Some(JobEnd::Continued) => GpuResourceStatus::Pending,
            _ if !receipt.started => GpuResourceStatus::Exited { used_secs: 0 },
            // The node ended the run at the job's maximum (pass 33, 8.6).
            Some(JobEnd::TimeLimit) => GpuResourceStatus::TimeLimit {
                used_secs: receipt.measured_secs.unwrap_or(0),
            },
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
