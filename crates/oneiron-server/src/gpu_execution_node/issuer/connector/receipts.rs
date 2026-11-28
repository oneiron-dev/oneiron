//! The receipts of a key on the issuer: each one is checked, then judged against the stored
//! rows and written in one write ([`oneiron::Vault::update_job_dispatch_and_observation`]), so a
//! slower call never writes over a newer receipt and the row's `Held` mark lands with the
//! receipt that proves it. The confirmed end bills the terminal receipt in one write too.
use oneiron::gpu_job::{GpuConnectorError, GpuTermination};
use oneiron::job_dispatch::{BootMark, DispatchClose, DispatchPhase, JobDispatch, JobObservation};

use super::{VaultMachineConnector, decode, encode, store, unavailable};
use crate::gpu_execution_node::issuer::billing::{billing, bracket, terminal};
use crate::gpu_execution_node::wire::{
    JobEnd, JobReceipt, JobState, JobSubmit, SignedJobReceipt, SignedJobSubmit,
};

/// What the judgement of one receipt found.
enum Judged {
    /// The receipt is the key's, in order: stored when it is the newest.
    Admitted,
    /// It went back in its journal, or came from another journal than the one that held the
    /// reserve: the node's history is lost, and the row says so.
    HistoryLost,
    /// The stored `Held` receipt could not be read back.
    HeldUnreadable(String),
}

impl VaultMachineConnector {
    /// Checks a receipt of `row`'s key and stores it when it is the newest: it must carry the
    /// node's signature, name this key, this node and this issuer, and never go back in the
    /// journal it came from. A receipt older than one the issuer holds, or from another journal
    /// than the one that held the reserve, means the node's history is lost: nothing is sent
    /// again. A `Held` receipt marks the row `Reserved` in the same write.
    pub(super) fn admit(
        &self,
        row: &JobDispatch,
        signed: SignedJobReceipt,
    ) -> Result<JobReceipt, GpuConnectorError> {
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
        let bytes = encode(&signed)?;
        let receipt = signed.receipt;
        let now_ms = self.now_ms();
        let end_mark = (receipt.state == JobState::Ended).then(|| self.parts.clock.boot_mark());
        let run_epoch = self.run_epoch(row)?;
        let (_, judged) = self
            .vault()
            .update_job_dispatch_and_observation(&row.key, |row, stored| {
                judge_receipt(
                    row,
                    stored,
                    &receipt,
                    bytes,
                    now_ms,
                    end_mark,
                    run_epoch.as_deref(),
                )
            })
            .map_err(store)?
            .ok_or_else(|| unavailable("no_dispatch_row"))?;
        match judged {
            Judged::Admitted => Ok(receipt),
            Judged::HistoryLost => Err(unavailable("history_lost")),
            Judged::HeldUnreadable(error) => Err(unavailable(format!("decode: {error}"))),
        }
    }

    /// The journal a session's next chunk (row W1) must be judged against, which no `Held`
    /// receipt binds since it is never reserved: its own first receipt's, or else its run's first
    /// key's. A receipt from another journal is the node's history lost, never a zero end.
    /// `None` for every other key.
    fn run_epoch(&self, row: &JobDispatch) -> Result<Option<String>, GpuConnectorError> {
        if row.held.is_some() {
            return Ok(None);
        }
        let Some(first) = decode::<SignedJobSubmit>(&row.submit)?.submit.continues else {
            return Ok(None);
        };
        let own = self.vault().job_observation(&row.key).map_err(store)?;
        let observation = match own {
            Some(own) => Some(own),
            None => self.vault().job_observation(&first).map_err(store)?,
        };
        Ok(observation.map(|observation| observation.epoch))
    }

    /// Whether the node journaled the key: the row holds its `Held` receipt or got past the
    /// reserve, or the issuer holds any receipt of the key. A journaled key the node no longer
    /// holds means its journal is gone.
    pub(super) fn journaled(&self, row: &JobDispatch) -> Result<bool, GpuConnectorError> {
        Ok(row.held.is_some()
            || row.phase >= DispatchPhase::Reserved
            || self
                .vault()
                .job_observation(&row.key)
                .map_err(store)?
                .is_some())
    }

    /// The terminal receipt the issuer already holds for the key, if any.
    pub(super) fn stored_terminal(
        &self,
        key: &str,
    ) -> Result<Option<JobReceipt>, GpuConnectorError> {
        let Some(observation) = self.vault().job_observation(key).map_err(store)? else {
            return Ok(None);
        };
        let held = decode::<SignedJobReceipt>(&observation.receipt)?.receipt;
        Ok((held.state == JobState::Ended).then_some(held))
    }

    /// Confirms the key's end on its terminal receipt: bills it, stores the meter and the typed
    /// terminal beside the receipt, and closes the dispatch for good, in one write. A session's
    /// slice that the run passed (row W1) confirms as [`GpuTermination::Continued`]: its run goes
    /// on under the next chunk's key.
    pub(super) fn confirm(
        &self,
        key: &str,
        submit: &JobSubmit,
        ended: &JobReceipt,
    ) -> Result<GpuTermination, GpuConnectorError> {
        let end_mark = self.parts.clock.boot_mark();
        let maximum_secs = submit.maximum_secs;
        let (row, confirmed) = self
            .vault()
            .update_job_dispatch_and_observation(key, |row, stored| {
                let Some(mut observation) = stored else {
                    return (None, None);
                };
                let end_seen = observation.end_seen.clone().unwrap_or(end_mark);
                let bracket = row.sent_boot.as_ref().map(|sent| bracket(sent, &end_seen));
                let billing = billing(ended, maximum_secs, bracket);
                let revoked = matches!(row.closed, Some(DispatchClose::Revoked { .. }));
                observation.terminal = Some(terminal(
                    ended,
                    billing,
                    revoked,
                    observation.last_measured_secs.unwrap_or(0),
                ));
                observation.end_seen = Some(end_seen);
                observation.meter = Some(billing.meter);
                let closes_now = row.phase != DispatchPhase::Closed;
                row.phase = DispatchPhase::Closed;
                (
                    Some(observation),
                    Some((billing.billed_secs, billing.meter, closes_now)),
                )
            })
            .map_err(store)?
            .ok_or_else(|| unavailable("no_dispatch_row"))?;
        let (billed_secs, meter, closes_now) =
            confirmed.ok_or_else(|| unavailable("no_observation"))?;
        // Row R4, 7.9: the end counts for the machine's guard on the issuer once, after the
        // write that closed the dispatch; a later confirm of the closed key counts nothing.
        if closes_now {
            self.count_machine_end(row.machine, ended, &meter);
        }
        // A session's slice the run passed carries no outputs: only the run's last slice does.
        if ended.end == Some(JobEnd::Continued) {
            return Ok(GpuTermination::Continued {
                used_secs: ended.measured_secs.unwrap_or(billed_secs),
                billed_secs,
            });
        }
        // Nor does a slice the run never reached (row W1): the node acknowledges outputs only
        // for the slice that holds the run's end, so a return opened here would stay owed.
        if ended.slice.is_some() && ended.end == Some(JobEnd::Withdrawn) {
            return Ok(GpuTermination::Confirmed { billed_secs });
        }
        // Row R4, EM-12 = A: the outputs land when the quote binds a result, then the node is
        // told it may clean them. What does not finish here is owed to the housekeeping pass.
        self.result_returns().return_outputs(&row, ended);
        Ok(GpuTermination::Confirmed { billed_secs })
    }

    /// Counts the end `ended` (billed as `meter`) for `machine`'s job guard on the issuer.
    fn count_machine_end(
        &self,
        machine: oneiron::EntityId,
        ended: &JobReceipt,
        meter: &oneiron::gpu_job::MeterVerdict,
    ) {
        match self.vault().machine_job_settings(machine) {
            Ok(settings) => super::super::guard::count_outcome(
                self.vault(),
                machine,
                &super::super::guard::machine_job_outcome(ended, meter, settings.fast_exit_secs),
                self.now_ms(),
            ),
            Err(error) => {
                tracing::warn!(machine = %machine.to_hex(), %error, "vault_machine: the job guard's settings not read; this end is not counted");
            }
        }
    }
}

/// Judges `receipt` against the row and the stored observation as they stand inside the write:
/// changes the row, and answers the observation to store when the receipt is the newest. The
/// meter, the typed terminal and the end mark of a stored observation are kept.
fn judge_receipt(
    row: &mut JobDispatch,
    stored: Option<JobObservation>,
    receipt: &JobReceipt,
    bytes: Vec<u8>,
    now_ms: u64,
    end_mark: Option<BootMark>,
    run_epoch: Option<&str>,
) -> (Option<JobObservation>, Judged) {
    let held_epoch = match row
        .held
        .as_deref()
        .map(oneiron_organ_protocol::from_slice::<SignedJobReceipt>)
        .transpose()
    {
        Ok(held) => held
            .map(|held| held.receipt.epoch)
            .or_else(|| run_epoch.map(str::to_owned)),
        Err(error) => return (None, Judged::HeldUnreadable(error.to_string())),
    };
    let went_back = stored
        .as_ref()
        .is_some_and(|stored| stored.epoch == receipt.epoch && receipt.seq < stored.seq);
    if went_back || held_epoch.is_some_and(|epoch| epoch != receipt.epoch) {
        row.history_lost_at_ms.get_or_insert(now_ms);
        return (None, Judged::HistoryLost);
    }
    if receipt.state == JobState::Held && row.held.is_none() {
        row.held = Some(bytes.clone());
        if row.phase < DispatchPhase::Reserved {
            row.phase = DispatchPhase::Reserved;
        }
    }
    let newer = stored
        .as_ref()
        .is_none_or(|stored| stored.epoch != receipt.epoch || receipt.seq > stored.seq);
    if !newer {
        return (None, Judged::Admitted);
    }
    let (last_measured_secs, end_seen, meter, terminal, started) = match stored {
        Some(stored) => (
            stored.last_measured_secs,
            stored.end_seen,
            stored.meter,
            stored.terminal,
            stored.started,
        ),
        None => (None, None, None, None, false),
    };
    // The node's word that the workload process ran: it runs now, or it ended after it ran.
    let ran = match receipt.state {
        JobState::Running => true,
        JobState::Ending | JobState::Ended => receipt.started,
        JobState::Held | JobState::Accepted | JobState::Staging | JobState::Launching => false,
    };
    let observation = JobObservation {
        key: row.key.clone(),
        machine: row.machine,
        device_id: receipt.device_id.clone(),
        receipt: bytes,
        epoch: receipt.epoch.clone(),
        seq: receipt.seq,
        last_measured_secs: receipt.measured_secs.or(last_measured_secs),
        observed_at_ms: now_ms,
        end_seen: end_seen.or(end_mark),
        meter,
        terminal,
        started: started || ran,
    };
    (Some(observation), Judged::Admitted)
}
