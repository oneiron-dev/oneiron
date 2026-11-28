//! What the connector sends a node for a key, and how `status` steps it: the reserve and the
//! submit, the gate before either goes out again, the stop, and the two steps of the 8.2 table.
//! Every reserve and submit reads the dispatch row again before it goes out, and sends nothing
//! once the issuer closed the key or found its history lost.
use oneiron::gpu_job::{GpuConnectorError, GpuResourceStatus, GpuTermination};
use oneiron::job_dispatch::{DispatchClose, DispatchPhase, JobDispatch};

use super::{
    Gate, Sent, VaultMachineConnector, call_error, decode, job_answer_label, receipt_status,
    unavailable,
};
use crate::gpu_execution_node::wire::{
    JobAnswer, JobEnd, JobReceipt, JobRequest, JobReserve, JobState, JobStatusAnswer,
    JobStatusRequest, JobSubmit, SignedJobSubmit,
};

impl VaultMachineConnector {
    /// The dispatch row of `key` when a reserve or a submit may still go out for it: not
    /// closing, not closed, and its history not lost.
    fn sendable(&self, key: &str) -> Result<Option<JobDispatch>, GpuConnectorError> {
        let row = self.current(key)?;
        Ok((row.phase < DispatchPhase::Closing && row.history_lost_at_ms.is_none()).then_some(row))
    }

    /// The reserve of `submit`'s key. A `Held` receipt is stored on the row with the receipt.
    pub(super) fn send_reserve(
        &self,
        row: &JobDispatch,
        submit: &JobSubmit,
    ) -> Result<Sent, GpuConnectorError> {
        let Some(row) = self.sendable(&row.key)? else {
            return Ok(Sent::Withheld);
        };
        let reserve = JobRequest::Reserve(JobReserve {
            key: submit.key.clone(),
            pin: submit.pin.clone(),
            slot: submit.slot.clone(),
            issuer: submit.issuer,
            starter: submit.starter,
            issued_at_ms: submit.issued_at_ms,
            not_after_ms: submit.not_after_ms,
        });
        let answer = match self.parts.client.job(row.machine, &reserve) {
            Ok(answer) => answer,
            Err(error) => return Ok(Sent::NoAnswer(call_error(error))),
        };
        let JobAnswer::Receipt(signed) = answer else {
            return Ok(Sent::NoReceipt(job_answer_label(&answer)));
        };
        Ok(Sent::Receipt(self.admit(&row, signed)?))
    }

    /// The stored signed submit, sent again as first signed. The first send marks the start of
    /// the issuer's bracket before it goes out.
    pub(super) fn send_submit(
        &self,
        row: &JobDispatch,
        signed: &SignedJobSubmit,
    ) -> Result<Sent, GpuConnectorError> {
        let Some(row) = self.sendable(&row.key)? else {
            return Ok(Sent::Withheld);
        };
        if row.sent_boot.is_none() {
            let mark = self.parts.clock.boot_mark();
            self.update(&row.key, |row| {
                row.sent_boot.get_or_insert(mark);
            })?;
        }
        let answer = match self
            .parts
            .client
            .job(row.machine, &JobRequest::Submit(signed.clone()))
        {
            Ok(answer) => answer,
            Err(error) => return Ok(Sent::NoAnswer(call_error(error))),
        };
        let JobAnswer::Receipt(receipt) = answer else {
            return Ok(Sent::NoReceipt(job_answer_label(&answer)));
        };
        let receipt = self.admit(&row, receipt)?;
        if !matches!(receipt.state, JobState::Held | JobState::Ended) {
            self.update(&row.key, |row| {
                if row.phase < DispatchPhase::Submitted {
                    row.phase = DispatchPhase::Submitted;
                }
            })?;
        }
        Ok(Sent::Receipt(receipt))
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
    pub(super) fn stop_and_read(
        &self,
        row: &JobDispatch,
    ) -> Result<GpuResourceStatus, GpuConnectorError> {
        Ok(match self.stop(row)? {
            Some(receipt) => {
                let signed = decode::<SignedJobSubmit>(&row.submit)?;
                self.ended_or_status(row, &signed.submit, &receipt)?
            }
            None => GpuResourceStatus::Pending,
        })
    }

    /// What `receipt` says to the engine; a session's slice that the run passed (row W1) is
    /// confirmed and billed here, so the engine settles it with no stop of the run.
    pub(super) fn ended_or_status(
        &self,
        row: &JobDispatch,
        submit: &JobSubmit,
        receipt: &JobReceipt,
    ) -> Result<GpuResourceStatus, GpuConnectorError> {
        if receipt.state != JobState::Ended || receipt.end != Some(JobEnd::Continued) {
            return Ok(receipt_status(receipt));
        }
        let billed_secs = match self.confirm(&row.key, submit, receipt)? {
            GpuTermination::Confirmed { billed_secs }
            | GpuTermination::Continued { billed_secs } => billed_secs,
            GpuTermination::Pending => return Ok(GpuResourceStatus::Pending),
        };
        Ok(GpuResourceStatus::Continued {
            used_secs: receipt.measured_secs.unwrap_or(0),
            billed_secs,
        })
    }

    /// The node's receipt of the key when it says the key has ended, asked before a revoke
    /// closes the key, so an end that came before the revoke is not taken for the revoke's.
    /// `None` when the node still runs it, does not hold it, did not answer, or its receipt
    /// does not check: the revoke then closes the key and stops it.
    pub(super) fn ended_at_node(&self, row: &JobDispatch) -> Option<JobReceipt> {
        let answer = self.parts.client.job_status(
            row.machine,
            &JobStatusRequest::Status {
                key: row.key.clone(),
            },
        );
        let Ok(JobStatusAnswer::Known(signed)) = answer else {
            return None;
        };
        self.admit(row, signed)
            .ok()
            .filter(|receipt| receipt.state == JobState::Ended)
    }

    /// One stop of the key: the node's receipt when it answered with one. An absent key the
    /// node journaled, and a lost history, are marked.
    pub(super) fn stop(&self, row: &JobDispatch) -> Result<Option<JobReceipt>, GpuConnectorError> {
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
            JobStatusAnswer::Known(signed) => Ok(Some(self.admit(row, signed)?)),
            JobStatusAnswer::Absent { .. } if self.journaled(row)? => {
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
    pub(super) fn status_absent(
        &self,
        row: &JobDispatch,
        signed: &SignedJobSubmit,
    ) -> Result<GpuResourceStatus, GpuConnectorError> {
        if self.journaled(row)? {
            self.mark_history_lost(&row.key)?;
            return Err(unavailable("history_lost"));
        }
        if signed.submit.continues.is_some() {
            return self.renewal_absent(row, signed);
        }
        if self.now_ms() >= row.not_after_ms {
            // Row R4, 7.9: the machine's journal never took the reserve in its whole window.
            super::super::guard::count_outcome(
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
            Sent::Receipt(_) | Sent::NoReceipt(_) | Sent::NoAnswer(_) | Sent::Withheld => {
                GpuResourceStatus::Pending
            }
        })
    }

    /// `status` of a session's next chunk the node does not hold (row W1): it holds no disk or
    /// device of its own, so no reserve ever goes out for it. Inside its window the same submit is
    /// sent again under the gate; after it, the key closes with no stop, since the node takes no
    /// submit past its window, and a renewal that missed its window is not the machine's failure.
    fn renewal_absent(
        &self,
        row: &JobDispatch,
        signed: &SignedJobSubmit,
    ) -> Result<GpuResourceStatus, GpuConnectorError> {
        if self.now_ms() >= row.not_after_ms {
            self.close(&row.key, DispatchClose::StartWindowPassed)?;
            return Ok(GpuResourceStatus::Pending);
        }
        // The renewal's own controls again (row W1), and the gate of a first send, with no
        // stop on a refusal: the key closes unsent.
        if let Some(code) = self.renewal_refusal(
            &row.job,
            row.machine,
            &signed.submit,
            signed.submit.maximum_secs,
        )? {
            self.close(&row.key, DispatchClose::RefusedBeforeSend { code })?;
            return Ok(GpuResourceStatus::Pending);
        }
        if let Err(refusal) = self.recheck(row, &signed.submit)? {
            self.close(
                &row.key,
                DispatchClose::RefusedBeforeSend {
                    code: refusal.code().to_owned(),
                },
            )?;
            return Ok(GpuResourceStatus::Pending);
        }
        if let Err(error) = self.reconciled.ensure(
            row.machine,
            self.vault(),
            self.parts.client.as_ref(),
            self.parts.orphans.as_ref(),
        ) {
            tracing::info!(node = %row.machine.to_hex(), error = %error, "vault_machine: the node is not reconciled yet");
            return Ok(GpuResourceStatus::Pending);
        }
        Ok(match self.send_submit(row, signed)? {
            Sent::Receipt(receipt) if receipt.state == JobState::Ended => {
                self.ended_or_status(row, &signed.submit, &receipt)?
            }
            Sent::Receipt(_) | Sent::NoReceipt(_) | Sent::NoAnswer(_) | Sent::Withheld => {
                GpuResourceStatus::Pending
            }
        })
    }

    /// `status` of a session's next chunk the issuer closed before the run reached it: the
    /// node's receipt when it holds the key (a send that was already on its way), with no stop
    /// and no send.
    pub(super) fn read_closed_renewal(
        &self,
        row: &JobDispatch,
        signed: &SignedJobSubmit,
    ) -> Result<GpuResourceStatus, GpuConnectorError> {
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
                let receipt = self.admit(row, receipt)?;
                match receipt.state {
                    JobState::Ended => self.ended_or_status(row, &signed.submit, &receipt),
                    _ => Ok(receipt_status(&receipt)),
                }
            }
            _ => Ok(GpuResourceStatus::Pending),
        }
    }

    /// `status` on the key's newest receipt, which [`Self::admit`] stored.
    pub(super) fn status_known(
        &self,
        row: &JobDispatch,
        signed: &SignedJobSubmit,
        receipt: &JobReceipt,
    ) -> Result<GpuResourceStatus, GpuConnectorError> {
        match receipt.state {
            JobState::Held => {
                // The admission stored the `Held` mark with the receipt.
                let row = self.current(&row.key)?;
                if self.now_ms() >= row.not_after_ms {
                    let closed = self.close(&row.key, DispatchClose::StartWindowPassed)?;
                    return self.stop_and_read(&closed);
                }
                if let Gate::Answer(status) = self.gate(&row, &signed.submit)? {
                    return Ok(status);
                }
                Ok(match self.send_submit(&row, signed)? {
                    Sent::Receipt(receipt) => receipt_status(&receipt),
                    Sent::NoReceipt(_) | Sent::NoAnswer(_) | Sent::Withheld => {
                        GpuResourceStatus::Pending
                    }
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
            JobState::Running | JobState::Ending => Ok(receipt_status(receipt)),
            JobState::Ended => self.ended_or_status(row, &signed.submit, receipt),
        }
    }
}
