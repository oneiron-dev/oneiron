//! The returned result (pass 33 row R4; EM-12 = A): what the issuer does with an ended key's
//! outputs.
//!
//! - With a quote that binds a result (`inputs.result { artifact, task }`), each returnable
//!   output the node hashed is fetched, checked against the signed sha256 and length, and
//!   proposed as the artifact's next version through the starter's lane, pending Keep
//!   ([`Vault::propose_gpu_job_result`]). An output the vault refuses, the node will not serve,
//!   or whose bytes do not match is recorded as refused and never asked again.
//! - Without one, or for a key whose workload never started, nothing is fetched.
//!
//! Either way the node is then told it may clean the payload (`Ack`), once no output is owed.
//! A fetch or an acknowledgement that did not arrive is asked again at the next housekeeping
//! pass. `JOB_RETURN` keeps what landed, what never will, and the acknowledgement.

use std::sync::Arc;

use oneiron::gpu_job::{GpuJobResultBinding, GpuJobResultFile};
use oneiron::job_dispatch::JobDispatch;
use oneiron::job_dispatch::machine_records::{JobReturn, ReturnRefusal};
use oneiron::machine_signature::MachineSignatures;
use oneiron::{EntityId, Vault};
use sha2::{Digest, Sha256};

use super::clock::IssuerClock;
use super::node_client::JobNodeClient;
use crate::gpu_execution_node::wire::{
    JobReceipt, JobState, JobStatusAnswer, JobStatusRequest, OutputDigest, OutputsState,
    SignedJobReceipt,
};

/// The parts one return needs: the issuer's store, its node calls, the key that checks a
/// receipt, and its clock.
pub struct ResultReturns {
    pub vault: Arc<Vault>,
    /// This install's MACHINE: the issuer a receipt must name.
    pub issuer: EntityId,
    pub client: Arc<dyn JobNodeClient>,
    pub signer: Arc<dyn MachineSignatures>,
    pub clock: Arc<dyn IssuerClock>,
}

/// How far one pass over a key's outputs came.
enum Outputs {
    /// Every returnable output landed or was refused, or none is wanted.
    Decided,
    /// An output is still owed: asked again at the next pass.
    Owed,
}

impl ResultReturns {
    /// Returns the outputs of `row`'s key after its terminal receipt `ended`, then acknowledges
    /// them. Best effort: what did not finish stays owed on `JOB_RETURN`.
    pub fn return_outputs(&self, row: &JobDispatch, ended: &JobReceipt) {
        let opened = self.vault.record_job_return(
            &row.key,
            row.machine,
            row.job,
            self.clock.now_ms(),
            |_| {},
        );
        let owed = match opened {
            Ok(owed) => owed,
            Err(error) => {
                tracing::warn!(key = %row.key, %error, "vault_machine: the job's return not opened; its outputs wait for the next pass");
                return;
            }
        };
        if owed.acknowledged_at_ms.is_some() {
            return;
        }
        if matches!(self.land(row, ended, &owed), Outputs::Owed) {
            return;
        }
        self.acknowledge(row);
    }

    /// The keys whose acknowledgement the issuer still owes: the housekeeping pass follows each
    /// with [`Self::follow_owed_return`].
    #[must_use]
    pub fn owed_keys(&self) -> Vec<String> {
        match self.vault.job_returns_owed() {
            Ok(owed) => owed.into_iter().map(|owed| owed.key).collect(),
            Err(error) => {
                tracing::warn!(%error, "vault_machine: owed job returns not read");
                Vec::new()
            }
        }
    }

    /// One owed key of the housekeeping pass, from its stored terminal receipt. The caller holds
    /// the key's lock, as the confirm that first returned it did, so two passes never land the
    /// same file.
    pub fn follow_owed_return(&self, key: &str) {
        let row = self.vault.job_dispatch(key).ok().flatten();
        let ended = self
            .vault
            .job_observation(key)
            .ok()
            .flatten()
            .and_then(|observation| {
                oneiron_organ_protocol::from_slice::<SignedJobReceipt>(&observation.receipt).ok()
            })
            .map(|signed| signed.receipt)
            .filter(|receipt| receipt.state == JobState::Ended);
        if let (Some(row), Some(ended)) = (row, ended) {
            self.return_outputs(&row, &ended);
        }
    }

    /// Lands each returnable output of `ended` that `owed` has not decided, when the job's quote
    /// binds a result.
    fn land(&self, row: &JobDispatch, ended: &JobReceipt, owed: &JobReturn) -> Outputs {
        let job = match self.vault.gpu_job(&row.job) {
            Ok(Some(job)) => job,
            Ok(None) => return Outputs::Decided,
            Err(error) => {
                tracing::warn!(key = %row.key, %error, "vault_machine: the job row not read; its outputs wait");
                return Outputs::Owed;
            }
        };
        // The dispatched chunk's own quote (the row's key is its idempotency key), never a
        // later chunk's: a resumed job may bind another result or none.
        let inputs = job
            .chunks
            .iter()
            .find(|chunk| chunk.idempotency_key == row.key)
            .map(|chunk| super::vault_machine_inputs(&chunk.quote.inputs));
        let binding = match inputs {
            Some(Ok(inputs)) => inputs.result,
            Some(Err(error)) => {
                tracing::warn!(key = %row.key, %error, "vault_machine: the chunk's stored quote inputs do not read; no result is bound");
                None
            }
            None => None,
        };
        let Some(binding) = binding else {
            return Outputs::Decided;
        };
        let outputs = match &ended.outputs {
            OutputsState::Hashed(outputs) => outputs.clone(),
            OutputsState::Failed { .. } => return Outputs::Decided,
            // A key whose workload never started has no outputs the node will ever hash (it
            // hashes them only after a run's release), and the node takes its Ack at once.
            OutputsState::Pending if !ended.started => return Outputs::Decided,
            OutputsState::Pending => match self.newest_outputs(row) {
                Some(outputs) => outputs,
                None => return Outputs::Owed,
            },
        };
        let mut state = Outputs::Decided;
        for output in outputs
            .iter()
            .filter(|output| output.returnable && !owed.is_decided(&output.name))
        {
            match self.land_one(row, &job, &binding, output) {
                Some(Ok(())) => self.decide(row, |owed| owed.landed.push(output.name.clone())),
                Some(Err(why)) => self.decide(row, |owed| {
                    owed.refused.push(ReturnRefusal {
                        name: output.name.clone(),
                        why,
                    });
                }),
                None => state = Outputs::Owed,
            }
        }
        state
    }

    /// Fetches `output`, checks it, and proposes it. `None`: the fetch did not arrive, asked
    /// again. `Some(Err(why))`: it never lands.
    fn land_one(
        &self,
        row: &JobDispatch,
        job: &oneiron::gpu_job::GpuJob,
        binding: &GpuJobResultBinding,
        output: &OutputDigest,
    ) -> Option<Result<(), String>> {
        let answer = self.client.job_status(
            row.machine,
            &JobStatusRequest::Fetch {
                key: row.key.clone(),
                name: output.name.clone(),
            },
        );
        let bytes = match answer {
            Ok(JobStatusAnswer::Output { bytes }) => bytes,
            Ok(JobStatusAnswer::Busy { .. }) | Err(_) => return None,
            Ok(JobStatusAnswer::Refused(refusal)) => {
                return Some(Err(format!(
                    "not_fetchable: {}",
                    super::job_refusal_code(&refusal)
                )));
            }
            Ok(other) => {
                return Some(Err(format!(
                    "not_fetchable: {}",
                    super::status_answer_kind(&other)
                )));
            }
        };
        let digest = format!("{:x}", Sha256::digest(&bytes));
        if u64::try_from(bytes.len()).ok() != Some(output.bytes) || digest != output.sha256 {
            return Some(Err("digest_mismatch".to_owned()));
        }
        let file = GpuJobResultFile {
            key: row.key.clone(),
            name: output.name.clone(),
            sha256: digest,
            bytes,
        };
        Some(
            self.vault
                .propose_gpu_job_result(job, binding, &file, self.clock.now_ms())
                .map(drop)
                .map_err(|error| format!("proposal_refused: {error}")),
        )
    }

    /// The outputs of the node's newest receipt of `row`'s key, once it hashed them and its
    /// receipt checks; `None` while it has not, or did not answer.
    fn newest_outputs(&self, row: &JobDispatch) -> Option<Vec<OutputDigest>> {
        let answer = self
            .client
            .job_status(
                row.machine,
                &JobStatusRequest::Find {
                    key: row.key.clone(),
                },
            )
            .ok()?;
        let JobStatusAnswer::Known(signed) = answer else {
            return None;
        };
        let receipt = &signed.receipt;
        let checked = receipt.key == row.key
            && receipt.machine == row.machine
            && receipt.issuer == self.issuer
            && signed.verify(self.signer.as_ref()).is_ok();
        match &signed.receipt.outputs {
            OutputsState::Hashed(outputs) if checked => Some(outputs.clone()),
            _ => None,
        }
    }

    /// Records one decided output on the key's return.
    fn decide(&self, row: &JobDispatch, change: impl FnOnce(&mut JobReturn)) {
        let written = self.vault.record_job_return(
            &row.key,
            row.machine,
            row.job,
            self.clock.now_ms(),
            change,
        );
        if let Err(error) = written {
            tracing::warn!(key = %row.key, %error, "vault_machine: a returned output not recorded; decided again at the next pass");
        }
    }

    /// Tells the node it may clean `row`'s payload, and records its answer.
    fn acknowledge(&self, row: &JobDispatch) {
        let answer = self.client.job_status(
            row.machine,
            &JobStatusRequest::Ack {
                key: row.key.clone(),
            },
        );
        match answer {
            Ok(JobStatusAnswer::Acknowledged) => {
                let now_ms = self.clock.now_ms();
                self.decide(row, |owed| {
                    owed.acknowledged_at_ms.get_or_insert(now_ms);
                });
            }
            Ok(other) => {
                tracing::debug!(key = %row.key, answer = super::status_answer_kind(&other), "vault_machine: the acknowledgement not taken yet; asked again at the next pass");
            }
            Err(error) => {
                tracing::debug!(key = %row.key, %error, "vault_machine: the acknowledgement did not arrive; asked again at the next pass");
            }
        }
    }
}
