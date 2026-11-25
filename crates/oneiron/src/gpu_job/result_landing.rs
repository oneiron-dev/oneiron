//! A GPU job's returned result as a proposal (pass 33 row R4; EM-12 = A): each returnable
//! output a vault machine ran becomes the bound artifact's next version, pending Keep, made by
//! the bound task and proposed through the job starter's own lane. The issuer fetches and
//! checks the bytes against the machine's signed receipt first; Keep is a separate act.
//!
//! A job that ended by itself still returns its result when its starter stopped standing
//! afterwards (its Grant expired or was revoked, or the starter was erased): the proposal then
//! waits in the owner's lane, written by the issuer as a System write, and Keep stays the
//! owner's act (RESULT-LANDING-LAPSED-STARTER = A, Engine 25 Nov 23:19; ARCH-0046). A job the
//! issuer stopped because a Grant or the approval was revoked never comes here (ARCH-0075).

use oneiron_contracts::fingerprint::ContentHash;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::GpuJob;
use crate::authority::live_agent_principal_in;
use crate::edit_settle::{NativeOutput, PendingProposalView};
use crate::error::{Error, RecordError, Result};
use crate::job_workload::WorkloadStarter;
use crate::policy_model::owners_in_txn;
use crate::provenance::made_by::{MadeBy, MadeByClass, MadeByProcess, MadeByTrigger};
use crate::write_envelope::WriteActor;
use crate::{EdgeActorClass, EntityId, Vault};

/// Where a job's result files land (EM-12 = A): the artifact whose next
/// version each becomes on Keep, and the task its made_by names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GpuJobResultBinding {
    pub artifact: EntityId,
    pub task: EntityId,
}

/// One returnable output fetched from the machine, already checked against
/// the signed receipt's SHA-256 and length and the returnable size limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuJobResultFile {
    pub key: String,
    pub name: String,
    pub sha256: String,
    pub bytes: Vec<u8>,
}

impl Vault {
    /// Lands `file` of `job` as a proposal on `binding.artifact`, with
    /// `binding.task` as its made_by trigger. While the starter stands, the
    /// starter writes it under their own read lane. Once the starter no longer
    /// stands, `issuer` (this install's MACHINE) writes it as a System write
    /// under the owner's lane. made_by still names the starter, or the issuer
    /// after the starter's erase (RESULT-LANDING-LAPSED-STARTER = A).
    /// [`Self::propose_native_output_with_reads`] takes the ordinary organ
    /// landing path without an organ hold. Keep is a separate act, and the
    /// owner's. The caller supplies the job's binding and a file it has
    /// verified against the receipt, and never calls this for a job it stopped
    /// because a Grant or the approval was revoked.
    ///
    /// The consume-once ref is `gpu-job-<job hex>-<digest hex>`. The digest
    /// is BLAKE3 over the JSON array `[job hex, key, name]`. The digest keeps
    /// the ref bounded and makes retries independent of order and file bytes.
    ///
    /// # Errors
    ///
    /// The starter no longer stands and the vault has no one live owner, the
    /// task is dead or unreadable in the landing lane, or the native output is
    /// refused (for example, the file's media type differs from the
    /// artifact's or the ref already waits or has settled). Store and lane
    /// errors propagate.
    pub fn propose_gpu_job_result(
        &self,
        job: &GpuJob,
        binding: &GpuJobResultBinding,
        file: &GpuJobResultFile,
        issuer: EntityId,
        retained_at: u64,
    ) -> Result<PendingProposalView> {
        let (actor, lane) = match self.standing_gpu_job_starter(job)? {
            Some(starter) => (starter, starter.entity_ref()),
            None => (
                WriteActor::new(issuer, EdgeActorClass::System),
                self.gpu_job_result_owner()?,
            ),
        };
        let reader = self.organ_landing_reader(Some(lane))?;
        // An erased starter is never named again: the issuer that writes the landing stands in.
        let made_by_actor = job.started_by.unwrap_or(issuer);

        let job_hex = job.id.to_hex();
        let identity = json!([job_hex, file.key, file.name]).to_string();
        let params_hash = ContentHash::of(identity.as_bytes()).to_hex();
        // Every version keeps the artifact's own media type, whatever the file is called.
        let media_type = self
            .get_blob_artifact(&binding.artifact)?
            .ok_or(Error::EntityNotFound)?
            .media_type;
        let output = NativeOutput {
            run_ref: format!("gpu-job-{job_hex}-{params_hash}"),
            name: file.name.clone(),
            media_type,
            bytes: file.bytes.clone(),
            report: json!({
                "job": job_hex,
                "key": file.key,
                "name": file.name,
                "sha256": file.sha256,
                "bytes": file.bytes.len(),
            })
            .to_string(),
            made_by: Some(MadeBy {
                inputs: Vec::new(),
                process: MadeByProcess {
                    actor: made_by_actor,
                    class: MadeByClass::Concluded,
                    identity: "gpu_job.result_landing".into(),
                    version: "1".into(),
                    params_hash,
                },
                at: retained_at,
                trigger: Some(MadeByTrigger::Task(binding.task)),
            }),
        };
        self.propose_native_output_with_reads(
            &binding.artifact,
            &output,
            Some(reader),
            (actor, retained_at),
            &[],
            None,
        )
    }

    /// The job's starter as the writer of its result while they stand: the
    /// owner as Human, an agent under a live Grant as Agent or System. `None`
    /// once they no longer stand, and after their erase.
    fn standing_gpu_job_starter(&self, job: &GpuJob) -> Result<Option<WriteActor>> {
        let Some(started_by) = job.started_by else {
            return Ok(None);
        };
        let class = match self.dispatch_starter(started_by)? {
            Some(WorkloadStarter::Owner(_)) => EdgeActorClass::Human,
            Some(WorkloadStarter::Grant(_)) => {
                // Dispatch already resolved the Grant; it does not return the class.
                let txn = self.store.env.read_txn()?;
                if live_agent_principal_in(&self.store, &txn, started_by, EdgeActorClass::Agent)? {
                    EdgeActorClass::Agent
                } else if live_agent_principal_in(
                    &self.store,
                    &txn,
                    started_by,
                    EdgeActorClass::System,
                )? {
                    EdgeActorClass::System
                } else {
                    return Ok(None);
                }
            }
            None => return Ok(None),
        };
        Ok(Some(WriteActor::new(started_by, class)))
    }

    /// The owner whose lane holds a result whose starter no longer stands: the
    /// vault's one live owner. No rule picks one of a shared vault's several
    /// live owners, so such a result is refused, as is one with no live owner.
    fn gpu_job_result_owner(&self) -> Result<EntityId> {
        let owners = {
            let txn = self.store.env.read_txn()?;
            owners_in_txn(self, &txn)?
        };
        match owners.as_slice() {
            [owner] => Ok(*owner),
            [] => Err(Error::Record(RecordError::AuthorityRefused(
                "the GPU job's starter no longer stands and no live owner holds its result",
            ))),
            _ => Err(Error::Record(RecordError::AuthorityRefused(
                "the GPU job's starter no longer stands and no one owner's lane holds its result",
            ))),
        }
    }
}
