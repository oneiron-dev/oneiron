//! A GPU job's returned result as a proposal (pass 33 row R4; EM-12 = A): each returnable
//! output a vault machine ran becomes the bound artifact's next version, pending Keep, made by
//! the bound task and proposed through the job starter's own lane. The issuer fetches and
//! checks the bytes against the machine's signed receipt first; Keep is a separate act.
//!
//! A job that ended by itself still returns its result when its starter stopped standing
//! afterwards (the Grant its chunk's submit names expired or was revoked, or the starter was
//! erased): the proposal then waits in the owner's lane, written by the issuer as a System
//! write, and Keep stays the owner's act (RESULT-LANDING-LAPSED-STARTER = A, Engine 25 Nov
//! 23:19; ARCH-0046). The issuer is then made_by's process, as the writer always is (FIX 9618),
//! and the starter stays named as made_by's input. A job a revoke stopped never comes here
//! (ARCH-0075). Since the owner's lane reads every row, a result binds only rows its starter
//! may read: the issuer checks the binding at each chunk's first dispatch
//! ([`Vault::gpu_job_result_binding_readable`]).

use oneiron_contracts::fingerprint::ContentHash;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::authority::live_agent_principal_in;
use crate::edit_settle::{NativeOutput, PendingProposalView};
use crate::error::{Error, RecordError, Result};
use crate::job_workload::WorkloadStarter;
use crate::llm::decision::questions::principal_lane;
use crate::policy_model::owners_in_txn;
use crate::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess, MadeByTrigger,
};
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
    /// Lands `file` of job `job` as a proposal on `binding.artifact`, with
    /// `binding.task` as its made_by trigger. `starter` is the starter the
    /// chunk's signed submit names. While that starter stands (the owner, or
    /// that exact Grant), the job's starter writes it under their own read
    /// lane. Otherwise `issuer` (this install's MACHINE) writes it as a
    /// System write under the owner's lane, made_by's process is the issuer,
    /// and the job's starter is made_by's input, unless they were erased
    /// (RESULT-LANDING-LAPSED-STARTER = A). The starter is read from the job
    /// row as it stands now, so an erase during the fetch is seen.
    /// [`Self::propose_native_output_with_reads`] takes the ordinary organ
    /// landing path without an organ hold. Keep is a separate act, and the
    /// owner's. The caller supplies the binding the dispatch checked and a
    /// file it has verified against the receipt, and never calls this for a
    /// job a revoke stopped.
    ///
    /// The consume-once ref is `gpu-job-<job hex>-<digest hex>`. The digest
    /// is BLAKE3 over the JSON array `[job hex, key, name]`. The digest keeps
    /// the ref bounded and makes retries independent of order and file bytes.
    ///
    /// # Errors
    ///
    /// The job row is gone; the starter no longer stands and the vault has no
    /// one live owner; the task is dead or unreadable in the landing lane; or
    /// the native output is refused (for example, the file's media type
    /// differs from the artifact's or the ref already waits or has settled).
    /// Store and lane errors propagate.
    pub fn propose_gpu_job_result(
        &self,
        job: EntityId,
        starter: Option<WorkloadStarter>,
        binding: &GpuJobResultBinding,
        file: &GpuJobResultFile,
        issuer: EntityId,
        retained_at: u64,
    ) -> Result<PendingProposalView> {
        let started_by = self.gpu_job(&job)?.ok_or(Error::EntityNotFound)?.started_by;
        let writer = match (starter, started_by) {
            (Some(starter), Some(started_by)) => {
                self.standing_gpu_job_result_writer(starter, started_by)?
            }
            _ => None,
        };
        let (actor, lane, inputs) = match writer {
            Some(writer) => (writer, writer.entity_ref(), Vec::new()),
            // An erased starter is never named again.
            None => (
                WriteActor::new(issuer, EdgeActorClass::System),
                self.gpu_job_result_owner()?,
                started_by
                    .map(|row| MadeByInput {
                        row,
                        role: MadeByInputRole::Input,
                    })
                    .into_iter()
                    .collect(),
            ),
        };
        let reader = self.organ_landing_reader(Some(lane))?;

        let job_hex = job.to_hex();
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
                inputs,
                process: MadeByProcess {
                    actor: actor.entity_ref(),
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

    /// Whether `principal`'s own read lane reads both rows `binding` names.
    /// The issuer asks it before each chunk's first dispatch and refuses a
    /// binding its starter cannot read, since a result whose starter lapsed
    /// lands through the owner's lane, which reads every row.
    ///
    /// # Errors
    ///
    /// A store or lane read failure.
    pub fn gpu_job_result_binding_readable(
        &self,
        principal: EntityId,
        binding: &GpuJobResultBinding,
    ) -> Result<bool> {
        principal_lane(self, principal)?.all_refs_readable(&[binding.artifact, binding.task])
    }

    /// The writer of a result while `starter`, the chunk's submit's starter,
    /// stands: the owner as Human, or the agent `started_by` under that exact
    /// live Grant, as Agent or System. `None` once it no longer stands.
    fn standing_gpu_job_result_writer(
        &self,
        starter: WorkloadStarter,
        started_by: EntityId,
    ) -> Result<Option<WriteActor>> {
        if !self.dispatch_starter_stands(starter)? {
            return Ok(None);
        }
        let class = match starter {
            WorkloadStarter::Owner(_) => EdgeActorClass::Human,
            WorkloadStarter::Grant(_) => {
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
