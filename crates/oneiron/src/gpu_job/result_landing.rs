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
//! and the starter stays named as made_by's input. That owner is the one who granted the
//! submit's Grant, while they are a live owner, else the vault's one live owner; with neither,
//! the result stays owed until one is. A job a revoke stopped never comes here (ARCH-0075).
//! Since the owner's lane reads every row, a result binds only rows its starter may read: the
//! start door checks an agent's binding under the credential it presented
//! ([`Memory::gpu_job_result_binding_admits`]), and the issuer checks it again under the
//! starter's own lane at each chunk's first dispatch
//! ([`Vault::gpu_job_result_binding_readable`]).

use oneiron_contracts::fingerprint::ContentHash;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::authority::live_agent_principal_in;
use crate::claim::ClaimReadStatus;
use crate::edit_settle::{NativeOutput, PendingProposalView};
use crate::error::{Error, Result};
use crate::federation::agent_grants_for_store_in_txn;
use crate::job_workload::WorkloadStarter;
use crate::llm::decision::questions::principal_lane;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::policy_model::{is_live_vault_owner_in_txn, owners_in_txn};
use crate::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess, MadeByTrigger,
};
use crate::write_envelope::WriteActor;
use crate::{EdgeActorClass, EntityId, Vault};

/// How many times one result is written: a write the envelope's admission refused because the
/// starter was erased or stopped standing after the read is resolved again and written again.
/// Both changes happen once, so the third write sees where the starter stands for good.
const RESULT_LANDING_WRITES: usize = 3;

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

/// Who writes a returned result, through whose read lane, and the starter its made_by names as
/// an input (none while the starter writes it, or once they were erased).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResultWriter {
    actor: EntityId,
    class: EdgeActorClass,
    lane: EntityId,
    starter_input: Option<EntityId>,
}

impl Vault {
    /// Lands `file` of job `job` as a proposal on `binding.artifact`, with
    /// `binding.task` as its made_by trigger. `starter` is the starter the
    /// chunk's signed submit names. While that starter stands (the owner, or
    /// that exact Grant), the job's starter writes it under their own read
    /// lane. Otherwise `issuer` (this install's MACHINE) writes it as a
    /// System write under the owner's lane ([`Self::gpu_job_result_lane_resolves`]),
    /// made_by's process is the issuer, and the job's starter is made_by's
    /// input, unless they were erased (RESULT-LANDING-LAPSED-STARTER = A).
    /// The starter is read from the job row as it stands now. A write refused
    /// because the starter was erased or stopped standing between that read
    /// and the write is resolved again and written again.
    /// [`Self::propose_native_output_with_reads`] takes the ordinary organ
    /// landing path without an organ hold. Keep is a separate act, and the
    /// owner's. The caller supplies the binding the dispatch checked and a
    /// file it has verified against the receipt, and never calls this for a
    /// job a revoke stopped.
    ///
    /// `Ok(None)`: the starter no longer stands and no owner's lane can hold
    /// the result yet; nothing was written and the caller keeps it owed.
    ///
    /// The consume-once ref is `gpu-job-<job hex>-<digest hex>`. The digest
    /// is BLAKE3 over the JSON array `[job hex, key, name]`. The digest keeps
    /// the ref bounded and makes retries independent of order and file bytes.
    ///
    /// # Errors
    ///
    /// The job row is gone; the task is dead or unreadable in the landing
    /// lane; or the native output is refused (for example, the file's media
    /// type differs from the artifact's or the ref already waits or has
    /// settled). Store and lane errors propagate.
    pub fn propose_gpu_job_result(
        &self,
        job: EntityId,
        starter: Option<WorkloadStarter>,
        binding: &GpuJobResultBinding,
        file: &GpuJobResultFile,
        issuer: EntityId,
        retained_at: u64,
    ) -> Result<Option<PendingProposalView>> {
        let mut writer = self.gpu_job_result_writer(job, starter, issuer)?;
        let mut writes = 0;
        loop {
            let Some(current) = writer else {
                return Ok(None);
            };
            writes += 1;
            let error =
                match self.propose_gpu_job_result_as(current, job, binding, file, retained_at) {
                    Ok(view) => return Ok(Some(view)),
                    Err(error) => error,
                };
            let again = self.gpu_job_result_writer(job, starter, issuer)?;
            if writes >= RESULT_LANDING_WRITES || again == writer {
                return Err(error);
            }
            writer = again;
        }
    }

    /// Whether a lane can hold job `job`'s result now: its submit's `starter`
    /// stands, or an owner's lane takes it. `false` while the starter no
    /// longer stands and no owner is resolved: the issuer keeps the result
    /// owed and fetches nothing yet.
    ///
    /// # Errors
    ///
    /// The job row is gone, or a store read fails.
    pub fn gpu_job_result_lane_resolves(
        &self,
        job: EntityId,
        starter: Option<WorkloadStarter>,
        issuer: EntityId,
    ) -> Result<bool> {
        Ok(self.gpu_job_result_writer(job, starter, issuer)?.is_some())
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

    /// One write of `file` by `writer`, the envelope built from it.
    fn propose_gpu_job_result_as(
        &self,
        writer: ResultWriter,
        job: EntityId,
        binding: &GpuJobResultBinding,
        file: &GpuJobResultFile,
        retained_at: u64,
    ) -> Result<PendingProposalView> {
        let actor = WriteActor::new(writer.actor, writer.class);
        let reader = self.organ_landing_reader(Some(writer.lane))?;
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
                inputs: writer
                    .starter_input
                    .map(|row| MadeByInput {
                        row,
                        role: MadeByInputRole::Input,
                    })
                    .into_iter()
                    .collect(),
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

    /// The writer of job `job`'s result as the vault stands now: its starter
    /// while `starter` stands, else the issuer under the owner's lane
    /// (`None` while no owner is resolved).
    fn gpu_job_result_writer(
        &self,
        job: EntityId,
        starter: Option<WorkloadStarter>,
        issuer: EntityId,
    ) -> Result<Option<ResultWriter>> {
        let started_by = self.gpu_job(&job)?.ok_or(Error::EntityNotFound)?.started_by;
        if let (Some(starter), Some(started_by)) = (starter, started_by)
            && let Some(class) = self.standing_gpu_job_starter_class(starter, started_by)?
        {
            return Ok(Some(ResultWriter {
                actor: started_by,
                class,
                lane: started_by,
                starter_input: None,
            }));
        }
        // An erased starter is never named again.
        Ok(self
            .gpu_job_result_owner(starter)?
            .map(|owner| ResultWriter {
                actor: issuer,
                class: EdgeActorClass::System,
                lane: owner,
                starter_input: started_by,
            }))
    }

    /// The class the job's starter writes as while `starter`, the chunk's
    /// submit's starter, stands: the owner as Human, or the agent
    /// `started_by` under that exact live Grant, as Agent or System. `None`
    /// once it no longer stands.
    fn standing_gpu_job_starter_class(
        &self,
        starter: WorkloadStarter,
        started_by: EntityId,
    ) -> Result<Option<EdgeActorClass>> {
        if !self.dispatch_starter_stands(starter)? {
            return Ok(None);
        }
        match starter {
            WorkloadStarter::Owner(_) => Ok(Some(EdgeActorClass::Human)),
            WorkloadStarter::Grant(_) => {
                let txn = self.store.env.read_txn()?;
                for class in [EdgeActorClass::Agent, EdgeActorClass::System] {
                    if live_agent_principal_in(&self.store, &txn, started_by, class)? {
                        return Ok(Some(class));
                    }
                }
                Ok(None)
            }
        }
    }

    /// The owner whose lane holds a result whose starter no longer stands:
    /// the owner who granted the submit's Grant (or the owner who started it)
    /// while they are a live owner, else the vault's one live owner. `None`
    /// when neither names one, for example a shared vault whose granting
    /// owner left, or a withdrawn Grant's in a shared vault.
    fn gpu_job_result_owner(&self, starter: Option<WorkloadStarter>) -> Result<Option<EntityId>> {
        let txn = self.store.env.read_txn()?;
        let named = match starter {
            Some(WorkloadStarter::Owner(owner)) => Some(owner),
            Some(WorkloadStarter::Grant(grant)) => {
                agent_grants_for_store_in_txn(&self.store, &txn)?
                    .into_iter()
                    .find(|standing| standing.id == grant)
                    .map(|standing| standing.delegated_by)
            }
            None => None,
        };
        if let Some(owner) = named
            && is_live_vault_owner_in_txn(self, &txn, &owner)?
        {
            return Ok(Some(owner));
        }
        Ok(match owners_in_txn(self, &txn)?.as_slice() {
            [owner] => Some(*owner),
            _ => None,
        })
    }
}

impl Memory<'_> {
    /// Whether this caller's own read lane, under the credential it
    /// presented (a slip's records list included), reads both rows `binding`
    /// names. The start door asks it of an agent's chunk whose quote binds a
    /// result, before the chunk is written: a result whose starter lapsed
    /// lands through the owner's lane, which reads every row.
    ///
    /// # Errors
    ///
    /// The caller's lane does not open, or a store read fails.
    pub fn gpu_job_result_binding_admits(
        &self,
        binding: &GpuJobResultBinding,
    ) -> MemoryResult<bool> {
        self.read_lane(ClaimReadStatus::Recorded)?
            .all_refs_readable(&[binding.artifact, binding.task])
            .map_err(MemoryError::from)
    }
}
