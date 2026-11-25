//! A GPU job's returned result as a proposal (pass 33 row R4; EM-12 = A): each returnable
//! output a vault machine ran becomes the bound artifact's next version, pending Keep, made by
//! the bound task and proposed through the job starter's own lane. The issuer fetches and
//! checks the bytes against the machine's signed receipt first; Keep is a separate act.

use oneiron_contracts::fingerprint::ContentHash;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::GpuJob;
use crate::authority::live_agent_principal_in;
use crate::edit_settle::{NativeOutput, PendingProposalView};
use crate::error::{Error, RecordError, Result};
use crate::job_workload::WorkloadStarter;
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
    /// Lands `file` of `job` as a proposal on `binding.artifact`, under the
    /// starter's own read lane, with `binding.task` as its made_by trigger.
    /// [`Self::propose_native_output_with_reads`] takes the ordinary organ
    /// landing path without an organ hold. Keep is a separate act. The caller
    /// supplies the job's binding and a file it has verified against the receipt.
    ///
    /// The consume-once ref is `gpu-job-<job hex>-<digest hex>`. The digest
    /// is BLAKE3 over the JSON array `[job hex, key, name]`. The digest keeps
    /// the ref bounded and makes retries independent of order and file bytes.
    ///
    /// # Errors
    ///
    /// The starter is absent or no longer stands, the task is dead or
    /// unreadable in the starter's lane, or the native output is refused (for
    /// example, the file's media type differs from the artifact's or the
    /// ref already waits or has settled). Store and lane errors propagate.
    pub fn propose_gpu_job_result(
        &self,
        job: &GpuJob,
        binding: &GpuJobResultBinding,
        file: &GpuJobResultFile,
        retained_at: u64,
    ) -> Result<PendingProposalView> {
        let starter_lapsed = || {
            Error::Record(RecordError::AuthorityRefused(
                "the GPU job's starter no longer stands",
            ))
        };
        let started_by = job.started_by.ok_or_else(starter_lapsed)?;
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
                    return Err(starter_lapsed());
                }
            }
            None => return Err(starter_lapsed()),
        };
        let actor = WriteActor::new(started_by, class);
        let reader = self.organ_landing_reader(Some(started_by))?;

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
                    actor: started_by,
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
}
