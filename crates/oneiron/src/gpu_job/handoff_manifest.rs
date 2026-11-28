//! A GPU job's handoff manifest (row RSI-ARTIFACT-HANDOFF; ARCH-0079 #stacking: "A losing
//! branch is rolled back but archived, so its outputs stay available"): one private JSON record
//! that links what one ended key returned to the job that made it, so the report, card, draft,
//! ranked next targets and nulls a workload declared as outputs stay findable as one handoff.
//!
//! - A result binding that names a `manifest` artifact (`application/json`) gets one version of
//!   it per ended key, pending Keep, written as the key's outputs are
//!   ([`Vault::propose_gpu_job_result`]'s writer), once every returnable output is decided and
//!   the node took the acknowledgement. Nothing is published: Keep is a separate act, and the
//!   owner's (#promote-publishes-nothing).
//! - The manifest names the engine's own records only: the job, the chunk key, the machine, the
//!   bound task, the workload pin the chunk's signed submit names, a line unit's block (arm,
//!   rung, unit key, attempt and the contract that is the arm's referee digest), the end, and
//!   for each output of the signed receipt its sha256, size and outcome. It never copies an
//!   output's bytes or any text from them.
//! - An output above the returnable bound (a trained GGUF) is never fetched: the manifest names
//!   it as `custody` on the node, by its signed sha256 and size, the machine and the key. The
//!   node deletes it `jobs.receipts.keep_days` after the acknowledgement (30 days by default)
//!   unless the owner copies it first; the custody entry carries the vault's time of the
//!   acknowledgement, and the node's keep days only when the issuer knows them
//!   ([GPU-JOB-OUTPUT-CUSTODY-HOLD] is the hold that ends only at an issuer release).

use oneiron_contracts::fingerprint::ContentHash;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::GpuJobResultBinding;
use super::result_landing::{ResultLanding, gpu_job_output_run_ref};
use crate::edit_settle::PendingProposalView;
use crate::error::Result;
use crate::job_workload::WorkloadStarter;
use crate::{EntityId, Vault};

/// The manifest's `schema`.
pub const GPU_JOB_HANDOFF_SCHEMA: &str = "oneiron.gpu_job_handoff.v1";

/// The only media type a manifest artifact takes.
const MANIFEST_MEDIA_TYPE: &str = "application/json";

/// The handoff manifest of one ended key, as its artifact version holds it (JSON).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuJobHandoff {
    /// [`GPU_JOB_HANDOFF_SCHEMA`].
    pub schema: String,
    pub job: EntityId,
    /// The chunk's dispatch key.
    pub key: String,
    /// The node that ran the key.
    pub machine: EntityId,
    /// The task the binding names.
    pub task: EntityId,
    pub workload: GpuJobHandoffWorkload,
    /// A line unit's block, as each landed output's report carries it: arm, rung, unit key,
    /// attempt and the contract the arm pinned. `None` for a job no unit claim names.
    pub unit: Option<serde_json::Value>,
    /// How the key ended, as the node's terminal receipt says.
    pub end: Option<serde_json::Value>,
    /// The occupied seconds the node measured; `None` for an unknown interval.
    pub measured_secs: Option<u64>,
    /// When the node took the issuer's acknowledgement, on the vault's clock (ms).
    pub acked_at_ms: u64,
    /// Every output the signed receipt hashed, in its order.
    pub outputs: Vec<GpuJobHandoffOutput>,
}

/// The workload the key ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuJobHandoffWorkload {
    /// The workload digest the chunk's signed submit names.
    pub digest: String,
    /// The pin the submit names; `None` when the stored submit does not decode.
    pub pin: Option<GpuJobHandoffPin>,
}

/// The exact revision that ran: the template, the commit and the contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuJobHandoffPin {
    pub template: String,
    pub commit: String,
    pub contract_sha256: String,
}

/// One output of the signed receipt and what became of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuJobHandoffOutput {
    pub name: String,
    pub sha256: String,
    pub bytes: u64,
    pub outcome: GpuJobHandoffOutcome,
}

/// What became of one output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GpuJobHandoffOutcome {
    /// Landed as the bound artifact's next version, pending Keep, under this consume-once ref.
    Landed { artifact: EntityId, run_ref: String },
    /// Never lands, and why (also `not_returned` for a returnable output the return never
    /// decided).
    Refused { why: String },
    /// Not returnable: it stays on the node, which deletes it `node_keep_days` after
    /// `acked_at_ms` unless the owner copies it.
    Custody {
        machine: EntityId,
        key: String,
        acked_at_ms: u64,
        /// The node's `jobs.receipts.keep_days` when the issuer knows it; `None` otherwise,
        /// never a guess.
        node_keep_days: Option<u64>,
    },
}

/// One output the node hashed in the key's terminal receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuJobHandoffDigest {
    pub name: String,
    pub sha256: String,
    pub bytes: u64,
    pub returnable: bool,
}

/// What the issuer read for one key's manifest: from the chunk's signed submit and the key's
/// terminal receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuJobHandoffReceipt {
    pub key: String,
    pub machine: EntityId,
    pub workload: GpuJobHandoffWorkload,
    pub end: Option<serde_json::Value>,
    pub measured_secs: Option<u64>,
    pub outputs: Vec<GpuJobHandoffDigest>,
}

/// What one landing of a manifest came to.
#[derive(Debug, Clone, PartialEq)]
pub enum GpuJobHandoffLanding {
    /// Landed on the manifest artifact, pending Keep.
    Landed(PendingProposalView),
    /// Not yet: the acknowledgement is still owed, or no lane can hold it. Asked again.
    Owed,
    /// It never lands, and why: `manifest_unbound` or `manifest_not_json`.
    Refused(&'static str),
}

impl Vault {
    /// Whether `binding`'s manifest, when it names one, is an `application/json` artifact. The
    /// start door and the unit reserve refuse a binding whose manifest is not
    /// (`result_manifest_not_json`), and the landing refuses it again.
    ///
    /// # Errors
    ///
    /// A store read failure.
    pub fn gpu_job_result_manifest_is_json(&self, binding: &GpuJobResultBinding) -> Result<bool> {
        let Some(manifest) = binding.manifest else {
            return Ok(true);
        };
        Ok(self
            .get_blob_artifact(&manifest)?
            .is_some_and(|artifact| media_type_is_json(&artifact.media_type)))
    }

    /// Lands key `receipt.key`'s handoff manifest of job `job` on `binding.manifest`, written as
    /// its outputs are (the starter while `starter` stands, else `issuer` under the owner's
    /// lane), made_by naming the task as trigger and `gpu_job.handoff_manifest` as process.
    /// Each output's outcome is read from the key's `JOB_RETURN` row: landed, refused, or
    /// custody for one the receipt marks not returnable. The caller never calls this for a
    /// job a revoke stopped.
    ///
    /// The consume-once ref is `gpu-job-<job hex>-handoff-<digest hex>`, the digest BLAKE3 over
    /// the JSON array `[job hex, key]`, so a retry lands it once.
    ///
    /// # Errors
    ///
    /// The job row is gone; the task is dead or unreadable in the landing lane; or the native
    /// output is refused (the ref already waits or has settled). Store and lane errors
    /// propagate.
    pub fn propose_gpu_job_handoff(
        &self,
        job: EntityId,
        starter: Option<WorkloadStarter>,
        binding: &GpuJobResultBinding,
        receipt: &GpuJobHandoffReceipt,
        issuer: EntityId,
        retained_at: u64,
    ) -> Result<GpuJobHandoffLanding> {
        let Some(manifest) = binding.manifest else {
            return Ok(GpuJobHandoffLanding::Refused("manifest_unbound"));
        };
        if !self.gpu_job_result_manifest_is_json(binding)? {
            return Ok(GpuJobHandoffLanding::Refused("manifest_not_json"));
        }
        let Some(returned) = self.job_return(&receipt.key)? else {
            return Ok(GpuJobHandoffLanding::Owed);
        };
        let Some(acked_at_ms) = returned.acknowledged_at_ms else {
            return Ok(GpuJobHandoffLanding::Owed);
        };
        let outputs = receipt
            .outputs
            .iter()
            .map(|output| GpuJobHandoffOutput {
                name: output.name.clone(),
                sha256: output.sha256.clone(),
                bytes: output.bytes,
                outcome: if returned.landed.iter().any(|name| *name == output.name) {
                    GpuJobHandoffOutcome::Landed {
                        artifact: binding.artifact,
                        run_ref: gpu_job_output_run_ref(job, &receipt.key, &output.name).0,
                    }
                } else if let Some(refused) = returned
                    .refused
                    .iter()
                    .find(|refused| refused.name == output.name)
                {
                    GpuJobHandoffOutcome::Refused {
                        why: refused.why.clone(),
                    }
                } else if output.returnable {
                    GpuJobHandoffOutcome::Refused {
                        why: "not_returned".to_owned(),
                    }
                } else {
                    GpuJobHandoffOutcome::Custody {
                        machine: receipt.machine,
                        key: receipt.key.clone(),
                        acked_at_ms,
                        node_keep_days: None,
                    }
                },
            })
            .collect();
        let handoff = GpuJobHandoff {
            schema: GPU_JOB_HANDOFF_SCHEMA.to_owned(),
            job,
            key: receipt.key.clone(),
            machine: receipt.machine,
            task: binding.task,
            workload: receipt.workload.clone(),
            unit: self.gpu_job_result_unit(job)?,
            end: receipt.end.clone(),
            measured_secs: receipt.measured_secs,
            acked_at_ms,
            outputs,
        };
        let job_hex = job.to_hex();
        let identity = json!([job_hex, receipt.key]).to_string();
        let params_hash = ContentHash::of(identity.as_bytes()).to_hex();
        let report = json!({
            "job": job_hex,
            "key": receipt.key,
            "schema": GPU_JOB_HANDOFF_SCHEMA,
        });
        let landing = ResultLanding {
            artifact: manifest,
            task: binding.task,
            run_ref: format!("gpu-job-{job_hex}-handoff-{params_hash}"),
            params_hash,
            name: "gpu_job_handoff.json",
            bytes: serde_json::to_vec(&handoff).expect("a handoff manifest serializes"),
            report: report.to_string(),
            process: "gpu_job.handoff_manifest",
        };
        Ok(
            match self.propose_gpu_job_landing(job, starter, issuer, retained_at, &landing)? {
                Some(view) => GpuJobHandoffLanding::Landed(view),
                None => GpuJobHandoffLanding::Owed,
            },
        )
    }
}

/// Whether `media_type` is `application/json`, parameters (`; charset=utf-8`) aside.
fn media_type_is_json(media_type: &str) -> bool {
    media_type
        .split(';')
        .next()
        .is_some_and(|essence| essence.trim().eq_ignore_ascii_case(MANIFEST_MEDIA_TYPE))
}
