//! Policy-bound extraction-teacher probe approval for manifest publication.
use super::{ModelBinding, ModelManifest, ModelRole, invalid};
use crate::{Vault, error::Result, llm::ModelId};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Evidence emitted by the offline bench runner. This is an operator receipt,
/// not a signature or a substitute for trusting the model-repository runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TeacherProbeApproval {
    pub probe_id: String,
    pub model: ModelId,
    pub binding_hash: String,
    pub f1_millionths: u32,
    pub policy_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_ref: Option<String>,
}

fn binding_hash(binding: &ModelBinding) -> Result<String> {
    let bytes = serde_json::to_vec(binding)
        .map_err(|e| invalid(&format!("teacher binding serialization failed: {e}")))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

impl TeacherProbeApproval {
    /// Called by the bench only after evaluating an actual checkpoint. The
    /// vault checks this receipt again against LIVE policy at the commit door.
    pub fn for_scored_checkpoint(
        manifest: &ModelManifest,
        policy: &TeacherProbePolicy,
        f1_millionths: u32,
    ) -> Result<Self> {
        let binding = manifest.binding(ModelRole::ExtractionTeacher)?;
        let approval = Self {
            probe_id: TEACHER_PROBE_ID.into(),
            model: binding.model.clone(),
            binding_hash: binding_hash(binding)?,
            f1_millionths,
            policy_hash: policy.identity_hash()?,
            holder_ref: policy.holder_ref.clone(),
        };
        approval.verify(manifest, policy)?;
        Ok(approval)
    }

    pub fn load(path: &Path) -> Result<Self> {
        serde_json::from_slice(&std::fs::read(path)?)
            .map_err(|e| invalid(&format!("invalid teacher probe approval: {e}")))
    }

    pub fn verify(&self, manifest: &ModelManifest, policy: &TeacherProbePolicy) -> Result<()> {
        policy.validate()?;
        let binding = manifest.binding(ModelRole::ExtractionTeacher)?;
        if self.probe_id != policy.probe_id
            || self.f1_millionths < policy.min_f1_millionths
            || self.f1_millionths > 1_000_000
            || self.policy_hash != policy.identity_hash()?
            || self.holder_ref != policy.holder_ref
            || self.model != binding.model
            || !binding.route_models.is_empty()
            || self.binding_hash != binding_hash(binding)?
        {
            return Err(invalid(
                "extraction_teacher requires matching passing probe approval and resolved policy",
            ));
        }
        Ok(())
    }
}

impl Vault {
    /// Snapshot the vault's declared teacher-probe policy for an offline
    /// bench. The holder selector selects a stored, restrict-only override.
    pub fn teacher_probe_policy(&self, holder_ref: Option<&str>) -> Result<TeacherProbePolicy> {
        let txn = self.store.env.read_txn()?;
        self.teacher_probe_policy_in_txn(&txn, holder_ref)
    }

    pub(super) fn teacher_probe_policy_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        holder_ref: Option<&str>,
    ) -> Result<TeacherProbePolicy> {
        crate::gate::resolve_policy_manifest(&self.store, txn)?
            .teacher_probe_policy(holder_ref)
            .ok_or_else(|| {
                invalid("teacher probe policy is missing, malformed, or widens its vault floor")
            })
    }
}

pub(crate) use crate::teacher_probe_policy::valid_holder_ref;
pub use crate::teacher_probe_policy::{TEACHER_PROBE_ID, TeacherProbePolicy};
