//! Policy-bound extraction-teacher probe approval for manifest publication.
use super::{ModelBinding, ModelManifest, ModelRole, invalid};
use crate::{Vault, error::Result, llm::ModelId};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const TEACHER_PROBE_ID: &str = "oneiron-conll-bio-v1";

/// Resolved vault policy exported to the offline bench. The vault re-resolves
/// it inside the teacher-pin transaction; a stale or caller-edited snapshot
/// cannot loosen the actual admission floor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeacherProbePolicy {
    pub probe_id: String,
    pub vault_min_f1_millionths: u32,
    pub min_f1_millionths: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_ref: Option<String>,
}

impl TeacherProbePolicy {
    pub(crate) fn resolved(
        vault_min: u32,
        effective_min: u32,
        holder: Option<&str>,
    ) -> Result<Self> {
        let policy = Self {
            probe_id: TEACHER_PROBE_ID.into(),
            vault_min_f1_millionths: vault_min,
            min_f1_millionths: effective_min,
            holder_ref: holder.map(str::to_owned),
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let policy: Self = serde_json::from_slice(&std::fs::read(path)?)
            .map_err(|e| invalid(&format!("invalid teacher probe policy: {e}")))?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<()> {
        if self.probe_id != TEACHER_PROBE_ID
            || !(1..=1_000_000).contains(&self.vault_min_f1_millionths)
            || !(self.vault_min_f1_millionths..=1_000_000).contains(&self.min_f1_millionths)
            || self
                .holder_ref
                .as_deref()
                .is_some_and(|id| !valid_holder_ref(id))
        {
            return Err(invalid("invalid resolved teacher probe policy"));
        }
        Ok(())
    }

    pub(crate) fn identity_hash(&self) -> Result<String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|e| invalid(&format!("teacher policy serialization failed: {e}")))?;
        Ok(blake3::hash(&bytes).to_hex().to_string())
    }
}

pub(crate) fn valid_holder_ref(holder: &str) -> bool {
    holder.len() == 32
        && holder
            .bytes()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
}

/// Evidence emitted by the offline bench runner. This is an operator receipt,
/// not a signature or a substitute for trusting the model-repository runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
