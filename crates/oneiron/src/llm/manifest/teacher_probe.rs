//! Pinned extraction-teacher probe approval for manifest publication.
use super::{ModelBinding, ModelManifest, ModelRole, invalid};
use crate::{error::Result, llm::ModelId};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const TEACHER_PROBE_ID: &str = "oneiron-conll-bio-v1";
pub const TEACHER_PROBE_MIN_F1: u32 = 800_000;

/// Evidence emitted by the offline bench runner. This is an operator receipt,
/// not a signature or a substitute for trusting the model-repository runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeacherProbeApproval {
    pub probe_id: String,
    pub model: ModelId,
    pub binding_hash: String,
    pub f1_millionths: u32,
}

fn binding_hash(binding: &ModelBinding) -> Result<String> {
    let bytes = serde_json::to_vec(binding)
        .map_err(|e| invalid(&format!("teacher binding serialization failed: {e}")))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

impl TeacherProbeApproval {
    /// Called by the bench only after evaluating an actual checkpoint. The
    /// vault checks this receipt again at the commit door.
    pub fn for_scored_checkpoint(manifest: &ModelManifest, f1_millionths: u32) -> Result<Self> {
        let binding = manifest.binding(ModelRole::ExtractionTeacher)?;
        let approval = Self {
            probe_id: TEACHER_PROBE_ID.into(),
            model: binding.model.clone(),
            binding_hash: binding_hash(binding)?,
            f1_millionths,
        };
        approval.verify(manifest)?;
        Ok(approval)
    }

    pub fn load(path: &Path) -> Result<Self> {
        serde_json::from_slice(&std::fs::read(path)?)
            .map_err(|e| invalid(&format!("invalid teacher probe approval: {e}")))
    }

    pub fn verify(&self, manifest: &ModelManifest) -> Result<()> {
        let binding = manifest.binding(ModelRole::ExtractionTeacher)?;
        if self.probe_id != TEACHER_PROBE_ID
            || self.f1_millionths < TEACHER_PROBE_MIN_F1
            || self.f1_millionths > 1_000_000
            || self.model != binding.model
            || !binding.route_models.is_empty()
            || self.binding_hash != binding_hash(binding)?
        {
            return Err(invalid(
                "extraction_teacher requires matching passing probe approval and no route overrides",
            ));
        }
        Ok(())
    }
}
