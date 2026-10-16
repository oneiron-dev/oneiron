//! Offline interchange with the model project. Checkpoints are opaque packed artifacts;
//! this module pins and admits them, but never trains weights or serves the teacher.
use super::{
    ModelBinding, ModelManifest, ModelRole, ModelSlot, TEACHER_APPROVAL, TeacherProbeApproval,
    TeacherProbePolicy, invalid,
};
use crate::side_table::{self, Named, SideTable};
use crate::{Vault, error::Result, llm::ModelId};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::Write, path::Path};

pub(super) const ENCODER_EXPORT: SideTable<(), EncoderExport, Named> =
    SideTable::new(&side_table::LLM_ENCODER_EXPORT);

/// A revisioned identity plus the BLAKE3 of one packed checkpoint file, including
/// its tokenizer, configuration and heads. The model project owns that format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointPin {
    pub model: ModelId,
    pub checkpoint_blake3: String,
}

impl CheckpointPin {
    pub fn from_file(model: ModelId, path: &Path) -> Result<Self> {
        Ok(Self {
            model,
            checkpoint_blake3: checkpoint_hash(path)?,
        })
    }

    pub fn verify_file(&self, path: &Path) -> Result<()> {
        valid_digest(&self.checkpoint_blake3)?;
        if self.checkpoint_blake3 != checkpoint_hash(path)? {
            return Err(invalid(
                "checkpoint artifact does not match its content pin",
            ));
        }
        Ok(())
    }
}

/// Lineage declared by the trusted model-project runner, not inferred from names
/// or weights by the engine. Both forks name the same explicit base artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedBaseFork {
    pub base: CheckpointPin,
    pub reasoner: CheckpointPin,
    pub teacher: CheckpointPin,
}

/// One offline job, targeting a candidate manifest's extraction encoder. Export
/// one job for each desired student; tier selection stays with the manifest.
/// Recipe and corpus hashes name model-project inputs, never raw vault text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncoderDistillationRequest {
    pub fork: SharedBaseFork,
    pub teacher_approval: TeacherProbeApproval,
    pub encoder: ModelBinding,
    pub recipe_blake3: String,
    pub corpus_blake3: String,
}

impl EncoderDistillationRequest {
    pub fn load(path: &Path) -> Result<Self> {
        let request: Self = serde_json::from_slice(&std::fs::read(path)?)
            .map_err(|e| invalid(&format!("invalid encoder distillation request: {e}")))?;
        request.validate_pins()?;
        Ok(request)
    }

    fn validate_pins(&self) -> Result<()> {
        for digest in [
            &self.fork.base.checkpoint_blake3,
            &self.fork.reasoner.checkpoint_blake3,
            &self.fork.teacher.checkpoint_blake3,
            &self.recipe_blake3,
            &self.corpus_blake3,
        ] {
            valid_digest(digest)?;
        }
        if self.encoder.slot != ModelSlot::Oneironer
            || !self.encoder.route_models.is_empty()
            || self.encoder.model == self.fork.teacher.model
            || self.encoder.model == self.fork.reasoner.model
        {
            return Err(invalid(
                "distillation requires a separate single-checkpoint Oneironer student",
            ));
        }
        Ok(())
    }

    pub fn verify(&self, manifest: &ModelManifest, policy: &TeacherProbePolicy) -> Result<()> {
        self.validate_pins()?;
        manifest.validate()?;
        self.teacher_approval.verify(manifest, policy)?;
        if self.fork.teacher.model != manifest.binding(ModelRole::ExtractionTeacher)?.model
            || self.fork.reasoner.model != manifest.binding(ModelRole::GenerativeReasoner)?.model
            || &self.encoder != manifest.binding(ModelRole::ExtractionEncoder)?
        {
            return Err(invalid(
                "distillation pins do not match candidate manifest roles",
            ));
        }
        Ok(())
    }

    /// Let the offline runner check the exact artifacts before beginning a job.
    /// The engine never opens these large source checkpoints on a serving path.
    pub fn verify_source_checkpoints(
        &self,
        base: &Path,
        reasoner: &Path,
        teacher: &Path,
    ) -> Result<()> {
        self.validate_pins()?;
        self.fork.base.verify_file(base)?;
        self.fork.reasoner.verify_file(reasoner)?;
        self.fork.teacher.verify_file(teacher)
    }

    pub fn identity_hash(&self) -> Result<String> {
        self.validate_pins()?;
        json_hash(self)
    }

    /// Write metadata for an external offline runner, not an inference request.
    /// The supplied policy is a snapshot; publication rechecks live vault policy.
    pub fn write(
        &self,
        manifest: &ModelManifest,
        policy: &TeacherProbePolicy,
        path: &Path,
    ) -> Result<()> {
        self.verify(manifest, policy)?;
        write_json(self, path)
    }
}

/// Model-project output bound to one exact job and its actual packed student.
/// Like the teacher probe approval, this is an operator receipt, not a signature
/// or a claim that Rust inspected training quality or proved model lineage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncoderExport {
    pub request: EncoderDistillationRequest,
    pub request_blake3: String,
    pub checkpoint: CheckpointPin,
}

impl EncoderExport {
    /// Call only after the model project has produced a real trained checkpoint.
    pub fn from_checkpoint(request: EncoderDistillationRequest, path: &Path) -> Result<Self> {
        let export = Self {
            request_blake3: request.identity_hash()?,
            checkpoint: CheckpointPin::from_file(request.encoder.model.clone(), path)?,
            request,
        };
        export.validate_pins()?;
        Ok(export)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let export: Self = serde_json::from_slice(&std::fs::read(path)?)
            .map_err(|e| invalid(&format!("invalid encoder export: {e}")))?;
        export.validate_pins()?;
        Ok(export)
    }

    fn validate_pins(&self) -> Result<()> {
        valid_digest(&self.request_blake3)?;
        valid_digest(&self.checkpoint.checkpoint_blake3)?;
        if self.request_blake3 != self.request.identity_hash()?
            || self.checkpoint.model != self.request.encoder.model
        {
            return Err(invalid(
                "encoder export does not match its distillation request",
            ));
        }
        Ok(())
    }

    pub fn verify(&self, manifest: &ModelManifest, policy: &TeacherProbePolicy) -> Result<()> {
        self.validate_pins()?;
        self.request.verify(manifest, policy)
    }

    pub fn verify_checkpoint(&self, path: &Path) -> Result<()> {
        self.validate_pins()?;
        self.checkpoint.verify_file(path)
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        self.validate_pins()?;
        write_json(self, path)
    }
}

impl Vault {
    /// Prepare a job using the already-admitted teacher receipt and live policy.
    /// The candidate may change the student without repinning the teacher.
    pub fn encoder_distillation_request(
        &self,
        candidate: &ModelManifest,
        fork: SharedBaseFork,
        recipe_blake3: String,
        corpus_blake3: String,
    ) -> Result<EncoderDistillationRequest> {
        let txn = self.store.env.read_txn()?;
        let approval = TEACHER_APPROVAL
            .get(&self.store, &txn, &())?
            .ok_or_else(|| invalid("distillation requires an approved extraction teacher"))?;
        let policy = self.teacher_probe_policy_in_txn(&txn, approval.holder_ref.as_deref())?;
        let request = EncoderDistillationRequest {
            fork,
            teacher_approval: approval,
            encoder: candidate.binding(ModelRole::ExtractionEncoder)?.clone(),
            recipe_blake3,
            corpus_blake3,
        };
        request.verify(candidate, &policy)?;
        Ok(request)
    }

    /// Verify the produced artifact, then atomically pin the encoder, its training
    /// provenance and the manifest under the current teacher-probe policy.
    pub fn set_model_manifest_with_encoder_export(
        &self,
        manifest: &ModelManifest,
        export: &EncoderExport,
        checkpoint_path: &Path,
    ) -> Result<()> {
        export.verify_checkpoint(checkpoint_path)?;
        self.write_model_manifest(manifest, None, Some(export))
    }

    /// Provenance of the currently pinned distilled encoder, if installed through
    /// the export door. A normal manifest update clears a no-longer-matching row.
    pub fn encoder_export(&self) -> Result<Option<EncoderExport>> {
        ENCODER_EXPORT.get(&self.store, &self.store.env.read_txn()?, &())
    }
}

fn valid_digest(digest: &str) -> Result<()> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("artifact pin must be a lowercase BLAKE3 digest"));
    }
    Ok(())
}

fn checkpoint_hash(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(invalid(
            "checkpoint must be a nonempty packed artifact file",
        ));
    }
    let mut hasher = blake3::Hasher::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(hasher.finalize().to_hex().to_string())
}

fn json_hash(value: &impl Serialize) -> Result<String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|e| invalid(&format!("distillation identity serialization failed: {e}")))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn write_json(value: &impl Serialize, path: &Path) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| invalid(&format!("encoder export serialization failed: {e}")))?;
    let mut file = File::options().write(true).create_new(true).open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}
