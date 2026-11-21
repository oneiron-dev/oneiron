//! Moved from `crates/oneiron/src/llm/manifest/encoder_export.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Result;
use oneiron_model::llm::ModelId;
use oneiron_model::model_binding::invalid;
use serde::Deserialize;
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::path::Path;

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

pub fn valid_digest(digest: &str) -> Result<()> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("artifact pin must be a lowercase BLAKE3 digest"));
    }
    Ok(())
}

pub fn checkpoint_hash(path: &Path) -> Result<String> {
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

pub fn json_hash(value: &impl Serialize) -> Result<String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|e| invalid(&format!("distillation identity serialization failed: {e}")))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

pub fn write_json(value: &impl Serialize, path: &Path) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| invalid(&format!("encoder export serialization failed: {e}")))?;
    let mut file = File::options().write(true).create_new(true).open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}
