//! Custody-backed Qwen3/ST files loaded by the ordinary local runtime.

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::Vault;
use oneiron::embed::{Embedder, EmbeddingProvenance};
use oneiron::training_pack::{CheckpointFileKind, PinnedCheckpoint};
use tempfile::TempDir;

use super::LocalEmbedder;
use super::model_manager::ModelManager;
use super::qwen3_embedding::Config;
use super::st_modules::Chain;
use crate::config::{EmbedderAttention, EmbedderConfig, EmbedderOutputQuantization};
use crate::embedder::QueryEmbedder;

/// Both towers share the same runtime and exact private load set. The runtime
/// drops before the directory, and no caller can clone its inner provider out.
pub(crate) struct CheckpointEmbedder {
    inner: Arc<LocalEmbedder>,
    checkpoint: PinnedCheckpoint,
    hash: [u8; 32],
    _dir: TempDir,
}

impl CheckpointEmbedder {
    /// Blocking. All files come from immutable custody, never a host directory
    /// or a network. Missing or unsupported inputs fail through the local loader.
    pub(crate) fn load(
        vault: &Vault,
        checkpoint: &PinnedCheckpoint,
        host: &EmbedderConfig,
    ) -> oneiron::Result<Arc<Self>> {
        let hash = checkpoint.content_hash()?;
        let hex = blake3::Hash::from(hash).to_hex().to_string();
        let temp = tempfile::tempdir().map_err(oneiron::Error::Io)?;
        let dir = temp.path().to_path_buf();
        let mut seen = BTreeSet::new();
        for file in &checkpoint.files {
            check_name(&file.name, file.kind)?;
            if !seen.insert(&file.name) {
                return Err(oneiron::Error::InvalidConfig(
                    "duplicate checkpoint file name".into(),
                ));
            }
            let bytes = vault.read_training_artifact(&file.content)?;
            if bytes.len() as u64 != file.content.bytes
                || *blake3::hash(&bytes).as_bytes() != file.content.blake3
            {
                return Err(oneiron::Error::InvalidConfig(
                    "training artifact content hash or length mismatch".into(),
                ));
            }
            let dest = dir.join(&file.name);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent).map_err(oneiron::Error::Io)?;
            }
            std::fs::write(&dest, &bytes).map_err(oneiron::Error::Io)?;
        }
        let raw = std::fs::read_to_string(dir.join("config.json")).map_err(|e| {
            oneiron::Error::InvalidConfig(format!("embedder model config.json: {e}"))
        })?;
        let body = Config::parse(&raw)?;
        let chain = Chain::read(&dir, EmbedderOutputQuantization::Int8)?;
        let mut offline = host.clone();
        offline.model_id = checkpoint.model.as_str().to_owned();
        offline.dimensions = chain.dimensions();
        offline.max_input_tokens = host.max_input_tokens.min(body.max_position_embeddings);
        // Runtime policy is the host's; function overrides are not the incumbent's.
        offline.query_instruction = None;
        offline.query_prompt_name = None;
        offline.local.model_dir = Some(dir);
        offline.local.attention = EmbedderAttention::Auto;
        offline.local.output_quantization = EmbedderOutputQuantization::Int8;
        offline.local.repo = checkpoint.model.as_str().to_owned();
        offline.local.revision = hex;
        let inner = LocalEmbedder::load(&offline, &ModelManager::default())?;
        Ok(Arc::new(Self {
            inner,
            checkpoint: checkpoint.clone(),
            hash,
            _dir: temp,
        }))
    }

    pub(crate) fn model_id(&self) -> &str {
        self.checkpoint.model.as_str()
    }

    pub(crate) fn dimensions(&self) -> usize {
        self.inner.dimensions()
    }

    pub(crate) fn checkpoint_hash(&self) -> [u8; 32] {
        self.hash
    }

    pub(crate) fn provenance(&self) -> EmbeddingProvenance {
        self.inner.provenance()
    }

    pub(crate) fn query(&self, text: &str) -> oneiron::Result<Vec<f32>> {
        self.inner.embed_query(text)
    }

    pub(crate) fn document(&self, text: &str) -> oneiron::Result<Vec<f32>> {
        let (mut vectors, _) = self.inner.embed_documents(&[text.to_owned()])?;
        vectors.pop().ok_or(oneiron::Error::InvariantViolation(
            "embedder answered a single document with no row",
        ))
    }
}

fn check_name(name: &str, kind: CheckpointFileKind) -> oneiron::Result<()> {
    if name.is_empty()
        || name.starts_with('/')
        || name.contains('\\')
        || name.chars().any(char::is_control)
        || name.split('/').any(|part| matches!(part, "" | "." | ".."))
        || (kind == CheckpointFileKind::Weights && !name.ends_with(".safetensors"))
    {
        return Err(oneiron::Error::InvalidConfig(
            "checkpoint files need relative names; weights must be safetensors".into(),
        ));
    }
    Ok(())
}
