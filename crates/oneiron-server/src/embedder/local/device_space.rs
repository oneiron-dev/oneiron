//! The model a device text space names (DEC-0005 #private-world-vectors;
//! census L5-26): the small model a private world embeds its rows with, run
//! in this process by the same loader as the vault's own local model.
//!
//! A space `<org>/<name>@<commit>@device` names the Hugging Face repository
//! `<org>/<name>` at that commit, as the vault's own local model names
//! itself (`repo@revision`). Its files download on the first embedding pass
//! that needs them, resumable, into the host's models root, and never at
//! boot. A repository that is not a shipped default runs unpinned by digest,
//! as any other does ([`model_manager`]). The commit is required: a branch
//! or a tag could move to other weights under the same space id, so a space
//! naming one is refused (L5-26-SOURCE = A, Engine 14 Nov 03:02).

use std::sync::Arc;

use oneiron::ModelId;
use oneiron::embed::{DEVICE_PLACE, Embedder, EmbeddingProvenance, EmbeddingSpace};

use super::LocalEmbedder;
use super::model_manager::{self, ModelManager, is_commit};
use super::qwen3_embedding::Config;
use crate::config::{EmbedderAttention, EmbedderConfig, EmbedderOutputQuantization};
use crate::embedder::QueryEmbedder;

/// A device text space's model, loaded. Its query and document towers share
/// one runtime.
pub(crate) struct DeviceSpaceModel {
    inner: Arc<LocalEmbedder>,
}

impl DeviceSpaceModel {
    /// The local settings that run `space`'s model on this host: the
    /// repository and commit its id names, its width, and the host's own
    /// device, threads, quantisation and models root. Nothing is read or
    /// fetched.
    ///
    /// # Errors
    ///
    /// [`oneiron::Error::InvalidConfig`] for a space whose id is not
    /// `<org>/<name>@<commit>@device` with a full commit, or whose repository
    /// and commit are not plain path segments.
    pub(crate) fn config_for(
        space: &EmbeddingSpace,
        host: &EmbedderConfig,
    ) -> oneiron::Result<EmbedderConfig> {
        let refused = || {
            oneiron::Error::InvalidConfig(format!(
                "embedding space {} names no device model: its id is <org>/<name>@<40-hex commit>@{DEVICE_PLACE}, a Hugging Face repository at a full commit",
                space.id
            ))
        };
        let (pinned, place) = space.id.rsplit_once('@').ok_or_else(refused)?;
        if place != DEVICE_PLACE {
            return Err(refused());
        }
        let model = ModelId::new(pinned).map_err(|_| refused())?;
        if !is_commit(model.revision()) {
            return Err(refused());
        }
        let mut config = host.clone();
        config.model_id = model.as_str().to_owned();
        config.dimensions = space.dimensions;
        // The vault's own model's prompts and attention are not this model's.
        config.query_instruction = None;
        config.query_prompt_name = None;
        config.local.repo = format!("{}/{}", model.provider(), model.name());
        config.local.revision = model.revision().to_owned();
        config.local.model_dir = None;
        config.local.attention = EmbedderAttention::Auto;
        config.local.output_quantization = EmbedderOutputQuantization::default();
        model_manager::model_dir(&config.local)?;
        Ok(config)
    }

    /// Whether the model's files are on this machine already, verified: a
    /// machine that embedded the space's rows before. Nothing is fetched.
    pub(crate) fn on_disk(config: &EmbedderConfig) -> bool {
        model_manager::verified_metadata_dir(&config.local).is_some()
    }

    /// Fetches what is missing, then loads the model, its input cap held to
    /// the window the model declares. Blocking and slow by nature: a first
    /// load downloads the files.
    ///
    /// # Errors
    ///
    /// A fetch, a file the loader refuses, or a model whose output width is
    /// not the space's.
    pub(crate) fn load(config: &EmbedderConfig) -> oneiron::Result<Arc<Self>> {
        let models = ModelManager::default();
        let dir = models.ensure_metadata(&config.local)?;
        let raw = std::fs::read_to_string(dir.join("config.json")).map_err(|error| {
            oneiron::Error::InvalidConfig(format!("device space model config.json: {error}"))
        })?;
        let window = Config::parse(&raw)?.max_position_embeddings;
        let mut config = config.clone();
        config.max_input_tokens = config.max_input_tokens.min(window);
        Ok(Arc::new(Self {
            inner: LocalEmbedder::load(&config, &models)?,
        }))
    }

    /// The device and runtime that compute its vectors.
    pub(crate) fn provenance(&self) -> EmbeddingProvenance {
        self.inner.provenance()
    }

    /// One query through the query tower.
    pub(crate) fn query(&self, text: &str) -> oneiron::Result<Vec<f32>> {
        self.inner.embed_query(text)
    }

    /// One stored document through the document tower.
    pub(crate) fn document(&self, text: &str) -> oneiron::Result<Vec<f32>> {
        let (mut vectors, _) = self.inner.embed_documents(&[text.to_owned()])?;
        vectors.pop().ok_or(oneiron::Error::InvariantViolation(
            "device space model answered a single document with no row",
        ))
    }
}
