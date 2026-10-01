//! What a local checkpoint declares about itself, read from its metadata files
//! alone: the body, how it attends, the module chain, the prompts.
//!
//! This is the whole of the provider's knowledge of a model. Nothing names one:
//! a checkpoint with a Qwen3 body and a sentence-transformers chain this
//! provider implements needs only its repository and commit in config.

use std::path::Path;

use super::prompts::{self, Prompts};
use super::qwen3_embedding::Config;
use super::st_modules::Chain;
use crate::config::{EmbedderAttention, EmbedderConfig};

/// A checkpoint, as its files and the host's overrides describe it.
#[derive(Clone, Debug)]
pub(super) struct LocalModelSpec {
    /// `config.json`, with the attention the body will run.
    pub(super) body: Config,
    pub(super) chain: Chain,
    pub(super) prompts: Prompts,
}

impl LocalModelSpec {
    /// Reads every metadata file the provider needs and checks them against
    /// the configured width and input cap. Weights are not touched.
    pub(super) fn read(model_dir: &Path, config: &EmbedderConfig) -> oneiron::Result<Self> {
        let raw = std::fs::read_to_string(model_dir.join("config.json")).map_err(|e| {
            oneiron::Error::InvalidConfig(format!("embedder model config.json: {e}"))
        })?;
        let declared = Config::parse(&raw)?;
        let body = match config.local.attention {
            EmbedderAttention::Auto => declared,
            EmbedderAttention::Causal => declared.attending(true),
            EmbedderAttention::Bidirectional => declared.attending(false),
        };
        let chain = Chain::read(model_dir, config.local.output_quantization)?;
        let prompts = prompts::resolve(
            model_dir,
            config.query_instruction.as_deref(),
            config.query_prompt_name.as_deref(),
        )?;
        super::check_dimensions(config, &body, &chain)?;
        super::check_input_window(config, &body)?;
        Ok(Self {
            body,
            chain,
            prompts,
        })
    }
}
