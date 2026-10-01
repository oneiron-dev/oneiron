//! What a local checkpoint declares about itself, read from its metadata files
//! alone: the body, how it attends, the module chain, the prompts.
//!
//! This is the whole of the provider's knowledge of a model. Nothing names one:
//! a checkpoint with a Qwen3 body and a sentence-transformers chain this
//! provider implements needs only its repository and commit in config.

use std::path::Path;

use super::prompts::{self, Prompts};
use super::qwen3_embedding::Config;
use super::st_modules::{Chain, PoolingMode, Step};
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

    /// The embedding-transform descriptor the vault pins beside the model id:
    /// everything the files and the host's overrides say that moves a stored
    /// document vector — attention, pooling, each step after it with every
    /// setting the runtime reads for it (a Dense module's directory, widths,
    /// activation and bias), the document prompt and the width. Query-only
    /// settings, weight precision, device and batch size move no stored vector
    /// and are left out.
    ///
    /// The input cap (`max_input_tokens`) is left out on purpose. It decides
    /// how much of a long document is read, not the space the vector lands in:
    /// a vector made under another cap is still comparable with every query,
    /// the same class of difference as weight precision.
    pub(super) fn transform(&self) -> String {
        let attention = if self.body.causal() {
            "causal"
        } else {
            "bidirectional"
        };
        let pool = match self.chain.pooling.mode {
            PoolingMode::LastToken => "lasttoken",
            PoolingMode::Mean => "mean",
            PoolingMode::Cls => "cls",
        };
        let document_prompt = if self.prompts.document.is_empty() {
            "none".to_owned()
        } else {
            serde_json::Value::from(self.prompts.document.as_str()).to_string()
        };
        let steps: Vec<String> = self
            .chain
            .steps
            .iter()
            .map(|step| match step {
                Step::Normalize => "normalize".to_owned(),
                Step::Int8Tanh => "quantize:int8".to_owned(),
                Step::BinaryTanh => "quantize:binary".to_owned(),
                Step::Dense {
                    path,
                    in_features,
                    out_features,
                    bias,
                    tanh,
                } => format!(
                    "dense:path={}:{in_features}>{out_features}:{}:bias={bias}",
                    serde_json::Value::from(path.as_str()),
                    if *tanh { "tanh" } else { "identity" }
                ),
            })
            .collect();
        let chain = if steps.is_empty() {
            "none".to_owned()
        } else {
            steps.join(",")
        };
        format!(
            "attn={attention};pool={pool};include_prompt={};doc_prompt={document_prompt};chain={chain};dims={}",
            self.chain.pooling.include_prompt,
            self.chain.dimensions()
        )
    }
}
