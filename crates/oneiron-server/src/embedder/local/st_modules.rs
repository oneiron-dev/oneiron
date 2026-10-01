//! The sentence-transformers module chain that turns hidden states into one
//! vector per input.
//!
//! Rebuilt from mistral.rs's `embedding_models/layers.rs` — see
//! `NOTICE-mistralrs.md`. The model's own `modules.json` declares the chain, so
//! the chain is read rather than assumed: a checkpoint that pools differently
//! would otherwise be embedded into a different space while reporting the same
//! `model_id`.

use candle_core::{DType, Tensor};
use serde::Deserialize;

use super::attention::l2_normalize;
use super::qwen3_embedding::Model;

/// One entry of `modules.json`.
#[derive(Clone, Debug, Deserialize)]
struct ModuleEntry {
    #[serde(rename = "type")]
    module_type: String,
    path: String,
}

/// `1_Pooling/config.json`, field for field as sentence-transformers writes it.
#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(default)]
pub(super) struct Pooling {
    pub(super) word_embedding_dimension: usize,
    pub(super) pooling_mode_cls_token: bool,
    pub(super) pooling_mode_mean_tokens: bool,
    pub(super) pooling_mode_max_tokens: bool,
    pub(super) pooling_mode_mean_sqrt_len_tokens: bool,
    pub(super) pooling_mode_weightedmean_tokens: bool,
    pub(super) pooling_mode_lasttoken: bool,
    pub(super) include_prompt: bool,
}

/// The pooling modes this provider implements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PoolingMode {
    /// The hidden state of the final token.
    LastToken,
    /// The mean over tokens. Exact over every row, because the provider never
    /// pads a group: there is no pad row for a mask to exclude.
    Mean,
}

/// A module after pooling, applied in the order `modules.json` declares it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
    /// `Normalize`: every row to unit length.
    Normalize,
    /// `FlexibleQuantizer` at its default `int8`: `tanh`, scaled by 127,
    /// rounded and clamped to `[-128, 127]`. The integers are the model's
    /// output, compared by cosine; the provider's own normalisation turns them
    /// into the unit vector every provider returns.
    Int8Tanh,
}

/// The one quantisation a `FlexibleQuantizer` applies when the caller passes
/// none, which is what `encode` does unless it is told otherwise.
const INT8_TANH_SCALE: f64 = 127.0;

impl Pooling {
    fn mode(self) -> oneiron::Result<PoolingMode> {
        if self.pooling_mode_lasttoken {
            return Ok(PoolingMode::LastToken);
        }
        if self.pooling_mode_mean_tokens {
            return Ok(PoolingMode::Mean);
        }
        // Named, not silently defaulted: pooling decides where the vector lands
        // in the space, so guessing it would corrupt a whole vault quietly.
        Err(oneiron::Error::InvalidConfig(
            "embedder model pooling mode is not supported (expected lasttoken or mean)".to_owned(),
        ))
    }
}

/// The chain, ready to apply.
#[derive(Debug)]
pub(super) struct StModules {
    mode: PoolingMode,
    steps: Vec<Step>,
    dimensions: usize,
}

impl StModules {
    /// Reads `modules.json` and the pooling config beside it.
    pub(super) fn load(model_dir: &std::path::Path) -> oneiron::Result<Self> {
        let raw = std::fs::read_to_string(model_dir.join("modules.json"))
            .map_err(|e| missing("modules.json", &e.to_string()))?;
        let entries: Vec<ModuleEntry> =
            serde_json::from_str(&raw).map_err(|e| missing("modules.json", &e.to_string()))?;
        let mut chain = entries
            .iter()
            .map(|entry| (short_type(&entry.module_type), entry));
        let Some(("Transformer", _)) = chain.next() else {
            return Err(oneiron::Error::InvalidConfig(
                "embedder model modules.json must start with a Transformer module".to_owned(),
            ));
        };
        let mut pooling: Option<Pooling> = None;
        let mut steps = Vec::new();
        for (kind, entry) in chain {
            match kind {
                "Pooling" => pooling = Some(read_pooling(model_dir, &entry.path)?),
                "Normalize" => steps.push(Step::Normalize),
                "FlexibleQuantizer" => steps.push(Step::Int8Tanh),
                // A Dense head would project into a different width, so it is
                // refused rather than ignored. No identity-Dense checkpoint is
                // in play today; one would arrive as a new accepted case with
                // its own test, not as a silent pass-through.
                other => {
                    return Err(oneiron::Error::InvalidConfig(format!(
                        "embedder model module {other:?} is not supported"
                    )));
                }
            }
        }
        let pooling = pooling.ok_or_else(|| {
            oneiron::Error::InvalidConfig(
                "embedder model modules.json declares no Pooling module".to_owned(),
            )
        })?;
        Ok(Self {
            mode: pooling.mode()?,
            steps,
            dimensions: pooling.word_embedding_dimension,
        })
    }

    /// Declared output width, checked against the configured `dimensions`.
    pub(super) fn dimensions(&self) -> usize {
        self.dimensions
    }

    /// `[batch, seq, hidden]` hidden states to `[batch, hidden]` vectors.
    ///
    /// Runs in f32 whatever the forward pass ran in: a mean over thousands of
    /// rows, or a rounding to integers, done in bf16 would move the vector by
    /// more than the weights' own precision does.
    pub(super) fn apply(&self, hidden: &Tensor) -> candle_core::Result<Tensor> {
        let hidden = hidden.to_dtype(DType::F32)?;
        let mut pooled = match self.mode {
            PoolingMode::LastToken => Model::last_rows(&hidden)?,
            PoolingMode::Mean => hidden.mean(1)?,
        };
        for step in &self.steps {
            pooled = match step {
                Step::Normalize => l2_normalize(&pooled)?,
                Step::Int8Tanh => (pooled.tanh()? * INT8_TANH_SCALE)?
                    .round()?
                    .clamp(-128f32, 127f32)?,
            };
        }
        Ok(pooled)
    }
}

/// `sentence_transformers.models.Pooling` and `Pooling` both name the same
/// module; the upstream loader accepts either spelling and so does this one.
fn short_type(module_type: &str) -> &str {
    module_type.rsplit('.').next().unwrap_or(module_type)
}

fn read_pooling(model_dir: &std::path::Path, path: &str) -> oneiron::Result<Pooling> {
    let file = model_dir.join(path).join("config.json");
    let raw = std::fs::read_to_string(&file)
        .map_err(|e| missing("Pooling config.json", &e.to_string()))?;
    serde_json::from_str(&raw).map_err(|e| missing("Pooling config.json", &e.to_string()))
}

fn missing(what: &str, reason: &str) -> oneiron::Error {
    oneiron::Error::InvalidConfig(format!("embedder model {what}: {reason}"))
}
