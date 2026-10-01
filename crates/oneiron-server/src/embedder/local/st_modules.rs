//! The sentence-transformers module chain that turns hidden states into one
//! vector per input.
//!
//! Rebuilt from mistral.rs's `embedding_models/layers.rs` — see
//! `NOTICE-mistralrs.md`. The model's own `modules.json` declares the chain, so
//! the chain is read rather than assumed: a checkpoint that pools differently
//! would otherwise be embedded into a different space while reporting the same
//! `model_id`. Every module this provider implements is named here once, by
//! its sentence-transformers type; any other module is refused by name.

use std::path::Path;

use candle_core::{DType, Device, Tensor};
use candle_nn::{Linear, Module, VarBuilder};
use serde::Deserialize;

use super::attention::l2_normalize;
use super::qwen3_embedding::Model;
use crate::config::EmbedderOutputQuantization;

/// One entry of `modules.json`.
#[derive(Clone, Debug, Deserialize)]
struct ModuleEntry {
    #[serde(rename = "type")]
    module_type: String,
    path: String,
}

/// A module kind this provider implements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Transformer,
    Pooling,
    Dense,
    Normalize,
    /// `st_quantize.FlexibleQuantizer`: tanh quantisation to int8 or binary.
    FlexibleQuantizer,
}

impl Kind {
    fn parse(module_type: &str) -> oneiron::Result<Self> {
        // `sentence_transformers.models.Pooling` and `Pooling` both name the
        // same module; the upstream loader accepts either spelling and so does
        // this one.
        match module_type.rsplit('.').next().unwrap_or(module_type) {
            "Transformer" => Ok(Self::Transformer),
            "Pooling" => Ok(Self::Pooling),
            "Dense" => Ok(Self::Dense),
            "Normalize" => Ok(Self::Normalize),
            "FlexibleQuantizer" => Ok(Self::FlexibleQuantizer),
            _ => Err(oneiron::Error::InvalidConfig(format!(
                "embedder model module {module_type:?} is not supported (expected Transformer, Pooling, Dense, Normalize or FlexibleQuantizer)"
            ))),
        }
    }

    /// Files this module reads under its own directory.
    const fn files(self) -> &'static [&'static str] {
        match self {
            Self::Pooling => &["config.json"],
            Self::Dense => &["config.json", "model.safetensors"],
            Self::Transformer | Self::Normalize | Self::FlexibleQuantizer => &[],
        }
    }
}

/// `modules.json`, parsed and checked for shape: a Transformer first, then
/// only modules this provider implements.
fn parse_entries(raw: &str) -> oneiron::Result<Vec<(Kind, String)>> {
    let entries: Vec<ModuleEntry> =
        serde_json::from_str(raw).map_err(|e| missing("modules.json", &e.to_string()))?;
    let kinds = entries
        .into_iter()
        .map(|entry| Ok((Kind::parse(&entry.module_type)?, entry.path)))
        .collect::<oneiron::Result<Vec<_>>>()?;
    if kinds.first().map(|(kind, _)| *kind) != Some(Kind::Transformer) {
        return Err(oneiron::Error::InvalidConfig(
            "embedder model modules.json must start with a Transformer module".to_owned(),
        ));
    }
    Ok(kinds)
}

/// The files `modules.json` says the chain reads, relative to the model
/// directory. The artifact manager fetches exactly these beside the body's
/// own, so a checkpoint whose chain is refused is refused before its weights
/// are downloaded.
pub(super) fn module_files(raw_modules_json: &str) -> oneiron::Result<Vec<String>> {
    Ok(parse_entries(raw_modules_json)?
        .into_iter()
        .flat_map(|(kind, path)| {
            kind.files().iter().map(move |file| {
                if path.is_empty() {
                    (*file).to_owned()
                } else {
                    format!("{path}/{file}")
                }
            })
        })
        .collect())
}

/// `1_Pooling/config.json`, field for field as sentence-transformers writes it.
#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(default)]
struct PoolingConfig {
    word_embedding_dimension: usize,
    pooling_mode_cls_token: bool,
    pooling_mode_mean_tokens: bool,
    pooling_mode_max_tokens: bool,
    pooling_mode_mean_sqrt_len_tokens: bool,
    pooling_mode_weightedmean_tokens: bool,
    pooling_mode_lasttoken: bool,
    include_prompt: bool,
}

/// The pooling modes this provider implements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PoolingMode {
    /// The hidden state of the final token.
    LastToken,
    /// The mean over tokens. A masked mean by construction: the provider never
    /// pads a group, so every row is a real token, and a prompt the model
    /// excludes (`include_prompt: false`) is skipped explicitly.
    Mean,
    /// The hidden state of the first token.
    Cls,
}

/// The Pooling module, resolved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Pooling {
    pub(super) mode: PoolingMode,
    /// Whether the prompt's tokens count toward the pool.
    pub(super) include_prompt: bool,
    /// The width the pool emits: the body's hidden size.
    pub(super) width: usize,
}

impl PoolingConfig {
    /// Exactly one mode this provider implements, or a refusal naming them.
    ///
    /// Named, not silently defaulted: pooling decides where the vector lands in
    /// the space, so guessing it would corrupt a whole vault quietly.
    fn resolve(self) -> oneiron::Result<Pooling> {
        let declared = [
            (
                "lasttoken",
                self.pooling_mode_lasttoken,
                Some(PoolingMode::LastToken),
            ),
            (
                "mean_tokens",
                self.pooling_mode_mean_tokens,
                Some(PoolingMode::Mean),
            ),
            (
                "cls_token",
                self.pooling_mode_cls_token,
                Some(PoolingMode::Cls),
            ),
            ("max_tokens", self.pooling_mode_max_tokens, None),
            (
                "mean_sqrt_len_tokens",
                self.pooling_mode_mean_sqrt_len_tokens,
                None,
            ),
            (
                "weightedmean_tokens",
                self.pooling_mode_weightedmean_tokens,
                None,
            ),
        ];
        let set: Vec<_> = declared.iter().filter(|(_, on, _)| *on).collect();
        let [(name, _, mode)] = set.as_slice() else {
            let names: Vec<&str> = set.iter().map(|(name, _, _)| *name).collect();
            return Err(oneiron::Error::InvalidConfig(format!(
                "embedder model pooling declares {names:?}; exactly one of lasttoken, mean_tokens or cls_token is supported"
            )));
        };
        let Some(mode) = mode else {
            return Err(oneiron::Error::InvalidConfig(format!(
                "embedder model pooling mode {name} is not supported (expected lasttoken, mean_tokens or cls_token)"
            )));
        };
        Ok(Pooling {
            mode: *mode,
            include_prompt: self.include_prompt,
            width: self.word_embedding_dimension,
        })
    }
}

/// `2_Dense/config.json`, as sentence-transformers writes it.
#[derive(Clone, Debug, Deserialize)]
struct DenseConfig {
    in_features: usize,
    out_features: usize,
    #[serde(default = "default_true")]
    bias: bool,
    /// sentence-transformers' own default when the key is absent.
    #[serde(default = "default_dense_activation")]
    activation_function: String,
}

const fn default_true() -> bool {
    true
}

fn default_dense_activation() -> String {
    "torch.nn.modules.activation.Tanh".to_owned()
}

/// A module after pooling, applied in the order `modules.json` declares it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Step {
    /// `Normalize`: every row to unit length.
    Normalize,
    /// `FlexibleQuantizer` at `int8`: `tanh`, scaled by 127, rounded and
    /// clamped to `[-128, 127]`. The integers are the model's output, compared
    /// by cosine; the provider's own normalisation turns them into the unit
    /// vector every provider returns.
    Int8Tanh,
    /// `FlexibleQuantizer` at `binary`: `+1` where the value is `≥ 0`, else `-1`.
    BinaryTanh,
    /// `Dense`: a linear projection read from `<path>/model.safetensors`, then
    /// `tanh` when the module declares it.
    Dense {
        path: String,
        in_features: usize,
        out_features: usize,
        bias: bool,
        tanh: bool,
    },
}

/// The chain the checkpoint declares, read from its metadata files alone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Chain {
    pub(super) pooling: Pooling,
    pub(super) steps: Vec<Step>,
}

impl Chain {
    /// Reads `modules.json` and the module configs it names.
    pub(super) fn read(
        model_dir: &Path,
        quantization: EmbedderOutputQuantization,
    ) -> oneiron::Result<Self> {
        let raw = std::fs::read_to_string(model_dir.join("modules.json"))
            .map_err(|e| missing("modules.json", &e.to_string()))?;
        let mut pooling: Option<Pooling> = None;
        let mut steps = Vec::new();
        // The width flowing between modules, known once the pool declares it.
        let mut width: Option<usize> = None;
        for (kind, path) in parse_entries(&raw)?.into_iter().skip(1) {
            match kind {
                Kind::Transformer => {
                    return Err(oneiron::Error::InvalidConfig(
                        "embedder model modules.json declares a second Transformer".to_owned(),
                    ));
                }
                Kind::Pooling => {
                    let config: PoolingConfig = read_json(model_dir, &path, "Pooling")?;
                    let resolved = config.resolve()?;
                    width = Some(resolved.width);
                    pooling = Some(resolved);
                }
                Kind::Normalize => steps.push(Step::Normalize),
                Kind::FlexibleQuantizer => steps.push(match quantization {
                    EmbedderOutputQuantization::Int8 => Step::Int8Tanh,
                    EmbedderOutputQuantization::Binary => Step::BinaryTanh,
                }),
                Kind::Dense => {
                    let config: DenseConfig = read_json(model_dir, &path, "Dense")?;
                    let tanh = match config.activation_function.rsplit('.').next() {
                        Some("Identity") => false,
                        Some("Tanh") => true,
                        _ => {
                            return Err(oneiron::Error::InvalidConfig(format!(
                                "embedder model Dense activation {:?} is not supported (expected Identity or Tanh)",
                                config.activation_function
                            )));
                        }
                    };
                    if width != Some(config.in_features) {
                        return Err(oneiron::Error::InvalidConfig(format!(
                            "embedder model Dense takes {} features, but the chain carries {width:?} to it",
                            config.in_features
                        )));
                    }
                    width = Some(config.out_features);
                    steps.push(Step::Dense {
                        path,
                        in_features: config.in_features,
                        out_features: config.out_features,
                        bias: config.bias,
                        tanh,
                    });
                }
            }
        }
        let pooling = pooling.ok_or_else(|| {
            oneiron::Error::InvalidConfig(
                "embedder model modules.json declares no Pooling module".to_owned(),
            )
        })?;
        Ok(Self { pooling, steps })
    }

    /// The width the chain emits: the last Dense's output, else the pool's.
    pub(super) fn dimensions(&self) -> usize {
        self.steps
            .iter()
            .rev()
            .find_map(|step| match step {
                Step::Dense { out_features, .. } => Some(*out_features),
                _ => None,
            })
            .unwrap_or(self.pooling.width)
    }
}

/// A step ready to run.
enum Ready {
    Normalize,
    Int8Tanh,
    BinaryTanh,
    Dense { linear: Linear, tanh: bool },
}

/// The chain, ready to apply: Dense weights loaded onto the run device.
pub(super) struct StModules {
    chain: Chain,
    ready: Vec<Ready>,
}

impl StModules {
    pub(super) fn load(chain: Chain, model_dir: &Path, device: &Device) -> oneiron::Result<Self> {
        let ready = chain
            .steps
            .iter()
            .map(|step| {
                Ok(match step {
                    Step::Normalize => Ready::Normalize,
                    Step::Int8Tanh => Ready::Int8Tanh,
                    Step::BinaryTanh => Ready::BinaryTanh,
                    Step::Dense {
                        path,
                        in_features,
                        out_features,
                        bias,
                        tanh,
                    } => Ready::Dense {
                        linear: load_dense(
                            &model_dir.join(path).join("model.safetensors"),
                            (*out_features, *in_features),
                            *bias,
                            device,
                        )
                        .map_err(|e| missing("Dense model.safetensors", &e.to_string()))?,
                        tanh: *tanh,
                    },
                })
            })
            .collect::<oneiron::Result<_>>()?;
        Ok(Self { chain, ready })
    }

    /// What the checkpoint declared.
    pub(super) fn chain(&self) -> &Chain {
        &self.chain
    }

    /// `[batch, seq, hidden]` hidden states to `[batch, dimensions]` vectors.
    ///
    /// `prompt_tokens` leading rows belong to the prompt; a mean pool that
    /// excludes the prompt skips them. Runs in f32 whatever the forward pass
    /// ran in: a mean over thousands of rows, or a rounding to integers, done
    /// in bf16 would move the vector by more than the weights' own precision
    /// does.
    pub(super) fn apply(
        &self,
        hidden: &Tensor,
        prompt_tokens: usize,
    ) -> candle_core::Result<Tensor> {
        let hidden = hidden.to_dtype(DType::F32)?;
        let pooling = self.chain.pooling;
        let mut pooled = match pooling.mode {
            PoolingMode::LastToken => Model::last_rows(&hidden)?,
            PoolingMode::Cls => Model::first_rows(&hidden)?,
            PoolingMode::Mean if pooling.include_prompt || prompt_tokens == 0 => hidden.mean(1)?,
            PoolingMode::Mean => {
                let seq = hidden.dim(1)?;
                if prompt_tokens >= seq {
                    candle_core::bail!("the input is all prompt; nothing is left to pool");
                }
                hidden
                    .narrow(1, prompt_tokens, seq - prompt_tokens)?
                    .mean(1)?
            }
        };
        for step in &self.ready {
            pooled = match step {
                Ready::Normalize => l2_normalize(&pooled)?,
                Ready::Int8Tanh => (pooled.tanh()? * INT8_TANH_SCALE)?
                    .round()?
                    .clamp(-128f32, 127f32)?,
                Ready::BinaryTanh => ((pooled.ge(0f64)?.to_dtype(DType::F32)? * 2.0)? - 1.0)?,
                Ready::Dense { linear, tanh } => {
                    let projected = linear.forward(&pooled)?;
                    if *tanh { projected.tanh()? } else { projected }
                }
            };
        }
        Ok(pooled)
    }
}

/// The scale a `FlexibleQuantizer` maps `tanh` onto at `int8`.
const INT8_TANH_SCALE: f64 = 127.0;

/// Reads `linear.weight` (and `linear.bias`) at f32 onto the run device.
fn load_dense(
    file: &Path,
    shape: (usize, usize),
    bias: bool,
    device: &Device,
) -> candle_core::Result<Linear> {
    // SAFETY: memory-mapped read-only for the lifetime of the builder; the
    // artifact manager only ever renames a finished download into place.
    let vb = unsafe { VarBuilder::from_mmaped_safetensors(&[file], DType::F32, device)? };
    let weight = vb.get(shape, "linear.weight")?;
    let bias = bias.then(|| vb.get(shape.0, "linear.bias")).transpose()?;
    Ok(Linear::new(weight, bias))
}

fn read_json<T: serde::de::DeserializeOwned>(
    model_dir: &Path,
    path: &str,
    module: &str,
) -> oneiron::Result<T> {
    let what = format!("{module} config.json");
    let raw = std::fs::read_to_string(model_dir.join(path).join("config.json"))
        .map_err(|e| missing(&what, &e.to_string()))?;
    serde_json::from_str(&raw).map_err(|e| missing(&what, &e.to_string()))
}

fn missing(what: &str, reason: &str) -> oneiron::Error {
    oneiron::Error::InvalidConfig(format!("embedder model {what}: {reason}"))
}
