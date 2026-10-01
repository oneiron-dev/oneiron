//! The sentence-transformers module chain that turns hidden states into one
//! vector per input.
//!
//! Rebuilt from mistral.rs's `embedding_models/layers.rs` — see
//! `NOTICE-mistralrs.md`. The model's own `modules.json` declares the chain, so
//! the chain is read rather than assumed: a checkpoint that pools differently
//! would otherwise be embedded into a different space while reporting the same
//! `model_id`. Every module this provider implements is named here once, by
//! its sentence-transformers type; any other module is refused by name.

use std::collections::BTreeMap;
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
    /// The module a `type` names, by its exact import path.
    ///
    /// Exact, never by the class name alone: `custom.Pooling` is somebody
    /// else's code, and running it with this provider's semantics would embed
    /// into a space the checkpoint's files do not describe.
    fn parse(module_type: &str) -> oneiron::Result<Self> {
        match module_type {
            "sentence_transformers.models.Transformer" => Ok(Self::Transformer),
            "sentence_transformers.models.Pooling" => Ok(Self::Pooling),
            "sentence_transformers.models.Dense" => Ok(Self::Dense),
            "sentence_transformers.models.Normalize" => Ok(Self::Normalize),
            // The quantizer a checkpoint ships beside its own weights, under
            // the import path its `modules.json` declares for it.
            "st_quantize.FlexibleQuantizer" => Ok(Self::FlexibleQuantizer),
            _ => Err(oneiron::Error::InvalidConfig(format!(
                "embedder model module {module_type:?} is not supported (expected sentence_transformers.models.Transformer, Pooling, Dense or Normalize, or st_quantize.FlexibleQuantizer)"
            ))),
        }
    }
}

/// A module's directory within the model, checked once when `modules.json` is
/// admitted and carried to every read and fetch after that.
///
/// Plain names only: no root, no prefix, no `.` or `..`, nothing a URL would
/// read as something other than a path segment. A `modules.json` therefore
/// cannot reach outside the directory the model's files live in, or pull
/// another revision's file in under this one's name. Symlinks are not refused:
/// a Hugging Face cache stores every file as one.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct ModulePath(String);

impl ModulePath {
    /// `""` and `"."` name the model directory itself.
    fn parse(raw: &str) -> oneiron::Result<Self> {
        if raw.is_empty() || raw == "." {
            return Ok(Self::default());
        }
        let plain = |segment: &str| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .chars()
                    .all(|c| !c.is_control() && !matches!(c, '\\' | ':' | '?' | '#' | '%'))
        };
        if !raw.split('/').all(plain) {
            return Err(oneiron::Error::InvalidConfig(format!(
                "embedder model module path {raw:?} is not a relative path of plain names"
            )));
        }
        Ok(Self(raw.to_owned()))
    }

    fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// The path as `modules.json` names it, `""` for the model directory.
    pub(super) fn as_str(&self) -> &str {
        &self.0
    }

    /// `file` under this module, as a path within the repository.
    fn file(&self, file: &str) -> String {
        if self.is_root() {
            file.to_owned()
        } else {
            format!("{}/{file}", self.0)
        }
    }
}

/// A module after pooling, as `modules.json` declares it.
enum Post {
    Normalize,
    FlexibleQuantizer,
    Dense(ModulePath),
}

/// `modules.json`, admitted: a Transformer at the model directory itself, then
/// exactly one Pooling, then only post-pooling modules this provider runs.
///
/// The runtime pools once and applies the rest in order, so a chain it would
/// have to reorder to run — a second pool, a step before the pool — is refused
/// rather than run as something other than what it declares.
struct Declared {
    pooling: ModulePath,
    post: Vec<Post>,
}

fn parse_entries(raw: &str) -> oneiron::Result<Declared> {
    let entries: Vec<ModuleEntry> =
        serde_json::from_str(raw).map_err(|e| missing("modules.json", &e.to_string()))?;
    let mut entries = entries.into_iter().map(|entry| {
        oneiron::Result::Ok((
            Kind::parse(&entry.module_type)?,
            ModulePath::parse(&entry.path)?,
        ))
    });
    match entries.next().transpose()? {
        // The body's files are read from the model directory itself.
        Some((Kind::Transformer, path)) if path.is_root() => {}
        Some((Kind::Transformer, path)) => {
            return Err(oneiron::Error::InvalidConfig(format!(
                "embedder model Transformer at {:?} is not supported; the body must sit at the model directory itself",
                path.0
            )));
        }
        _ => {
            return Err(oneiron::Error::InvalidConfig(
                "embedder model modules.json must start with a Transformer module".to_owned(),
            ));
        }
    }
    let mut pooling = None;
    let mut post = Vec::new();
    for entry in entries {
        let (kind, path) = entry?;
        let step = match (kind, &pooling) {
            (Kind::Transformer, _) => {
                return Err(oneiron::Error::InvalidConfig(
                    "embedder model modules.json declares a second Transformer".to_owned(),
                ));
            }
            (Kind::Pooling, None) => {
                pooling = Some(path);
                continue;
            }
            (Kind::Pooling, Some(_)) => {
                return Err(oneiron::Error::InvalidConfig(
                    "embedder model modules.json declares a second Pooling".to_owned(),
                ));
            }
            (_, None) => {
                return Err(oneiron::Error::InvalidConfig(format!(
                    "embedder model modules.json declares {kind:?} before its Pooling"
                )));
            }
            (Kind::Normalize, Some(_)) => Post::Normalize,
            (Kind::FlexibleQuantizer, Some(_)) => Post::FlexibleQuantizer,
            (Kind::Dense, Some(_)) => Post::Dense(path),
        };
        post.push(step);
    }
    let pooling = pooling.ok_or_else(|| {
        oneiron::Error::InvalidConfig(
            "embedder model modules.json declares no Pooling module".to_owned(),
        )
    })?;
    Ok(Declared { pooling, post })
}

/// The files `modules.json` says the chain reads, relative to the model
/// directory: each module's config, then each module's weights. The artifact
/// manager fetches exactly these beside the body's own, so a checkpoint whose
/// chain is refused is refused before its weights are downloaded.
pub(super) fn module_files(raw_modules_json: &str) -> oneiron::Result<ModuleFiles> {
    let declared = parse_entries(raw_modules_json)?;
    let mut files = ModuleFiles {
        configs: vec![declared.pooling.file("config.json")],
        weights: Vec::new(),
    };
    for step in &declared.post {
        if let Post::Dense(path) = step {
            files.configs.push(path.file("config.json"));
            files.weights.push(path.file("model.safetensors"));
        }
    }
    Ok(files)
}

/// What the chain reads, split by what it decides: the configs say how the
/// chain runs, the weights only what it multiplies by.
pub(super) struct ModuleFiles {
    pub(super) configs: Vec<String>,
    pub(super) weights: Vec<String>,
}

/// `1_Pooling/config.json`, field for field as sentence-transformers writes it,
/// with its defaults for a key the file leaves out.
#[derive(Clone, Debug, Deserialize)]
struct PoolingConfig {
    #[serde(default)]
    word_embedding_dimension: usize,
    #[serde(default)]
    pooling_mode_cls_token: bool,
    #[serde(default)]
    pooling_mode_mean_tokens: bool,
    #[serde(default)]
    pooling_mode_max_tokens: bool,
    #[serde(default)]
    pooling_mode_mean_sqrt_len_tokens: bool,
    #[serde(default)]
    pooling_mode_weightedmean_tokens: bool,
    #[serde(default)]
    pooling_mode_lasttoken: bool,
    /// sentence-transformers keeps the prompt in the pool unless told not to.
    #[serde(default = "default_true")]
    include_prompt: bool,
    /// Every other key. A `pooling_mode_*` among them is a mode this provider
    /// does not know, and is refused rather than dropped.
    #[serde(flatten)]
    other: BTreeMap<String, serde_json::Value>,
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
    fn resolve(&self) -> oneiron::Result<Pooling> {
        if let Some(unknown) = self
            .other
            .keys()
            .find(|key| key.starts_with("pooling_mode_"))
        {
            return Err(oneiron::Error::InvalidConfig(format!(
                "embedder model pooling mode {unknown} is not supported (expected lasttoken, mean_tokens or cls_token)"
            )));
        }
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
        path: ModulePath,
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
        let declared = parse_entries(&raw)?;
        let pooling =
            read_json::<PoolingConfig>(model_dir, &declared.pooling, "Pooling")?.resolve()?;
        // The width flowing between modules.
        let mut width = pooling.width;
        let mut steps = Vec::new();
        for post in declared.post {
            steps.push(match post {
                Post::Normalize => Step::Normalize,
                Post::FlexibleQuantizer => match quantization {
                    EmbedderOutputQuantization::Int8 => Step::Int8Tanh,
                    EmbedderOutputQuantization::Binary => Step::BinaryTanh,
                },
                Post::Dense(path) => {
                    let config: DenseConfig = read_json(model_dir, &path, "Dense")?;
                    let tanh = match config.activation_function.as_str() {
                        "torch.nn.modules.linear.Identity" => false,
                        "torch.nn.modules.activation.Tanh" => true,
                        _ => {
                            return Err(oneiron::Error::InvalidConfig(format!(
                                "embedder model Dense activation {:?} is not supported (expected torch.nn.modules.linear.Identity or torch.nn.modules.activation.Tanh)",
                                config.activation_function
                            )));
                        }
                    };
                    if width != config.in_features {
                        return Err(oneiron::Error::InvalidConfig(format!(
                            "embedder model Dense takes {} features, but the chain carries {width} to it",
                            config.in_features
                        )));
                    }
                    width = config.out_features;
                    Step::Dense {
                        path,
                        in_features: config.in_features,
                        out_features: config.out_features,
                        bias: config.bias,
                        tanh,
                    }
                }
            });
        }
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
                            &model_dir.join(path.file("model.safetensors")),
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
                Ready::Int8Tanh => {
                    round_ties_even(&(pooled.tanh()? * INT8_TANH_SCALE)?)?.clamp(-128f32, 127f32)?
                }
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

/// `torch.round`: to the nearest integer, a half to the even one.
///
/// candle's own `round` takes a half away from zero, so a component landing on
/// `2.5` would become `3` where the checkpoint emits `2`, and normalising the
/// vector afterwards does not undo a different integer. Done on the host: the
/// pooled rows are one small row per input.
fn round_ties_even(tensor: &Tensor) -> candle_core::Result<Tensor> {
    let rounded: Vec<f32> = tensor
        .flatten_all()?
        .to_vec1::<f32>()?
        .into_iter()
        .map(f32::round_ties_even)
        .collect();
    Tensor::from_vec(rounded, tensor.shape(), tensor.device())
}

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
    path: &ModulePath,
    module: &str,
) -> oneiron::Result<T> {
    let what = format!("{module} config.json");
    let raw = std::fs::read_to_string(model_dir.join(path.file("config.json")))
        .map_err(|e| missing(&what, &e.to_string()))?;
    serde_json::from_str(&raw).map_err(|e| missing(&what, &e.to_string()))
}

fn missing(what: &str, reason: &str) -> oneiron::Error {
    oneiron::Error::InvalidConfig(format!("embedder model {what}: {reason}"))
}
