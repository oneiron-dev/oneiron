//! The `local` provider: the model runs in this process, on candle.
//!
//! Rebuilt from the upstream runtime's embedding stack and left standing on the
//! released candle — the model body, the sentence-transformers chain, the
//! quantise-at-load step, the attention dispatch and the no-padding batching,
//! with its engine, scheduler, request channels and CLI left behind. File-level
//! provenance is in `NOTICE-mistralrs.md` beside this module.
//!
//! Zero setup for the operator: the pinned artifacts are fetched on first use,
//! verified by digest, quantised at load, and the vault serves at rung 0 until
//! that finishes.
//!
//! Configuration, not code, says which model runs: the repository and commit
//! name the files, and the files say the rest — the attention in
//! `config.json`, the module chain in `modules.json`, the prompts in
//! `config_sentence_transformers.json` ([`spec`]).

pub(super) mod attention;
pub(super) mod batcher;
pub(super) mod device;
pub(super) mod isq;
pub(crate) mod model_manager;
pub(super) mod prompts;
pub(super) mod qwen3_embedding;
pub(super) mod spec;
pub(super) mod st_modules;

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use candle_core::{DType, Device, Tensor};
use candle_nn::VarBuilder;
use oneiron::embed::{Embedder, EmbedderLocality, PendingEmbeddingInput};
use tokenizers::Tokenizer;

use self::prompts::Prompts;
use self::qwen3_embedding::{Config, Model};
use self::spec::LocalModelSpec;
use self::st_modules::{Chain, StModules};
use super::{EmbedderCommon, QueryEmbedder};
use crate::config::EmbedderConfig;

pub(crate) struct LocalEmbedder {
    common: EmbedderCommon,
    /// One model, one lock. candle tensors are shareable but the mask cache is
    /// not, and the reconciler calls `embed` from one worker thread anyway.
    model: Mutex<Model>,
    modules: StModules,
    /// What each side carries before its text.
    prompts: Prompts,
    /// Leading prompt rows a pool that excludes the prompt skips, per side.
    query_prompt_tokens: usize,
    document_prompt_tokens: usize,
    /// The model's tokenizer, truncating at the input cap and never padding.
    tokenizer: Tokenizer,
    /// How this model turns text into stored vectors ([`LocalModelSpec::transform`]).
    transform: String,
    batch_size: usize,
    truncations: AtomicU64,
}

/// The transform descriptor of the local model as its files on this host
/// describe it, or `None` when they are not here yet or do not read: the
/// worker checks the loaded model's once the files arrive.
pub(crate) fn transform_on_disk(config: &EmbedderConfig) -> Option<String> {
    let dir = model_manager::model_dir(&config.local).ok()?;
    if !dir.join("modules.json").is_file() {
        return None;
    }
    LocalModelSpec::read(&dir, config)
        .ok()
        .map(|spec| spec.transform())
}

pub(crate) fn prepare(config: &EmbedderConfig) -> oneiron::Result<&'static str> {
    prepare_with_manager(config, &model_manager::ModelManager::default())
}

fn prepare_with_manager(
    config: &EmbedderConfig,
    models: &model_manager::ModelManager,
) -> oneiron::Result<&'static str> {
    // A named device must fail before an expensive first-use download, not
    // after fetching the entire checkpoint and discovering no GPU is usable.
    let device = device::resolve_device(config.local.device, &config.local.auto_devices)?;
    models.ensure_all(&config.local)?;
    Ok(device::device_label(&device))
}

impl LocalEmbedder {
    /// Fetches what is missing, loads the model, and quantises it.
    ///
    /// Blocking and slow by nature: a first run downloads gigabytes and
    /// every run quantises the projections. The caller runs it off the async
    /// runtime.
    pub(super) fn load(
        config: &EmbedderConfig,
        models: &model_manager::ModelManager,
    ) -> oneiron::Result<std::sync::Arc<Self>> {
        Self::load_at(config, models, device::run_dtype(config.local.quant))
    }

    /// [`Self::load`] with the activation precision named rather than derived
    /// from `quant`. The parity rows use it to run unquantised f32, the one
    /// precision that separates a port error from rounding.
    fn load_at(
        config: &EmbedderConfig,
        models: &model_manager::ModelManager,
        dtype: DType,
    ) -> oneiron::Result<std::sync::Arc<Self>> {
        let run_device = device::resolve_device(config.local.device, &config.local.auto_devices)?;
        let dir = models.ensure_all(&config.local)?;
        let spec = LocalModelSpec::read(&dir, config)?;
        let tokenizer = Tokenizer::from_file(dir.join("tokenizer.json")).map_err(|e| {
            oneiron::Error::InvalidConfig(format!("embedder model tokenizer.json: {e}"))
        })?;
        let tokenizer = batcher::for_provider(tokenizer, config.max_input_tokens)?;
        let prompt_tokens = |prompt: &str| {
            if spec.chain.pooling.include_prompt {
                return Ok(0);
            }
            batcher::prompt_tokens(&tokenizer, prompt)
        };
        let query_prompt_tokens = prompt_tokens(&spec.prompts.query)?;
        let document_prompt_tokens = prompt_tokens(&spec.prompts.document)?;
        let transform = spec.transform();
        let started = Instant::now();
        let model = load_body(&dir, &spec.body, config, &run_device, dtype)?;
        let modules = StModules::load(spec.chain, &dir, &run_device)?;
        tracing::info!(
            device = device::device_label(&run_device),
            quant = config.local.quant.as_str(),
            threads = load_threads(config.local.threads),
            load_ms = started.elapsed().as_millis(),
            causal = spec.body.causal(),
            pooling = ?modules.chain().pooling.mode,
            steps = modules.chain().steps.len(),
            query_prompt_chars = spec.prompts.query.chars().count(),
            document_prompt_chars = spec.prompts.document.chars().count(),
            dimensions = modules.chain().dimensions(),
            "local embedder ready"
        );
        Ok(std::sync::Arc::new(Self {
            common: EmbedderCommon::from_config(config),
            model: Mutex::new(model),
            modules,
            prompts: spec.prompts,
            query_prompt_tokens,
            document_prompt_tokens,
            tokenizer,
            transform,
            batch_size: config.batch_size.max(1),
            truncations: AtomicU64::new(0),
        }))
    }

    /// How this model turns text into stored vectors.
    pub(super) fn transform(&self) -> &str {
        &self.transform
    }

    /// Embeds document texts in input order, each behind the model's own
    /// document prompt.
    fn embed_documents(&self, texts: &[String]) -> oneiron::Result<Vec<Vec<f32>>> {
        let prompted: Vec<String> = texts
            .iter()
            .map(|text| format!("{}{text}", self.prompts.document))
            .collect();
        self.embed_texts(&prompted, self.document_prompt_tokens)
    }

    /// Embeds already-prompted texts in input order. `prompt_tokens` leading
    /// rows of each are the prompt's, for a pool that excludes it.
    fn embed_texts(
        &self,
        texts: &[String],
        prompt_tokens: usize,
    ) -> oneiron::Result<Vec<Vec<f32>>> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        let tokenized = batcher::tokenize(&self.tokenizer, texts)?;
        let truncated = tokenized.iter().filter(|item| item.truncated).count() as u64;
        if truncated > 0 {
            self.truncations.fetch_add(truncated, Ordering::Relaxed);
        }
        let lengths: Vec<usize> = tokenized.iter().map(|item| item.ids.len()).collect();
        let groups = batcher::group_equal_lengths(&lengths, self.batch_size);
        let mut vectors: Vec<Option<Vec<f32>>> = vec![None; texts.len()];
        // Poison recovery: the only state behind this lock is a cache of causal
        // masks, which a panic cannot leave inconsistent, and refusing it would
        // disable the embedder for the life of the process.
        let mut model = self
            .model
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for group in &groups {
            let rows = self.embed_group(&mut model, &tokenized, group, prompt_tokens)?;
            for (index, row) in group.iter().zip(rows) {
                vectors[*index] = Some(row);
            }
        }
        drop(model);
        vectors
            .into_iter()
            .map(|row| {
                row.ok_or(oneiron::Error::InvariantViolation(
                    "embedder left an input unembedded",
                ))
            })
            .collect()
    }

    /// One equal-length group: stack, forward, pool, finish.
    fn embed_group(
        &self,
        model: &mut Model,
        tokenized: &[batcher::Tokenized],
        group: &[usize],
        prompt_tokens: usize,
    ) -> oneiron::Result<Vec<Vec<f32>>> {
        let ids: Vec<u32> = group
            .iter()
            .flat_map(|index| tokenized[*index].ids.iter().copied())
            .collect();
        let seq = tokenized[group[0]].ids.len();
        let shape = (group.len(), seq);
        let ids = Tensor::from_vec(ids, shape, model.device()).map_err(candle_failed)?;
        let hidden = model.forward(&ids).map_err(candle_failed)?;
        let pooled = self
            .modules
            .apply(&hidden, prompt_tokens)
            .map_err(candle_failed)?;
        let rows: Vec<Vec<f32>> = pooled
            .to_dtype(DType::F32)
            .and_then(|pooled| pooled.to_vec2())
            .map_err(candle_failed)?;
        rows.into_iter()
            .map(|row| self.common.finish_vector(row))
            .collect()
    }
}

fn load_body(
    dir: &std::path::Path,
    model_config: &Config,
    config: &EmbedderConfig,
    run_device: &Device,
    dtype: DType,
) -> oneiron::Result<Model> {
    let weights = dir.join("model.safetensors");
    // Read at f32, which holds every checkpoint's own precision exactly — bf16
    // for one model, f32 for another — so the quantiser starts from the
    // official values rather than from a bf16 rounding of them. Each load door
    // narrows to what it stores.
    //
    // SAFETY: the file is memory-mapped read-only for the lifetime of the
    // builder, and nothing in this process writes it: the artifact manager only
    // ever renames a freshly downloaded file INTO place, and it verified this
    // file's digest before we got here.
    let backend = unsafe { isq::NarrowingSafetensors::new(&weights).map_err(candle_failed)? };
    let vb = VarBuilder::from_backend(Box::new(backend), DType::F32, Device::Cpu);
    Model::load(
        model_config,
        &vb,
        config.local.quant,
        run_device,
        dtype,
        config.max_input_tokens,
        load_threads(config.local.threads),
    )
    .map_err(candle_failed)
}

/// Threads the load-time quantisation spreads over.
///
/// `0` means this machine's parallelism. Capped at eight: past that the work is
/// bound by reading the memory-mapped weights rather than by quantising them,
/// and a load should not monopolise a host that is also serving.
fn load_threads(configured: usize) -> usize {
    if configured > 0 {
        return configured;
    }
    std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(8)
}

/// The pool must read the body's width, and the chain must emit exactly the
/// width the vault was opened with.
fn check_dimensions(config: &EmbedderConfig, body: &Config, chain: &Chain) -> oneiron::Result<()> {
    if chain.pooling.width != body.hidden_size {
        return Err(oneiron::Error::InvalidConfig(format!(
            "embedder model pooling width is {}, hidden_size is {}",
            chain.pooling.width, body.hidden_size
        )));
    }
    let got = chain.dimensions();
    if got != config.dimensions {
        return Err(oneiron::Error::InvalidConfig(format!(
            "embedder model output width is {got}, configured dimensions is {}",
            config.dimensions
        )));
    }
    Ok(())
}

/// The input cap must fit the window the model itself declares.
///
/// Read from the `config.json` the checkpoint ships, for every checkpoint
/// alike: without it the rotary tables come up short and the failure surfaces
/// as an out-of-range narrow in the middle of a forward pass.
fn check_input_window(config: &EmbedderConfig, model_config: &Config) -> oneiron::Result<()> {
    if config.max_input_tokens > model_config.max_position_embeddings {
        return Err(oneiron::Error::InvalidConfig(format!(
            "embedder max_input_tokens is {}, above the model's context window of {}",
            config.max_input_tokens, model_config.max_position_embeddings
        )));
    }
    Ok(())
}

fn candle_failed(error: candle_core::Error) -> oneiron::Error {
    oneiron::Error::UpstreamToolFailure {
        tool: "embedder-local",
        code: error.to_string(),
    }
}

impl Embedder for LocalEmbedder {
    fn model_id(&self) -> &str {
        &self.common.model_id
    }

    fn dimensions(&self) -> usize {
        self.common.dimensions
    }

    fn locality(&self) -> EmbedderLocality {
        EmbedderLocality::OnDevice
    }

    fn embed(&self, inputs: &[PendingEmbeddingInput]) -> oneiron::Result<Vec<Vec<f32>>> {
        let texts: Vec<String> = inputs
            .iter()
            .map(|input| self.common.document_text(input))
            .collect::<oneiron::Result<_>>()?;
        self.embed_documents(&texts)
    }
}

impl QueryEmbedder for LocalEmbedder {
    fn truncations(&self) -> u64 {
        self.truncations.load(Ordering::Relaxed)
    }

    fn embed_query(&self, text: &str) -> oneiron::Result<Vec<f32>> {
        let mut vectors = self.embed_texts(
            &[format!("{}{text}", self.prompts.query)],
            self.query_prompt_tokens,
        )?;
        vectors.pop().ok_or(oneiron::Error::InvariantViolation(
            "embedder answered a single query with no row",
        ))
    }
}

#[cfg(test)]
mod tests;
