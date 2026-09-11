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

pub(super) mod attention;
pub(super) mod batcher;
pub(super) mod device;
pub(super) mod isq;
pub(crate) mod model_manager;
pub(super) mod qwen3_embedding;
pub(super) mod st_modules;

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use candle_core::{DType, Device, Tensor};
use candle_nn::VarBuilder;
use oneiron::embed::{Embedder, EmbedderLocality, PendingEmbeddingInput};
use tokenizers::Tokenizer;

use self::qwen3_embedding::{Config, Model};
use self::st_modules::StModules;
use super::{EmbedderCommon, QueryEmbedder};
use crate::config::EmbedderConfig;

pub(crate) struct LocalEmbedder {
    common: EmbedderCommon,
    /// One model, one lock. candle tensors are shareable but the mask cache is
    /// not, and the reconciler calls `embed` from one worker thread anyway.
    model: Mutex<Model>,
    modules: StModules,
    tokenizer: Tokenizer,
    max_input_tokens: usize,
    batch_size: usize,
    truncations: AtomicU64,
}

impl LocalEmbedder {
    /// Fetches what is missing, loads the model, and quantises it.
    ///
    /// Blocking and slow by nature: a first run downloads over a gigabyte and
    /// every run quantises the projections. The caller runs it off the async
    /// runtime.
    pub(super) fn load(config: &EmbedderConfig) -> oneiron::Result<std::sync::Arc<Self>> {
        let dir = model_manager::ensure_all(&config.local)?;
        let raw_config = std::fs::read_to_string(dir.join("config.json")).map_err(|e| {
            oneiron::Error::InvalidConfig(format!("embedder model config.json: {e}"))
        })?;
        let model_config = Config::parse(&raw_config)?;
        let modules = StModules::load(&dir)?;
        check_dimensions(config, &model_config, &modules)?;
        let tokenizer = Tokenizer::from_file(dir.join("tokenizer.json")).map_err(|e| {
            oneiron::Error::InvalidConfig(format!("embedder model tokenizer.json: {e}"))
        })?;
        let run_device = device::resolve_device(config.local.device)?;
        let dtype = device::run_dtype(config.local.quant);
        let started = Instant::now();
        let model = load_body(&dir, &model_config, config, &run_device, dtype)?;
        tracing::info!(
            device = device::device_label(&run_device),
            quant = config.local.quant.as_str(),
            threads = load_threads(config.local.threads),
            load_ms = started.elapsed().as_millis(),
            dimensions = modules.dimensions(),
            "local embedder ready"
        );
        Ok(std::sync::Arc::new(Self {
            common: EmbedderCommon::from_config(config),
            model: Mutex::new(model),
            modules,
            tokenizer,
            max_input_tokens: config.max_input_tokens,
            batch_size: config.batch_size.max(1),
            truncations: AtomicU64::new(0),
        }))
    }

    /// Embeds already-projected texts in input order.
    fn embed_texts(&self, texts: &[String]) -> oneiron::Result<Vec<Vec<f32>>> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        let tokenized = batcher::tokenize(&self.tokenizer, texts, self.max_input_tokens)?;
        let truncated = tokenized.iter().filter(|item| item.truncated).count() as u64;
        if truncated > 0 {
            self.truncations.fetch_add(truncated, Ordering::Relaxed);
        }
        let lengths: Vec<usize> = tokenized.iter().map(|item| item.ids.len()).collect();
        let groups = batcher::group_equal_lengths(&lengths, self.batch_size);
        let mut vectors: Vec<Option<Vec<f32>>> = vec![None; texts.len()];
        let mut model = self
            .model
            .lock()
            .map_err(|_| oneiron::Error::InvariantViolation("embedder model lock poisoned"))?;
        for group in &groups {
            let rows = self.embed_group(&mut model, &tokenized, group)?;
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
    ) -> oneiron::Result<Vec<Vec<f32>>> {
        let ids: Vec<u32> = group
            .iter()
            .flat_map(|index| tokenized[*index].ids.iter().copied())
            .collect();
        let seq = tokenized[group[0]].ids.len();
        let shape = (group.len(), seq);
        let ids = Tensor::from_vec(ids, shape, model.device()).map_err(candle_failed)?;
        let hidden = model.forward(&ids).map_err(candle_failed)?;
        let pooled = self.modules.apply(&hidden).map_err(candle_failed)?;
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
    // SAFETY: the file is memory-mapped read-only for the lifetime of the
    // builder, and nothing in this process writes it: the artifact manager only
    // ever renames a freshly downloaded file INTO place, and it verified this
    // file's digest before we got here.
    let vb = unsafe {
        VarBuilder::from_mmaped_safetensors(&[&weights], DType::BF16, &Device::Cpu)
            .map_err(candle_failed)?
    };
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

/// The model must produce exactly the width the vault was opened with.
fn check_dimensions(
    config: &EmbedderConfig,
    model_config: &Config,
    modules: &StModules,
) -> oneiron::Result<()> {
    for (what, got) in [
        ("hidden_size", model_config.hidden_size),
        ("pooling width", modules.dimensions()),
    ] {
        if got != config.dimensions {
            return Err(oneiron::Error::InvalidConfig(format!(
                "embedder model {what} is {got}, configured dimensions is {}",
                config.dimensions
            )));
        }
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
        self.embed_texts(&texts)
    }
}

impl QueryEmbedder for LocalEmbedder {
    fn truncations(&self) -> u64 {
        self.truncations.load(Ordering::Relaxed)
    }

    fn embed_query(&self, text: &str) -> oneiron::Result<Vec<f32>> {
        let mut vectors = self.embed_texts(&[self.common.query_text(text)])?;
        vectors.pop().ok_or(oneiron::Error::InvariantViolation(
            "embedder answered a single query with no row",
        ))
    }
}

#[cfg(test)]
mod tests;
