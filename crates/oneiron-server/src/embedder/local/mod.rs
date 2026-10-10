//! The `local` provider: the model runs in this process, on candle.
//!
//! Rebuilt from the upstream runtime's embedding stack and left standing on the
//! released candle — the model body, the sentence-transformers chain, the
//! quantise-at-load step and the attention dispatch, with its engine,
//! scheduler, request channels and CLI left behind. File-level provenance is in
//! `NOTICE-mistralrs.md` beside this module. Inputs are packed rather than
//! padded ([`batcher`]); on x86_64 the quantised projections run on this
//! crate's own tiled kernel ([`cpu_q8`]).
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
pub(super) mod cpu_q8;
pub(super) mod device;
pub(super) mod isq;
pub(crate) mod model_manager;
pub(super) mod prompts;
pub(super) mod qwen3_embedding;
pub(super) mod spec;
pub(super) mod st_modules;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use candle_core::{DType, Device};
use candle_nn::VarBuilder;
use oneiron::embed::{Embedder, EmbedderLocality, PendingEmbeddingInput};
use tokenizers::Tokenizer;

use self::isq::Q8Kernel;
use self::prompts::Prompts;
use self::qwen3_embedding::{Config, LoadContext, Model};
use self::spec::LocalModelSpec;
use self::st_modules::{Chain, StModules};
use super::{EmbedderCommon, QueryEmbedder};
use crate::config::EmbedderConfig;

/// Tokens one forward packs, at most; one input longer than this runs alone.
///
/// Enough rows that every weight is read once for many tokens, and few enough
/// that a forward's activations stay near 40 MiB. Each token holds about
/// 80 KiB of them at the widest step.
const FORWARD_TOKENS: usize = 512;

pub(crate) struct LocalEmbedder {
    common: EmbedderCommon,
    /// The body. Forwards share it and run side by side; a bulk forward parks
    /// between layers while a query runs ([`QueryFirst`]).
    model: Model,
    queries_first: QueryFirst,
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
    /// Inputs one forward packs, at most.
    batch_size: usize,
    /// Tokens one forward packs, at most ([`FORWARD_TOKENS`]).
    forward_tokens: usize,
    truncations: AtomicU64,
}

/// Which prompt a text is embedded behind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Side {
    Query,
    Document,
}

/// Whether a call runs first or makes way.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Priority {
    /// Someone is waiting on it: a recall's query.
    Query,
    /// Filling the vault: parks between layers while any query runs.
    Bulk,
}

/// What one call embedded: each text's output from the model's module chain,
/// before the numerics contract normalises and rounds it, and the tokens read.
pub(super) struct Embedded {
    pub(super) rows: Vec<Vec<f32>>,
    pub(super) tokens: usize,
}

/// Queries first. A bulk forward checks in before every layer and waits there
/// while any query runs; a query never waits for a bulk forward, so a recall
/// shares the device with at most one bulk layer already under way.
#[derive(Default)]
struct QueryFirst {
    running: Mutex<usize>,
    done: Condvar,
}

impl QueryFirst {
    fn enter(&self) -> QueryRunning<'_> {
        *count(&self.running) += 1;
        QueryRunning(self)
    }

    fn make_way(&self) {
        let mut running = count(&self.running);
        while *running > 0 {
            running = self
                .done
                .wait(running)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

/// Poison recovery: the count is a plain integer that no panic leaves half
/// written, and refusing it would stall every bulk forward for the life of
/// the process.
fn count(running: &Mutex<usize>) -> MutexGuard<'_, usize> {
    running.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A query in flight; dropping it lets parked bulk forwards go once none is.
struct QueryRunning<'a>(&'a QueryFirst);

impl Drop for QueryRunning<'_> {
    fn drop(&mut self) {
        let mut running = count(&self.0.running);
        *running = running.saturating_sub(1);
        if *running == 0 {
            self.0.done.notify_all();
        }
    }
}

/// The transform descriptor of the local model as its files on this host
/// describe it, read only from metadata that is complete and verified by the
/// loader's own rules ([`model_manager::verified_metadata_dir`]). `None` when
/// it is not, or does not read: the worker checks the loaded model's once the
/// files have been fetched and verified.
pub(crate) fn transform_on_disk(config: &EmbedderConfig) -> Option<String> {
    let dir = model_manager::verified_metadata_dir(&config.local)?;
    LocalModelSpec::read(&dir, config)
        .ok()
        .map(|spec| spec.transform())
}

/// The transform descriptor of the local model, fetching and verifying its
/// metadata files when they are not on this host. No weights are fetched.
pub(crate) fn resolve_transform(config: &EmbedderConfig) -> oneiron::Result<String> {
    let dir = model_manager::ModelManager::default().ensure_metadata(&config.local)?;
    Ok(LocalModelSpec::read(&dir, config)?.transform())
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
        Self::load_at(
            config,
            models,
            device::run_dtype(config.local.quant),
            Q8Kernel::Tiled,
        )
    }

    /// [`Self::load`] with the activation precision and the Q8_0 kernel named
    /// rather than derived. The parity rows use it to run unquantised f32, the
    /// one precision that separates a port error from rounding, and to hold
    /// the tiled kernel to candle's own.
    fn load_at(
        config: &EmbedderConfig,
        models: &model_manager::ModelManager,
        dtype: DType,
        kernel: Q8Kernel,
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
        let context = LoadContext {
            quant: config.local.quant,
            kernel,
            device: &run_device,
            dtype,
        };
        let model = load_body(&dir, &spec.body, config, &context)?;
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
            model,
            queries_first: QueryFirst::default(),
            modules,
            prompts: spec.prompts,
            query_prompt_tokens,
            document_prompt_tokens,
            tokenizer,
            transform,
            batch_size: config.batch_size.max(1),
            forward_tokens: FORWARD_TOKENS,
            truncations: AtomicU64::new(0),
        }))
    }

    /// How this model turns text into stored vectors.
    pub(super) fn transform(&self) -> &str {
        &self.transform
    }

    /// Embeds texts in input order, each behind `side`'s prompt, or behind
    /// `instruction` when a caller names its own query prompt (as a vault's
    /// `query_instruction` does).
    pub(super) fn embed_raw(
        &self,
        texts: &[String],
        side: Side,
        instruction: Option<&str>,
        priority: Priority,
    ) -> oneiron::Result<Embedded> {
        let (prompt, prompt_tokens) = match (side, instruction) {
            (_, Some(instruction)) => (instruction, self.prompt_tokens(instruction)?),
            (Side::Query, None) => (self.prompts.query.as_str(), self.query_prompt_tokens),
            (Side::Document, None) => (self.prompts.document.as_str(), self.document_prompt_tokens),
        };
        let prompted: Vec<String> = texts.iter().map(|text| format!("{prompt}{text}")).collect();
        self.embed_texts(&prompted, prompt_tokens, priority)
    }

    /// Leading rows a prompt takes that the pool skips: none when the pool
    /// includes the prompt.
    fn prompt_tokens(&self, prompt: &str) -> oneiron::Result<usize> {
        if self.modules.chain().pooling.include_prompt {
            return Ok(0);
        }
        batcher::prompt_tokens(&self.tokenizer, prompt)
    }

    /// Embeds already-prompted texts in input order. `prompt_tokens` leading
    /// rows of each are the prompt's, for a pool that excludes it.
    fn embed_texts(
        &self,
        texts: &[String],
        prompt_tokens: usize,
        priority: Priority,
    ) -> oneiron::Result<Embedded> {
        if texts.is_empty() {
            return Ok(Embedded {
                rows: Vec::new(),
                tokens: 0,
            });
        }
        let tokenized = batcher::tokenize(&self.tokenizer, texts)?;
        let truncated = tokenized.iter().filter(|item| item.truncated).count() as u64;
        if truncated > 0 {
            self.truncations.fetch_add(truncated, Ordering::Relaxed);
        }
        let lengths: Vec<usize> = tokenized.iter().map(|item| item.ids.len()).collect();
        let cpu = matches!(self.model.device(), Device::Cpu);
        let forwards = if cpu {
            batcher::pack(&lengths, self.batch_size, self.forward_tokens)
        } else {
            batcher::group_equal_lengths(&lengths, self.batch_size)
        };
        let _query = (priority == Priority::Query).then(|| self.queries_first.enter());
        let park = || {
            if priority == Priority::Bulk {
                // A GPU runs what it was handed in order, so a query would
                // queue behind every layer a bulk forward had already
                // submitted: finish each layer before checking. A failure
                // here surfaces on the forward's next operation.
                if !cpu {
                    let _ = self.model.device().synchronize();
                }
                self.queries_first.make_way();
            }
        };
        let mut rows: Vec<Option<Vec<f32>>> = vec![None; texts.len()];
        for forward in &forwards {
            let inputs: Vec<&[u32]> = forward
                .iter()
                .map(|index| tokenized[*index].ids.as_slice())
                .collect();
            let states = self.model.forward(&inputs, &park).map_err(candle_failed)?;
            let mut indices = forward.iter();
            for state in &states {
                let pooled: Vec<Vec<f32>> = self
                    .modules
                    .apply(state, prompt_tokens)
                    .and_then(|pooled| pooled.to_dtype(DType::F32)?.to_vec2())
                    .map_err(candle_failed)?;
                for (index, row) in indices.by_ref().zip(pooled) {
                    rows[*index] = Some(row);
                }
            }
        }
        let rows = rows
            .into_iter()
            .map(|row| {
                row.ok_or(oneiron::Error::InvariantViolation(
                    "embedder left an input unembedded",
                ))
            })
            .collect::<oneiron::Result<_>>()?;
        Ok(Embedded {
            rows,
            tokens: lengths.iter().sum(),
        })
    }

    /// Embeds texts and holds each output to the numerics contract.
    fn embed_finished(
        &self,
        texts: &[String],
        side: Side,
        priority: Priority,
    ) -> oneiron::Result<Vec<Vec<f32>>> {
        self.embed_raw(texts, side, None, priority)?
            .rows
            .into_iter()
            .map(|row| self.common.finish_vector(row))
            .collect()
    }

    /// Embeds document texts in input order, each behind the model's own
    /// document prompt.
    fn embed_documents(&self, texts: &[String]) -> oneiron::Result<Vec<Vec<f32>>> {
        self.embed_finished(texts, Side::Document, Priority::Bulk)
    }
}

fn load_body(
    dir: &std::path::Path,
    model_config: &Config,
    config: &EmbedderConfig,
    context: &LoadContext<'_>,
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
        context,
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
        let mut vectors = self.embed_finished(&[text.to_owned()], Side::Query, Priority::Query)?;
        vectors.pop().ok_or(oneiron::Error::InvariantViolation(
            "embedder answered a single query with no row",
        ))
    }
}

#[cfg(test)]
pub(super) mod bench;
#[cfg(test)]
mod tests;
