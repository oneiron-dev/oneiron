//! The embedding model body: a Qwen3 decoder stack with no language head.
//!
//! Rebuilt from mistral.rs's `embedding_models/qwen3_embedding.rs` — see
//! `NOTICE-mistralrs.md`. Structure and tensor names are the source's:
//! `embed_tokens` → N decoder layers (q/k/v/o projections, per-head q and k
//! norms, RoPE, attention, SwiGLU MLP) → a final norm → per-token hidden
//! states. No `lm_head` is loaded, because none is used.
//!
//! Nothing here names a model. Any checkpoint whose `config.json` carries the
//! Qwen3 fields and whose weights carry the Qwen3 tensor names loads; one that
//! does not is refused by the first field or tensor it lacks. Whether it
//! attends causally or bidirectionally is its own `config.json`'s declaration:
//! an encoder trained bidirectionally on this layout differs from a causal one
//! in its mask and nothing else.

use std::sync::Mutex;

use candle_core::{DType, Device, IndexOp, Module, Storage, Tensor};
use candle_nn::{RmsNorm, VarBuilder};
use rayon::prelude::*;
use serde::Deserialize;

use super::attention::{causal_mask, grouped_attention};
use super::isq::{Proj, Q8Kernel, load_plain, load_proj};
use crate::config::EmbedderQuant;

/// `config.json` as the model ships it. Unknown keys are ignored on purpose:
/// the file carries inference knobs (`use_cache`, `layer_types`) that do not
/// apply to a single forward pass over packed, unpadded inputs, and a class name
/// (`architectures`) that says nothing the fields below do not.
#[derive(Clone, Debug, Deserialize)]
pub(super) struct Config {
    pub(super) hidden_size: usize,
    pub(super) num_hidden_layers: usize,
    pub(super) num_attention_heads: usize,
    pub(super) num_key_value_heads: usize,
    pub(super) intermediate_size: usize,
    pub(super) vocab_size: usize,
    pub(super) rope_theta: f64,
    pub(super) rms_norm_eps: f64,
    pub(super) max_position_embeddings: usize,
    /// Absent in some Qwen3 configs, where it is `hidden_size / heads`.
    #[serde(default)]
    head_dim: Option<usize>,
    /// `true`: every position attends to every other.
    #[serde(default)]
    use_bidirectional_attention: Option<bool>,
    /// The same declaration, the other way round, as some configs spell it.
    #[serde(default)]
    is_causal: Option<bool>,
    /// The attention the body runs with: the declaration above, resolved at
    /// parse, unless the host overrides it with [`Config::attending`].
    #[serde(skip)]
    causal: bool,
}

impl Config {
    /// Parses, or names the field that is missing or inconsistent.
    pub(super) fn parse(raw: &str) -> oneiron::Result<Self> {
        let mut config: Self = serde_json::from_str(raw).map_err(|e| {
            oneiron::Error::InvalidConfig(format!("embedder model config.json: {e}"))
        })?;
        config.causal = config.declared_causal()?;
        if config.num_key_value_heads == 0
            || !config
                .num_attention_heads
                .is_multiple_of(config.num_key_value_heads)
        {
            return Err(oneiron::Error::InvalidConfig(format!(
                "embedder model has {} attention heads over {} key-value heads",
                config.num_attention_heads, config.num_key_value_heads
            )));
        }
        Ok(config)
    }

    /// Whether the body attends causally.
    pub(super) const fn causal(&self) -> bool {
        self.causal
    }

    /// The same body, attending as the host says rather than as declared.
    pub(super) const fn attending(mut self, causal: bool) -> Self {
        self.causal = causal;
        self
    }

    /// Whether the checkpoint declares causal attention. Declaring neither key
    /// means causal, which is what a Qwen3 body was trained as.
    fn declared_causal(&self) -> oneiron::Result<bool> {
        match (self.use_bidirectional_attention, self.is_causal) {
            (Some(bidirectional), Some(causal)) if bidirectional == causal => {
                Err(oneiron::Error::InvalidConfig(format!(
                    "embedder model config.json declares use_bidirectional_attention = {bidirectional} and is_causal = {causal}"
                )))
            }
            (Some(bidirectional), _) => Ok(!bidirectional),
            (None, Some(causal)) => Ok(causal),
            (None, None) => Ok(true),
        }
    }

    pub(super) fn head_dim(&self) -> usize {
        self.head_dim
            .unwrap_or(self.hidden_size / self.num_attention_heads.max(1))
    }
}

/// The prefix the body's tensors actually sit under.
///
/// A body-only checkpoint writes `embed_tokens.weight`; one exported from a
/// causal-LM wrapper writes `model.embed_tokens.weight`. Both describe the same
/// stack, so the prefix is probed rather than assumed — the default local model
/// is the unprefixed shape, and assuming the other was the first thing to fail.
fn body_root<'a>(vb: &VarBuilder<'a>) -> candle_core::Result<VarBuilder<'a>> {
    if vb.contains_tensor("embed_tokens.weight") {
        return Ok(vb.clone());
    }
    let nested = vb.pp("model");
    if nested.contains_tensor("embed_tokens.weight") {
        return Ok(nested);
    }
    candle_core::bail!(
        "embedder model weights carry neither embed_tokens.weight nor model.embed_tokens.weight"
    )
}

/// Cosine and sine tables for rotary position embeddings.
struct Rotary {
    cos: Tensor,
    sin: Tensor,
}

impl Rotary {
    fn new(
        theta: f64,
        head_dim: usize,
        max_seq: usize,
        dtype: DType,
        device: &Device,
    ) -> candle_core::Result<Self> {
        let half = head_dim / 2;
        let inverse: Vec<f32> = (0..half)
            .map(|index| {
                let exponent = 2.0 * index as f64 / head_dim as f64;
                (1.0 / theta.powf(exponent)) as f32
            })
            .collect();
        let inverse = Tensor::from_vec(inverse, (1, half), device)?;
        let positions = Tensor::arange(0u32, max_seq as u32, device)?
            .to_dtype(DType::F32)?
            .reshape((max_seq, 1))?;
        let angles = positions.matmul(&inverse)?;
        Ok(Self {
            cos: angles.cos()?.to_dtype(dtype)?,
            sin: angles.sin()?.to_dtype(dtype)?,
        })
    }

    /// Applies the rotation to `[b, heads, seq, head_dim]`.
    fn apply(&self, xs: &Tensor, seq: usize) -> candle_core::Result<Tensor> {
        let cos = self.cos.narrow(0, 0, seq)?;
        let sin = self.sin.narrow(0, 0, seq)?;
        candle_nn::rotary_emb::rope(&xs.contiguous()?, &cos, &sin)
    }
}

struct Attention {
    q_proj: Proj,
    k_proj: Proj,
    v_proj: Proj,
    o_proj: Proj,
    q_norm: RmsNorm,
    k_norm: RmsNorm,
    heads: usize,
    kv_heads: usize,
    head_dim: usize,
    scale: f32,
}

impl Attention {
    fn load(cfg: &Config, vb: &VarBuilder<'_>, ctx: &LoadContext<'_>) -> candle_core::Result<Self> {
        let head_dim = cfg.head_dim();
        let q_dim = cfg.num_attention_heads * head_dim;
        let kv_dim = cfg.num_key_value_heads * head_dim;
        let eps = cfg.rms_norm_eps;
        Ok(Self {
            q_proj: ctx.proj(vb, "self_attn.q_proj.weight", q_dim, cfg.hidden_size)?,
            k_proj: ctx.proj(vb, "self_attn.k_proj.weight", kv_dim, cfg.hidden_size)?,
            v_proj: ctx.proj(vb, "self_attn.v_proj.weight", kv_dim, cfg.hidden_size)?,
            o_proj: ctx.proj(vb, "self_attn.o_proj.weight", cfg.hidden_size, q_dim)?,
            q_norm: RmsNorm::new(ctx.plain(vb, "self_attn.q_norm.weight", head_dim)?, eps),
            k_norm: RmsNorm::new(ctx.plain(vb, "self_attn.k_norm.weight", head_dim)?, eps),
            heads: cfg.num_attention_heads,
            kv_heads: cfg.num_key_value_heads,
            head_dim,
            scale: 1.0 / (head_dim as f32).sqrt(),
        })
    }

    /// `xs` holds the forward's rows as its [`Layout`] shapes them. The
    /// projections run once over all of them; attention runs per input, over
    /// that input's own rows, or once over a group of equal-length inputs.
    fn forward(&self, xs: &Tensor, layout: &Layout, model: &Model) -> candle_core::Result<Tensor> {
        let queries = self.q_proj.forward(xs)?;
        let keys = self.k_proj.forward(xs)?;
        let values = self.v_proj.forward(xs)?;
        let merged = match layout {
            Layout::Group { inputs, len } => {
                self.attend([&queries, &keys, &values], *inputs, *len, model)?
            }
            Layout::Packed(spans) => {
                let mut attended = Vec::with_capacity(spans.len());
                for span in spans {
                    let rows = |projected: &Tensor| projected.narrow(0, span.start, span.len);
                    let heads = self.attend(
                        [&rows(&queries)?, &rows(&keys)?, &rows(&values)?],
                        1,
                        span.len,
                        model,
                    )?;
                    attended.push(heads.reshape((span.len, self.heads * self.head_dim))?);
                }
                match attended.len() {
                    1 => attended.remove(0),
                    _ => Tensor::cat(&attended, 0)?,
                }
            }
        };
        self.o_proj.forward(&merged)
    }

    /// Attention over `inputs` inputs of `len` tokens each, from their
    /// projected rows in order; `[inputs, len, heads * head_dim]`.
    fn attend(
        &self,
        [queries, keys, values]: [&Tensor; 3],
        inputs: usize,
        len: usize,
        model: &Model,
    ) -> candle_core::Result<Tensor> {
        // Per-HEAD q/k norms, as the source applies them: reshape to heads
        // first, normalise inside each head, then rotate.
        let split = |projected: &Tensor, heads: usize| -> candle_core::Result<Tensor> {
            projected
                .reshape((inputs, len, heads, self.head_dim))?
                .transpose(1, 2)
        };
        let q = split(queries, self.heads)?;
        let k = split(keys, self.kv_heads)?;
        let v = split(values, self.kv_heads)?;
        let q = model
            .rotary
            .apply(&self.q_norm.forward(&q.contiguous()?)?, len)?;
        let k = model
            .rotary
            .apply(&self.k_norm.forward(&k.contiguous()?)?, len)?;
        let mask = model.mask(len)?;
        let attended = grouped_attention(
            &q,
            &k,
            &v.contiguous()?,
            mask.as_ref(),
            model.causal,
            self.scale,
        )?;
        attended
            .transpose(1, 2)?
            .reshape((inputs, len, self.heads * self.head_dim))
    }
}

struct Mlp {
    gate_proj: Proj,
    up_proj: Proj,
    down_proj: Proj,
}

impl Mlp {
    fn load(cfg: &Config, vb: &VarBuilder<'_>, ctx: &LoadContext<'_>) -> candle_core::Result<Self> {
        let (hidden, inter) = (cfg.hidden_size, cfg.intermediate_size);
        Ok(Self {
            gate_proj: ctx.proj(vb, "mlp.gate_proj.weight", inter, hidden)?,
            up_proj: ctx.proj(vb, "mlp.up_proj.weight", inter, hidden)?,
            down_proj: ctx.proj(vb, "mlp.down_proj.weight", hidden, inter)?,
        })
    }

    fn forward(&self, xs: &Tensor) -> candle_core::Result<Tensor> {
        let gate = self.gate_proj.forward(xs)?;
        let up = self.up_proj.forward(xs)?;
        let gated = match cpu_swiglu(&gate, &up)? {
            Some(gated) => gated,
            None => (gate.silu()? * up)?,
        };
        self.down_proj.forward(&gated)
    }
}

/// Values one task of [`cpu_swiglu`] covers.
const SWIGLU_CHUNK: usize = 16 * 1024;

/// `silu(gate) * up` on the CPU in one pass over every thread, computed per
/// value exactly as candle's two ops compute it (`v / (1 + exp(-v))`, then the
/// product). candle runs each of those on one thread, over the widest
/// activations a packed forward has. `None` off the CPU or away from
/// contiguous f32, where candle's ops run.
fn cpu_swiglu(gate: &Tensor, up: &Tensor) -> candle_core::Result<Option<Tensor>> {
    if !matches!(gate.device(), Device::Cpu)
        || gate.dtype() != DType::F32
        || up.dtype() != DType::F32
        || gate.shape() != up.shape()
    {
        return Ok(None);
    }
    let (gate_storage, gate_layout) = gate.storage_and_layout();
    let (up_storage, up_layout) = up.storage_and_layout();
    let (Storage::Cpu(gate_values), Storage::Cpu(up_values)) = (&*gate_storage, &*up_storage)
    else {
        return Ok(None);
    };
    let (Some((gate_start, gate_end)), Some((up_start, up_end))) = (
        gate_layout.contiguous_offsets(),
        up_layout.contiguous_offsets(),
    ) else {
        return Ok(None);
    };
    let gate_values = &gate_values.as_slice::<f32>()?[gate_start..gate_end];
    let up_values = &up_values.as_slice::<f32>()?[up_start..up_end];
    let mut gated = vec![0f32; gate_values.len()];
    gated
        .par_chunks_mut(SWIGLU_CHUNK)
        .zip(gate_values.par_chunks(SWIGLU_CHUNK))
        .zip(up_values.par_chunks(SWIGLU_CHUNK))
        .for_each(|((gated, gate), up)| {
            for ((out, &v), &u) in gated.iter_mut().zip(gate).zip(up) {
                *out = v / (1.0 + (-v).exp()) * u;
            }
        });
    Tensor::from_vec(gated, gate.shape(), &Device::Cpu).map(Some)
}

struct DecoderLayer {
    input_layernorm: RmsNorm,
    self_attn: Attention,
    post_attention_layernorm: RmsNorm,
    mlp: Mlp,
}

impl DecoderLayer {
    fn load(cfg: &Config, vb: &VarBuilder<'_>, ctx: &LoadContext<'_>) -> candle_core::Result<Self> {
        let eps = cfg.rms_norm_eps;
        Ok(Self {
            input_layernorm: RmsNorm::new(
                ctx.plain(vb, "input_layernorm.weight", cfg.hidden_size)?,
                eps,
            ),
            self_attn: Attention::load(cfg, vb, ctx)?,
            post_attention_layernorm: RmsNorm::new(
                ctx.plain(vb, "post_attention_layernorm.weight", cfg.hidden_size)?,
                eps,
            ),
            mlp: Mlp::load(cfg, vb, ctx)?,
        })
    }

    fn forward(&self, xs: &Tensor, layout: &Layout, model: &Model) -> candle_core::Result<Tensor> {
        let attended = self
            .self_attn
            .forward(&self.input_layernorm.forward(xs)?, layout, model)?;
        let xs = (xs + attended)?;
        let fed = self
            .mlp
            .forward(&self.post_attention_layernorm.forward(&xs)?)?;
        xs + fed
    }
}

/// Where and at what precision every tensor lands, and which kernel runs a
/// quantised projection.
pub(super) struct LoadContext<'a> {
    pub(super) quant: EmbedderQuant,
    pub(super) kernel: Q8Kernel,
    pub(super) device: &'a Device,
    pub(super) dtype: DType,
}

impl LoadContext<'_> {
    fn proj(
        &self,
        vb: &VarBuilder<'_>,
        name: &str,
        out_dim: usize,
        in_dim: usize,
    ) -> candle_core::Result<Proj> {
        load_proj(
            vb,
            name,
            out_dim,
            in_dim,
            self.quant,
            self.kernel,
            self.device,
            self.dtype,
        )
    }

    fn plain(&self, vb: &VarBuilder<'_>, name: &str, len: usize) -> candle_core::Result<Tensor> {
        load_plain(vb, name, len, self.device, self.dtype)
    }
}

/// Loads the decoder layers, quantising them across a small thread pool.
///
/// Quantising 28 layers of projections is the whole cost of a start: serially it
/// dominates the load, and it is embarrassingly parallel because each layer
/// reads a disjoint slice of the memory-mapped weights. The upstream runtime
/// reaches its three-second load the same way.
///
/// `threads == 1` keeps the serial path, which is what a single-core host and
/// every deterministic-debugging session want.
fn load_layers(
    cfg: &Config,
    model: &VarBuilder<'_>,
    ctx: &LoadContext<'_>,
    threads: usize,
) -> candle_core::Result<Vec<DecoderLayer>> {
    let count = cfg.num_hidden_layers;
    let workers = threads.clamp(1, count.max(1));
    if workers <= 1 {
        return (0..count)
            .map(|index| DecoderLayer::load(cfg, &model.pp("layers").pp(index.to_string()), ctx))
            .collect();
    }
    let slots: Vec<std::sync::Mutex<Option<DecoderLayer>>> =
        (0..count).map(|_| std::sync::Mutex::new(None)).collect();
    let failures = std::sync::Mutex::new(Vec::<candle_core::Error>::new());
    std::thread::scope(|scope| {
        for worker in 0..workers {
            let slots = &slots;
            let failures = &failures;
            scope.spawn(move || {
                for index in (worker..count).step_by(workers) {
                    let layer =
                        DecoderLayer::load(cfg, &model.pp("layers").pp(index.to_string()), ctx);
                    match layer {
                        Ok(layer) => {
                            if let Ok(mut slot) = slots[index].lock() {
                                *slot = Some(layer);
                            }
                        }
                        Err(error) => {
                            if let Ok(mut failures) = failures.lock() {
                                failures.push(error);
                            }
                            return;
                        }
                    }
                }
            });
        }
    });
    if let Some(error) = failures.lock().ok().and_then(|mut f| f.pop()) {
        return Err(error);
    }
    slots
        .into_iter()
        .enumerate()
        .map(|(index, slot)| {
            slot.into_inner()
                .ok()
                .flatten()
                .ok_or_else(|| candle_core::Error::msg(format!("layer {index} did not load")))
        })
        .collect()
}

/// Distinct sequence lengths the mask cache holds at once.
///
/// A corpus settles on a handful of input lengths, so a few entries carry
/// nearly every pass. The bound is what keeps a
/// long-lived process from holding one `s × s` tensor for every length it has
/// ever been asked to embed.
pub(super) const MASK_CACHE_CAPACITY: usize = 8;

/// Additive causal masks, at most [`MASK_CACHE_CAPACITY`] of them.
///
/// Insertion-ordered, oldest first: a full cache drops its oldest entry before
/// taking a new one, so what this holds is bounded by the eight lengths most
/// recently first seen rather than by uptime.
pub(super) struct MaskCache {
    entries: Vec<(usize, Tensor)>,
}

impl MaskCache {
    pub(super) const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// The mask for one sequence length, built once per length.
    pub(super) fn get_or_build(
        &mut self,
        seq: usize,
        device: &Device,
    ) -> candle_core::Result<Tensor> {
        if let Some((_, mask)) = self.entries.iter().find(|(length, _)| *length == seq) {
            return Ok(mask.clone());
        }
        let mask = causal_mask(seq, device)?;
        if self.entries.len() >= MASK_CACHE_CAPACITY {
            self.entries.remove(0);
        }
        self.entries.push((seq, mask.clone()));
        Ok(mask)
    }
}

/// Where one packed input's rows sit: its first row and how many.
#[derive(Clone, Copy, Debug)]
struct Span {
    start: usize,
    len: usize,
}

/// How one forward's rows are laid out.
enum Layout {
    /// Inputs of one length, as `[inputs, len, hidden]`, attended together:
    /// the shapes every forward had before packing, which a GPU's quantised
    /// kernels choose between by.
    Group { inputs: usize, len: usize },
    /// Inputs of several lengths back to back, as `[tokens, hidden]`.
    Packed(Vec<Span>),
}

/// The body. `forward` returns post-norm hidden states, one row per token.
pub(super) struct Model {
    /// Kept at bf16 whatever the run precision: 152k × 1024 values is the
    /// largest tensor in the model and a gather needs no arithmetic width.
    embed_tokens: Tensor,
    layers: Vec<DecoderLayer>,
    norm: RmsNorm,
    rotary: Rotary,
    /// One additive mask per distinct sequence length, bounded. Rebuilding an
    /// `s × s` mask per input is the one avoidable cost in the eager path;
    /// keeping every length ever seen is the other. Never touched by a
    /// bidirectional body, which masks nothing. Its own lock, held only to
    /// look a mask up: forwards share the model and run side by side.
    mask_cache: Mutex<MaskCache>,
    /// Whether attention hides future positions: the checkpoint's declaration.
    causal: bool,
    device: Device,
    dtype: DType,
    hidden_size: usize,
}

impl Model {
    /// Loads the body from a safetensors file already on disk.
    ///
    /// `vb` must be a CPU builder over the official weights, at a precision
    /// that holds them exactly; the run device and precision come from
    /// `device` and `quant`, and the attention from [`Config::causal`].
    pub(super) fn load(
        cfg: &Config,
        vb: &VarBuilder<'_>,
        ctx: &LoadContext<'_>,
        max_seq: usize,
        threads: usize,
    ) -> candle_core::Result<Self> {
        let (device, dtype) = (ctx.device, ctx.dtype);
        let model = body_root(vb)?;
        let embed_tokens = load_plain(
            &model,
            "embed_tokens.weight",
            (cfg.vocab_size, cfg.hidden_size),
            device,
            DType::BF16,
        )?;
        let layers = load_layers(cfg, &model, ctx, threads)?;
        let norm = RmsNorm::new(
            ctx.plain(&model, "norm.weight", cfg.hidden_size)?,
            cfg.rms_norm_eps,
        );
        let rotary = Rotary::new(
            cfg.rope_theta,
            cfg.head_dim(),
            max_seq.min(cfg.max_position_embeddings).max(1),
            dtype,
            device,
        )?;
        Ok(Self {
            embed_tokens,
            layers,
            norm,
            rotary,
            mask_cache: Mutex::new(MaskCache::new()),
            causal: cfg.causal(),
            device: device.clone(),
            dtype,
            hidden_size: cfg.hidden_size,
        })
    }

    pub(super) fn device(&self) -> &Device {
        &self.device
    }

    /// Several inputs' token ids to their post-norm hidden states, in input
    /// order: one `[inputs, len, hidden]` block for inputs of one length,
    /// otherwise one `[1, len, hidden]` block per input.
    ///
    /// Inputs of several lengths are packed, not padded: their tokens run
    /// back to back as one `[tokens, hidden]` matrix through every row-wise
    /// step — the embedding lookup, the projections, the norms, the MLP —
    /// which is where a forward spends its time, and only attention splits
    /// it, so each input attends to its own tokens alone. On the CPU every
    /// row-wise step treats a row the same whatever rows surround it, so an
    /// input's states do not depend on what it was packed with. A GPU's
    /// quantised matmul picks its kernel by the row count, which is why the
    /// provider sends a GPU only groups of one length (`batcher`).
    ///
    /// `between_layers` runs before the forward allocates its activations and
    /// before each later layer: the provider takes the model's turn there, so
    /// a forward waiting for it holds only token ids, and a bulk forward gives
    /// it up to a waiting query.
    pub(super) fn forward(
        &self,
        inputs: &[&[u32]],
        between_layers: &mut dyn FnMut(),
    ) -> candle_core::Result<Vec<Tensor>> {
        let mut spans = Vec::with_capacity(inputs.len());
        let mut ids = Vec::with_capacity(inputs.iter().map(|input| input.len()).sum());
        for input in inputs {
            spans.push(Span {
                start: ids.len(),
                len: input.len(),
            });
            ids.extend_from_slice(input);
        }
        let tokens = ids.len();
        let len = spans.first().map_or(0, |span| span.len);
        let layout = if spans.iter().all(|span| span.len == len) {
            Layout::Group {
                inputs: spans.len(),
                len,
            }
        } else {
            Layout::Packed(spans)
        };
        let shape: candle_core::Shape = match &layout {
            Layout::Group { inputs, len } => (*inputs, *len, self.hidden_size).into(),
            Layout::Packed(_) => (tokens, self.hidden_size).into(),
        };
        between_layers();
        let ids = Tensor::from_vec(ids, tokens, &self.device)?;
        let mut xs = self
            .embed_tokens
            .index_select(&ids, 0)?
            .reshape(shape)?
            .to_dtype(self.dtype)?;
        for (index, layer) in self.layers.iter().enumerate() {
            if index > 0 {
                between_layers();
            }
            xs = layer.forward(&xs, &layout, self)?;
        }
        let xs = self.norm.forward(&xs)?;
        match layout {
            Layout::Group { .. } => Ok(vec![xs]),
            Layout::Packed(spans) => spans
                .iter()
                .map(|span| xs.narrow(0, span.start, span.len)?.unsqueeze(0))
                .collect(),
        }
    }

    /// The additive mask attention over `len` positions takes, if any.
    ///
    /// The fused Metal kernel masks causally on its own, so that path builds
    /// and caches nothing: an `s × s` tensor no kernel reads is pure cost. A
    /// bidirectional body over one unpadded input has nothing to mask at all.
    fn mask(&self, len: usize) -> candle_core::Result<Option<Tensor>> {
        if !self.causal || matches!(self.device, Device::Metal(_)) {
            return Ok(None);
        }
        // Poison recovery: the cache only ever holds whole masks.
        let mut cache = self
            .mask_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.get_or_build(len, &self.device).map(Some)
    }

    /// The first row of every sequence, which is what CLS pooling reads.
    pub(super) fn first_rows(hidden: &Tensor) -> candle_core::Result<Tensor> {
        hidden.i((.., 0, ..))
    }

    /// The last row of every sequence, which is what last-token pooling reads.
    pub(super) fn last_rows(hidden: &Tensor) -> candle_core::Result<Tensor> {
        let seq = hidden.dim(1)?;
        hidden.i((.., seq - 1, ..))
    }
}
