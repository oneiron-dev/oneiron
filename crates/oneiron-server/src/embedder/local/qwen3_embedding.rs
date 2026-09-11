//! The embedding model body: a Qwen3 decoder stack with no language head.
//!
//! Rebuilt from mistral.rs's `embedding_models/qwen3_embedding.rs` — see
//! `NOTICE-mistralrs.md`. Structure and tensor names are the source's:
//! `embed_tokens` → N decoder layers (q/k/v/o projections, per-head q and k
//! norms, RoPE, causal attention, SwiGLU MLP) → a final norm → per-token hidden
//! states. No `lm_head` is loaded, because none is used.

use candle_core::{D, DType, Device, IndexOp, Module, Tensor};
use candle_nn::{RmsNorm, VarBuilder};
use serde::Deserialize;

use super::attention::{causal_mask, grouped_causal_attention};
use super::isq::{Proj, load_plain, load_proj};
use crate::config::EmbedderQuant;

/// Model classes this provider accepts.
///
/// The upstream runtime mapped only `Qwen3ForCausalLM` and so refused the
/// body-only checkpoint outright. Both names describe the same decoder stack —
/// the difference is a head this code never loads — so both are accepted.
const ACCEPTED_ARCHITECTURES: [&str; 2] = ["Qwen3Model", "Qwen3ForCausalLM"];

/// `config.json` as the model ships it. Unknown keys are ignored on purpose:
/// the file carries inference knobs (`use_cache`, `layer_types`) that do not
/// apply to a single forward pass over an unpadded batch.
#[derive(Clone, Debug, Deserialize)]
pub(super) struct Config {
    pub(super) architectures: Vec<String>,
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
}

impl Config {
    /// Parses and accepts, or names the class it refuses.
    pub(super) fn parse(raw: &str) -> oneiron::Result<Self> {
        let config: Self = serde_json::from_str(raw).map_err(|e| {
            oneiron::Error::InvalidConfig(format!("embedder model config.json: {e}"))
        })?;
        let accepted = config
            .architectures
            .iter()
            .any(|name| ACCEPTED_ARCHITECTURES.contains(&name.as_str()));
        if !accepted {
            return Err(oneiron::Error::InvalidConfig(format!(
                "embedder model class {:?} is not supported (expected one of {ACCEPTED_ARCHITECTURES:?})",
                config.architectures
            )));
        }
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

    fn forward(
        &self,
        xs: &Tensor,
        rotary: &Rotary,
        mask: Option<&Tensor>,
    ) -> candle_core::Result<Tensor> {
        let (batch, seq, _) = xs.dims3()?;
        // Per-HEAD q/k norms, as the source applies them: reshape to heads
        // first, normalise inside each head, then rotate.
        let split = |projected: Tensor, heads: usize| -> candle_core::Result<Tensor> {
            projected
                .reshape((batch, seq, heads, self.head_dim))?
                .transpose(1, 2)
        };
        let q = split(self.q_proj.forward(xs)?, self.heads)?;
        let k = split(self.k_proj.forward(xs)?, self.kv_heads)?;
        let v = split(self.v_proj.forward(xs)?, self.kv_heads)?;
        let q = rotary.apply(&self.q_norm.forward(&q.contiguous()?)?, seq)?;
        let k = rotary.apply(&self.k_norm.forward(&k.contiguous()?)?, seq)?;
        let attended = grouped_causal_attention(&q, &k, &v.contiguous()?, mask, self.scale)?;
        let merged = attended
            .transpose(1, 2)?
            .reshape((batch, seq, self.heads * self.head_dim))?;
        self.o_proj.forward(&merged)
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
        let gated = self.gate_proj.forward(xs)?.silu()?;
        self.down_proj
            .forward(&(gated * self.up_proj.forward(xs)?)?)
    }
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

    fn forward(
        &self,
        xs: &Tensor,
        rotary: &Rotary,
        mask: Option<&Tensor>,
    ) -> candle_core::Result<Tensor> {
        let attended = self
            .self_attn
            .forward(&self.input_layernorm.forward(xs)?, rotary, mask)?;
        let xs = (xs + attended)?;
        let fed = self
            .mlp
            .forward(&self.post_attention_layernorm.forward(&xs)?)?;
        xs + fed
    }
}

/// Where and at what precision every tensor lands.
struct LoadContext<'a> {
    quant: EmbedderQuant,
    device: &'a Device,
    dtype: DType,
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
/// Inputs arrive grouped by equal length and a corpus settles on a handful of
/// them, so a few entries carry nearly every pass. The bound is what keeps a
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

    /// The lengths held right now, oldest first.
    pub(super) fn lengths(&self) -> Vec<usize> {
        self.entries.iter().map(|(length, _)| *length).collect()
    }
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
    /// `s × s` mask per batch is the one avoidable cost in the eager path;
    /// keeping every length ever seen is the other.
    mask_cache: MaskCache,
    device: Device,
    dtype: DType,
    hidden_size: usize,
}

impl Model {
    /// Loads the body from a safetensors file already on disk.
    ///
    /// `vb` must be a CPU builder over the official bf16 weights; the run
    /// device and precision come from `device` and `quant`.
    pub(super) fn load(
        cfg: &Config,
        vb: &VarBuilder<'_>,
        quant: EmbedderQuant,
        device: &Device,
        dtype: DType,
        max_seq: usize,
        threads: usize,
    ) -> candle_core::Result<Self> {
        let ctx = LoadContext {
            quant,
            device,
            dtype,
        };
        let model = body_root(vb)?;
        let embed_tokens = load_plain(
            &model,
            "embed_tokens.weight",
            (cfg.vocab_size, cfg.hidden_size),
            device,
            DType::BF16,
        )?;
        let layers = load_layers(cfg, &model, &ctx, threads)?;
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
            mask_cache: MaskCache::new(),
            device: device.clone(),
            dtype,
            hidden_size: cfg.hidden_size,
        })
    }

    pub(super) fn device(&self) -> &Device {
        &self.device
    }

    /// `[batch, seq]` token ids, equal lengths and no padding, to
    /// `[batch, seq, hidden]` post-norm hidden states.
    ///
    /// `&mut self` rather than `&self`: the only mutable state is the mask
    /// cache, and the provider already holds the whole model behind one lock,
    /// so a second lock inside it would guard nothing.
    pub(super) fn forward(&mut self, ids: &Tensor) -> candle_core::Result<Tensor> {
        let seq = ids.dim(D::Minus1)?;
        // The fused Metal kernel masks causally on its own, so that path builds
        // and caches nothing: an `s × s` tensor no kernel reads is pure cost.
        let mask = if matches!(self.device, Device::Metal(_)) {
            None
        } else {
            Some(self.mask_cache.get_or_build(seq, &self.device)?)
        };
        let mut xs = self
            .embed_tokens
            .index_select(&ids.flatten_all()?, 0)?
            .reshape((ids.dim(0)?, seq, self.hidden_size))?
            .to_dtype(self.dtype)?;
        for layer in &self.layers {
            xs = layer.forward(&xs, &self.rotary, mask.as_ref())?;
        }
        self.norm.forward(&xs)
    }

    /// The last row of every sequence, which is what last-token pooling reads.
    pub(super) fn last_rows(hidden: &Tensor) -> candle_core::Result<Tensor> {
        let seq = hidden.dim(1)?;
        hidden.i((.., seq - 1, ..))
    }
}
