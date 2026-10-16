//! Bidirectional extraction backbones. Dimensions and attention settings come
//! from the checkpoint's config.json, never a model-name lookup.

use candle_core::{D, Module, Tensor};
use candle_nn::{
    Embedding, LayerNorm, Linear, VarBuilder, embedding, layer_norm, linear, linear_no_bias,
};
use serde::Deserialize;

use crate::config::oneironer::OneironerBackbone;

#[derive(Deserialize)]
pub(super) struct Config {
    pub(super) model_type: String,
    pub(super) hidden_size: usize,
    pub(super) num_hidden_layers: usize,
    pub(super) num_attention_heads: usize,
    pub(super) intermediate_size: usize,
    pub(super) vocab_size: usize,
    pub(super) max_position_embeddings: usize,
    pub(super) type_vocab_size: usize,
    pub(super) layer_norm_eps: f64,
    pub(super) hidden_act: String,
    #[serde(default)]
    position_embedding_type: Option<String>,
    #[serde(default)]
    rope_theta: Option<f32>,
    #[serde(default)]
    rope_scaling: Option<serde_json::Value>,
    #[serde(default)]
    layer_norm_type: Option<String>,
    #[serde(default)]
    pack_qkv: Option<bool>,
    #[serde(default)]
    logn_attention_scale: bool,
}

impl Config {
    pub(super) fn validate(&self, selected: OneironerBackbone) -> anyhow::Result<bool> {
        let gte = match self.model_type.as_str() {
            "new" => true,
            "bert" => false,
            _ => anyhow::bail!("local oneironer supports new (GTE) and bert backbones"),
        };
        anyhow::ensure!(
            matches!(selected, OneironerBackbone::Auto)
                || (gte && selected == OneironerBackbone::Gte)
                || (!gte && selected == OneironerBackbone::Bert),
            "oneironer.backbone disagrees with config.json"
        );
        anyhow::ensure!(
            self.hidden_size > 0
                && self.num_attention_heads > 0
                && self.hidden_size % self.num_attention_heads == 0
                && self.num_hidden_layers > 0
                && self.intermediate_size > 0
                && self.vocab_size > 0
                && self.max_position_embeddings > 0
                && self.layer_norm_eps.is_finite()
                && self.layer_norm_eps > 0.0,
            "invalid extraction backbone dimensions or layer norm epsilon"
        );
        anyhow::ensure!(
            self.hidden_act == "gelu",
            "extraction backbone requires exact GELU"
        );
        anyhow::ensure!(
            self.layer_norm_type
                .as_deref()
                .is_none_or(|kind| kind == "layer_norm")
                && self.rope_scaling.is_none()
                && !self.logn_attention_scale,
            "unsupported extraction normalization or attention scaling"
        );
        if gte {
            anyhow::ensure!(
                self.pack_qkv.unwrap_or(true)
                    && self.position_embedding_type.as_deref() == Some("rope")
                    && (self.hidden_size / self.num_attention_heads) % 2 == 0
                    && self
                        .rope_theta
                        .is_some_and(|theta| theta.is_finite() && theta > 0.0),
                "GTE extraction requires packed QKV and unscaled rotary attention"
            );
        } else {
            anyhow::ensure!(
                self.position_embedding_type
                    .as_deref()
                    .is_none_or(|kind| kind == "absolute"),
                "BERT extraction requires absolute positions"
            );
        }
        Ok(gte)
    }
}

enum Queries {
    Packed(Linear),
    Separate(Linear, Linear, Linear),
}

struct Layer {
    queries: Queries,
    output: Linear,
    attention_norm: LayerNorm,
    up: Linear,
    down: Linear,
    output_norm: LayerNorm,
}

pub(super) struct Backbone {
    words: Embedding,
    token_type: Option<Tensor>,
    positions: Option<Embedding>,
    embedding_norm: LayerNorm,
    layers: Vec<Layer>,
    rotary: Option<(Tensor, Tensor)>,
    width: usize,
    heads: usize,
    intermediate: usize,
}

impl Backbone {
    pub(super) fn load(
        vb: VarBuilder<'_>,
        config: &Config,
        gte: bool,
        cap: usize,
    ) -> candle_core::Result<Self> {
        let width = config.hidden_size;
        let words = embedding(
            config.vocab_size,
            width,
            vb.pp("embeddings.word_embeddings"),
        )?;
        let token_type = if config.type_vocab_size == 0 {
            None
        } else {
            Some(
                vb.get(
                    (config.type_vocab_size, width),
                    "embeddings.token_type_embeddings.weight",
                )?
                .narrow(0, 0, 1)?,
            )
        };
        let positions = if gte {
            None
        } else {
            Some(embedding(
                config.max_position_embeddings,
                width,
                vb.pp("embeddings.position_embeddings"),
            )?)
        };
        let embedding_norm =
            layer_norm(width, config.layer_norm_eps, vb.pp("embeddings.LayerNorm"))?;
        let mut layers = Vec::new();
        for index in 0..config.num_hidden_layers {
            let layer = vb.pp(format!("encoder.layer.{index}"));
            let (queries, output, attention_norm, up, down, output_norm) = if gte {
                (
                    Queries::Packed(linear(width, 3 * width, layer.pp("attention.qkv_proj"))?),
                    linear(width, width, layer.pp("attention.o_proj"))?,
                    layer_norm(width, config.layer_norm_eps, layer.pp("attn_ln"))?,
                    linear_no_bias(
                        width,
                        2 * config.intermediate_size,
                        layer.pp("mlp.up_gate_proj"),
                    )?,
                    linear(config.intermediate_size, width, layer.pp("mlp.down_proj"))?,
                    layer_norm(width, config.layer_norm_eps, layer.pp("mlp_ln"))?,
                )
            } else {
                (
                    Queries::Separate(
                        linear(width, width, layer.pp("attention.self.query"))?,
                        linear(width, width, layer.pp("attention.self.key"))?,
                        linear(width, width, layer.pp("attention.self.value"))?,
                    ),
                    linear(width, width, layer.pp("attention.output.dense"))?,
                    layer_norm(
                        width,
                        config.layer_norm_eps,
                        layer.pp("attention.output.LayerNorm"),
                    )?,
                    linear(
                        width,
                        config.intermediate_size,
                        layer.pp("intermediate.dense"),
                    )?,
                    linear(config.intermediate_size, width, layer.pp("output.dense"))?,
                    layer_norm(width, config.layer_norm_eps, layer.pp("output.LayerNorm"))?,
                )
            };
            layers.push(Layer {
                queries,
                output,
                attention_norm,
                up,
                down,
                output_norm,
            });
        }
        let rotary = if gte {
            let dim = width / config.num_attention_heads;
            let theta = config.rope_theta.unwrap_or_default();
            let frequencies: Vec<f32> = (0..cap)
                .flat_map(|position| {
                    (0..dim)
                        .step_by(2)
                        .map(move |index| position as f32 / theta.powf(index as f32 / dim as f32))
                })
                .collect();
            let frequencies = Tensor::from_vec(frequencies, (cap, dim / 2), vb.device())?;
            Some((frequencies.cos()?, frequencies.sin()?))
        } else {
            None
        };
        Ok(Self {
            words,
            token_type,
            positions,
            embedding_norm,
            layers,
            rotary,
            width,
            heads: config.num_attention_heads,
            intermediate: config.intermediate_size,
        })
    }

    /// One unpadded sequence; every head reuses these exact hidden states.
    pub(super) fn forward(&self, ids: &[u32]) -> candle_core::Result<Tensor> {
        let length = ids.len();
        let device = self.words.embeddings().device();
        let ids = Tensor::new(ids, device)?;
        let mut hidden = self.words.forward(&ids)?;
        if let Some(token_type) = &self.token_type {
            hidden = hidden.broadcast_add(token_type)?;
        }
        if let Some(positions) = &self.positions {
            let ids = Tensor::arange(0u32, length as u32, device)?;
            hidden = (hidden + positions.forward(&ids)?)?;
        }
        hidden = self.embedding_norm.forward(&hidden)?;
        let dim = self.width / self.heads;
        let shape = (1, length, self.heads, dim);
        for layer in &self.layers {
            let (query, key, value) = match &layer.queries {
                Queries::Packed(projection) => {
                    let packed = projection.forward(&hidden)?;
                    (
                        packed.narrow(1, 0, self.width)?,
                        packed.narrow(1, self.width, self.width)?,
                        packed.narrow(1, 2 * self.width, self.width)?,
                    )
                }
                Queries::Separate(query, key, value) => (
                    query.forward(&hidden)?,
                    key.forward(&hidden)?,
                    value.forward(&hidden)?,
                ),
            };
            let mut query = query.reshape(shape)?.transpose(1, 2)?.contiguous()?;
            let mut key = key.reshape(shape)?.transpose(1, 2)?.contiguous()?;
            let value = value.reshape(shape)?.transpose(1, 2)?.contiguous()?;
            if let Some((cos, sin)) = &self.rotary {
                let cos = cos.narrow(0, 0, length)?;
                let sin = sin.narrow(0, 0, length)?;
                query = candle_nn::rotary_emb::rope(&query, &cos, &sin)?;
                key = candle_nn::rotary_emb::rope(&key, &cos, &sin)?;
            }
            let scores = (query.matmul(&key.t()?)? / (dim as f64).sqrt())?;
            let attention = candle_nn::ops::softmax_last_dim(&scores)?
                .matmul(&value)?
                .transpose(1, 2)?
                .contiguous()?
                .reshape((length, self.width))?;
            hidden = layer
                .attention_norm
                .forward(&(layer.output.forward(&attention)? + &hidden)?)?;
            let up = layer.up.forward(&hidden)?;
            let activated = if self.rotary.is_some() {
                (up.narrow(D::Minus1, 0, self.intermediate)?
                    * up.narrow(D::Minus1, self.intermediate, self.intermediate)?
                        .gelu_erf()?)?
            } else {
                up.gelu_erf()?
            };
            hidden = layer
                .output_norm
                .forward(&(layer.down.forward(&activated)? + &hidden)?)?;
        }
        Ok(hidden)
    }
}
