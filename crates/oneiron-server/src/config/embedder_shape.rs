//! Keys that override what a local checkpoint declares about its own shape.
//!
//! The local provider reads a model's attention, module chain and prompts from
//! the model's own files. These keys exist for a checkpoint whose files say
//! less than they should, or that offers a choice; a model whose files are
//! complete needs none of them.

use std::str::FromStr;

use serde::Deserialize;

/// How the body attends.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum EmbedderAttention {
    /// What the checkpoint's `config.json` declares (`use_bidirectional_attention`
    /// or `is_causal`), causal when it declares neither.
    #[default]
    Auto,
    /// Every position sees only itself and the positions before it.
    Causal,
    /// Every position sees every other.
    Bidirectional,
}

impl EmbedderAttention {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Causal => "causal",
            Self::Bidirectional => "bidirectional",
        }
    }
}

impl FromStr for EmbedderAttention {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "auto" => Ok(Self::Auto),
            "causal" => Ok(Self::Causal),
            "bidirectional" => Ok(Self::Bidirectional),
            other => Err(format!(
                "unknown embedder attention {other:?} (expected auto, causal or bidirectional)"
            )),
        }
    }
}

/// What a `FlexibleQuantizer` module in the chain emits.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum EmbedderOutputQuantization {
    /// `round(tanh(x) · 127)`, clamped to the int8 range: the module's own
    /// default.
    #[default]
    Int8,
    /// `+1` where `x ≥ 0`, else `-1`.
    Binary,
}

impl EmbedderOutputQuantization {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Int8 => "int8",
            Self::Binary => "binary",
        }
    }
}

impl FromStr for EmbedderOutputQuantization {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "int8" => Ok(Self::Int8),
            "binary" => Ok(Self::Binary),
            other => Err(format!(
                "unknown embedder output quantization {other:?} (expected int8 or binary)"
            )),
        }
    }
}

pub(super) fn parse_attention(value: &str) -> Result<EmbedderAttention, String> {
    value.parse()
}

pub(super) fn parse_output_quantization(value: &str) -> Result<EmbedderOutputQuantization, String> {
    value.parse()
}
