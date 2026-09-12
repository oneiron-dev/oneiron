//! Quantise-at-load, in one function.
//!
//! Rebuilt from mistral.rs's in-situ quantisation — see `NOTICE-mistralrs.md`.
//! The mechanism is small once the executor around it is left behind: read the
//! official bf16 weight on the CPU, quantise it to Q8_0, upload the blocks to
//! the run device, and wrap the result in candle's own `QMatMul`. That is why
//! the shipped artifact is the model's official repository rather than a
//! third-party GGUF: the quantiser is ours and runs in about three seconds.

use candle_core::quantized::{GgmlDType, QMatMul, QTensor};
use candle_core::{DType, Device, Module, Tensor};
use candle_nn::{Linear, VarBuilder};

use crate::config::EmbedderQuant;

/// A projection, at whichever precision it was loaded.
///
/// Two variants rather than a trait object: the local provider needs exactly
/// these two, and mistral.rs's `QuantMethod` trait — eight required methods and
/// about thirty provided ones — exists to serve a dozen formats we do not run.
pub(super) enum Proj {
    Dense(Linear),
    Q8(QMatMul),
}

impl Proj {
    pub(super) fn forward(&self, xs: &Tensor) -> candle_core::Result<Tensor> {
        match self {
            Self::Dense(linear) => linear.forward(xs),
            Self::Q8(matmul) => matmul.forward(xs),
        }
    }
}

/// Loads one projection weight, quantising it when asked.
///
/// `vb` must be a CPU builder: `quantize_onto` reads the source on the host and
/// writes the blocks straight to `device`, so the full-precision copy never
/// lands on the GPU and peak memory stays at one tensor rather than one model.
pub(super) fn load_proj(
    vb: &VarBuilder<'_>,
    name: &str,
    out_dim: usize,
    in_dim: usize,
    quant: EmbedderQuant,
    device: &Device,
    dtype: DType,
) -> candle_core::Result<Proj> {
    let weight = vb.get((out_dim, in_dim), name)?;
    match quant {
        EmbedderQuant::Q8_0 => {
            let quantised = QTensor::quantize_onto(&weight, GgmlDType::Q8_0, device)?;
            Ok(Proj::Q8(QMatMul::from_qtensor(quantised)?))
        }
        EmbedderQuant::None => Ok(Proj::Dense(Linear::new(
            weight.to_device(device)?.to_dtype(dtype)?,
            None,
        ))),
    }
}

/// Loads a plain tensor onto the run device at the run precision.
///
/// Norm weights and the embedding table take this door: an embedding lookup is
/// a gather, not a matmul, and quantising a norm would cost accuracy for a
/// vector of a thousand values.
pub(super) fn load_plain(
    vb: &VarBuilder<'_>,
    name: &str,
    shape: impl Into<candle_core::Shape>,
    device: &Device,
    dtype: DType,
) -> candle_core::Result<Tensor> {
    vb.get(shape, name)?.to_device(device)?.to_dtype(dtype)
}
