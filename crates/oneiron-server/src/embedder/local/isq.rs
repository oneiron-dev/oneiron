//! Quantise-at-load, in one function.
//!
//! Rebuilt from mistral.rs's in-situ quantisation — see `NOTICE-mistralrs.md`.
//! The mechanism is small once the executor around it is left behind: read the
//! official bf16 weight on the CPU, quantise it to Q8_0, upload the blocks to
//! the run device, and wrap the result in candle's own `QMatMul`. That is why
//! the shipped artifact is the model's official repository rather than a
//! third-party GGUF: the quantiser is ours and runs in about three seconds.

use candle_core::quantized::{GgmlDType, QMatMul, QTensor};
use candle_core::safetensors::MmapedSafetensors;
use candle_core::{DType, Device, Module, Shape, Tensor};
use candle_nn::var_builder::SimpleBackend;
use candle_nn::{Init, Linear, VarBuilder};

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
            weight.to_dtype(dtype)?.to_device(device)?,
            None,
        ))),
    }
}

/// Loads a plain tensor onto the run device at `dtype`.
///
/// Norm weights and the embedding table take this door: an embedding lookup is
/// a gather, not a matmul, and quantising a norm would cost accuracy for a
/// vector of a thousand values. The tensor is narrowed to `dtype` on the host,
/// so the largest one never reaches the device wider than it is kept.
pub(super) fn load_plain(
    vb: &VarBuilder<'_>,
    name: &str,
    shape: impl Into<candle_core::Shape>,
    device: &Device,
    dtype: DType,
) -> candle_core::Result<Tensor> {
    vb.get_with_hints_dtype(shape, name, Default::default(), dtype)?
        .to_device(device)
}

/// The checkpoint's safetensors, read so that narrowing a tensor never holds
/// a wide copy of it.
///
/// candle's own backend loads a tensor at its stored precision and converts it
/// afterwards, so narrowing an f32 checkpoint's embedding table to bf16 first
/// allocates the whole table at f32 — over half a gigabyte that macOS's
/// allocator keeps after it is freed, for the life of the process. This reads
/// an f32 tensor asked for at bf16 element by element straight out of the
/// mapping, with the same rounding candle's conversion uses, and hands every
/// other read to candle unchanged.
pub(super) struct NarrowingSafetensors(MmapedSafetensors);

impl NarrowingSafetensors {
    /// Maps the file and reads its header.
    ///
    /// # Safety
    ///
    /// As [`MmapedSafetensors::new`]: the file must not change while mapped.
    pub(super) unsafe fn new(path: &std::path::Path) -> candle_core::Result<Self> {
        // SAFETY: the caller's promise is the one the mapping needs.
        Ok(Self(unsafe { MmapedSafetensors::new(path)? }))
    }
}

impl SimpleBackend for NarrowingSafetensors {
    fn get(
        &self,
        shape: Shape,
        name: &str,
        init: Init,
        dtype: DType,
        device: &Device,
    ) -> candle_core::Result<Tensor> {
        let view = self.0.get(name)?;
        if dtype != DType::BF16 || DType::try_from(view.dtype())? != DType::F32 {
            return SimpleBackend::get(&self.0, shape, name, init, dtype, device);
        }
        if view.shape() != shape.dims() {
            candle_core::bail!(
                "shape mismatch for {name}: expected {shape:?}, got {:?}",
                view.shape()
            );
        }
        let narrowed: Vec<half::bf16> = view
            .data()
            .chunks_exact(4)
            .map(|bytes| {
                half::bf16::from_f32(f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            })
            .collect();
        Tensor::from_vec(narrowed, shape, &Device::Cpu)?.to_device(device)
    }

    fn get_unchecked(
        &self,
        name: &str,
        dtype: DType,
        device: &Device,
    ) -> candle_core::Result<Tensor> {
        SimpleBackend::get_unchecked(&self.0, name, dtype, device)
    }

    fn contains_tensor(&self, name: &str) -> bool {
        SimpleBackend::contains_tensor(&self.0, name)
    }
}
