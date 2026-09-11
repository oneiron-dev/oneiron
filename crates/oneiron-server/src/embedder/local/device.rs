//! Which candle device the local provider runs on, and at what precision.

use candle_core::{DType, Device};

use crate::config::{EmbedderDevice, EmbedderQuant};

/// Resolves the configured device against what this build can actually reach.
///
/// `auto` prefers the GPU and falls back to the CPU without complaint, because
/// a CPU host is a supported deployment, only a slower one. A NAMED device
/// that is unavailable is an error rather than a silent downgrade: an operator
/// who wrote `device = "metal"` and got the CPU would read the throughput as a
/// model problem.
pub(super) fn resolve_device(configured: EmbedderDevice) -> oneiron::Result<Device> {
    match configured {
        EmbedderDevice::Cpu => Ok(Device::Cpu),
        EmbedderDevice::Metal => Device::new_metal(0).map_err(|e| {
            oneiron::Error::InvalidConfig(format!("embedder device metal is unavailable: {e}"))
        }),
        EmbedderDevice::Auto => Ok(Device::new_metal(0).unwrap_or(Device::Cpu)),
    }
}

/// The dtype activations run in.
///
/// Q8_0 runs in f32: candle's quantised matmul takes f32 activations on every
/// backend, and the weights are 8-bit regardless, so the activation width
/// costs almost nothing. `quant = "none"` keeps the official bf16 end to end,
/// which is the only reason to ask for it.
pub(super) const fn run_dtype(quant: EmbedderQuant) -> DType {
    match quant {
        EmbedderQuant::Q8_0 => DType::F32,
        EmbedderQuant::None => DType::BF16,
    }
}

/// Human-readable device name for the one log line the loader emits.
pub(super) fn device_label(device: &Device) -> &'static str {
    match device {
        Device::Cpu => "cpu",
        Device::Cuda(_) => "cuda",
        Device::Metal(_) => "metal",
    }
}
