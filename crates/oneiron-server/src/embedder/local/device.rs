//! Which candle device the local provider runs on, and at what precision.

use candle_core::{DType, Device};
use oneiron::embed::{EmbeddingDevice, EmbeddingProvenance};

use crate::config::{EmbedderDevice, EmbedderQuant};

/// candle's version, as this crate's `Cargo.toml` pins it (`=`).
const CANDLE_VERSION: &str = "0.11.0";

/// The order a CPU sums each projection in: candle's portable dot product on
/// x86_64 (or the tiled kernel, which equals it bit for bit), its AVX2 one on
/// a build that targets AVX2, and the architecture's own elsewhere
/// ([`super::cpu_q8::REPRODUCES_CANDLE`]).
const CPU_KERNEL: &str = if cfg!(all(target_arch = "x86_64", target_feature = "avx2")) {
    "x86_64+avx2"
} else {
    std::env::consts::ARCH
};

/// Resolves the configured device against what this build can actually reach.
///
/// `auto` tries only the vault's ordered policy candidates. CPU is a fallback
/// only when that row permits it. A candidate that is unavailable is skipped;
/// no available permitted candidate is a configuration refusal. A NAMED device
/// that is unavailable is an error rather than a silent downgrade: an operator
/// who wrote `device = "metal"` and got the CPU would read the throughput as a
/// model problem.
pub(super) fn resolve_device(
    configured: EmbedderDevice,
    auto_devices: &[EmbedderDevice],
) -> oneiron::Result<Device> {
    match configured {
        EmbedderDevice::Cpu => Ok(Device::Cpu),
        EmbedderDevice::Metal => Device::new_metal(0).map_err(|e| {
            oneiron::Error::InvalidConfig(format!("embedder device metal is unavailable: {e}"))
        }),
        EmbedderDevice::Cuda => Device::new_cuda(0).map_err(|e| {
            oneiron::Error::InvalidConfig(format!("embedder device cuda is unavailable: {e}"))
        }),
        EmbedderDevice::Auto => {
            for candidate in auto_devices {
                let available = match candidate {
                    EmbedderDevice::Metal => Device::new_metal(0),
                    EmbedderDevice::Cuda => Device::new_cuda(0),
                    EmbedderDevice::Cpu => return Ok(Device::Cpu),
                    EmbedderDevice::Auto => {
                        return Err(oneiron::Error::InvalidConfig(
                            "embedder.policy.auto_devices cannot contain auto".to_owned(),
                        ));
                    }
                };
                if let Ok(device) = available {
                    return Ok(device);
                }
            }
            Err(oneiron::Error::InvalidConfig(
                "no permitted auto embedder device is available; narrow embedder.policy.auto_devices or choose a named device".to_owned(),
            ))
        }
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

/// Who computes this provider's vectors: the device it resolved and the
/// runtime build, stored beside each vector (ARCH-0036). It is never part of
/// the space, which the same model shares on every device.
pub(super) fn provenance(device: &Device, quant: EmbedderQuant) -> EmbeddingProvenance {
    let runtime = format!("candle {CANDLE_VERSION} {}", quant.as_str());
    match device {
        Device::Cpu => {
            EmbeddingProvenance::new(EmbeddingDevice::Cpu, format!("{runtime} {CPU_KERNEL}"))
        }
        Device::Cuda(_) => EmbeddingProvenance::new(EmbeddingDevice::Cuda, runtime),
        Device::Metal(_) => EmbeddingProvenance::new(EmbeddingDevice::Metal, runtime),
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
