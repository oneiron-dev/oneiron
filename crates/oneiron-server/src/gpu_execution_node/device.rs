//! The GPUs this machine has and what runs on them now, read live from the
//! NVIDIA driver at each ask. Nothing here keeps a reading: the slot table
//! asks again at every availability answer, reservation and launch
//! recheck, so a card is never offered from an old reading.

use std::io::Read;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

pub use oneiron::machine_capacity::GpuDevice;

/// The driver's command-line query tool.
const NVIDIA_SMI: &str = "nvidia-smi";

/// The longest one driver query may take before it counts as failed, so a
/// hung driver never holds the slot table.
pub const GPU_QUERY_TIMEOUT: Duration = Duration::from_secs(10);

/// How often a running query is checked for its end.
const QUERY_POLL: Duration = Duration::from_millis(10);

/// One compute process the driver reports on a card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuComputeProcess {
    /// The card it runs on (the driver's UUID).
    pub device_id: String,
    /// Its process id, when the driver gives one.
    pub pid: Option<u32>,
}

/// Why this machine could not say what its GPUs are, what runs on them,
/// which of them another booker holds, or whether it is drained.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum GpuProbeError {
    #[error("gpu_probe.unavailable: the GPU driver could not be queried: {reason}")]
    Unavailable { reason: String },
    #[error("gpu_probe.unreadable: the GPU driver answered a line this probe cannot read: {line}")]
    Unreadable { line: String },
    #[error(
        "gpu_probe.withheld_unreadable: the list of GPUs another booker holds could not be read: {reason}"
    )]
    WithheldUnreadable { reason: String },
    #[error("gpu_probe.drain_unreadable: the GPU drain file could not be read: {reason}")]
    DrainUnreadable { reason: String },
}

/// What the slot table asks of this machine's GPU driver, at each ask.
pub trait GpuDeviceProbe: Send + Sync {
    /// Each GPU's device id, model and memory.
    ///
    /// # Errors
    ///
    /// [`GpuProbeError`] when the driver cannot be queried or answers a
    /// line it cannot read.
    fn devices(&self) -> Result<Vec<GpuDevice>, GpuProbeError>;

    /// Every compute process on every GPU now.
    ///
    /// # Errors
    ///
    /// [`GpuProbeError`] when the driver cannot be queried or answers a
    /// line it cannot read.
    fn compute_processes(&self) -> Result<Vec<GpuComputeProcess>, GpuProbeError>;
}

/// The shipped probe: `nvidia-smi`, one query per ask.
#[derive(Debug, Clone, Copy, Default)]
pub struct NvidiaSmiProbe;

impl GpuDeviceProbe for NvidiaSmiProbe {
    fn devices(&self) -> Result<Vec<GpuDevice>, GpuProbeError> {
        parse_device_lines(&query(&[
            "--query-gpu=uuid,name,memory.total",
            "--format=csv,noheader,nounits",
        ])?)
    }

    fn compute_processes(&self) -> Result<Vec<GpuComputeProcess>, GpuProbeError> {
        parse_compute_process_lines(&query(&[
            "--query-compute-apps=gpu_uuid,pid",
            "--format=csv,noheader,nounits",
        ])?)
    }
}

/// This machine's GPUs as the capacity probe records them: empty where the
/// driver is absent or fails, as on a machine with no NVIDIA GPU.
#[must_use]
pub fn recorded_gpu_devices() -> Vec<GpuDevice> {
    NvidiaSmiProbe.devices().unwrap_or_default()
}

/// Reads `nvidia-smi --query-gpu=uuid,name,memory.total
/// --format=csv,noheader,nounits` lines: the UUID first, the memory last,
/// the model between them (a model name may itself hold a comma).
///
/// # Errors
///
/// [`GpuProbeError::Unreadable`] for a line with no UUID, model or memory
/// count.
pub fn parse_device_lines(text: &str) -> Result<Vec<GpuDevice>, GpuProbeError> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            let unreadable = || GpuProbeError::Unreadable {
                line: line.to_owned(),
            };
            let (device_id, rest) = line.split_once(',').ok_or_else(unreadable)?;
            let (model, memory) = rest.rsplit_once(',').ok_or_else(unreadable)?;
            let device_id = plain_device_id(device_id).ok_or_else(unreadable)?;
            let model = model.trim();
            if model.is_empty() {
                return Err(unreadable());
            }
            Ok(GpuDevice {
                device_id,
                model: model.to_owned(),
                memory_total_mib: memory.trim().parse().map_err(|_| unreadable())?,
            })
        })
        .collect()
}

/// Reads `nvidia-smi --query-compute-apps=gpu_uuid,pid
/// --format=csv,noheader,nounits` lines. A line whose process id the driver
/// does not give still names a process on its card.
///
/// # Errors
///
/// [`GpuProbeError::Unreadable`] for a line with no card UUID.
pub fn parse_compute_process_lines(text: &str) -> Result<Vec<GpuComputeProcess>, GpuProbeError> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            let unreadable = || GpuProbeError::Unreadable {
                line: line.to_owned(),
            };
            let (device_id, pid) = line.split_once(',').unwrap_or((line, ""));
            Ok(GpuComputeProcess {
                device_id: plain_device_id(device_id).ok_or_else(unreadable)?,
                pid: pid.trim().parse().ok(),
            })
        })
        .collect()
}

/// A device id as the driver writes it: not empty, no whitespace or
/// control characters.
fn plain_device_id(id: &str) -> Option<String> {
    let id = id.trim();
    (!id.is_empty() && !id.chars().any(|c| c.is_whitespace() || c.is_control()))
        .then(|| id.to_owned())
}

/// Runs one driver query and answers its output, within
/// [`GPU_QUERY_TIMEOUT`]: its exit and the end of its output both wait no
/// longer, and a query past it is killed and reaped off the caller's path.
fn query(args: &[&str]) -> Result<String, GpuProbeError> {
    let unavailable = |reason: String| GpuProbeError::Unavailable { reason };
    let mut child = oneiron_spawn::command(NVIDIA_SMI)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| unavailable(format!("{NVIDIA_SMI} did not start: {error}")))?;
    let Some(mut stdout) = child.stdout.take() else {
        abandon(child);
        return Err(unavailable(format!("{NVIDIA_SMI} gave no output pipe")));
    };
    // Read while it runs, so a long answer never fills the pipe and stalls it.
    let (sender, output) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut text = String::new();
        let read = stdout.read_to_string(&mut text).map(|_| text);
        // An abandoned query has no receiver left; its output is dropped.
        sender.send(read).ok();
    });
    let deadline = Instant::now() + GPU_QUERY_TIMEOUT;
    let late = || {
        unavailable(format!(
            "{NVIDIA_SMI} did not answer within {} s",
            GPU_QUERY_TIMEOUT.as_secs()
        ))
    };
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(QUERY_POLL),
            Ok(None) => {
                abandon(child);
                return Err(late());
            }
            Err(error) => {
                abandon(child);
                return Err(unavailable(format!(
                    "{NVIDIA_SMI} could not be waited on: {error}"
                )));
            }
        }
    };
    let text = output
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| late())?
        .map_err(|error| unavailable(format!("{NVIDIA_SMI}'s output: {error}")))?;
    if !status.success() {
        return Err(unavailable(format!("{NVIDIA_SMI} exited with {status}")));
    }
    Ok(text)
}

/// Kills a query no longer waited for and reaps it on its own thread, so a
/// driver call that never returns holds that thread, not the caller.
fn abandon(mut child: std::process::Child) {
    if let Err(error) = child.kill() {
        tracing::debug!(%error, "the GPU driver query had already ended");
    }
    std::thread::spawn(move || {
        if let Err(error) = child.wait() {
            tracing::debug!(%error, "the GPU driver query could not be reaped");
        }
    });
}
