//! Device probes behind one trait (pass 34, `34-compute-general/DESIGN.md`
//! 2.1, row S5): what each device of this machine is, as [`DeviceFacts`],
//! and what computes on it now. One probe per driver family, each read live
//! at every ask: NVIDIA through `nvidia-smi` ([`NvidiaSmiProbe`]), AMD
//! through the `amdgpu` driver's sysfs files ([`AmdgpuSysfsProbe`]), Intel
//! through `xpu-smi` ([`XpuSmiProbe`]), and the Apple GPU through
//! `system_profiler` ([`SystemProfilerProbe`]).
//!
//! A probe reports a device by its kind, features and memory. Placement
//! reads only those ([`oneiron::job_workload::DeviceClaim::is_met_by`]):
//! the vendor and the model a probe reports are shown to people and never
//! matched, so a claim for a `Gpu` with the `rocm` feature is met by any
//! device that reports both, whoever made it.

pub mod amdgpu_sysfs;
pub mod apple_system_profiler;
pub mod xpu_smi;

use oneiron::job_workload::{DeviceFacts, DeviceState};

use super::device::{
    GpuComputeProcess, GpuDeviceProbe, GpuProbeError, NvidiaSmiProbe, gpu_device_facts,
};

pub use amdgpu_sysfs::AmdgpuSysfsProbe;
pub use apple_system_profiler::{SystemProfilerProbe, parse_system_profiler_devices};
pub use xpu_smi::{XpuSmiProbe, parse_xpu_smi_device_detail, parse_xpu_smi_device_list};

/// What a probe can say about the processes computing on its devices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComputeProcesses {
    /// Every compute process on each device the probe lists as
    /// [`oneiron::job_workload::DeviceClosure::Closed`], read now. An empty
    /// list means none runs.
    Listed(Vec<GpuComputeProcess>),
    /// This probe can never list every process on its devices (an Apple
    /// GPU; an Intel GPU, whose process list shows another user's processes
    /// only to a privileged caller), a fact of the probe and not a failed
    /// read: each device it lists is
    /// [`oneiron::job_workload::DeviceClosure::Admitted`], and its lease is
    /// a count of the claimants this machine let in.
    NeverListed,
}

/// One driver family's probe: the plug-in seam of pass 34, 2.1.
pub trait DeviceProbe: Send + Sync {
    /// Each device this probe finds now, in [`DeviceState::Offered`] with
    /// one claimant: the machine's offer and its holders set the state. A
    /// machine with no device of this family answers an empty list.
    ///
    /// # Errors
    ///
    /// [`GpuProbeError::Unavailable`] when the driver or its tool cannot
    /// be read, [`GpuProbeError::Unreadable`] when it answers something
    /// this probe cannot read.
    fn list(&self) -> Result<Vec<DeviceFacts>, GpuProbeError>;

    /// What computes on this probe's devices now. A failed read is an
    /// error, never an empty list: the device then counts as busy.
    ///
    /// # Errors
    ///
    /// As [`DeviceProbe::list`].
    fn processes(&self) -> Result<ComputeProcesses, GpuProbeError>;
}

impl DeviceProbe for NvidiaSmiProbe {
    fn list(&self) -> Result<Vec<DeviceFacts>, GpuProbeError> {
        Ok(self
            .devices()?
            .iter()
            .map(|device| gpu_device_facts(device, DeviceState::Offered))
            .collect())
    }

    fn processes(&self) -> Result<ComputeProcesses, GpuProbeError> {
        self.compute_processes().map(ComputeProcesses::Listed)
    }
}

/// Memory in bytes as whole MiB, rounded down.
fn bytes_to_mib(bytes: u64) -> u64 {
    bytes / (1024 * 1024)
}
