//! A vault machine that runs GPU jobs and pinned workloads for the vault's
//! issuer (pass 33, `33-exec-node/DESIGN.md`): what its GPUs are and what
//! runs on them now ([`device`]), what it offers and answers when asked
//! ([`availability`]), the slots it holds and leases on them, beside its
//! memory floor ([`slots`]), the home's choice of a GPU among the vault's
//! machines ([`selection`]), the job protocols' messages ([`wire`]), the
//! node's two mesh services ([`service`]), and the node's job service with
//! its journal ([`jobs`]).

pub mod availability;
pub mod device;
#[cfg(unix)]
pub mod jobs;
pub mod selection;
#[cfg(feature = "mesh")]
pub mod service;
pub mod slots;
pub mod wire;

pub use availability::{
    GPU_DRAIN_AFTER_FAILURES, GPU_SLOT_HOLD_SECS, GpuAvailability, GpuDeviceAvailability,
    GpuDeviceOffer, GpuDeviceState, GpuDiskReading, GpuJobDisk,
};
pub use device::{
    GPU_QUERY_TIMEOUT, GpuComputeProcess, GpuDevice, GpuDeviceProbe, GpuProbeError, NvidiaSmiProbe,
    parse_compute_process_lines, parse_device_lines, recorded_gpu_devices,
};
pub use selection::{
    GpuNodeCandidate, GpuSelectionRefusal, GpuSlotPeer, GpuSlotPeerError, GpuSlotPlacement,
    LocalGpuSlotPeer, gpu_node_candidates, select_gpu_slot,
};
#[cfg(feature = "mesh")]
pub use service::{JobService, JobStatusService};
pub use slots::{
    GpuDeviceLease, GpuDeviceProcesses, GpuJobEnd, GpuSlotHold, GpuSlotLease, GpuSlotRefusal,
    GpuSlotRequest, GpuSlotTable, MachineGpus,
};
