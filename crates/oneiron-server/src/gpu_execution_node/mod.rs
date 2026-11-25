//! A vault machine that runs pinned workloads for the vault's issuer (pass
//! 33, `33-exec-node/DESIGN.md`): the job protocols' messages ([`wire`])
//! and the node's two mesh services ([`service`]). Its GPUs: what they are
//! and what runs on them now ([`device`]), what it offers and answers when
//! asked ([`availability`]), the slots it leases on them, beside its memory
//! floor ([`slots`]), and a read that picks a machine's GPU before a quote
//! ([`selection`]). The issuer's side: the `vault_machine` GPU job connector
//! ([`issuer`]).

pub mod availability;
pub mod device;
pub mod issuer;
pub mod selection;
#[cfg(feature = "mesh")]
pub mod service;
pub mod slots;
pub mod wire;

pub use availability::{
    GPU_DRAIN_AFTER_FAILURES, GpuAvailability, GpuDeviceAvailability, GpuDeviceOffer,
    GpuDeviceState, GpuDiskReading, GpuJobDisk,
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
    GpuDeviceLease, GpuDeviceProcesses, GpuLeaseEnd, GpuSlotGrant, GpuSlotLease, GpuSlotRefusal,
    GpuSlotRequest, GpuSlotTable, MachineGpus,
};
