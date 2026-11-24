//! A vault machine that runs GPU jobs: what its GPUs are and what runs on
//! them now ([`device`]), what it offers and answers when asked
//! ([`availability`]), the slots it leases on them, beside its memory floor
//! ([`slots`]), and a read that picks a machine's GPU before a quote
//! ([`selection`]).

pub mod availability;
pub mod device;
pub mod selection;
pub mod slots;

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
pub use slots::{
    GpuDeviceLease, GpuDeviceProcesses, GpuLeaseEnd, GpuSlotGrant, GpuSlotLease, GpuSlotRefusal,
    GpuSlotRequest, GpuSlotTable, MachineGpus,
};
