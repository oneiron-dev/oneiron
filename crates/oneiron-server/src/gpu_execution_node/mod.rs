//! A vault machine that runs GPU jobs: what its GPUs are and what runs on
//! them now ([`device`]), the slots it holds and leases on them, beside its
//! memory floor ([`slots`]), and the home's choice of a GPU among the
//! vault's machines ([`selection`]).

pub mod device;
pub mod selection;
pub mod slots;

pub use device::{
    GPU_QUERY_TIMEOUT, GpuComputeProcess, GpuDevice, GpuDeviceProbe, GpuProbeError, NvidiaSmiProbe,
    parse_compute_process_lines, parse_device_lines, recorded_gpu_devices,
};
pub use selection::{
    GpuNodeCandidate, GpuSelectionRefusal, GpuSlotPeer, GpuSlotPeerError, GpuSlotPlacement,
    LocalGpuSlotPeer, gpu_node_candidates, select_gpu_slot,
};
pub use slots::{
    GPU_DRAIN_AFTER_FAILURES, GPU_SLOT_HOLD_SECS, GpuAvailability, GpuDeviceAvailability,
    GpuDeviceLease, GpuDeviceOffer, GpuDeviceProcesses, GpuDeviceState, GpuDiskReading, GpuJobDisk,
    GpuJobEnd, GpuSlotHold, GpuSlotLease, GpuSlotRefusal, GpuSlotRequest, GpuSlotTable,
    MachineGpus,
};
