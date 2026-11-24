//! A vault machine that runs GPU jobs: what its GPUs are and what runs on
//! them now ([`device`]), the slots it holds on them ([`slots`]), and the
//! home's choice of a slot among the vault's machines ([`selection`]).

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
    GPU_SLOT_HOLD_SECS, GpuAvailability, GpuDeviceAvailability, GpuDeviceOffer, GpuDeviceState,
    GpuSlotGrant, GpuSlotRefusal, GpuSlotRequest, GpuSlotTable,
};
