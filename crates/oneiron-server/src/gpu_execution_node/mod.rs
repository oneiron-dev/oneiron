//! A vault machine that runs GPU jobs and pinned workloads for the vault's
//! issuer (pass 33, `33-exec-node/DESIGN.md`): what its GPUs are and what
//! runs on them now ([`device`]), what it offers and answers when asked
//! ([`availability`]), the slots it leases on them, beside its memory floor
//! ([`slots`]), a read that picks a machine's GPU before a quote
//! ([`selection`]), the job protocols' messages ([`wire`]), the node's own
//! configuration and templates ([`node_settings`]), the node's gate,
//! controls and authority tick ([`node`]), and its two mesh services
//! ([`service`]).

pub mod availability;
pub mod device;
pub mod node;
pub mod node_settings;
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
pub use node::{
    AuthorityEnded, ExecutionNode, GateAsk, NodeControls, NodeKeys, execution_node_file,
};
pub use node_settings::{ExecutionNodeSettings, NodeTemplate};
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
