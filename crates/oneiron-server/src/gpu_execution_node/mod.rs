//! A vault machine that runs pinned workloads for the vault's issuer (pass
//! 33, `33-exec-node/DESIGN.md`): the job protocols' messages ([`wire`]),
//! the node's own configuration and templates ([`node_settings`]), the
//! node's gate, controls and authority tick ([`node`]), its two mesh
//! services ([`service`]), and the node's keys with their journal
//! ([`jobs`]). Its GPUs: what they are and what runs on them now
//! ([`device`]), what it offers and answers when asked ([`availability`]),
//! the slots it leases on them, beside its memory floor ([`slots`]), and a
//! read that picks a machine's GPU before a quote ([`selection`]). The
//! issuer's side: the `vault_machine` GPU job connector ([`issuer`]).

pub mod availability;
pub mod device;
pub mod issuer;
#[cfg(unix)]
pub mod jobs;
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
    AuthorityEnded, ExecutionNode, GateAsk, NodeControls, NodeKeys, NodeSnapshot,
    execution_node_file,
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
