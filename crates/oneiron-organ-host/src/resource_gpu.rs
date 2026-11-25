//! GPU leases, beside the memory floor's ([`crate::FloorLease`]). The node
//! takes a device lease inside its launch commit, then immediately calls
//! [`GpuDeviceLease::confirm_launch`]. There is no hold during staging.
//!
//! A fresh driver reading must show the GPU offered, not withheld, untaken,
//! and running no compute process. The disk must have room past its reserve.
//! A paused or drained machine takes no new GPU work, and a quarantined GPU
//! cannot be leased or confirmed for launch.
//!
//! The lease lives for the workload's life. [`GpuDeviceLease::keep`] hands
//! the slot to the journaled key until the machine's table ends it. After a
//! restart the node reattaches its live keys and replays quarantines from its
//! journal. [`GpuDeviceLease::finish`] records how the job ended; repeated
//! failures can drain the machine until a person clears it.

use oneiron::machine_capacity::GpuDevice;
use serde::{Deserialize, Serialize};

/// What a GPU lease asks for. `key` is the job chunk's
/// idempotency key: one key holds at most one GPU.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuSlotRequest {
    pub key: String,
    /// This GPU only, by the driver's device id.
    #[serde(default)]
    pub device_id: Option<String>,
    /// A GPU of this model only, as the driver names it.
    #[serde(default)]
    pub model: Option<String>,
    /// The least GPU memory it needs, in MiB.
    #[serde(default)]
    pub min_memory_mib: u64,
    /// The bytes the job will write on the machine's disk (its staged
    /// inputs and its outputs); the booking claims them past the disk's
    /// reserve.
    #[serde(default)]
    pub disk_bytes: u64,
}

impl GpuSlotRequest {
    /// Whether `device` is a GPU this request may take.
    #[must_use]
    pub fn admits(&self, device: &GpuDevice) -> bool {
        self.device_id
            .as_ref()
            .is_none_or(|id| *id == device.device_id)
            && self
                .model
                .as_ref()
                .is_none_or(|model| *model == device.model)
            && device.memory_total_mib >= self.min_memory_mib
    }
}

/// A GPU granted under a workload's key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuSlotGrant {
    pub key: String,
    pub device: GpuDevice,
    /// When the GPU was taken, in Unix milliseconds.
    pub granted_at_ms: u64,
}

/// The compute processes the driver lists on one GPU now.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuDeviceProcesses {
    /// Their process ids.
    pub pids: Vec<u32>,
    /// How many it lists with no process id.
    pub hidden: u32,
}

impl GpuDeviceProcesses {
    /// Whether no compute process runs on the GPU.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pids.is_empty() && self.hidden == 0
    }
}

/// Why no GPU was leased or confirmed for launch.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum GpuSlotRefusal {
    #[error("gpu_slots.unknown_device: this machine has no GPU {device_id}")]
    UnknownDevice { device_id: String },
    #[error("gpu_slots.not_offered: this machine does not offer GPU {device_id}")]
    NotOffered { device_id: String },
    #[error("gpu_slots.withheld: another booker holds GPU {device_id}")]
    Withheld { device_id: String },
    #[error("gpu_slots.busy: a compute process runs on GPU {device_id}")]
    Busy { device_id: String, pids: Vec<u32> },
    #[error("gpu_slots.taken: another lease or job holds GPU {device_id}")]
    Taken { device_id: String },
    #[error("gpu_slots.no_match: no GPU of this machine meets the request")]
    NoMatch,
    #[error("gpu_slots.none_free: no GPU of this machine that meets the request is free")]
    NoneFree,
    #[error("gpu_slots.not_held: no GPU is taken under this key")]
    NotHeld,
    #[error(
        "gpu_slots.disk_under_reserve: the booking needs {needed_bytes} free bytes on the disk (its reserve, the other bookings' claims and this job's bytes), and the disk has {free_bytes}"
    )]
    DiskUnderReserve { needed_bytes: u64, free_bytes: u64 },
    #[error(
        "gpu_slots.quarantined: GPU {device_id} takes no job until a clean probe or a person clears it: {why}"
    )]
    Quarantined { device_id: String, why: String },
    #[error("gpu_slots.paused: this machine takes no new GPU job now: {reason}")]
    Paused { reason: String },
    #[error("gpu_slots.drained: this machine takes no GPU job until a person clears it: {reason}")]
    Drained { reason: String },
    #[error("gpu_slots.unmeasured: {reason}")]
    Unmeasured { reason: String },
}

/// How a job that held a GPU ended, as its runner reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "end", rename_all = "snake_case")]
pub enum GpuLeaseEnd {
    /// The job's process finished its work.
    Succeeded,
    /// The job failed on this machine (it did not start, or its process
    /// failed). Several in a row drain the machine.
    Failed { reason: String },
    /// It was stopped on request; this says nothing about the machine.
    Cancelled,
}

/// One of this machine's GPUs, leased to one workload and held until it
/// drops, finishes or is kept.
pub trait GpuDeviceLease: Send {
    /// The GPU it holds, under which key, and since when.
    fn grant(&self) -> &GpuSlotGrant;

    /// The launch recheck, just before each start of the job's process on
    /// the GPU: a fresh reading shows it still offered, not withheld, and
    /// running no compute process, and the machine neither paused nor
    /// drained. A retry is checked afresh, whatever an earlier confirmation
    /// answered.
    ///
    /// # Errors
    ///
    /// Why the process must not start ([`GpuSlotRefusal::Busy`] names the
    /// processes found). The lease still holds the GPU until it drops.
    fn confirm_launch(&mut self) -> Result<(), GpuSlotRefusal>;

    /// The compute processes on its GPU now, from a fresh reading: after the
    /// job's processes are gone, any left are another's.
    ///
    /// # Errors
    ///
    /// [`GpuSlotRefusal::Unmeasured`] when the driver cannot be read.
    fn end_check(&self) -> Result<GpuDeviceProcesses, GpuSlotRefusal>;

    /// Gives the GPU back and records how its job ended. Dropping the lease
    /// instead gives it back and records nothing.
    fn finish(self: Box<Self>, end: GpuLeaseEnd);

    /// Hands the GPU to the journaled key until the machine's slot table
    /// ends it by key.
    fn keep(self: Box<Self>) -> GpuSlotGrant;
}

/// This machine's GPUs, as the host leases them to calls. The server's
/// implementation is its GPU slot table.
pub trait MachineGpus: Send + Sync {
    /// Leases the GPU already taken by `request.key` if it has no live
    /// lease, or, for a new key, picks the free matching GPU with the least
    /// memory from a fresh reading without waiting.
    ///
    /// # Errors
    ///
    /// [`GpuSlotRefusal`]: why no GPU was leased. A refusal holds nothing.
    fn try_lease(
        &self,
        request: &GpuSlotRequest,
    ) -> Result<Box<dyn GpuDeviceLease>, GpuSlotRefusal>;
}
