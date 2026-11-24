//! GPU leases, beside the memory floor's ([`crate::FloorLease`]): a call
//! that runs on one of this machine's GPUs holds that GPU alone, from its
//! admission until its lease drops or finishes.
//!
//! The host leases a GPU from [`MachineGpus`] (in the server, its GPU slot
//! table) at the call's admission, never waiting. The lease is taken from a
//! fresh driver reading: the GPU is offered, not withheld by another booker,
//! held by no other call, and runs no compute process. The machine's disk is
//! not under its reserve, and the machine is not drained. Just before the
//! call's process starts, [`GpuDeviceLease::confirm_launch`] checks the GPU
//! again. A call that took an earlier reservation (a hold under the same
//! key) takes that GPU over.
//!
//! [`GpuDeviceLease::finish`] records how the job ended. A machine whose
//! jobs fail several times in a row is drained: it leases no GPU until a
//! person clears it.

use oneiron::machine_capacity::GpuDevice;
use serde::{Deserialize, Serialize};

/// What a GPU reservation or lease asks for. `key` is the job chunk's
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

/// Why no GPU was reserved, leased or launched.
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
    #[error("gpu_slots.taken: another reservation or call holds GPU {device_id}")]
    Taken { device_id: String },
    #[error("gpu_slots.no_match: no GPU of this machine meets the request")]
    NoMatch,
    #[error("gpu_slots.none_free: no GPU of this machine that meets the request is free")]
    NoneFree,
    #[error(
        "gpu_slots.disk_under_reserve: the booking needs {needed_bytes} free bytes on the disk (its reserve, the other bookings' claims and this job's bytes), and the disk has {free_bytes}"
    )]
    DiskUnderReserve { needed_bytes: u64, free_bytes: u64 },
    #[error("gpu_slots.drained: this machine takes no GPU job until a person clears it: {reason}")]
    Drained { reason: String },
    #[error("gpu_slots.unmeasured: {reason}")]
    Unmeasured { reason: String },
}

/// How a job that held a GPU ended, as its runner reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "end", rename_all = "snake_case")]
pub enum GpuJobEnd {
    /// The job's process finished its work.
    Succeeded,
    /// The job failed on this machine (it did not start, or its process
    /// failed). Several in a row drain the machine.
    Failed { reason: String },
    /// It was stopped on request; this says nothing about the machine.
    Cancelled,
}

/// One of this machine's GPUs, leased to one call and held until it drops
/// or finishes.
pub trait GpuDeviceLease: Send {
    /// The GPU it holds.
    fn device(&self) -> &GpuDevice;

    /// The key it holds the GPU under.
    fn key(&self) -> &str;

    /// The launch recheck, just before the call's process starts on the GPU:
    /// a fresh reading shows it still offered, not withheld, and running no
    /// compute process, and the machine is not drained. Once confirmed, it
    /// stays confirmed.
    ///
    /// # Errors
    ///
    /// Why the process must not start. The lease still holds the GPU until
    /// it drops.
    fn confirm_launch(&mut self) -> Result<(), GpuSlotRefusal>;

    /// Gives the GPU back and records how its job ended. Dropping the lease
    /// instead gives it back and records nothing.
    fn finish(self: Box<Self>, end: GpuJobEnd);
}

/// This machine's GPUs, as the host leases them to calls. The server's
/// implementation is its GPU slot table.
pub trait MachineGpus: Send + Sync {
    /// Leases one GPU that meets `request` now, from a fresh reading, never
    /// waiting: the GPU an earlier hold under `request.key` reserved, else
    /// the free matching GPU with the least memory.
    ///
    /// # Errors
    ///
    /// [`GpuSlotRefusal`]: why no GPU was leased. A refusal holds nothing.
    fn try_lease(
        &self,
        request: &GpuSlotRequest,
    ) -> Result<Box<dyn GpuDeviceLease>, GpuSlotRefusal>;
}
