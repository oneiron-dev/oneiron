//! What this machine offers the vault's GPU jobs, and what it answers when
//! asked: the offer (`[gpu_jobs.devices]`), the jobs' disk, and the
//! availability answer a caller may use to pick a machine before a quote.

use std::collections::BTreeSet;
use std::path::PathBuf;

use oneiron::job_workload::{DeviceFacts, DeviceState, HeldDevice, Sharing};
use serde::{Deserialize, Serialize};

use super::device::{GpuDevice, gpu_device_facts};
use super::slots::{GpuSlotRefusal, GpuSlotRequest};

/// How many jobs in a row must finish failed before the machine is drained.
pub const GPU_DRAIN_AFTER_FAILURES: u32 = 3;

/// Which of this machine's GPUs it offers to the vault's GPU jobs, and how
/// (`[gpu_jobs.devices]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuDeviceOffer {
    /// The offered GPUs, by device id. Empty, the default, offers none.
    pub offered: BTreeSet<String>,
    /// A file naming the GPUs another booker holds now, one device id per
    /// line (`#` starts a comment line), read at every ask. Once a file is
    /// named, a file that cannot be read offers nothing. `None` means no
    /// other booker.
    pub withheld_file: Option<PathBuf>,
    /// Failed jobs in a row that drain this machine. 0 never drains it.
    pub drain_after_failures: u32,
    /// Where a drain is written, so it outlasts a restart. A person deletes
    /// it to clear the drain. `None` keeps the drain in memory only.
    pub drain_file: Option<PathBuf>,
    /// Where the table takes one lock file per offered GPU, for as long as
    /// it runs, and keeps each launched job's record, so no other Oneiron
    /// server on this machine offers the same GPU, even while a job outlives
    /// its server. It must exist and be the one directory every server that
    /// sees these GPUs names. `None` takes no lock and keeps no record: one
    /// server on the machine.
    pub owner_lock_dir: Option<PathBuf>,
}

impl Default for GpuDeviceOffer {
    fn default() -> Self {
        Self {
            offered: BTreeSet::new(),
            withheld_file: None,
            drain_after_failures: GPU_DRAIN_AFTER_FAILURES,
            drain_file: None,
            owner_lock_dir: None,
        }
    }
}

/// What the disk a GPU job writes on holds now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuDiskReading {
    /// The bytes an unprivileged writer may still use there.
    pub free_bytes: u64,
    /// The free bytes no work takes.
    pub reserve_bytes: u64,
    /// The bytes work in flight has claimed past the reserve.
    pub claimed_bytes: u64,
}

impl GpuDiskReading {
    /// Whether a booking of `bytes` more fits past the reserve and every
    /// claim.
    #[must_use]
    pub fn fits(&self, bytes: u64) -> bool {
        self.free_bytes
            >= self
                .reserve_bytes
                .saturating_add(self.claimed_bytes)
                .saturating_add(bytes)
    }
}

/// The disk a GPU job writes on, as its booking claims room there.
pub trait GpuJobDisk: Send + Sync {
    /// Claims `bytes` past the disk's reserve and every other claim, held
    /// until the returned claim drops. 0 bytes still requires the disk to
    /// be at or above its reserve.
    ///
    /// # Errors
    ///
    /// [`GpuSlotRefusal::DiskUnderReserve`] when they do not fit;
    /// [`GpuSlotRefusal::Unmeasured`] when the disk cannot be read.
    fn claim(&self, bytes: u64) -> Result<Box<dyn Send + Sync>, GpuSlotRefusal>;

    /// Claims `bytes` a live job booked before a restart, whatever the disk
    /// holds now: the job may still write them, so new bookings count them.
    /// Held until the returned claim drops.
    fn restore(&self, bytes: u64) -> Box<dyn Send + Sync>;

    /// What the disk holds now.
    ///
    /// # Errors
    ///
    /// The error reading its free space.
    fn reading(&self) -> std::io::Result<GpuDiskReading>;
}

/// The server's disk floor as a GPU job's disk: a booking claims its bytes
/// with the uploads, backups and spools that claim theirs there.
impl GpuJobDisk for crate::machine::DiskFloor {
    fn claim(&self, bytes: u64) -> Result<Box<dyn Send + Sync>, GpuSlotRefusal> {
        match self.claim_room(bytes) {
            Ok(claim) => Ok(Box::new(claim)),
            Err(oneiron::code_sandbox::SpoolFloorRefusal::AtFloor(at)) => {
                Err(GpuSlotRefusal::DiskUnderReserve {
                    needed_bytes: at.needed,
                    free_bytes: at.available,
                })
            }
            Err(oneiron::code_sandbox::SpoolFloorRefusal::Unmeasured(error)) => {
                Err(GpuSlotRefusal::Unmeasured {
                    reason: format!("the GPU job disk's free space could not be read: {error}"),
                })
            }
        }
    }

    fn restore(&self, bytes: u64) -> Box<dyn Send + Sync> {
        Box::new(self.restore_room(bytes))
    }

    fn reading(&self) -> std::io::Result<GpuDiskReading> {
        let (free_bytes, reserve_bytes, claimed_bytes) = self.measured()?;
        Ok(GpuDiskReading {
            free_bytes,
            reserve_bytes,
            claimed_bytes,
        })
    }
}

/// What one of this machine's GPUs is doing, as an availability answer
/// reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum GpuDeviceState {
    /// Offered, not withheld, untaken, and no compute process runs on it.
    Free,
    /// A compute process this table did not launch runs on it, with the
    /// process ids the driver gave.
    Busy { pids: Vec<u32> },
    /// It takes no new job until cleared; `key` still takes the slot, if any.
    Quarantined { why: String, key: Option<String> },
    /// The workload under `key` leased it, and its process has not started.
    Leased { key: String },
    /// The job under `key` runs on it.
    Launched { key: String },
    /// Another booker holds it.
    Withheld,
    /// This machine does not offer it.
    NotOffered,
}

impl GpuDeviceState {
    /// The key a lease or job takes the GPU under, even during quarantine.
    #[must_use]
    pub fn key(&self) -> Option<&str> {
        match self {
            Self::Quarantined { key, .. } => key.as_deref(),
            Self::Leased { key } | Self::Launched { key } => Some(key),
            Self::Free | Self::Busy { .. } | Self::Withheld | Self::NotOffered => None,
        }
    }
}

/// One GPU in an availability answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuDeviceAvailability {
    pub device: GpuDevice,
    pub state: GpuDeviceState,
}

impl GpuDeviceAvailability {
    /// This GPU as placement reads it (pass 34, 2.1), for
    /// [`oneiron::job_workload::ResourceRequest::place_devices`]. A free GPU
    /// is offered. A GPU that runs another's compute process, that another
    /// booker holds or that this machine does not offer is withheld: no
    /// claim takes it now. A GPU leased, launched or quarantined under a key
    /// has that key as its one exclusive holder.
    #[must_use]
    pub fn held(&self) -> HeldDevice {
        let (state, holder) = match &self.state {
            GpuDeviceState::Free => (DeviceState::Offered, None),
            GpuDeviceState::Busy { .. } | GpuDeviceState::Withheld | GpuDeviceState::NotOffered => {
                (DeviceState::Withheld, None)
            }
            GpuDeviceState::Leased { key } | GpuDeviceState::Launched { key } => (
                DeviceState::Leased {
                    keys: vec![key.clone()],
                },
                Some(Sharing::Exclusive),
            ),
            GpuDeviceState::Quarantined { why, key } => (
                DeviceState::Quarantined { why: why.clone() },
                key.as_ref().map(|_| Sharing::Exclusive),
            ),
        };
        HeldDevice {
            facts: gpu_device_facts(&self.device, state),
            holders: holder.into_iter().collect(),
        }
    }

    /// What this GPU is and does, as [`Self::held`] reads it.
    #[must_use]
    pub fn facts(&self) -> DeviceFacts {
        self.held().facts
    }
}

/// Whether `request` may take `device`, a GPU the driver listed, whatever it
/// is doing now.
pub(super) fn admits_gpu(request: &GpuSlotRequest, device: &GpuDevice) -> bool {
    request.admits(&gpu_device_facts(device, DeviceState::Offered))
}

/// What this machine's GPUs are doing, read from the driver when it was
/// asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuAvailability {
    /// When the driver was read, in Unix milliseconds.
    pub measured_at_ms: u64,
    /// While the machine is paused, why. It then takes no new GPU work.
    #[serde(default)]
    pub paused: Option<String>,
    /// While the machine is drained, why. It then takes no GPU work.
    #[serde(default)]
    pub drained: Option<String>,
    /// What the jobs' disk holds now, when the table books on one.
    #[serde(default)]
    pub disk: Option<GpuDiskReading>,
    pub devices: Vec<GpuDeviceAvailability>,
}

impl GpuAvailability {
    /// Every GPU of the answer as placement reads it
    /// ([`GpuDeviceAvailability::held`]). While the machine is paused or
    /// drained, a caller places nothing on it.
    #[must_use]
    pub fn held_devices(&self) -> Vec<HeldDevice> {
        self.devices
            .iter()
            .map(GpuDeviceAvailability::held)
            .collect()
    }

    /// The free GPUs that meet `request`. There are none while the machine is
    /// paused, drained or while its disk has no room for the request's bytes.
    /// A GPU id the answer lists on more than one line is never offered,
    /// whatever each line says: the machine's own reading refuses such an
    /// answer (`GpuProbeError::RepeatedDevice`), so its slot table leases
    /// nothing from it.
    pub fn free_matching<'a>(
        &'a self,
        request: &'a GpuSlotRequest,
    ) -> impl Iterator<Item = &'a GpuDevice> + 'a {
        let open = self.paused.is_none()
            && self.drained.is_none()
            && self.disk.is_none_or(|disk| disk.fits(request.disk_bytes));
        self.devices
            .iter()
            .filter(move |device| {
                open && device.state == GpuDeviceState::Free
                    && admits_gpu(request, &device.device)
                    && !self.lists_more_than_once(&device.device.device_id)
            })
            .map(|device| &device.device)
    }

    /// Whether the answer lists `device_id` on more than one line.
    fn lists_more_than_once(&self, device_id: &str) -> bool {
        self.devices
            .iter()
            .filter(|device| device.device.device_id == device_id)
            .nth(1)
            .is_some()
    }
}
