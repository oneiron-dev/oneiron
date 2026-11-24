//! What this machine offers the vault's GPU jobs, and what it answers when
//! asked: the offer (`[gpu_jobs.devices]`), the jobs' disk, and the
//! availability answer the home selects from.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::device::GpuDevice;
use super::slots::{GpuSlotRefusal, GpuSlotRequest};

/// How long a hold keeps its GPU before a lease must take it, in seconds:
/// two minutes.
pub const GPU_SLOT_HOLD_SECS: u64 = 120;

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
    /// How long a hold keeps its GPU before a lease takes it, in seconds.
    pub hold_secs: u64,
    /// Failed jobs in a row that drain this machine. 0 never drains it.
    pub drain_after_failures: u32,
    /// Where a drain is written, so it outlasts a restart. A person deletes
    /// it to clear the drain. `None` keeps the drain in memory only.
    pub drain_file: Option<PathBuf>,
    /// Where the table takes one lock file per offered GPU, for as long as
    /// it runs, so no other Oneiron server on this machine offers the same
    /// GPU. `None` takes no lock.
    pub owner_lock_dir: Option<PathBuf>,
}

impl Default for GpuDeviceOffer {
    fn default() -> Self {
        Self {
            offered: BTreeSet::new(),
            withheld_file: None,
            hold_secs: GPU_SLOT_HOLD_SECS,
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
    /// The home's hold under `key` keeps it until a lease takes it.
    Held { key: String },
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
    /// The key a hold, lease or job takes the GPU under.
    #[must_use]
    pub fn key(&self) -> Option<&str> {
        match self {
            Self::Held { key } | Self::Leased { key } | Self::Launched { key } => Some(key),
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

/// What this machine's GPUs are doing, read from the driver when it was
/// asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuAvailability {
    /// When the driver was read, in Unix milliseconds.
    pub measured_at_ms: u64,
    /// While the machine is drained, why. It then takes no GPU work.
    #[serde(default)]
    pub drained: Option<String>,
    /// What the jobs' disk holds now, when the table books on one.
    #[serde(default)]
    pub disk: Option<GpuDiskReading>,
    pub devices: Vec<GpuDeviceAvailability>,
}

impl GpuAvailability {
    /// The free GPUs that meet `request`. There are none while the machine is
    /// drained or while its disk has no room for the request's bytes.
    pub fn free_matching<'a>(
        &'a self,
        request: &'a GpuSlotRequest,
    ) -> impl Iterator<Item = &'a GpuDevice> + 'a {
        let open =
            self.drained.is_none() && self.disk.is_none_or(|disk| disk.fits(request.disk_bytes));
        self.devices
            .iter()
            .filter(move |device| {
                open && device.state == GpuDeviceState::Free && request.admits(&device.device)
            })
            .map(|device| &device.device)
    }
}
