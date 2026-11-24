//! This machine's GPU slots: one job per offered GPU. A reservation takes a
//! GPU atomically under one lock, after a fresh driver reading shows it
//! offered, not withheld, held by no other reservation, and running no
//! compute process. The launch rechecks the same just before the job's
//! process starts. Nothing is ever admitted from the hourly capacity record.
//!
//! One booker per GPU: a GPU named in `[gpu_jobs.devices].withheld_file`
//! belongs to another booker, whatever writes that file, and is never
//! offered. The file is read at every ask.
//!
//! The slots live in memory. After a restart a job still running shows as a
//! compute process on its GPU, so no new reservation takes that GPU.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use serde::{Deserialize, Serialize};

use super::device::{GpuComputeProcess, GpuDevice, GpuDeviceProbe, GpuProbeError};

/// How long a reservation holds its GPU before its launch confirms it, in
/// seconds: two minutes.
pub const GPU_SLOT_HOLD_SECS: u64 = 120;

/// Which of this machine's GPUs it offers to the vault's GPU jobs
/// (`[gpu_jobs.devices]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuDeviceOffer {
    /// The offered GPUs, by device id. Empty, the default, offers none.
    pub offered: BTreeSet<String>,
    /// A file naming the GPUs another booker holds now, one device id per
    /// line (`#` starts a comment line), read at every ask. Once one is
    /// named, a file that cannot be read offers nothing. `None`: no other
    /// booker.
    pub withheld_file: Option<PathBuf>,
    /// How long a reservation holds its GPU before its launch, in seconds.
    pub hold_secs: u64,
}

impl Default for GpuDeviceOffer {
    fn default() -> Self {
        Self {
            offered: BTreeSet::new(),
            withheld_file: None,
            hold_secs: GPU_SLOT_HOLD_SECS,
        }
    }
}

/// What one of this machine's GPUs is doing, as an availability answer
/// reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum GpuDeviceState {
    /// Offered, not withheld, held by no reservation, and no compute
    /// process runs on it.
    Free,
    /// A compute process this table did not launch runs on it: the process
    /// ids the driver gave.
    Busy { pids: Vec<u32> },
    /// A reservation holds it until its launch.
    Held { key: String },
    /// The job this table launched under `key` runs on it.
    Launched { key: String },
    /// Another booker holds it.
    Withheld,
    /// This machine does not offer it.
    NotOffered,
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
    pub devices: Vec<GpuDeviceAvailability>,
}

impl GpuAvailability {
    /// The free GPUs that meet `request`.
    pub fn free_matching<'a>(
        &'a self,
        request: &'a GpuSlotRequest,
    ) -> impl Iterator<Item = &'a GpuDevice> + 'a {
        self.devices
            .iter()
            .filter(|device| device.state == GpuDeviceState::Free && request.admits(&device.device))
            .map(|device| &device.device)
    }
}

/// What a reservation asks for. `key` is the chunk's idempotency key: the
/// same key always answers the same grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuSlotRequest {
    pub key: String,
    /// This GPU only, by device id.
    #[serde(default)]
    pub device_id: Option<String>,
    /// A GPU of this model only, as the driver names it.
    #[serde(default)]
    pub model: Option<String>,
    /// The least GPU memory it needs, in MiB.
    #[serde(default)]
    pub min_memory_mib: u64,
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

/// A held GPU slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuSlotGrant {
    pub key: String,
    pub device: GpuDevice,
    /// When the reservation took the GPU, in Unix milliseconds.
    pub held_at_ms: u64,
    /// When it lapses unless its launch confirms it first.
    pub hold_until_ms: u64,
}

/// Why this machine reserved or launched no slot.
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
    #[error("gpu_slots.taken: another reservation holds GPU {device_id}")]
    Taken { device_id: String },
    #[error("gpu_slots.no_match: no GPU of this machine meets the request")]
    NoMatch,
    #[error("gpu_slots.none_free: no GPU of this machine that meets the request is free")]
    NoneFree,
    #[error("gpu_slots.not_held: no reservation is held under this key")]
    NotHeld,
    #[error("gpu_slots.lapsed: the reservation lapsed before its launch")]
    Lapsed,
    #[error("gpu_slots.unmeasured: {probe}")]
    Unmeasured { probe: GpuProbeError },
}

/// One reservation, launched or not.
#[derive(Debug, Clone)]
struct Slot {
    grant: GpuSlotGrant,
    launched: bool,
}

/// One fresh reading of the driver and the withheld list.
struct Reading {
    devices: Vec<GpuDevice>,
    processes: Vec<GpuComputeProcess>,
    withheld: BTreeSet<String>,
}

impl Reading {
    /// The process ids on `device_id`, or `None` when no process runs there.
    fn processes_on(&self, device_id: &str) -> Option<Vec<u32>> {
        let mut on = self
            .processes
            .iter()
            .filter(|process| process.device_id == device_id)
            .peekable();
        on.peek()?;
        Some(on.filter_map(|process| process.pid).collect())
    }
}

/// This machine's GPU slots: at most one reservation per GPU.
pub struct GpuSlotTable {
    probe: Arc<dyn GpuDeviceProbe>,
    offer: GpuDeviceOffer,
    slots: Mutex<Vec<Slot>>,
}

impl std::fmt::Debug for GpuSlotTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GpuSlotTable")
            .field("offer", &self.offer)
            .field("slots", &*self.lock())
            .finish_non_exhaustive()
    }
}

impl GpuSlotTable {
    /// A table with no reservation, reading `probe` at every ask.
    #[must_use]
    pub fn new(probe: Arc<dyn GpuDeviceProbe>, offer: GpuDeviceOffer) -> Self {
        Self {
            probe,
            offer,
            slots: Mutex::default(),
        }
    }

    /// The GPUs this machine offers, and how.
    #[must_use]
    pub fn offer(&self) -> &GpuDeviceOffer {
        &self.offer
    }

    /// What each GPU is doing now, from a fresh driver reading. A lapsed hold
    /// is dropped first.
    ///
    /// # Errors
    ///
    /// [`GpuProbeError`] when the driver or the withheld list cannot be
    /// read: then nothing is offered.
    pub fn availability(&self, now_ms: u64) -> Result<GpuAvailability, GpuProbeError> {
        let mut slots = self.lock();
        lapse(&mut slots, now_ms);
        let reading = self.read()?;
        let devices = reading
            .devices
            .iter()
            .map(|device| GpuDeviceAvailability {
                device: device.clone(),
                state: self.state(&reading, slot_on(&slots, &device.device_id), device),
            })
            .collect();
        Ok(GpuAvailability {
            measured_at_ms: now_ms,
            devices,
        })
    }

    /// Holds one GPU for `request` until `now_ms` plus the hold, under the
    /// table's one lock and after a fresh driver reading. Unpinned, it takes
    /// the free matching GPU with the least memory, then the lowest device
    /// id. The same key again answers the grant it already holds.
    ///
    /// # Errors
    ///
    /// [`GpuSlotRefusal`]: why no GPU was held. A refusal holds nothing.
    pub fn reserve(
        &self,
        request: &GpuSlotRequest,
        now_ms: u64,
    ) -> Result<GpuSlotGrant, GpuSlotRefusal> {
        let mut slots = self.lock();
        lapse(&mut slots, now_ms);
        if let Some(slot) = slots.iter().find(|slot| slot.grant.key == request.key) {
            return Ok(slot.grant.clone());
        }
        let reading = self
            .read()
            .map_err(|probe| GpuSlotRefusal::Unmeasured { probe })?;
        let device = match &request.device_id {
            Some(device_id) => {
                let device = reading
                    .devices
                    .iter()
                    .find(|device| device.device_id == *device_id)
                    .ok_or_else(|| GpuSlotRefusal::UnknownDevice {
                        device_id: device_id.clone(),
                    })?;
                if !request.admits(device) {
                    return Err(GpuSlotRefusal::NoMatch);
                }
                match self.state(&reading, slot_on(&slots, device_id), device) {
                    GpuDeviceState::Free => device,
                    state => return Err(refusal(device, state)),
                }
            }
            None => {
                let mut matching: Vec<&GpuDevice> = reading
                    .devices
                    .iter()
                    .filter(|device| request.admits(device))
                    .collect();
                if matching.is_empty() {
                    return Err(GpuSlotRefusal::NoMatch);
                }
                matching.sort_by(|a, b| {
                    a.memory_total_mib
                        .cmp(&b.memory_total_mib)
                        .then_with(|| a.device_id.cmp(&b.device_id))
                });
                matching
                    .into_iter()
                    .find(|device| {
                        self.state(&reading, slot_on(&slots, &device.device_id), device)
                            == GpuDeviceState::Free
                    })
                    .ok_or(GpuSlotRefusal::NoneFree)?
            }
        };
        let grant = GpuSlotGrant {
            key: request.key.clone(),
            device: device.clone(),
            held_at_ms: now_ms,
            hold_until_ms: now_ms.saturating_add(self.offer.hold_secs.saturating_mul(1000)),
        };
        slots.push(Slot {
            grant: grant.clone(),
            launched: false,
        });
        Ok(grant)
    }

    /// The launch recheck, just before the job's process starts: the hold
    /// under `key` has not lapsed, and a fresh reading shows its GPU still
    /// offered, not withheld, and running no compute process. The slot is
    /// then launched and never lapses; [`Self::release`] ends it. Asked again
    /// once launched, it answers the same grant.
    ///
    /// # Errors
    ///
    /// [`GpuSlotRefusal`]: why the job must not start. A lapsed hold is
    /// dropped; any other refusal leaves the hold as it was.
    pub fn confirm_launch(&self, key: &str, now_ms: u64) -> Result<GpuSlotGrant, GpuSlotRefusal> {
        let mut slots = self.lock();
        let Some(at) = slots.iter().position(|slot| slot.grant.key == key) else {
            return Err(GpuSlotRefusal::NotHeld);
        };
        if slots[at].launched {
            return Ok(slots[at].grant.clone());
        }
        if now_ms >= slots[at].grant.hold_until_ms {
            slots.remove(at);
            return Err(GpuSlotRefusal::Lapsed);
        }
        let reading = self
            .read()
            .map_err(|probe| GpuSlotRefusal::Unmeasured { probe })?;
        let held = &slots[at].grant.device;
        let device = reading
            .devices
            .iter()
            .find(|device| device.device_id == held.device_id)
            .ok_or_else(|| GpuSlotRefusal::UnknownDevice {
                device_id: held.device_id.clone(),
            })?;
        // The hold is this key's own, so the GPU is judged as if unheld.
        match self.state(&reading, None, device) {
            GpuDeviceState::Free => {
                slots[at].launched = true;
                Ok(slots[at].grant.clone())
            }
            state => Err(refusal(device, state)),
        }
    }

    /// Ends the slot under `key`, held or launched: its runner calls this
    /// once the job's process is gone. Answers whether a slot was held.
    pub fn release(&self, key: &str) -> bool {
        let mut slots = self.lock();
        let before = slots.len();
        slots.retain(|slot| slot.grant.key != key);
        slots.len() != before
    }

    /// What `device` is doing in `reading`, with `slot` the reservation on
    /// it, if any.
    fn state(&self, reading: &Reading, slot: Option<&Slot>, device: &GpuDevice) -> GpuDeviceState {
        if !self.offer.offered.contains(&device.device_id) {
            return GpuDeviceState::NotOffered;
        }
        if let Some(slot) = slot.filter(|slot| slot.launched) {
            return GpuDeviceState::Launched {
                key: slot.grant.key.clone(),
            };
        }
        if reading.withheld.contains(&device.device_id) {
            return GpuDeviceState::Withheld;
        }
        if let Some(slot) = slot {
            return GpuDeviceState::Held {
                key: slot.grant.key.clone(),
            };
        }
        match reading.processes_on(&device.device_id) {
            Some(pids) => GpuDeviceState::Busy { pids },
            None => GpuDeviceState::Free,
        }
    }

    /// One fresh reading: the withheld list, the GPUs, their processes.
    fn read(&self) -> Result<Reading, GpuProbeError> {
        let withheld = self.withheld()?;
        Ok(Reading {
            devices: self.probe.devices()?,
            processes: self.probe.compute_processes()?,
            withheld,
        })
    }

    /// The GPUs another booker holds now.
    fn withheld(&self) -> Result<BTreeSet<String>, GpuProbeError> {
        let Some(path) = &self.offer.withheld_file else {
            return Ok(BTreeSet::new());
        };
        let text =
            std::fs::read_to_string(path).map_err(|error| GpuProbeError::WithheldUnreadable {
                reason: format!("{}: {error}", path.display()),
            })?;
        Ok(text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(str::to_owned)
            .collect())
    }

    fn lock(&self) -> MutexGuard<'_, Vec<Slot>> {
        // Each change is one push, remove or flag under the lock, so a holder
        // that panicked left the slots whole.
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The reservation on `device_id`, if any.
fn slot_on<'a>(slots: &'a [Slot], device_id: &str) -> Option<&'a Slot> {
    slots
        .iter()
        .find(|slot| slot.grant.device.device_id == device_id)
}

/// Drops every hold that lapsed by `now_ms`; a launched slot never lapses.
fn lapse(slots: &mut Vec<Slot>, now_ms: u64) {
    slots.retain(|slot| slot.launched || now_ms < slot.grant.hold_until_ms);
}

/// The refusal a GPU in `state` answers a reservation or a launch with.
fn refusal(device: &GpuDevice, state: GpuDeviceState) -> GpuSlotRefusal {
    let device_id = device.device_id.clone();
    match state {
        GpuDeviceState::NotOffered => GpuSlotRefusal::NotOffered { device_id },
        GpuDeviceState::Withheld => GpuSlotRefusal::Withheld { device_id },
        GpuDeviceState::Busy { pids } => GpuSlotRefusal::Busy { device_id, pids },
        GpuDeviceState::Held { .. } | GpuDeviceState::Launched { .. } => {
            GpuSlotRefusal::Taken { device_id }
        }
        GpuDeviceState::Free => GpuSlotRefusal::NoneFree,
    }
}
