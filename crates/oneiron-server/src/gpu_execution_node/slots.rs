//! This machine's GPU slots: one job per offered GPU, beside the machine's
//! memory floor. A slot is taken under one lock, after a fresh driver
//! reading shows the GPU offered, not withheld, untaken, and running no
//! compute process. The disk must also have room past its reserve, and the
//! machine must not be drained. Nothing is ever admitted from the hourly
//! capacity record.
//!
//! A slot is taken in one of two ways:
//! - a hold ([`GpuSlotTable::hold`]): the home's reservation ahead of the
//!   job's start, keyed by the job chunk's idempotency key. It lapses
//!   after `hold_secs` unless a call takes it.
//! - a lease ([`GpuSlotTable::lease`], or [`MachineGpus::try_lease`]): the
//!   call that runs the job holds its GPU from its admission until the lease
//!   drops or finishes. A lease under a held key takes that hold's GPU. Just
//!   before the job's process starts, [`GpuSlotLease::confirm_launch`]
//!   checks the GPU again.
//!
//! One booker per GPU: a GPU named in `[gpu_jobs.devices].withheld_file`
//! belongs to another booker, whatever writes that file, and is never
//! offered. The file is read at every ask.
//!
//! The drain guard: once `drain_after_failures` jobs in a row finish
//! failed, the machine takes no new GPU work until a person clears it
//! ([`GpuSlotTable::clear_drain`], or by deleting the drain file). With a
//! `drain_file`, the drain outlasts a restart.
//!
//! The slots live in memory. After a restart a job still running shows as a
//! compute process on its GPU, so no new slot takes that GPU.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use serde::{Deserialize, Serialize};

pub use oneiron_organ_host::{
    GpuDeviceLease, GpuJobEnd, GpuSlotRefusal, GpuSlotRequest, MachineGpus,
};

use super::device::{GpuComputeProcess, GpuDevice, GpuDeviceProbe, GpuProbeError};

/// How long a hold keeps its GPU before a call must take it, in seconds:
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
    /// How long a hold keeps its GPU before a call takes it, in seconds.
    pub hold_secs: u64,
    /// Failed jobs in a row that drain this machine. 0 never drains it.
    pub drain_after_failures: u32,
    /// Where a drain is written, so it outlasts a restart. A person deletes
    /// it to clear the drain. `None` keeps the drain in memory only.
    pub drain_file: Option<PathBuf>,
}

impl Default for GpuDeviceOffer {
    fn default() -> Self {
        Self {
            offered: BTreeSet::new(),
            withheld_file: None,
            hold_secs: GPU_SLOT_HOLD_SECS,
            drain_after_failures: GPU_DRAIN_AFTER_FAILURES,
            drain_file: None,
        }
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
    /// The home's hold under `key` keeps it until a call takes it.
    Held { key: String },
    /// The call under `key` leased it, and its process has not started.
    Leased { key: String },
    /// The job under `key` runs on it.
    Launched { key: String },
    /// Another booker holds it.
    Withheld,
    /// This machine does not offer it.
    NotOffered,
}

impl GpuDeviceState {
    /// The key a hold, lease or launched job takes the GPU under.
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
    pub devices: Vec<GpuDeviceAvailability>,
}

impl GpuAvailability {
    /// The free GPUs that meet `request`; none while the machine is drained.
    pub fn free_matching<'a>(
        &'a self,
        request: &'a GpuSlotRequest,
    ) -> impl Iterator<Item = &'a GpuDevice> + 'a {
        self.devices
            .iter()
            .filter(|device| {
                self.drained.is_none()
                    && device.state == GpuDeviceState::Free
                    && request.admits(&device.device)
            })
            .map(|device| &device.device)
    }
}

/// A GPU held for the home ahead of its job's start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuSlotHold {
    pub key: String,
    pub device: GpuDevice,
    /// When the GPU was taken, in Unix milliseconds.
    pub held_at_ms: u64,
    /// When the hold lapses unless a call takes it first.
    pub hold_until_ms: u64,
}

/// How far a slot has come.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Held,
    Leased,
    Launched,
}

/// One taken GPU, and the disk room its booking claimed.
struct Slot {
    hold: GpuSlotHold,
    stage: Stage,
    _disk: Option<Box<dyn Send + Sync>>,
}

impl std::fmt::Debug for Slot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Slot")
            .field("hold", &self.hold)
            .field("stage", &self.stage)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
struct State {
    slots: Vec<Slot>,
    failures_in_a_row: u32,
    /// A drain with no file to hold it (none named, or its write failed).
    drain_in_memory: Option<String>,
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

struct Shared {
    probe: Arc<dyn GpuDeviceProbe>,
    offer: GpuDeviceOffer,
    disk: Option<Arc<dyn GpuJobDisk>>,
    state: Mutex<State>,
}

/// This machine's GPU slots: at most one hold or lease per GPU.
pub struct GpuSlotTable {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for GpuSlotTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GpuSlotTable")
            .field("offer", &self.shared.offer)
            .field("state", &*self.shared.lock())
            .finish_non_exhaustive()
    }
}

impl GpuSlotTable {
    /// A table with nothing taken that reads `probe` at every ask, with no
    /// disk claim.
    #[must_use]
    pub fn new(probe: Arc<dyn GpuDeviceProbe>, offer: GpuDeviceOffer) -> Self {
        Self::with_disk(probe, offer, None)
    }

    /// A table whose bookings also claim their bytes on `disk`.
    #[must_use]
    pub fn with_disk(
        probe: Arc<dyn GpuDeviceProbe>,
        offer: GpuDeviceOffer,
        disk: Option<Arc<dyn GpuJobDisk>>,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                probe,
                offer,
                disk,
                state: Mutex::default(),
            }),
        }
    }

    /// The GPUs this machine offers, and how.
    #[must_use]
    pub fn offer(&self) -> &GpuDeviceOffer {
        &self.shared.offer
    }

    /// What each GPU is doing now, from a fresh driver reading, and whether
    /// the machine is drained. A lapsed hold is dropped first.
    ///
    /// # Errors
    ///
    /// [`GpuProbeError`] when the driver, the withheld list or the drain
    /// file cannot be read: then nothing is offered.
    pub fn availability(&self, now_ms: u64) -> Result<GpuAvailability, GpuProbeError> {
        let shared = &self.shared;
        let mut state = shared.lock();
        lapse(&mut state, now_ms);
        let drained = shared.drained(&state)?;
        let reading = shared.read()?;
        let devices = reading
            .devices
            .iter()
            .map(|device| GpuDeviceAvailability {
                device: device.clone(),
                state: shared.state_of(&reading, slot_on(&state.slots, &device.device_id), device),
            })
            .collect();
        Ok(GpuAvailability {
            measured_at_ms: now_ms,
            drained,
            devices,
        })
    }

    /// Holds one GPU for `request` until `now_ms` plus the hold: the home's
    /// reservation ahead of the job's start. The same key again answers the
    /// hold it already has.
    ///
    /// # Errors
    ///
    /// [`GpuSlotRefusal`]: why no GPU was held. A refusal holds nothing.
    pub fn hold(
        &self,
        request: &GpuSlotRequest,
        now_ms: u64,
    ) -> Result<GpuSlotHold, GpuSlotRefusal> {
        let shared = &self.shared;
        let mut state = shared.lock();
        lapse(&mut state, now_ms);
        if let Some(slot) = state.slots.iter().find(|slot| slot.hold.key == request.key) {
            return Ok(slot.hold.clone());
        }
        let hold = shared.take(&mut state, request, now_ms, Stage::Held)?;
        Ok(hold)
    }

    /// Leases one GPU for the call that runs `request`'s job: the GPU a hold
    /// under the same key keeps, else a fresh pick, as [`Self::hold`]
    /// picks. The GPU stays the call's until the lease drops or finishes.
    ///
    /// # Errors
    ///
    /// [`GpuSlotRefusal`]: why no GPU was leased. One key leases at most
    /// one GPU at a time ([`GpuSlotRefusal::Taken`]).
    pub fn lease(
        &self,
        request: &GpuSlotRequest,
        now_ms: u64,
    ) -> Result<GpuSlotLease, GpuSlotRefusal> {
        let shared = &self.shared;
        let mut state = shared.lock();
        lapse(&mut state, now_ms);
        if let Some(reason) = shared.drained(&state).map_err(unmeasured)? {
            return Err(GpuSlotRefusal::Drained { reason });
        }
        let held = state
            .slots
            .iter()
            .position(|slot| slot.hold.key == request.key);
        let hold = match held {
            Some(at) if state.slots[at].stage == Stage::Held => {
                state.slots[at].stage = Stage::Leased;
                state.slots[at].hold.clone()
            }
            Some(at) => {
                return Err(GpuSlotRefusal::Taken {
                    device_id: state.slots[at].hold.device.device_id.clone(),
                });
            }
            None => shared.take(&mut state, request, now_ms, Stage::Leased)?,
        };
        Ok(GpuSlotLease {
            shared: Arc::clone(shared),
            hold,
            ended: false,
        })
    }

    /// Ends the home's hold under `key` before any call took it. Answers
    /// whether a hold was there. A leased GPU is its call's to give back.
    pub fn release(&self, key: &str) -> bool {
        let mut state = self.shared.lock();
        let before = state.slots.len();
        state
            .slots
            .retain(|slot| !(slot.hold.key == key && slot.stage == Stage::Held));
        state.slots.len() != before
    }

    /// Why this machine is drained, while it is.
    ///
    /// # Errors
    ///
    /// [`GpuProbeError::DrainUnreadable`] when the drain file cannot be
    /// read.
    pub fn drained(&self) -> Result<Option<String>, GpuProbeError> {
        let state = self.shared.lock();
        self.shared.drained(&state)
    }

    /// A person's clear of the drain: the machine takes GPU work again, and
    /// its count of failed jobs starts over.
    ///
    /// # Errors
    ///
    /// The drain file's removal error; the drain then stands.
    pub fn clear_drain(&self) -> std::io::Result<()> {
        let mut state = self.shared.lock();
        if let Some(file) = &self.shared.offer.drain_file {
            match std::fs::remove_file(file) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        state.failures_in_a_row = 0;
        state.drain_in_memory = None;
        Ok(())
    }
}

impl MachineGpus for GpuSlotTable {
    fn try_lease(
        &self,
        request: &GpuSlotRequest,
    ) -> Result<Box<dyn GpuDeviceLease>, GpuSlotRefusal> {
        Ok(Box::new(
            self.lease(request, oneiron_base::unix_millis_now())?,
        ))
    }
}

/// One GPU leased to the call that runs its job. Dropping it gives the GPU
/// back; [`Self::finish`] also records how the job ended.
#[derive(Debug)]
pub struct GpuSlotLease {
    shared: Arc<Shared>,
    hold: GpuSlotHold,
    ended: bool,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("offer", &self.offer)
            .finish_non_exhaustive()
    }
}

impl GpuSlotLease {
    /// The GPU it holds, and since when.
    #[must_use]
    pub fn hold(&self) -> &GpuSlotHold {
        &self.hold
    }

    /// The launch recheck, just before the job's process starts: a fresh
    /// reading shows its GPU still offered, not withheld, and running no
    /// compute process, and the machine is not drained. Once confirmed it
    /// stays confirmed.
    ///
    /// # Errors
    ///
    /// [`GpuSlotRefusal`]: why the job must not start. The lease still
    /// holds its GPU.
    pub fn confirm_launch(&mut self) -> Result<(), GpuSlotRefusal> {
        let shared = &self.shared;
        let mut state = shared.lock();
        let Some(at) = state
            .slots
            .iter()
            .position(|slot| slot.hold.key == self.hold.key)
        else {
            return Err(GpuSlotRefusal::Taken {
                device_id: self.hold.device.device_id.clone(),
            });
        };
        if state.slots[at].stage == Stage::Launched {
            return Ok(());
        }
        if let Some(reason) = shared.drained(&state).map_err(unmeasured)? {
            return Err(GpuSlotRefusal::Drained { reason });
        }
        let reading = shared.read().map_err(unmeasured)?;
        let device = reading
            .devices
            .iter()
            .find(|device| device.device_id == self.hold.device.device_id)
            .ok_or_else(|| GpuSlotRefusal::UnknownDevice {
                device_id: self.hold.device.device_id.clone(),
            })?;
        // The slot is this lease's own, so the GPU is judged as if untaken.
        match shared.state_of(&reading, None, device) {
            GpuDeviceState::Free => {
                state.slots[at].stage = Stage::Launched;
                Ok(())
            }
            other => Err(refusal(device, other)),
        }
    }

    /// Gives the GPU back and records how its job ended: a success starts
    /// the count of failed jobs over, a failure adds to it (and drains the
    /// machine at `drain_after_failures`), a cancel leaves it as it was.
    pub fn finish(mut self, end: GpuJobEnd) {
        self.ended = true;
        self.shared.end(&self.hold.key, Some(&end));
    }
}

impl Drop for GpuSlotLease {
    fn drop(&mut self) {
        if !self.ended {
            self.shared.end(&self.hold.key, None);
        }
    }
}

impl GpuDeviceLease for GpuSlotLease {
    fn device(&self) -> &GpuDevice {
        &self.hold.device
    }

    fn key(&self) -> &str {
        &self.hold.key
    }

    fn confirm_launch(&mut self) -> Result<(), GpuSlotRefusal> {
        Self::confirm_launch(self)
    }

    fn finish(self: Box<Self>, end: GpuJobEnd) {
        Self::finish(*self, end);
    }
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        // Each change is one push, removal, flag or count under the lock, so
        // a holder that panicked left the state whole.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes one GPU for `request` at `stage`, from a fresh reading: the
    /// drain, the pick, the disk claim, then the slot.
    fn take(
        &self,
        state: &mut State,
        request: &GpuSlotRequest,
        now_ms: u64,
        stage: Stage,
    ) -> Result<GpuSlotHold, GpuSlotRefusal> {
        if let Some(reason) = self.drained(state).map_err(unmeasured)? {
            return Err(GpuSlotRefusal::Drained { reason });
        }
        let reading = self.read().map_err(unmeasured)?;
        let device = self.pick(&reading, &state.slots, request)?.clone();
        let disk = match &self.disk {
            Some(disk) => Some(disk.claim(request.disk_bytes)?),
            None => None,
        };
        let hold = GpuSlotHold {
            key: request.key.clone(),
            device,
            held_at_ms: now_ms,
            hold_until_ms: now_ms.saturating_add(self.offer.hold_secs.saturating_mul(1000)),
        };
        state.slots.push(Slot {
            hold: hold.clone(),
            stage,
            _disk: disk,
        });
        Ok(hold)
    }

    /// The GPU `request` takes in `reading`: its pinned GPU when free, else
    /// the free matching GPU with the least memory, then the lowest id.
    fn pick<'a>(
        &self,
        reading: &'a Reading,
        slots: &[Slot],
        request: &GpuSlotRequest,
    ) -> Result<&'a GpuDevice, GpuSlotRefusal> {
        if let Some(device_id) = &request.device_id {
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
            return match self.state_of(reading, slot_on(slots, device_id), device) {
                GpuDeviceState::Free => Ok(device),
                state => Err(refusal(device, state)),
            };
        }
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
                self.state_of(reading, slot_on(slots, &device.device_id), device)
                    == GpuDeviceState::Free
            })
            .ok_or(GpuSlotRefusal::NoneFree)
    }

    /// What `device` is doing in `reading`, with `slot` the slot on it, if
    /// any.
    fn state_of(
        &self,
        reading: &Reading,
        slot: Option<&Slot>,
        device: &GpuDevice,
    ) -> GpuDeviceState {
        if !self.offer.offered.contains(&device.device_id) {
            return GpuDeviceState::NotOffered;
        }
        if let Some(slot) = slot.filter(|slot| slot.stage == Stage::Launched) {
            return GpuDeviceState::Launched {
                key: slot.hold.key.clone(),
            };
        }
        if reading.withheld.contains(&device.device_id) {
            return GpuDeviceState::Withheld;
        }
        match slot {
            Some(slot) if slot.stage == Stage::Leased => GpuDeviceState::Leased {
                key: slot.hold.key.clone(),
            },
            Some(slot) => GpuDeviceState::Held {
                key: slot.hold.key.clone(),
            },
            None => match reading.processes_on(&device.device_id) {
                Some(pids) => GpuDeviceState::Busy { pids },
                None => GpuDeviceState::Free,
            },
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

    /// Why the machine is drained, while it is: the drain file's first line,
    /// or a drain kept in memory.
    fn drained(&self, state: &State) -> Result<Option<String>, GpuProbeError> {
        if let Some(reason) = &state.drain_in_memory {
            return Ok(Some(reason.clone()));
        }
        let Some(path) = &self.offer.drain_file else {
            return Ok(None);
        };
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(Some(
                text.lines()
                    .map(str::trim)
                    .find(|line| !line.is_empty())
                    .unwrap_or("drained")
                    .to_owned(),
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(GpuProbeError::DrainUnreadable {
                reason: format!("{}: {error}", path.display()),
            }),
        }
    }

    /// Ends the slot under `key` and counts how its job ended.
    fn end(&self, key: &str, end: Option<&GpuJobEnd>) {
        let mut state = self.lock();
        state.slots.retain(|slot| slot.hold.key != key);
        match end {
            Some(GpuJobEnd::Succeeded) => state.failures_in_a_row = 0,
            Some(GpuJobEnd::Failed { reason }) => {
                state.failures_in_a_row = state.failures_in_a_row.saturating_add(1);
                let limit = self.offer.drain_after_failures;
                if limit > 0 && state.failures_in_a_row >= limit {
                    let drain = format!(
                        "drained after {} failed GPU jobs in a row; the last: {reason}",
                        state.failures_in_a_row
                    );
                    state.failures_in_a_row = 0;
                    self.drain(&mut state, drain);
                }
            }
            Some(GpuJobEnd::Cancelled) | None => {}
        }
    }

    /// Drains the machine: into the drain file when one is named, else (or
    /// when the write fails) in memory.
    fn drain(&self, state: &mut State, drain: String) {
        tracing::warn!(%drain, "this machine takes no new GPU job until a person clears the drain");
        if let Some(path) = &self.offer.drain_file {
            let text = format!(
                "{drain}\nDelete this file to clear the drain; the machine then takes GPU jobs again.\n"
            );
            match std::fs::write(path, text) {
                Ok(()) => return,
                Err(error) => tracing::warn!(
                    %error,
                    path = %path.display(),
                    "the GPU drain file could not be written; the drain is kept in memory"
                ),
            }
        }
        state.drain_in_memory = Some(drain);
    }
}

/// The slot on `device_id`, if any.
fn slot_on<'a>(slots: &'a [Slot], device_id: &str) -> Option<&'a Slot> {
    slots
        .iter()
        .find(|slot| slot.hold.device.device_id == device_id)
}

/// Drops every hold that lapsed by `now_ms`; a leased or launched slot
/// never lapses.
fn lapse(state: &mut State, now_ms: u64) {
    state
        .slots
        .retain(|slot| slot.stage != Stage::Held || now_ms < slot.hold.hold_until_ms);
}

/// The refusal a GPU in `state` answers a booking or a launch with.
fn refusal(device: &GpuDevice, state: GpuDeviceState) -> GpuSlotRefusal {
    let device_id = device.device_id.clone();
    match state {
        GpuDeviceState::NotOffered => GpuSlotRefusal::NotOffered { device_id },
        GpuDeviceState::Withheld => GpuSlotRefusal::Withheld { device_id },
        GpuDeviceState::Busy { pids } => GpuSlotRefusal::Busy { device_id, pids },
        GpuDeviceState::Held { .. }
        | GpuDeviceState::Leased { .. }
        | GpuDeviceState::Launched { .. } => GpuSlotRefusal::Taken { device_id },
        GpuDeviceState::Free => GpuSlotRefusal::NoneFree,
    }
}

fn unmeasured(probe: GpuProbeError) -> GpuSlotRefusal {
    GpuSlotRefusal::Unmeasured {
        reason: probe.to_string(),
    }
}
