//! This machine's GPU slots: one job per offered GPU, beside the machine's
//! memory floor. A slot is taken under one lock, after a fresh driver
//! reading shows the GPU offered, not withheld, untaken, and running no
//! compute process. The disk must also have room past its reserve, and the
//! machine must not be drained. Nothing is ever admitted from the hourly
//! capacity record.
//!
//! A slot is taken under a key (the job chunk's idempotency key):
//! - a hold ([`GpuSlotTable::hold`]): the home's reservation ahead of the
//!   job's start. It lapses after `hold_secs` unless a lease takes it.
//! - a lease ([`GpuSlotTable::lease`], or [`MachineGpus::try_lease`]): the
//!   workload holds its GPU from its admission until the lease drops or
//!   finishes. A lease under a held key takes that hold's GPU. Just before
//!   the job's process starts, [`GpuSlotLease::confirm_launch`] checks the
//!   GPU again. [`GpuSlotLease::keep`] hands the slot to a job that
//!   outlives the lease; it then stays under its key until
//!   [`GpuSlotTable::finish`] or [`GpuSlotTable::release`] ends it.
//! - a reattach ([`GpuSlotTable::reattach`]): after a restart, a job that
//!   still runs takes its GPU again under its key.
//!
//! One booker per GPU: a GPU named in `[gpu_jobs.devices].withheld_file`
//! belongs to another booker, whatever writes that file, and is never
//! offered. The file is read at every ask, after the driver. On one
//! machine, each offered GPU is owned by one Oneiron server at a time: the
//! table holds a lock file per GPU in `owner_lock_dir` while it runs, and a
//! GPU whose lock another server (or another vault in this process) holds
//! reads as withheld.
//!
//! The drain guard: once `drain_after_failures` jobs in a row finish
//! failed, the machine takes no new GPU work until a person clears it
//! ([`GpuSlotTable::clear_drain`], or by deleting the drain file). With a
//! `drain_file`, the drain outlasts a restart.
//!
//! The slots live in memory. After a restart a job still running shows as a
//! compute process on its GPU, so no new slot takes that GPU until the job
//! reattaches or ends.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

pub use oneiron_organ_host::{
    GpuDeviceLease, GpuDeviceProcesses, GpuJobEnd, GpuSlotHold, GpuSlotRefusal, GpuSlotRequest,
    MachineGpus,
};

use super::availability::{
    GpuAvailability, GpuDeviceAvailability, GpuDeviceOffer, GpuDeviceState, GpuJobDisk,
};
use super::device::{GpuComputeProcess, GpuDevice, GpuDeviceProbe, GpuProbeError};

mod lease;

pub use lease::GpuSlotLease;

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
    /// A live [`GpuSlotLease`] holds it; else its key does (a hold, a kept
    /// slot or a reattached job).
    guarded: bool,
    _disk: Option<Box<dyn Send + Sync>>,
}

impl std::fmt::Debug for Slot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Slot")
            .field("hold", &self.hold)
            .field("stage", &self.stage)
            .field("guarded", &self.guarded)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
struct State {
    slots: Vec<Slot>,
    /// The offered GPUs this table owns on this machine, each by its open
    /// lock file.
    owner_locks: BTreeMap<String, std::fs::File>,
    failures_in_a_row: u32,
    /// A drain with no file to hold it (none named, or its write failed).
    drain_in_memory: Option<String>,
}

impl State {
    fn at(&self, key: &str) -> Option<usize> {
        self.slots.iter().position(|slot| slot.hold.key == key)
    }
}

/// One fresh reading of the driver and the withheld list, and the GPUs this
/// table owns (`None`: it takes no owner lock).
struct Reading {
    devices: Vec<GpuDevice>,
    processes: Vec<GpuComputeProcess>,
    withheld: BTreeSet<String>,
    owned: Option<BTreeSet<String>>,
}

impl Reading {
    /// The compute processes on `device_id`.
    fn processes_on(&self, device_id: &str) -> GpuDeviceProcesses {
        processes_on(&self.processes, device_id)
    }
}

/// The compute processes on `device_id` among `processes`.
fn processes_on(processes: &[GpuComputeProcess], device_id: &str) -> GpuDeviceProcesses {
    let mut on = GpuDeviceProcesses::default();
    for process in processes
        .iter()
        .filter(|process| process.device_id == device_id)
    {
        match process.pid {
            Some(pid) => on.pids.push(pid),
            None => on.hidden = on.hidden.saturating_add(1),
        }
    }
    on
}

/// This server's lock on `device_id` in `dir`, when no other holds it. The
/// lock lasts as long as the open file.
fn owner_lock(dir: &Path, device_id: &str) -> Option<std::fs::File> {
    std::fs::create_dir_all(dir).ok()?;
    let name: String = device_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(dir.join(format!("{name}.lock")))
        .ok()?;
    file.try_lock().ok()?;
    Some(file)
}

struct Shared {
    probe: Arc<dyn GpuDeviceProbe>,
    offer: GpuDeviceOffer,
    disk: Option<Arc<dyn GpuJobDisk>>,
    state: Mutex<State>,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("offer", &self.offer)
            .finish_non_exhaustive()
    }
}

/// This machine's GPU slots: at most one slot per GPU, and per key.
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

    /// What each GPU is doing now, from a fresh driver reading, whether the
    /// machine is drained, and what its jobs' disk holds. A lapsed hold is
    /// dropped first.
    ///
    /// # Errors
    ///
    /// [`GpuProbeError`] when the driver, the withheld list, the drain file
    /// or the disk cannot be read: then nothing is offered.
    pub fn availability(&self, now_ms: u64) -> Result<GpuAvailability, GpuProbeError> {
        let shared = &self.shared;
        let mut state = shared.lock();
        lapse(&mut state, now_ms);
        let reading = shared.read(&mut state)?;
        let drained = shared.drained(&state)?;
        let disk = match &shared.disk {
            Some(disk) => Some(
                disk.reading()
                    .map_err(|error| GpuProbeError::DiskUnreadable {
                        reason: error.to_string(),
                    })?,
            ),
            None => None,
        };
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
            disk,
            devices,
        })
    }

    /// Holds one GPU for `request` until `now_ms` plus the hold: the home's
    /// reservation ahead of the job's start. The same key again answers the
    /// slot it already has.
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
        if let Some(reason) = shared.drained(&state).map_err(unmeasured)? {
            return Err(GpuSlotRefusal::Drained { reason });
        }
        if let Some(at) = state.at(&request.key) {
            return Ok(state.slots[at].hold.clone());
        }
        shared.take(&mut state, request, now_ms, Stage::Held, false)
    }

    /// Leases one GPU for the workload that runs `request`'s job: the GPU
    /// its key already takes (a hold, a kept slot or a reattached job),
    /// else a fresh pick, as [`Self::hold`] picks. The GPU stays the
    /// workload's until the lease drops, finishes or is kept.
    ///
    /// # Errors
    ///
    /// [`GpuSlotRefusal`]: why no GPU was leased. One key has at most one
    /// live lease ([`GpuSlotRefusal::Taken`]).
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
        let hold = match state.at(&request.key) {
            Some(at) if state.slots[at].guarded => {
                return Err(GpuSlotRefusal::Taken {
                    device_id: state.slots[at].hold.device.device_id.clone(),
                });
            }
            Some(at) => {
                // A hold checked the disk's room; the lease claims its own
                // bytes, and a refusal leaves the hold as it was. A kept slot
                // keeps the claim its first lease took.
                let disk = match (&shared.disk, state.slots[at].stage) {
                    (Some(disk), Stage::Held) => Some(disk.claim(request.disk_bytes)?),
                    _ => None,
                };
                let slot = &mut state.slots[at];
                if disk.is_some() {
                    slot._disk = disk;
                }
                slot.guarded = true;
                if slot.stage == Stage::Held {
                    slot.stage = Stage::Leased;
                }
                slot.hold.clone()
            }
            None => shared.take(&mut state, request, now_ms, Stage::Leased, true)?,
        };
        Ok(GpuSlotLease {
            shared: Arc::clone(shared),
            hold,
            ended: false,
        })
    }

    /// After a restart, gives a job that still runs on `device_id` its GPU
    /// again under `key`, launched and kept. The job's own processes are on
    /// the GPU, so no free check applies; another slot on it refuses.
    ///
    /// # Errors
    ///
    /// [`GpuSlotRefusal::UnknownDevice`], [`GpuSlotRefusal::Taken`] (another
    /// key takes the GPU, or this key takes another GPU), or
    /// [`GpuSlotRefusal::Unmeasured`].
    pub fn reattach(
        &self,
        key: &str,
        device_id: &str,
        now_ms: u64,
    ) -> Result<GpuSlotHold, GpuSlotRefusal> {
        let shared = &self.shared;
        let mut state = shared.lock();
        lapse(&mut state, now_ms);
        if let Some(at) = state.at(key) {
            let hold = &state.slots[at].hold;
            return if hold.device.device_id == device_id {
                Ok(hold.clone())
            } else {
                Err(GpuSlotRefusal::Taken {
                    device_id: hold.device.device_id.clone(),
                })
            };
        }
        let reading = shared.read(&mut state).map_err(unmeasured)?;
        let device = reading
            .devices
            .iter()
            .find(|device| device.device_id == device_id)
            .ok_or_else(|| GpuSlotRefusal::UnknownDevice {
                device_id: device_id.to_owned(),
            })?;
        if slot_on(&state.slots, device_id).is_some() {
            return Err(GpuSlotRefusal::Taken {
                device_id: device_id.to_owned(),
            });
        }
        let hold = GpuSlotHold {
            key: key.to_owned(),
            device: device.clone(),
            held_at_ms: now_ms,
            hold_until_ms: now_ms,
        };
        state.slots.push(Slot {
            hold: hold.clone(),
            stage: Stage::Launched,
            guarded: false,
            _disk: None,
        });
        Ok(hold)
    }

    /// The compute processes on the GPU `key` takes, from a fresh reading.
    ///
    /// # Errors
    ///
    /// [`GpuSlotRefusal::NotHeld`] for a key that takes no GPU;
    /// [`GpuSlotRefusal::Unmeasured`] when the driver cannot be read.
    pub fn end_check(&self, key: &str) -> Result<GpuDeviceProcesses, GpuSlotRefusal> {
        let state = self.shared.lock();
        let at = state.at(key).ok_or(GpuSlotRefusal::NotHeld)?;
        let processes = self.shared.probe.compute_processes().map_err(unmeasured)?;
        Ok(processes_on(
            &processes,
            &state.slots[at].hold.device.device_id,
        ))
    }

    /// Ends the slot `key` takes with no live lease (a hold, a kept slot or
    /// a reattached job), recording nothing. Answers whether one ended. A
    /// GPU under a live lease is that lease's to give back.
    pub fn release(&self, key: &str) -> bool {
        let mut state = self.shared.lock();
        self.shared.end_unguarded(&mut state, key, None)
    }

    /// Ends the kept or reattached slot under `key` and records how its job
    /// ended, as [`GpuSlotLease::finish`] does. Answers whether one ended.
    pub fn finish(&self, key: &str, end: &GpuJobEnd) -> bool {
        let mut state = self.shared.lock();
        self.shared.end_unguarded(&mut state, key, Some(end))
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
        guarded: bool,
    ) -> Result<GpuSlotHold, GpuSlotRefusal> {
        let reading = self.read(state).map_err(unmeasured)?;
        if let Some(reason) = self.drained(state).map_err(unmeasured)? {
            return Err(GpuSlotRefusal::Drained { reason });
        }
        let device = self.pick(&reading, &state.slots, request)?.clone();
        // A hold checks that the job's bytes fit past the reserve now; the
        // lease that runs the job claims them, so a hold that lapses holds
        // no disk.
        let disk = match (&self.disk, stage) {
            (Some(disk), Stage::Held) => {
                let room = disk.reading().map_err(|error| GpuSlotRefusal::Unmeasured {
                    reason: format!("the GPU job disk's free space could not be read: {error}"),
                })?;
                if !room.fits(request.disk_bytes) {
                    return Err(GpuSlotRefusal::DiskUnderReserve {
                        needed_bytes: room
                            .reserve_bytes
                            .saturating_add(room.claimed_bytes)
                            .saturating_add(request.disk_bytes),
                        free_bytes: room.free_bytes,
                    });
                }
                None
            }
            (Some(disk), _) => Some(disk.claim(request.disk_bytes)?),
            (None, _) => None,
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
            guarded,
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
    /// any. A slot always shows its key, so the home sees where a key is
    /// even on a GPU withheld since.
    fn state_of(
        &self,
        reading: &Reading,
        slot: Option<&Slot>,
        device: &GpuDevice,
    ) -> GpuDeviceState {
        if let Some(slot) = slot {
            let key = slot.hold.key.clone();
            return match slot.stage {
                Stage::Held => GpuDeviceState::Held { key },
                Stage::Leased => GpuDeviceState::Leased { key },
                Stage::Launched => GpuDeviceState::Launched { key },
            };
        }
        if !self.offer.offered.contains(&device.device_id) {
            return GpuDeviceState::NotOffered;
        }
        let owned_elsewhere = reading
            .owned
            .as_ref()
            .is_some_and(|owned| !owned.contains(&device.device_id));
        if owned_elsewhere || reading.withheld.contains(&device.device_id) {
            return GpuDeviceState::Withheld;
        }
        let on = reading.processes_on(&device.device_id);
        if on.is_empty() {
            GpuDeviceState::Free
        } else {
            GpuDeviceState::Busy { pids: on.pids }
        }
    }

    /// One fresh reading: the GPUs and their processes, then the withheld
    /// list and the GPUs this table owns.
    fn read(&self, state: &mut State) -> Result<Reading, GpuProbeError> {
        let devices = self.probe.devices()?;
        let processes = self.probe.compute_processes()?;
        let withheld = self.withheld()?;
        let owned = self.own_offered(state);
        Ok(Reading {
            devices,
            processes,
            withheld,
            owned,
        })
    }

    /// Takes the owner lock of every offered GPU this table does not own
    /// yet, and answers the ones it owns (`None`: it takes no lock). A lock
    /// another server holds is asked again at the next reading.
    fn own_offered(&self, state: &mut State) -> Option<BTreeSet<String>> {
        let dir = self.offer.owner_lock_dir.as_ref()?;
        for device_id in &self.offer.offered {
            if !state.owner_locks.contains_key(device_id)
                && let Some(lock) = owner_lock(dir, device_id)
            {
                state.owner_locks.insert(device_id.clone(), lock);
            }
        }
        Some(state.owner_locks.keys().cloned().collect())
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

    /// Ends the unguarded slot under `key`, if there is one.
    fn end_unguarded(&self, state: &mut State, key: &str, end: Option<&GpuJobEnd>) -> bool {
        match state.at(key) {
            Some(at) if !state.slots[at].guarded => {
                self.end(state, key, end);
                true
            }
            _ => false,
        }
    }

    /// Ends the slot under `key` and counts how its job ended.
    fn end(&self, state: &mut State, key: &str, end: Option<&GpuJobEnd>) {
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
                    self.drain(state, drain);
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

/// Drops every hold that lapsed by `now_ms`; a leased, kept or launched slot
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
