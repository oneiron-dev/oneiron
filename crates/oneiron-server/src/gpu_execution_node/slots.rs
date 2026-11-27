//! This machine's GPU slots: one job per offered GPU, beside the machine's
//! memory floor. The node takes a [`GpuSlotTable::lease`] inside its launch
//! commit, then calls [`GpuSlotLease::confirm_launch`] back to back under the
//! node's lock. There is no hold during staging. A fresh driver reading
//! must show the GPU offered, not withheld, untaken and running no compute
//! process. The disk must have room past its reserve. Nothing is admitted
//! from the hourly capacity record.
//!
//! A lease lives for the workload's life. [`GpuSlotLease::keep`] hands the
//! slot to the journaled key until [`GpuSlotTable::finish`] or
//! [`GpuSlotTable::release`] ends it. After a restart the node reattaches
//! live keys with [`GpuSlotTable::reattach`].
//!
//! One booker per GPU: a GPU named in `[gpu_jobs.devices].withheld_file`
//! belongs to another booker, whatever writes that file, and is never
//! offered. The file is read at every ask, after the driver, on the
//! table's one reader thread (`withheld`): an ask waits at most
//! `WITHHELD_READ_TIMEOUT` for it, and a read that has not returned by then
//! (a lost network mount) reads as unreadable, so nothing is offered. On
//! one machine, each offered GPU is owned by one Oneiron server at a time:
//! the table holds a lock file per GPU in `owner_lock_dir` while it runs,
//! and a GPU whose lock another server (or another vault in this process)
//! holds reads as withheld.
//!
//! A launched job keeps its GPU past its server's life: each launch
//! confirmation writes the GPU's kept record (the job's key) beside its
//! lock, and only the end of that slot removes it. While a record stands,
//! no table takes the GPU's lock unless it holds the record's key, so a
//! server that stops while its job runs leaves the GPU withheld for that
//! job, and takes it back with [`GpuSlotTable::reattach`] after a restart.
//! A key whose job did not survive the restart is ended with
//! [`GpuSlotTable::release`] or [`GpuSlotTable::finish`], which also clear
//! its record; a record no server ends keeps its GPU withheld until a person
//! deletes it.
//!
//! The drain guard: once `drain_after_failures` jobs in a row finish
//! failed, the machine takes no new GPU work until a person clears it
//! ([`GpuSlotTable::clear_drain`], or by deleting the drain file). With a
//! `drain_file`, the drain outlasts a restart.
//!
//! A pause refuses new leases and launch confirmations on the machine. A
//! quarantine does the same on one GPU until a clean probe or a person
//! clears it. Slots, pause and quarantine live in memory. The node journals
//! quarantines and replays them into the table after a restart; the table
//! writes no quarantine file.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use oneiron::job_workload::HeldDevice;

pub use oneiron_organ_host::{
    GpuDeviceLease, GpuDeviceProcesses, GpuLeaseEnd, GpuSlotGrant, GpuSlotRefusal, GpuSlotRequest,
    MachineGpus,
};

use super::availability::{
    GpuAvailability, GpuDeviceAvailability, GpuDeviceOffer, GpuDeviceState, GpuJobDisk, admits_gpu,
};
use super::device::{DeviceSample, GpuComputeProcess, GpuDevice, GpuDeviceProbe, GpuProbeError};

mod drain;
mod lease;
mod ownership;
mod withheld;

pub use lease::GpuSlotLease;
use ownership::kept_for;
use withheld::WithheldListReader;

/// How far a slot has come.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Leased,
    Launched,
}

/// One taken GPU, and the disk room its booking claimed.
struct Slot {
    grant: GpuSlotGrant,
    stage: Stage,
    /// A live [`GpuSlotLease`] holds it; else its key does (a kept slot or
    /// a reattached job).
    guarded: bool,
    _disk: Option<Box<dyn Send + Sync>>,
}

impl std::fmt::Debug for Slot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Slot")
            .field("grant", &self.grant)
            .field("stage", &self.stage)
            .field("guarded", &self.guarded)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
struct State {
    slots: Vec<Slot>,
    quarantined: BTreeMap<String, String>,
    paused: Option<String>,
    /// The offered GPUs this table owns on this machine, each by its open
    /// lock file.
    owner_locks: BTreeMap<String, std::fs::File>,
    failures_in_a_row: u32,
    /// A drain with no file to hold it (none named, or its write failed).
    drain_in_memory: Option<String>,
}

impl State {
    fn at(&self, key: &str) -> Option<usize> {
        self.slots.iter().position(|slot| slot.grant.key == key)
    }

    fn check_quarantine(&self, device_id: &str) -> Result<(), GpuSlotRefusal> {
        if let Some(why) = self.quarantined.get(device_id) {
            return Err(GpuSlotRefusal::Quarantined {
                device_id: device_id.to_owned(),
                why: why.clone(),
            });
        }
        Ok(())
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

struct Shared {
    probe: Arc<dyn GpuDeviceProbe>,
    offer: GpuDeviceOffer,
    disk: Option<Arc<dyn GpuJobDisk>>,
    /// The withheld list's reader, when a file is named.
    withheld: Option<WithheldListReader>,
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
        let withheld = offer.withheld_file.clone().map(WithheldListReader::new);
        Self {
            shared: Arc::new(Shared {
                probe,
                offer,
                disk,
                withheld,
                state: Mutex::default(),
            }),
        }
    }

    /// The GPUs this machine offers, and how.
    #[must_use]
    pub fn offer(&self) -> &GpuDeviceOffer {
        &self.shared.offer
    }

    /// Reads the device IDs another booker withholds now, without probing the driver.
    ///
    /// # Errors
    ///
    /// [`GpuProbeError`] when the withheld list cannot be read.
    #[cfg(unix)]
    pub(crate) fn booker_withheld(&self) -> Result<BTreeSet<String>, GpuProbeError> {
        self.shared.withheld()
    }

    /// Each device's temperature, power draw and memory in use now, where
    /// the probe gives them: a reading for the breadcrumb lines (pass 34,
    /// 7.3), not a hold.
    ///
    /// # Errors
    ///
    /// [`GpuProbeError`] when the driver cannot be read.
    pub fn samples(&self) -> Result<Vec<DeviceSample>, GpuProbeError> {
        self.shared.probe.samples()
    }

    /// What each GPU is doing now, from a fresh driver reading, whether the
    /// machine is paused or drained, and what its jobs' disk holds.
    ///
    /// # Errors
    ///
    /// [`GpuProbeError`] when the driver, the withheld list, the drain file
    /// or the disk cannot be read: then nothing is offered.
    pub fn availability(&self, now_ms: u64) -> Result<GpuAvailability, GpuProbeError> {
        self.availability_on(now_ms, None)
    }

    /// [`Self::availability`] on the given withheld list: the reading uses
    /// it in place of the file, so a caller that already sampled the list
    /// judges the devices on that same sample.
    ///
    /// # Errors
    ///
    /// [`GpuProbeError`] when the driver, the drain file or the disk cannot
    /// be read: then nothing is offered.
    pub fn availability_with_withheld(
        &self,
        now_ms: u64,
        withheld: BTreeSet<String>,
    ) -> Result<GpuAvailability, GpuProbeError> {
        self.availability_on(now_ms, Some(withheld))
    }

    /// [`Self::availability`] on `withheld` (`None`: the list is read from
    /// its file).
    fn availability_on(
        &self,
        now_ms: u64,
        withheld: Option<BTreeSet<String>>,
    ) -> Result<GpuAvailability, GpuProbeError> {
        let shared = &self.shared;
        let mut state = shared.lock();
        let reading = shared.read_with(&mut state, withheld)?;
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
                state: shared.state_of(
                    &reading,
                    &state,
                    slot_on(&state.slots, &device.device_id),
                    device,
                ),
            })
            .collect();
        Ok(GpuAvailability {
            measured_at_ms: now_ms,
            paused: state.paused.clone(),
            drained,
            disk,
            devices,
        })
    }

    /// Every GPU as placement reads it (pass 34, 2.1), from one fresh
    /// reading, for [`oneiron::job_workload::ResourceRequest::place_devices`]
    /// ([`GpuDeviceAvailability::held`]). It takes nothing: the launch
    /// commit leases each placed device by its id.
    ///
    /// # Errors
    ///
    /// [`GpuSlotRefusal::Paused`] or [`GpuSlotRefusal::Drained`] while the
    /// machine takes no new GPU work; [`GpuSlotRefusal::Unmeasured`] when the
    /// reading fails.
    pub fn held_devices(&self, now_ms: u64) -> Result<Vec<HeldDevice>, GpuSlotRefusal> {
        let availability = self.availability(now_ms).map_err(unmeasured)?;
        if let Some(reason) = availability.paused {
            return Err(GpuSlotRefusal::Paused { reason });
        }
        if let Some(reason) = availability.drained {
            return Err(GpuSlotRefusal::Drained { reason });
        }
        Ok(availability.held_devices())
    }

    /// Leases one GPU for the workload that runs `request`'s job: the GPU
    /// its key already takes (a kept slot or a reattached job), else the
    /// best-fit free GPU from a fresh reading. The GPU stays the workload's
    /// until the lease drops, finishes or is kept.
    ///
    /// # Errors
    ///
    /// [`GpuSlotRefusal`]: why no GPU was leased. One key has at most one
    /// live lease ([`GpuSlotRefusal::Taken`]), and leases one device
    /// ([`GpuSlotRefusal::ClaimCount`]).
    pub fn lease(
        &self,
        request: &GpuSlotRequest,
        now_ms: u64,
    ) -> Result<GpuSlotLease, GpuSlotRefusal> {
        request.check_count()?;
        let shared = &self.shared;
        let mut state = shared.lock();
        if let Some(reason) = &state.paused {
            return Err(GpuSlotRefusal::Paused {
                reason: reason.clone(),
            });
        }
        let at = state.at(&request.key);
        if let Some(device_id) = at
            .map(|at| state.slots[at].grant.device.device_id.as_str())
            .or(request.device_id.as_deref())
        {
            state.check_quarantine(device_id)?;
        }
        if let Some(reason) = shared.drained(&state).map_err(unmeasured)? {
            return Err(GpuSlotRefusal::Drained { reason });
        }
        let grant = match at {
            Some(at) if state.slots[at].guarded => {
                return Err(GpuSlotRefusal::Taken {
                    device_id: state.slots[at].grant.device.device_id.clone(),
                });
            }
            Some(at) => {
                let slot = &mut state.slots[at];
                slot.guarded = true;
                slot.grant.clone()
            }
            None => shared.take(&mut state, request, now_ms)?,
        };
        Ok(GpuSlotLease {
            shared: Arc::clone(shared),
            grant,
            ended: false,
        })
    }

    /// After a restart, gives a job that still runs on `device_id` its GPU
    /// again under `key`, launched and kept, with the `disk_bytes` its
    /// journaled booking claimed: they count on the disk again, whatever it
    /// holds now, before any new work is admitted. The job's own processes
    /// are on the GPU, so no free check applies, even in quarantine. A GPU
    /// another server owns is taken back only when its kept record names
    /// `key`. Another slot on it refuses.
    ///
    /// # Errors
    ///
    /// [`GpuSlotRefusal::UnknownDevice`], [`GpuSlotRefusal::Taken`] (another
    /// key takes the GPU, or this key takes another GPU),
    /// [`GpuSlotRefusal::Withheld`] (another server owns it and its record
    /// names another key), or [`GpuSlotRefusal::Unmeasured`].
    pub fn reattach(
        &self,
        key: &str,
        device_id: &str,
        disk_bytes: u64,
        now_ms: u64,
    ) -> Result<GpuSlotGrant, GpuSlotRefusal> {
        let shared = &self.shared;
        let mut state = shared.lock();
        if let Some(at) = state.at(key) {
            let grant = &state.slots[at].grant;
            return if grant.device.device_id == device_id {
                Ok(grant.clone())
            } else {
                Err(GpuSlotRefusal::Taken {
                    device_id: grant.device.device_id.clone(),
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
        // A GPU another server of this machine owns is not this table's to
        // take back, whatever runs on it, unless its kept record names this
        // key: the job this server launched before it stopped.
        let kept_here = shared
            .offer
            .owner_lock_dir
            .as_deref()
            .is_some_and(|dir| kept_for(dir, device_id, key));
        if !kept_here
            && reading
                .owned
                .as_ref()
                .is_some_and(|owned| !owned.contains(device_id))
        {
            return Err(GpuSlotRefusal::Withheld {
                device_id: device_id.to_owned(),
            });
        }
        if slot_on(&state.slots, device_id).is_some() {
            return Err(GpuSlotRefusal::Taken {
                device_id: device_id.to_owned(),
            });
        }
        if !kept_here && let Err(error) = shared.keep_record(device_id, key) {
            tracing::warn!(
                %error,
                device_id,
                key,
                "the reattached GPU's kept record could not be written; the GPU stays this server's only while it runs"
            );
        }
        let disk = shared.disk.as_ref().map(|disk| disk.restore(disk_bytes));
        let grant = GpuSlotGrant {
            key: key.to_owned(),
            device: device.clone(),
            granted_at_ms: now_ms,
        };
        state.slots.push(Slot {
            grant: grant.clone(),
            stage: Stage::Launched,
            guarded: false,
            _disk: disk,
        });
        Ok(grant)
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
            &state.slots[at].grant.device.device_id,
        ))
    }

    /// Ends the kept or reattached slot under `key`, recording nothing.
    /// Answers whether one ended. A GPU under a live lease is that lease's
    /// to give back. With no slot under `key` (a journaled job that did not
    /// survive a restart), it clears the kept record that names `key` on a
    /// GPU no live server holds.
    pub fn release(&self, key: &str) -> bool {
        let mut state = self.shared.lock();
        self.shared.end_unguarded(&mut state, key, None)
    }

    /// Ends the kept or reattached slot under `key` and records how its job
    /// ended, as [`GpuSlotLease::finish`] does. Answers whether one ended.
    /// With no slot under `key`, it records nothing and clears `key`'s kept
    /// record as [`Self::release`] does.
    pub fn finish(&self, key: &str, end: &GpuLeaseEnd) -> bool {
        let mut state = self.shared.lock();
        self.shared.end_unguarded(&mut state, key, Some(end))
    }

    /// Records why `device_id` cannot take a new job, even if the driver
    /// does not list it now. An existing slot stays with its key. The node
    /// journals and replays quarantines; this table keeps them in memory.
    pub fn quarantine(&self, device_id: &str, why: String) {
        self.shared
            .lock()
            .quarantined
            .insert(device_id.to_owned(), why);
    }

    /// Clears this GPU's quarantine after a clean probe or at a person's
    /// request. Returns whether one was cleared.
    pub fn clear_quarantine(&self, device_id: &str) -> bool {
        self.shared.lock().quarantined.remove(device_id).is_some()
    }

    /// Sets the in-memory reason to refuse new GPU work, or clears the
    /// pause. Existing slots stay with their keys.
    pub fn set_paused(&self, paused: Option<String>) {
        self.shared.lock().paused = paused;
    }
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        // Each change is one push, removal, flag or count under the lock, so
        // a holder that panicked left the state whole.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Grants a new, guarded slot from a fresh reading and claims its disk
    /// room. Reusing an existing slot does not claim disk again.
    fn take(
        &self,
        state: &mut State,
        request: &GpuSlotRequest,
        now_ms: u64,
    ) -> Result<GpuSlotGrant, GpuSlotRefusal> {
        let reading = self.read(state).map_err(unmeasured)?;
        if let Some(reason) = self.drained(state).map_err(unmeasured)? {
            return Err(GpuSlotRefusal::Drained { reason });
        }
        let device = self.pick(&reading, state, request)?.clone();
        let disk = self
            .disk
            .as_ref()
            .map(|disk| disk.claim(request.disk_bytes))
            .transpose()?;
        let grant = GpuSlotGrant {
            key: request.key.clone(),
            device,
            granted_at_ms: now_ms,
        };
        state.slots.push(Slot {
            grant: grant.clone(),
            stage: Stage::Leased,
            guarded: true,
            _disk: disk,
        });
        Ok(grant)
    }

    /// The GPU `request` takes in `reading`: its pinned GPU when free, or,
    /// if not pinned, the free match with the least memory, then lowest id.
    /// If none are free, report the first matching quarantine, if any.
    fn pick<'a>(
        &self,
        reading: &'a Reading,
        state: &State,
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
            if !admits_gpu(request, device) {
                return Err(GpuSlotRefusal::NoMatch);
            }
            return match self.state_of(reading, state, slot_on(&state.slots, device_id), device) {
                GpuDeviceState::Free => Ok(device),
                state => Err(refusal(device, state)),
            };
        }
        let mut matching: Vec<&GpuDevice> = reading
            .devices
            .iter()
            .filter(|device| admits_gpu(request, device))
            .collect();
        if matching.is_empty() {
            return Err(GpuSlotRefusal::NoMatch);
        }
        matching.sort_by(|a, b| {
            a.memory_total_mib
                .cmp(&b.memory_total_mib)
                .then_with(|| a.device_id.cmp(&b.device_id))
        });
        let mut quarantined = None;
        for device in matching {
            let slot = slot_on(&state.slots, &device.device_id);
            match self.state_of(reading, state, slot, device) {
                GpuDeviceState::Free => return Ok(device),
                blocked @ GpuDeviceState::Quarantined { .. } if quarantined.is_none() => {
                    quarantined = Some(refusal(device, blocked));
                }
                _ => {}
            }
        }
        Err(quarantined.unwrap_or(GpuSlotRefusal::NoneFree))
    }

    /// What `device` is doing in `reading`, with `slot` the slot on it, if
    /// any. Its key still shows when the GPU is quarantined or withheld.
    fn state_of(
        &self,
        reading: &Reading,
        state: &State,
        slot: Option<&Slot>,
        device: &GpuDevice,
    ) -> GpuDeviceState {
        if let Some(why) = state.quarantined.get(&device.device_id) {
            return GpuDeviceState::Quarantined {
                why: why.clone(),
                key: slot.map(|slot| slot.grant.key.clone()),
            };
        }
        if let Some(slot) = slot {
            let key = slot.grant.key.clone();
            return match slot.stage {
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
    /// list and the GPUs this table owns. A reading that lists one GPU id
    /// twice is refused ([`GpuProbeError::RepeatedDevice`]).
    fn read(&self, state: &mut State) -> Result<Reading, GpuProbeError> {
        self.read_with(state, None)
    }

    /// One fresh reading on `withheld` (`None`: the withheld list is read
    /// from its file).
    fn read_with(
        &self,
        state: &mut State,
        withheld: Option<BTreeSet<String>>,
    ) -> Result<Reading, GpuProbeError> {
        let devices = self.probe.devices()?;
        if let Some(device_id) = repeated_device_id(&devices) {
            return Err(GpuProbeError::RepeatedDevice { device_id });
        }
        let processes = self.probe.compute_processes()?;
        let withheld = match withheld {
            Some(withheld) => withheld,
            None => self.withheld()?,
        };
        let owned = self.own_offered(state);
        Ok(Reading {
            devices,
            processes,
            withheld,
            owned,
        })
    }

    /// The GPUs another booker holds now, from the reader thread within
    /// `WITHHELD_READ_TIMEOUT`.
    fn withheld(&self) -> Result<BTreeSet<String>, GpuProbeError> {
        match &self.withheld {
            Some(reader) => reader.read(),
            None => Ok(BTreeSet::new()),
        }
    }

    /// Ends the unguarded slot under `key`, if there is one; with none, clears
    /// `key`'s kept records.
    fn end_unguarded(&self, state: &mut State, key: &str, end: Option<&GpuLeaseEnd>) -> bool {
        match state.at(key) {
            Some(at) if !state.slots[at].guarded => {
                self.end(state, key, end);
                true
            }
            Some(_) => false,
            None => {
                self.forget_records_of(state, key);
                false
            }
        }
    }

    /// Ends the slot under `key`, with its GPU's kept record, and counts how
    /// its job ended.
    fn end(&self, state: &mut State, key: &str, end: Option<&GpuLeaseEnd>) {
        if let Some(at) = state.at(key) {
            let slot = state.slots.remove(at);
            self.forget_record(&slot.grant.device.device_id, key);
        }
        match end {
            Some(GpuLeaseEnd::Succeeded) => state.failures_in_a_row = 0,
            Some(GpuLeaseEnd::Failed { reason }) => {
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
            Some(GpuLeaseEnd::Cancelled) | None => {}
        }
    }
}

/// The slot on `device_id`, if any.
fn slot_on<'a>(slots: &'a [Slot], device_id: &str) -> Option<&'a Slot> {
    slots
        .iter()
        .find(|slot| slot.grant.device.device_id == device_id)
}

/// The refusal a GPU in `state` answers a booking or a launch with.
fn refusal(device: &GpuDevice, state: GpuDeviceState) -> GpuSlotRefusal {
    let device_id = device.device_id.clone();
    match state {
        GpuDeviceState::NotOffered => GpuSlotRefusal::NotOffered { device_id },
        GpuDeviceState::Withheld => GpuSlotRefusal::Withheld { device_id },
        GpuDeviceState::Busy { pids } => GpuSlotRefusal::Busy { device_id, pids },
        GpuDeviceState::Quarantined { why, .. } => GpuSlotRefusal::Quarantined { device_id, why },
        GpuDeviceState::Leased { .. } | GpuDeviceState::Launched { .. } => {
            GpuSlotRefusal::Taken { device_id }
        }
        GpuDeviceState::Free => GpuSlotRefusal::NoneFree,
    }
}

/// The first GPU id that `devices` lists on more than one line.
fn repeated_device_id(devices: &[GpuDevice]) -> Option<String> {
    let mut listed = BTreeSet::new();
    devices
        .iter()
        .find(|device| !listed.insert(device.device_id.as_str()))
        .map(|device| device.device_id.clone())
}

fn unmeasured(probe: GpuProbeError) -> GpuSlotRefusal {
    GpuSlotRefusal::Unmeasured {
        reason: probe.to_string(),
    }
}
