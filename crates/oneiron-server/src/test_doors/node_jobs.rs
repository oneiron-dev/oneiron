//! Scripted parts for the node's job service (pass 33, `33-exec-node/DESIGN.md`
//! section 11: the journal's tests run against a scripted unit manager and
//! need no privilege). A test builds a [`ScriptedNode`] on a temporary
//! directory, opens [`NodeJobs`] on it, and steps the node with
//! [`NodeJobs::tick`]. Opening a second [`NodeJobs`] on the same parts is an
//! engine restart; [`ScriptedNodeClock::reboot`] is a host reset.
//!
//! - [`ScriptedJobUnits`]: the service manager. A started unit runs until the
//!   test ends it; the end step writes `ended.json` as root would.
//! - [`ScriptedDevices`]: the GPU slot table, with a device probe the test
//!   can fail and compute processes it can place on a device.
//! - [`ScriptedAdmission`], [`ScriptedFloor`], [`ScriptedSigner`],
//!   [`ScriptedAuthority`], [`ScriptedStager`].

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron::machine_capacity::GpuDevice;
use oneiron::machine_signature::{MachineSignatureError, MachineSignatures};
use oneiron_organ_host::{FloorLease, FloorRefusal, GpuSlotHold, MachineFloor};

use crate::gpu_execution_node::jobs::job_unit::{
    END_RECORD_FILE_NAME, LAUNCH_FILE_NAME, write_file_synced,
};
use crate::gpu_execution_node::jobs::node_parts::{
    GpuDeviceLease, GpuDeviceProcesses, GpuJobEnd, GpuSlotRefusal, GpuSlotRequest,
};
use crate::gpu_execution_node::jobs::{
    AuthorityPosition, EndRecord, JobKeyId, JobUnit, JobUnitError, JobUnitPhase, JobUnitStatus,
    LaunchFile, NodeAdmission, NodeClock, NodeControls, NodeDevices, NodeJobParts, NodeJobPaths,
    NodeJobs, StageFailure, StageOrder, Stager,
};
use crate::gpu_execution_node::wire::WorkloadPin;

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The node's boot and clocks, as a test sets them.
#[derive(Debug)]
pub struct ScriptedNodeClock {
    boot_id: Mutex<String>,
    boot_ns: AtomicU64,
    wall_ms: AtomicU64,
}

impl ScriptedNodeClock {
    /// A clock in boot `boot-1`, ten seconds after the boot, at
    /// `wall_ms`.
    #[must_use]
    pub fn new(wall_ms: u64) -> Arc<Self> {
        Arc::new(Self {
            boot_id: Mutex::new("boot-1".to_owned()),
            boot_ns: AtomicU64::new(10_000_000_000),
            wall_ms: AtomicU64::new(wall_ms),
        })
    }

    /// Moves both clocks on by `millis`.
    pub fn advance_ms(&self, millis: u64) {
        self.boot_ns
            .fetch_add(millis.saturating_mul(1_000_000), Ordering::SeqCst);
        self.wall_ms.fetch_add(millis, Ordering::SeqCst);
    }

    /// A host reset: a new boot id, the boot clock starts again.
    pub fn reboot(&self, boot_id: &str) {
        *locked(&self.boot_id) = boot_id.to_owned();
        self.boot_ns.store(5_000_000_000, Ordering::SeqCst);
        self.wall_ms.fetch_add(60_000, Ordering::SeqCst);
    }
}

impl NodeClock for ScriptedNodeClock {
    fn boot_id(&self) -> String {
        locked(&self.boot_id).clone()
    }

    fn boot_ns(&self) -> u64 {
        self.boot_ns.load(Ordering::SeqCst)
    }

    fn wall_ms(&self) -> u64 {
        self.wall_ms.load(Ordering::SeqCst)
    }
}

/// What the scripted service manager does with the next start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptedStart {
    /// The unit starts and the workload runs.
    Run,
    /// The prepare step refuses: the end step records that the workload
    /// never started.
    RefuseInPrepare(String),
    /// The service manager does not take the start.
    NotTaken,
}

/// The service manager's result for a unit whose workload ran.
#[derive(Debug, Clone, Copy)]
struct ScriptedEnd<'a> {
    service_result: &'a str,
    exit_code: &'a str,
    exit_status: &'a str,
    cgroup_empty: bool,
    cutoff_fired: bool,
}

impl<'a> ScriptedEnd<'a> {
    fn exited(status: &'a str) -> Self {
        Self {
            service_result: "exit-code",
            exit_code: "exited",
            exit_status: status,
            cgroup_empty: true,
            cutoff_fired: false,
        }
    }

    fn killed() -> Self {
        Self {
            service_result: "success",
            exit_code: "killed",
            exit_status: "TERM",
            cgroup_empty: true,
            cutoff_fired: false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ScriptedUnit {
    phase: JobUnitPhase,
    cgroup_empty: bool,
}

#[derive(Debug)]
struct UnitsState {
    units: BTreeMap<JobKeyId, ScriptedUnit>,
    starts: BTreeMap<JobKeyId, u32>,
    answering: bool,
    next_start: ScriptedStart,
}

/// The service manager, scripted. It writes `ended.json` as the unit's root
/// end step would, from the key's `launch.json`.
#[derive(Debug)]
pub struct ScriptedJobUnits {
    state_dir: PathBuf,
    clock: Arc<ScriptedNodeClock>,
    state: Mutex<UnitsState>,
}

impl ScriptedJobUnits {
    /// A service manager with no unit, answering.
    #[must_use]
    pub fn new(state_dir: &Path, clock: Arc<ScriptedNodeClock>) -> Arc<Self> {
        Arc::new(Self {
            state_dir: state_dir.to_owned(),
            clock,
            state: Mutex::new(UnitsState {
                units: BTreeMap::new(),
                starts: BTreeMap::new(),
                answering: true,
                next_start: ScriptedStart::Run,
            }),
        })
    }

    /// How many times the key's unit was started.
    #[must_use]
    pub fn starts(&self, key: &str) -> u32 {
        locked(&self.state)
            .starts
            .get(&JobKeyId::for_key(key))
            .copied()
            .unwrap_or(0)
    }

    /// How many unit starts there were in all.
    #[must_use]
    pub fn total_starts(&self) -> u32 {
        locked(&self.state).starts.values().sum()
    }

    /// The key's unit phase now.
    #[must_use]
    pub fn phase(&self, key: &str) -> JobUnitPhase {
        locked(&self.state)
            .units
            .get(&JobKeyId::for_key(key))
            .map_or(JobUnitPhase::Inactive, |unit| unit.phase)
    }

    /// Whether the service manager answers (false: every call fails).
    pub fn set_answering(&self, answering: bool) {
        locked(&self.state).answering = answering;
    }

    /// What the next start does.
    pub fn set_next_start(&self, start: ScriptedStart) {
        locked(&self.state).next_start = start;
    }

    /// The workload exits with `code`: the end step writes the end record
    /// and the unit is inactive and empty.
    pub fn exit(&self, key: &str, code: i32) {
        let status = code.to_string();
        self.end_unit(key, &ScriptedEnd::exited(&status));
    }

    /// The cutoff timer stops the unit.
    pub fn cut_off(&self, key: &str) {
        self.end_unit(
            key,
            &ScriptedEnd {
                cutoff_fired: true,
                ..ScriptedEnd::killed()
            },
        );
    }

    /// The end step ran, and a process of the unit remained.
    pub fn exit_with_leftover(&self, key: &str) {
        self.end_unit(
            key,
            &ScriptedEnd {
                cgroup_empty: false,
                ..ScriptedEnd::exited("0")
            },
        );
    }

    /// The unit is gone with no end record (the end step left none).
    pub fn vanish(&self, key: &str) {
        locked(&self.state).units.insert(
            JobKeyId::for_key(key),
            ScriptedUnit {
                phase: JobUnitPhase::Inactive,
                cgroup_empty: true,
            },
        );
    }

    /// Every unit is gone, as after a reboot.
    pub fn clear(&self) {
        locked(&self.state).units.clear();
    }

    /// A unit that no key of the journal started.
    pub fn start_outside_the_journal(&self, id: &JobKeyId) {
        locked(&self.state).units.insert(
            id.clone(),
            ScriptedUnit {
                phase: JobUnitPhase::Active,
                cgroup_empty: false,
            },
        );
    }

    fn end_unit(&self, key: &str, end: &ScriptedEnd<'_>) {
        let id = JobKeyId::for_key(key);
        let record = EndRecord {
            key: key.to_owned(),
            service_result: end.service_result.to_owned(),
            exit_code: Some(end.exit_code.to_owned()),
            exit_status: Some(end.exit_status.to_owned()),
            boot_id: self.clock.boot_id(),
            end_boot_ns: self.clock.boot_ns(),
            cutoff_fired: end.cutoff_fired,
            workload_started: true,
            cgroup_empty: end.cgroup_empty,
            refusal: None,
        };
        self.write_end_record(&id, &record);
        locked(&self.state).units.insert(
            id,
            ScriptedUnit {
                phase: JobUnitPhase::Inactive,
                cgroup_empty: end.cgroup_empty,
            },
        );
    }

    fn write_end_record(&self, id: &JobKeyId, record: &EndRecord) {
        let path = id.control_dir(&self.state_dir).join(END_RECORD_FILE_NAME);
        let bytes = serde_json::to_vec(record).unwrap_or_default();
        if let Err(error) = write_file_synced(&path, &bytes) {
            tracing::warn!(%error, "scripted end record not written");
        }
    }

    fn launch_key(&self, id: &JobKeyId) -> Option<String> {
        let path = id.control_dir(&self.state_dir).join(LAUNCH_FILE_NAME);
        let bytes = std::fs::read(path).ok()?;
        let launch: LaunchFile = serde_json::from_slice(&bytes).ok()?;
        (JobKeyId::for_key(&launch.key) == *id).then_some(launch.key)
    }

    fn unavailable(unit: &JobKeyId) -> JobUnitError {
        JobUnitError {
            unit: unit.unit_name(),
            reason: "scripted: not answering".to_owned(),
        }
    }
}

impl JobUnit for ScriptedJobUnits {
    fn start(&self, unit: &JobKeyId) -> Result<(), JobUnitError> {
        let next = {
            let mut state = locked(&self.state);
            if !state.answering {
                return Err(Self::unavailable(unit));
            }
            let next = state.next_start.clone();
            if next == ScriptedStart::NotTaken {
                return Err(Self::unavailable(unit));
            }
            *state.starts.entry(unit.clone()).or_insert(0) += 1;
            state.units.insert(
                unit.clone(),
                ScriptedUnit {
                    phase: JobUnitPhase::Active,
                    cgroup_empty: false,
                },
            );
            next
        };
        if let ScriptedStart::RefuseInPrepare(reason) = next {
            let key = self.launch_key(unit).unwrap_or_default();
            let record = EndRecord {
                key,
                service_result: "exit-code".to_owned(),
                exit_code: None,
                exit_status: None,
                boot_id: self.clock.boot_id(),
                end_boot_ns: self.clock.boot_ns(),
                cutoff_fired: false,
                workload_started: false,
                cgroup_empty: true,
                refusal: Some(reason),
            };
            self.write_end_record(unit, &record);
            locked(&self.state).units.insert(
                unit.clone(),
                ScriptedUnit {
                    phase: JobUnitPhase::Inactive,
                    cgroup_empty: true,
                },
            );
        }
        Ok(())
    }

    fn stop(&self, unit: &JobKeyId) -> Result<(), JobUnitError> {
        let running = {
            let state = locked(&self.state);
            if !state.answering {
                return Err(Self::unavailable(unit));
            }
            state
                .units
                .get(unit)
                .is_some_and(|scripted| scripted.phase != JobUnitPhase::Inactive)
        };
        if running {
            match self.launch_key(unit) {
                Some(key) => self.end_unit(&key, &ScriptedEnd::killed()),
                None => {
                    locked(&self.state).units.insert(
                        unit.clone(),
                        ScriptedUnit {
                            phase: JobUnitPhase::Inactive,
                            cgroup_empty: true,
                        },
                    );
                }
            }
        }
        Ok(())
    }

    fn status(&self, unit: &JobKeyId) -> Result<JobUnitStatus, JobUnitError> {
        let state = locked(&self.state);
        if !state.answering {
            return Err(Self::unavailable(unit));
        }
        Ok(state.units.get(unit).map_or(
            JobUnitStatus {
                phase: JobUnitPhase::Inactive,
                cgroup_empty: true,
            },
            |scripted| JobUnitStatus {
                phase: scripted.phase,
                cgroup_empty: scripted.cgroup_empty,
            },
        ))
    }

    fn live_units(&self) -> Result<Vec<(JobKeyId, JobUnitStatus)>, JobUnitError> {
        let state = locked(&self.state);
        if !state.answering {
            return Err(JobUnitError {
                unit: "oneiron-job@*".to_owned(),
                reason: "scripted: not answering".to_owned(),
            });
        }
        Ok(state
            .units
            .iter()
            .filter(|(_, unit)| unit.phase != JobUnitPhase::Inactive || !unit.cgroup_empty)
            .map(|(id, unit)| {
                (
                    id.clone(),
                    JobUnitStatus {
                        phase: unit.phase,
                        cgroup_empty: unit.cgroup_empty,
                    },
                )
            })
            .collect())
    }
}

#[derive(Debug, Clone)]
struct ScriptedDevice {
    device: GpuDevice,
    offered: bool,
    /// Compute processes of another account on the device.
    foreign_pids: Vec<u32>,
    taken_by: Option<String>,
}

#[derive(Debug, Default)]
struct DevicesState {
    devices: Vec<ScriptedDevice>,
    leases: u32,
    probe_fails: bool,
    finished: Vec<(String, GpuJobEnd)>,
}

/// The machine's GPUs, scripted: each taken by at most one key.
#[derive(Debug, Clone, Default)]
pub struct ScriptedDevices {
    state: Arc<Mutex<DevicesState>>,
}

impl ScriptedDevices {
    /// One offered device of `memory_total_mib`, free.
    #[must_use]
    pub fn one(device_id: &str, memory_total_mib: u64) -> Arc<Self> {
        let devices = Self::default();
        locked(&devices.state).devices.push(ScriptedDevice {
            device: GpuDevice {
                device_id: device_id.to_owned(),
                model: "scripted".to_owned(),
                memory_total_mib,
            },
            offered: true,
            foreign_pids: Vec::new(),
            taken_by: None,
        });
        Arc::new(devices)
    }

    /// Puts compute processes of another account on the device.
    pub fn set_foreign_pids(&self, device_id: &str, pids: Vec<u32>) {
        let mut state = locked(&self.state);
        if let Some(device) = state
            .devices
            .iter_mut()
            .find(|device| device.device.device_id == device_id)
        {
            device.foreign_pids = pids;
        }
    }

    /// Offers or withholds the device.
    pub fn set_offered(&self, device_id: &str, offered: bool) {
        let mut state = locked(&self.state);
        if let Some(device) = state
            .devices
            .iter_mut()
            .find(|device| device.device.device_id == device_id)
        {
            device.offered = offered;
        }
    }

    /// Whether the device probe fails.
    pub fn set_probe_fails(&self, fails: bool) {
        locked(&self.state).probe_fails = fails;
    }

    /// The key the device is taken by.
    #[must_use]
    pub fn taken_by(&self, device_id: &str) -> Option<String> {
        locked(&self.state)
            .devices
            .iter()
            .find(|device| device.device.device_id == device_id)
            .and_then(|device| device.taken_by.clone())
    }

    /// How many leases were given in all.
    #[must_use]
    pub fn leases_given(&self) -> u32 {
        locked(&self.state).leases
    }

    /// Every finished key with how its job ended.
    #[must_use]
    pub fn finished(&self) -> Vec<(String, GpuJobEnd)> {
        locked(&self.state).finished.clone()
    }

    fn free(&self, key: &str) {
        for device in &mut locked(&self.state).devices {
            if device.taken_by.as_deref() == Some(key) {
                device.taken_by = None;
            }
        }
    }
}

struct ScriptedLease {
    devices: ScriptedDevices,
    hold: GpuSlotHold,
    open: bool,
}

impl GpuDeviceLease for ScriptedLease {
    fn hold(&self) -> &GpuSlotHold {
        &self.hold
    }

    fn confirm_launch(&mut self) -> Result<(), GpuSlotRefusal> {
        Ok(())
    }

    fn end_check(&self) -> Result<GpuDeviceProcesses, GpuSlotRefusal> {
        self.devices.end_check(&self.hold.key)
    }

    fn finish(mut self: Box<Self>, end: GpuJobEnd) {
        self.open = false;
        NodeDevices::finish(&self.devices, &self.hold.key, &end);
    }

    fn keep(mut self: Box<Self>) -> GpuSlotHold {
        self.open = false;
        self.hold.clone()
    }
}

impl Drop for ScriptedLease {
    fn drop(&mut self) {
        if self.open {
            self.devices.free(&self.hold.key);
        }
    }
}

impl NodeDevices for ScriptedDevices {
    fn could_take(&self, request: &GpuSlotRequest) -> Result<(), String> {
        let state = locked(&self.state);
        state
            .devices
            .iter()
            .any(|device| device.offered && request.admits(&device.device))
            .then_some(())
            .ok_or_else(|| "no_device".to_owned())
    }

    fn lease_for_launch(
        &self,
        request: &GpuSlotRequest,
    ) -> Result<Box<dyn GpuDeviceLease>, GpuSlotRefusal> {
        let mut state = locked(&self.state);
        let Some(device) = state
            .devices
            .iter_mut()
            .find(|device| request.admits(&device.device))
        else {
            return Err(GpuSlotRefusal::NoMatch);
        };
        let device_id = device.device.device_id.clone();
        if !device.offered {
            return Err(GpuSlotRefusal::Withheld { device_id });
        }
        if device.taken_by.is_some() {
            return Err(GpuSlotRefusal::Taken { device_id });
        }
        if !device.foreign_pids.is_empty() {
            return Err(GpuSlotRefusal::Busy {
                device_id,
                pids: device.foreign_pids.clone(),
            });
        }
        device.taken_by = Some(request.key.clone());
        let hold = GpuSlotHold {
            key: request.key.clone(),
            device: device.device.clone(),
            held_at_ms: 0,
            hold_until_ms: u64::MAX,
        };
        state.leases += 1;
        Ok(Box::new(ScriptedLease {
            devices: self.clone(),
            hold,
            open: true,
        }))
    }

    fn reattach(&self, key: &str, device_id: &str) -> Result<(), GpuSlotRefusal> {
        let mut state = locked(&self.state);
        let Some(device) = state
            .devices
            .iter_mut()
            .find(|device| device.device.device_id == device_id)
        else {
            return Err(GpuSlotRefusal::UnknownDevice {
                device_id: device_id.to_owned(),
            });
        };
        match &device.taken_by {
            Some(other) if other != key => Err(GpuSlotRefusal::Taken {
                device_id: device_id.to_owned(),
            }),
            _ => {
                device.taken_by = Some(key.to_owned());
                Ok(())
            }
        }
    }

    fn end_check(&self, key: &str) -> Result<GpuDeviceProcesses, GpuSlotRefusal> {
        let state = locked(&self.state);
        if state.probe_fails {
            return Err(GpuSlotRefusal::Unmeasured {
                reason: "scripted probe failure".to_owned(),
            });
        }
        state
            .devices
            .iter()
            .find(|device| device.taken_by.as_deref() == Some(key))
            .map(|device| GpuDeviceProcesses {
                pids: device.foreign_pids.clone(),
                hidden: 0,
            })
            .ok_or(GpuSlotRefusal::NotHeld)
    }

    fn finish(&self, key: &str, end: &GpuJobEnd) {
        self.free(key);
        locked(&self.state)
            .finished
            .push((key.to_owned(), end.clone()));
    }
}

#[derive(Debug, Clone)]
struct AdmissionState {
    controls: NodeControls,
    templates: BTreeMap<String, String>,
    pin_refusal: Option<String>,
    disk_free_mib: u64,
    disk_reserve_mib: u64,
    issuer_refusal: Option<String>,
    drains: Vec<String>,
    staging_limit_secs: u64,
}

/// The node's configuration and fold, scripted: enabled, one template, room
/// on the disk, the issuer live.
#[derive(Debug)]
pub struct ScriptedAdmission {
    state: Mutex<AdmissionState>,
}

impl ScriptedAdmission {
    /// An enabled node holding `template` at `digest`.
    #[must_use]
    pub fn new(template: &str, digest: &str) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(AdmissionState {
                controls: NodeControls {
                    enabled: true,
                    paused: None,
                    drained: None,
                },
                templates: BTreeMap::from([(template.to_owned(), digest.to_owned())]),
                pin_refusal: None,
                disk_free_mib: 1 << 20,
                disk_reserve_mib: 0,
                issuer_refusal: None,
                drains: Vec::new(),
                staging_limit_secs: 600,
            }),
        })
    }

    /// Sets the local controls.
    pub fn set_controls(&self, controls: NodeControls) {
        locked(&self.state).controls = controls;
    }

    /// Changes a template's digest (an edit of the root-owned file).
    pub fn set_template_digest(&self, template: &str, digest: &str) {
        locked(&self.state)
            .templates
            .insert(template.to_owned(), digest.to_owned());
    }

    /// The template check's refusal for every pin.
    pub fn set_pin_refusal(&self, refusal: Option<&str>) {
        locked(&self.state).pin_refusal = refusal.map(str::to_owned);
    }

    /// The payload disk's free space and its reserve.
    pub fn set_disk(&self, free_mib: u64, reserve_mib: u64) {
        let mut state = locked(&self.state);
        state.disk_free_mib = free_mib;
        state.disk_reserve_mib = reserve_mib;
    }

    /// The issuer's grant or standing refusal, as the fold reads it.
    pub fn set_issuer_refusal(&self, refusal: Option<&str>) {
        locked(&self.state).issuer_refusal = refusal.map(str::to_owned);
    }

    /// The staging limit, in seconds.
    pub fn set_staging_limit_secs(&self, secs: u64) {
        locked(&self.state).staging_limit_secs = secs;
    }

    /// Every drain the job service asked for.
    #[must_use]
    pub fn drains(&self) -> Vec<String> {
        locked(&self.state).drains.clone()
    }
}

impl NodeAdmission for ScriptedAdmission {
    fn controls(&self) -> NodeControls {
        locked(&self.state).controls.clone()
    }

    fn issuer_live(&self, _issuer: EntityId) -> Result<(), String> {
        locked(&self.state)
            .issuer_refusal
            .clone()
            .map_or(Ok(()), Err)
    }

    fn admit_pin(&self, pin: &WorkloadPin) -> Result<(), String> {
        let state = locked(&self.state);
        if let Some(refusal) = &state.pin_refusal {
            return Err(refusal.clone());
        }
        match state.templates.get(&pin.template) {
            Some(digest) if *digest == pin.template_digest => Ok(()),
            Some(_) => Err("template_digest_changed".to_owned()),
            None => Err("template_unknown".to_owned()),
        }
    }

    fn template_digest(&self, template: &str) -> Option<String> {
        locked(&self.state).templates.get(template).cloned()
    }

    fn disk_room(&self, booked_mib: u64, request_mib: u64) -> Result<(), String> {
        let state = locked(&self.state);
        let needed = booked_mib
            .saturating_add(request_mib)
            .saturating_add(state.disk_reserve_mib);
        (state.disk_free_mib >= needed)
            .then_some(())
            .ok_or_else(|| "disk_short".to_owned())
    }

    fn drain(&self, why: &str) {
        let mut state = locked(&self.state);
        state.drains.push(why.to_owned());
        state.controls.drained = Some(why.to_owned());
    }

    fn staging_limit_secs(&self) -> u64 {
        locked(&self.state).staging_limit_secs
    }
}

/// The machine's memory line, scripted: `total` bytes, no waiting.
#[derive(Debug)]
pub struct ScriptedFloor {
    total: u64,
    leased: Arc<AtomicU64>,
}

impl ScriptedFloor {
    /// A floor of `total_mib`.
    #[must_use]
    pub fn new(total_mib: u64) -> Arc<Self> {
        Arc::new(Self {
            total: total_mib.saturating_mul(1024 * 1024),
            leased: Arc::new(AtomicU64::new(0)),
        })
    }

    /// The bytes leased now.
    #[must_use]
    pub fn leased_bytes(&self) -> u64 {
        self.leased.load(Ordering::SeqCst)
    }
}

struct ScriptedFloorLease {
    bytes: u64,
    leased: Arc<AtomicU64>,
}

impl Drop for ScriptedFloorLease {
    fn drop(&mut self) {
        self.leased.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

impl FloorLease for ScriptedFloorLease {
    fn grow(
        &mut self,
        more: u64,
        _deadline: Instant,
        _stopped: &dyn Fn() -> bool,
    ) -> Result<(), FloorRefusal> {
        self.bytes += more;
        self.leased.fetch_add(more, Ordering::SeqCst);
        Ok(())
    }

    fn materialized(&mut self, _reserved: u64, _actual: u64) {}

    fn shrink(&mut self, bytes: u64) {
        let bytes = bytes.min(self.bytes);
        self.bytes -= bytes;
        self.leased.fetch_sub(bytes, Ordering::SeqCst);
    }

    fn grow_untimed(&mut self, more: u64, stopped: &dyn Fn() -> bool) -> Result<(), FloorRefusal> {
        self.grow(more, Instant::now(), stopped)
    }
}

impl MachineFloor for ScriptedFloor {
    fn check_irreducible_peak(&self, _pinned: u64, bytes: u64) -> Result<(), FloorRefusal> {
        (bytes <= self.total)
            .then_some(())
            .ok_or(FloorRefusal::Floor {
                needed: bytes,
                available: self.total,
            })
    }

    fn try_lease(&self, bytes: u64) -> Result<Option<Box<dyn FloorLease>>, FloorRefusal> {
        let leased = self.leased.load(Ordering::SeqCst);
        if leased.saturating_add(bytes) > self.total {
            return Ok(None);
        }
        self.leased.fetch_add(bytes, Ordering::SeqCst);
        Ok(Some(Box::new(ScriptedFloorLease {
            bytes,
            leased: Arc::clone(&self.leased),
        })))
    }

    fn track_allocated(&self, bytes: u64) -> Box<dyn FloorLease> {
        self.leased.fetch_add(bytes, Ordering::SeqCst);
        Box::new(ScriptedFloorLease {
            bytes,
            leased: Arc::clone(&self.leased),
        })
    }

    fn lease(
        &self,
        bytes: u64,
        _deadline: Instant,
        _stopped: &dyn Fn() -> bool,
    ) -> Result<Box<dyn FloorLease>, FloorRefusal> {
        self.try_lease(bytes)?.ok_or(FloorRefusal::Deadline)
    }
}

/// A machine-key signer for tests: a keyed blake3 hash per machine, so a
/// signature by one machine never verifies as another's.
#[derive(Debug, Clone, Copy)]
pub struct ScriptedSigner {
    machine: EntityId,
}

impl ScriptedSigner {
    /// The signer of `machine`.
    #[must_use]
    pub fn new(machine: EntityId) -> Arc<Self> {
        Arc::new(Self { machine })
    }

    /// The machine it signs as.
    #[must_use]
    pub fn machine(&self) -> EntityId {
        self.machine
    }

    /// The signature `machine` makes over `message` under `domain`.
    #[must_use]
    pub fn signature_of(machine: EntityId, domain: &[u8], message: &[u8]) -> [u8; 64] {
        let key = blake3::derive_key("oneiron scripted machine signer", machine.as_bytes());
        let mut hasher = blake3::Hasher::new_keyed(&key);
        hasher.update(domain);
        hasher.update(&[0]);
        hasher.update(message);
        let mut signature = [0u8; 64];
        hasher.finalize_xof().fill(&mut signature);
        signature
    }
}

impl MachineSignatures for ScriptedSigner {
    fn sign(
        &self,
        domain: &[u8],
        message: &[u8],
    ) -> Result<(EntityId, [u8; 64]), MachineSignatureError> {
        Ok((
            self.machine,
            Self::signature_of(self.machine, domain, message),
        ))
    }

    fn verify(
        &self,
        machine: EntityId,
        domain: &[u8],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), MachineSignatureError> {
        (Self::signature_of(machine, domain, message) == *signature)
            .then_some(())
            .ok_or(MachineSignatureError::Mismatch { machine })
    }
}

/// The node's fold position, scripted: whether it holds the submit's heads.
#[derive(Debug, Default)]
pub struct ScriptedAuthority {
    stale: AtomicBool,
}

impl ScriptedAuthority {
    /// A fold that holds every position.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Whether the fold lags every submit's position.
    pub fn set_stale(&self, stale: bool) {
        self.stale.store(stale, Ordering::SeqCst);
    }
}

impl AuthorityPosition for ScriptedAuthority {
    fn folded(&self, _heads: &[String]) -> bool {
        !self.stale.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Default)]
struct StagerState {
    holding: bool,
    entered: u32,
    refusal: Option<String>,
}

/// Staging, scripted: completes at once, or waits in each stage until the
/// test lets it go, or refuses.
#[derive(Debug, Default)]
pub struct ScriptedStager {
    state: Mutex<StagerState>,
    changed: Condvar,
}

impl ScriptedStager {
    /// A stager that completes at once.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Whether each stage waits until [`Self::let_go`].
    pub fn hold(&self) {
        locked(&self.state).holding = true;
    }

    /// Lets every waiting and later stage complete.
    pub fn let_go(&self) {
        locked(&self.state).holding = false;
        self.changed.notify_all();
    }

    /// The reason every later stage refuses with.
    pub fn set_refusal(&self, refusal: Option<&str>) {
        locked(&self.state).refusal = refusal.map(str::to_owned);
    }

    /// Waits until `count` stages have begun, up to `timeout`.
    #[must_use]
    pub fn wait_entered(&self, count: u32, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut state = locked(&self.state);
        while state.entered < count {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            state = self
                .changed
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        true
    }
}

impl Stager for ScriptedStager {
    fn stage(&self, _order: &StageOrder, closed: &dyn Fn() -> bool) -> Result<(), StageFailure> {
        let mut state = locked(&self.state);
        state.entered += 1;
        self.changed.notify_all();
        while state.holding {
            if closed() {
                return Err(StageFailure::Closed);
            }
            state = self
                .changed
                .wait_timeout(state, Duration::from_millis(20))
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        if closed() {
            return Err(StageFailure::Closed);
        }
        state
            .refusal
            .clone()
            .map_or(Ok(()), |reason| Err(StageFailure::Refused(reason)))
    }
}

/// Every scripted part of one node, on one directory.
#[derive(Debug, Clone)]
pub struct ScriptedNode {
    pub paths: NodeJobPaths,
    pub clock: Arc<ScriptedNodeClock>,
    pub units: Arc<ScriptedJobUnits>,
    pub devices: Arc<ScriptedDevices>,
    pub admission: Arc<ScriptedAdmission>,
    pub floor: Arc<ScriptedFloor>,
    pub signer: Arc<ScriptedSigner>,
    pub authority: Arc<ScriptedAuthority>,
    pub stager: Arc<ScriptedStager>,
}

impl ScriptedNode {
    /// A node `machine` on `root` (its `state` and `work` directories), one
    /// 24 GiB device `GPU-scripted-0`, 26 GiB of job memory, and `template`
    /// at `digest`.
    #[must_use]
    pub fn new(root: &Path, machine: EntityId, template: &str, digest: &str, wall_ms: u64) -> Self {
        let paths = NodeJobPaths {
            state_dir: root.join("state"),
            work_dir: root.join("work"),
        };
        let clock = ScriptedNodeClock::new(wall_ms);
        Self {
            units: ScriptedJobUnits::new(&paths.state_dir, Arc::clone(&clock)),
            paths,
            clock,
            devices: ScriptedDevices::one("GPU-scripted-0", 24 * 1024),
            admission: ScriptedAdmission::new(template, digest),
            floor: ScriptedFloor::new(26 * 1024),
            signer: ScriptedSigner::new(machine),
            authority: ScriptedAuthority::new(),
            stager: ScriptedStager::new(),
        }
    }

    /// The parts, as [`NodeJobs::open`] takes them.
    #[must_use]
    pub fn parts(&self) -> NodeJobParts {
        NodeJobParts {
            machine: self.signer.machine(),
            admission: self.admission.clone(),
            devices: self.devices.clone(),
            floor: self.floor.clone(),
            units: self.units.clone(),
            clock: self.clock.clone(),
            signer: self.signer.clone(),
            stager: self.stager.clone(),
            authority: self.authority.clone(),
        }
    }

    /// Opens the node's job service: its first start, or an engine restart.
    #[must_use]
    pub fn open(&self) -> NodeJobs {
        NodeJobs::open(self.paths.clone(), self.parts())
    }
}

/// Sets the hook that fails the journal's next appends between their write
/// and their sync (`None` clears it).
pub fn fail_journal_sync(jobs: &NodeJobs, failing: bool) {
    let fault: Option<crate::gpu_execution_node::jobs::journal_file::JournalAppendFault> = failing
        .then(|| {
            let injected = || -> std::io::Result<()> {
                Err(std::io::Error::other("injected: the sync failed"))
            };
            Arc::new(injected) as crate::gpu_execution_node::jobs::journal_file::JournalAppendFault
        });
    jobs.set_journal_append_fault(fault);
}
