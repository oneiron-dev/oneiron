//! The scripted service manager: the job units it starts and ends as a
//! test tells it, and the end step that writes `ended.json` as root would.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use oneiron::job_workload::{BoundReport, BoundStrength, ScopeCapabilities};

use super::{ScriptedNodeClock, locked};
use crate::gpu_execution_node::jobs::job_unit::{
    END_RECORD_FILE_NAME, LAUNCH_FILE_NAME, write_file_synced,
};
use crate::gpu_execution_node::jobs::{
    EndRecord, JobKeyId, JobUnit, JobUnitError, JobUnitPhase, JobUnitStatus, LaunchFile, NodeClock,
    RenewRefusal,
};

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
    /// Whether it answers a unit's status (false: it still lists its
    /// units).
    status_answering: bool,
    next_start: ScriptedStart,
    /// Every signal delivered, in order: the unit and the signal's name.
    signals: Vec<(JobKeyId, String)>,
    probe: ScopeCapabilities,
    /// Each unit's cutoff as its renewals moved it (row W1), and whether a
    /// renewal is taken.
    cutoffs: BTreeMap<JobKeyId, u64>,
    renewing: bool,
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
                status_answering: true,
                next_start: ScriptedStart::Run,
                signals: Vec::new(),
                probe: Self::kernel_scope(),
                cutoffs: BTreeMap::new(),
                renewing: true,
            }),
        })
    }

    /// The cutoff the key's unit holds after its renewals: `None` while no
    /// renewal moved it, so it stays where the launch armed it.
    #[must_use]
    pub fn renewed_cutoff(&self, key: &str) -> Option<u64> {
        locked(&self.state)
            .cutoffs
            .get(&JobKeyId::for_key(key))
            .copied()
    }

    /// Whether the scope takes a renewal (false: it answers unavailable).
    pub fn set_renewing(&self, renewing: bool) {
        locked(&self.state).renewing = renewing;
    }

    /// The signals delivered to the key's unit, in order.
    #[must_use]
    pub fn signals(&self, key: &str) -> Vec<String> {
        let id = JobKeyId::for_key(key);
        locked(&self.state)
            .signals
            .iter()
            .filter(|(unit, _)| *unit == id)
            .map(|(_, signal)| signal.clone())
            .collect()
    }

    /// A scope whose kernel gives every bound: what `probe` answers until a
    /// test sets another.
    #[must_use]
    pub fn kernel_scope() -> ScopeCapabilities {
        let kernel = || BoundReport {
            strength: BoundStrength::Kernel,
            evidence: "scripted".to_owned(),
        };
        ScopeCapabilities {
            tree_kill: kernel(),
            cutoff_without_engine: kernel(),
            emptiness: kernel(),
            memory_cap: kernel(),
            cpu_cap: kernel(),
            file_wall: kernel(),
            network_closed: kernel(),
            device_closure: kernel(),
            processes_hidden: kernel(),
            write_rate_cap: kernel(),
        }
    }

    /// What `probe` answers from now on.
    pub fn set_probe(&self, scope: ScopeCapabilities) {
        locked(&self.state).probe = scope;
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

    /// Whether the service manager answers a unit's status; it lists its
    /// units either way.
    pub fn set_status_answering(&self, answering: bool) {
        locked(&self.state).status_answering = answering;
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

    /// The end step wrote the end record, as [`Self::exit`] with 0 does, but
    /// the unit is still stopping: its phase is `Stopping` and its control
    /// group is not empty yet, so the release check waits for it.
    pub fn exit_while_stopping(&self, key: &str) {
        self.end_unit(key, &ScriptedEnd::exited("0"));
        locked(&self.state).units.insert(
            JobKeyId::for_key(key),
            ScriptedUnit {
                phase: JobUnitPhase::Stopping,
                cgroup_empty: false,
            },
        );
    }

    /// The stopping unit is gone: inactive with an empty control group, so
    /// the release check runs. The end record stays as written.
    pub fn finish_stopping(&self, key: &str) {
        locked(&self.state).units.insert(
            JobKeyId::for_key(key),
            ScriptedUnit {
                phase: JobUnitPhase::Inactive,
                cgroup_empty: true,
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
    fn probe(&self) -> ScopeCapabilities {
        locked(&self.state).probe.clone()
    }

    /// Moves the unit's cutoff forward, never back, as the systemd scope's
    /// root handoff does.
    fn renew(&self, unit: &JobKeyId, cutoff_boot_ns: u64) -> Result<(), RenewRefusal> {
        let mut state = locked(&self.state);
        let running = state
            .units
            .get(unit)
            .is_some_and(|scripted| scripted.phase == JobUnitPhase::Active);
        // As root's handoff: only a running unit's cutoff moves.
        if !state.answering || !state.renewing || !running {
            return Err(RenewRefusal::Unit(Self::unavailable(unit)));
        }
        let held = state.cutoffs.entry(unit.clone()).or_insert(cutoff_boot_ns);
        *held = (*held).max(cutoff_boot_ns);
        Ok(())
    }

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
        if !state.answering || !state.status_answering {
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

    fn signal(&self, unit: &JobKeyId, signal: &str) -> Result<(), JobUnitError> {
        let mut state = locked(&self.state);
        if !state.answering {
            return Err(Self::unavailable(unit));
        }
        state.signals.push((unit.clone(), signal.to_owned()));
        Ok(())
    }
}
