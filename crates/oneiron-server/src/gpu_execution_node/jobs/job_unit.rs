//! The job unit as the engine sees it (design pass 33, 7.6): one instance of
//! the service manager's job unit template per key, started and stopped by
//! name, and the two files the engine and the unit's root steps exchange:
//! - `launch.json` ([`LaunchFile`]): the engine writes it before the launch
//!   commit; the unit's prepare step checks it against the root-owned
//!   configuration;
//! - `ended.json` ([`EndRecord`]): the unit's end step writes it after every
//!   process of the unit is gone; the engine reads it, level-triggered, at
//!   every tick and at start.
//!
//! [`JobUnit`] is the service manager, behind a trait: row R3b builds the
//! systemd implementation; tests use a scripted one. [`NodeClock`] is the
//! boot id and the boot clock, so a test can stand in for a reboot.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use oneiron::job_workload::{BoundRequirement, DeviceLease, ScopeBound, ScopeCapabilities};

use crate::gpu_execution_node::wire::{ScopeClass, ScopeFacts};

/// The name every job unit instance starts with.
pub const JOB_UNIT_TEMPLATE_PREFIX: &str = "oneiron-job@";

/// The job unit's suffix.
pub const JOB_UNIT_SUFFIX: &str = ".service";

/// The key's control directory, under `state_dir`.
pub const CONTROL_DIR_NAME: &str = "control";

/// The engine's launch parameters, in the key's control directory.
pub const LAUNCH_FILE_NAME: &str = "launch.json";

/// The unit's end record, in the key's control directory.
pub const END_RECORD_FILE_NAME: &str = "ended.json";

/// The engine's last tick for a launched key, in its control directory.
pub const TICK_FILE_NAME: &str = "tick";

/// The last signed receipt, in the key's control directory.
pub const RECEIPT_FILE_NAME: &str = "receipt.msgpack";

/// The hex digits of `blake3(key)` that name a key's unit, its control
/// directory and its payload directory.
pub const JOB_KEY_ID_HEX_DIGITS: usize = 32;

/// How long before a run's stop time (its cutoff less the stop grace) the
/// scope still takes a renewal (row W1). The systemd scope's handoff runs
/// in a control handler that lives at most 30 s, and the old cutoff timer
/// fires half a second before its stop time; a renewal this early has its
/// record written before the old timer can fire.
pub const RENEW_BEFORE_STOP_NS: u64 = 31_000_000_000;

/// The id that names one key on this node: the first 32 hex digits of the
/// blake3 hash of the key. The unit instance, the control directory and the
/// payload directory all carry it, so the prepare step can check that the
/// key in `launch.json` hashes to the instance it runs as.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JobKeyId(String);

impl JobKeyId {
    /// The id of `key`.
    #[must_use]
    pub fn for_key(key: &str) -> Self {
        let hash = oneiron_contracts::fingerprint::ContentHash::of(key.as_bytes());
        Self(hash.to_hex()[..JOB_KEY_ID_HEX_DIGITS].to_owned())
    }

    /// Reads an id from a unit instance name or a directory name: exactly
    /// 32 lower-case hex digits.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        (text.len() == JOB_KEY_ID_HEX_DIGITS
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        .then(|| Self(text.to_owned()))
    }

    /// The 32 hex digits.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The unit's full name, `oneiron-job@<id>.service`.
    #[must_use]
    pub fn unit_name(&self) -> String {
        format!("{JOB_UNIT_TEMPLATE_PREFIX}{}{JOB_UNIT_SUFFIX}", self.0)
    }

    /// The key's control directory under `state_dir`.
    #[must_use]
    pub fn control_dir(&self, state_dir: &Path) -> PathBuf {
        state_dir.join(CONTROL_DIR_NAME).join(&self.0)
    }

    /// The key's payload directory under `work_dir`.
    #[must_use]
    pub fn payload_dir(&self, work_dir: &Path) -> PathBuf {
        work_dir.join(&self.0)
    }
}

impl std::fmt::Display for JobKeyId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Where a unit is in the service manager's life cycle. A unit the service
/// manager has never started reads as [`JobUnitPhase::Inactive`], the same
/// as one that ended: only the end record tells them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobUnitPhase {
    /// The start was asked for, and the prepare step may be running.
    Starting,
    /// The workload's process runs.
    Active,
    /// The unit is being stopped.
    Stopping,
    /// Not running, ended or never started.
    Inactive,
}

/// The service manager's answer about one unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobUnitStatus {
    pub phase: JobUnitPhase,
    /// Whether the unit's control group holds no process. A unit that is
    /// inactive with a process left is one the kernel could not kill.
    pub cgroup_empty: bool,
}

impl JobUnitStatus {
    /// Whether the unit is inactive and holds no process.
    #[must_use]
    pub fn is_gone(&self) -> bool {
        self.phase == JobUnitPhase::Inactive && self.cgroup_empty
    }
}

/// The service manager did not answer. It is never read as "inactive".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("job_unit.unavailable: the service manager did not answer for {unit}: {reason}")]
pub struct JobUnitError {
    pub unit: String,
    pub reason: String,
}

/// What a launch under a template that requires `required` lacks on
/// `scope`, by name: each bound of the minimum contract the scope does not
/// enforce (it kills the whole tree, enforces the cutoff with the engine
/// stopped and tells when the tree is empty, I4 and I5), then each
/// requirement it does not meet, as the template spells it
/// (`memory_cap:kernel`; pass 34 section 2.2, the blocker
/// `NoScope { missing }`). Empty when the launch may go on.
#[must_use]
pub fn scope_missing(scope: &ScopeCapabilities, required: &[BoundRequirement]) -> Vec<String> {
    let mut missing: Vec<String> = ScopeBound::MINIMUM_CONTRACT
        .into_iter()
        .filter(|bound| !scope.report(*bound).strength.is_enforced())
        .map(|bound| bound.name().to_owned())
        .collect();
    for requirement in scope.missing(required) {
        let name = requirement.to_string();
        if !missing.contains(&name) {
            missing.push(name);
        }
    }
    missing
}

/// Why a unit's cutoff was not renewed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RenewRefusal {
    /// This scope cannot move a cutoff: a session's renewal on it continues
    /// nothing, and the run ends at its cutoff.
    #[error("job_unit.renew_unsupported: this launch scope does not renew a cutoff")]
    Unsupported,
    #[error(transparent)]
    Unit(#[from] JobUnitError),
}

/// The service manager, as the node's job service uses it: the launch
/// scope seam of pass 34, 2.2. The engine's account may start and stop
/// instances of the job unit template and nothing else. Every call returns
/// within a bounded time: an implementation that asks a service manager
/// puts its own timeout on the ask and answers [`JobUnitError`] past it,
/// since the end handling asks under the admission lock.
pub trait JobUnit: Send + Sync {
    /// The class of scope the unit runs its workload in: the host scope (the
    /// job unit's own OS account and control group) for the systemd unit and
    /// the scripted one.
    fn class(&self) -> ScopeClass {
        ScopeClass::Host
    }

    /// What this machine's scope can enforce now, bound by bound. The
    /// launch commit refuses a launch while the minimum contract is not met.
    fn probe(&self) -> ScopeCapabilities;

    /// Moves the unit's cutoff forward to `cutoff_boot_ns`, only from a
    /// journaled renewal (pass 34, 2.5; row W1), and never back: asked again
    /// for a cutoff it holds, it changes nothing. A scope takes a renewal
    /// until [`RENEW_BEFORE_STOP_NS`] before the run's current stop time.
    ///
    /// # Errors
    ///
    /// [`RenewRefusal::Unsupported`], the default, for a scope that cannot
    /// move a cutoff; [`RenewRefusal::Unit`] when the service manager did
    /// not take it.
    fn renew(&self, unit: &JobKeyId, cutoff_boot_ns: u64) -> Result<(), RenewRefusal> {
        let _ = (unit, cutoff_boot_ns);
        Err(RenewRefusal::Unsupported)
    }

    /// What the key's scope proved for its run (pass 34, 2.2): the receipt's
    /// `scope`. `None` when the unit never prepared, or the scope keeps no
    /// record of it.
    fn scope_facts(&self, unit: &JobKeyId) -> Option<ScopeFacts> {
        let _ = unit;
        None
    }

    /// Asks the service manager to start the key's unit. It returns once the
    /// start is queued; it does not wait for the workload.
    ///
    /// # Errors
    ///
    /// [`JobUnitError`] when the service manager did not take the start.
    fn start(&self, unit: &JobKeyId) -> Result<(), JobUnitError>;

    /// Asks the service manager to stop the key's unit: every process of it.
    ///
    /// # Errors
    ///
    /// [`JobUnitError`] when the service manager did not take the stop.
    fn stop(&self, unit: &JobKeyId) -> Result<(), JobUnitError>;

    /// The unit's phase and whether its control group is empty, now.
    ///
    /// # Errors
    ///
    /// [`JobUnitError`] when the service manager did not answer.
    fn status(&self, unit: &JobKeyId) -> Result<JobUnitStatus, JobUnitError>;

    /// Every instance of the job unit template that is not inactive, or
    /// that is inactive with a process left.
    ///
    /// # Errors
    ///
    /// [`JobUnitError`] when the service manager did not answer.
    fn live_units(&self) -> Result<Vec<(JobKeyId, JobUnitStatus)>, JobUnitError>;

    /// Sends the operating-system signal `signal` (a name such as `USR1`,
    /// which the template chose) to the unit's main process: a checkpoint
    /// notice (design 7.1 `Signal`). It never stops the unit or moves its
    /// cutoff.
    ///
    /// # Errors
    ///
    /// [`JobUnitError`] when the service manager did not take it. A scope
    /// that cannot deliver one answers so, and the notice is lost, as a
    /// notice may be.
    fn signal(&self, unit: &JobKeyId, signal: &str) -> Result<(), JobUnitError> {
        Err(JobUnitError {
            unit: unit.unit_name(),
            reason: format!("signal {signal}: this launch scope delivers no signal"),
        })
    }
}

/// The boot this node runs in and its boot clock. The boot clock counts
/// while the machine is suspended and starts again at each boot, so an
/// interval on it is only read within one boot id.
pub trait NodeClock: Send + Sync {
    /// The kernel's id for this boot.
    fn boot_id(&self) -> String;

    /// Nanoseconds since this boot, on the boot clock.
    fn boot_ns(&self) -> u64;

    /// Unix milliseconds.
    fn wall_ms(&self) -> u64;
}

/// The machine's own clock: the kernel's boot id and `CLOCK_BOOTTIME`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemNodeClock;

impl NodeClock for SystemNodeClock {
    fn boot_id(&self) -> String {
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map(|text| text.trim().to_owned())
            .unwrap_or_default()
    }

    fn boot_ns(&self) -> u64 {
        boot_clock_ns()
    }

    fn wall_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            })
    }
}

#[cfg(target_os = "linux")]
fn boot_clock_ns() -> u64 {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `now` is a valid, writable timespec, and CLOCK_BOOTTIME is a
    // clock id the kernel knows.
    let answer = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &raw mut now) };
    if answer != 0 {
        return 0;
    }
    u64::try_from(now.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::try_from(now.tv_nsec).unwrap_or(0))
}

/// Not a boot clock: a machine without Linux runs no job (it has no job
/// unit), so the wall clock only keeps the node's answers well formed there.
#[cfg(not(target_os = "linux"))]
fn boot_clock_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
        })
}

/// The unit's exact parameters, written by the engine into the key's control
/// directory before the launch commit. The prepare step reads it as
/// untrusted input: the pin passes the node file's own admission check
/// (`ExecutionNodeSettings::admit_pin`) again, as root, and every other value
/// must fit the root-owned configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchFile {
    /// The job key. Its [`JobKeyId`] must equal the unit's instance name.
    pub key: String,
    /// The pin the key was reserved and submitted with.
    pub pin: crate::gpu_execution_node::wire::WorkloadPin,
    /// The devices the unit may open, one per placed claim, by the
    /// vendor's id; empty for a request with no device claim (no device is
    /// allowed).
    pub devices: Vec<DeviceLease>,
    /// The host memory leased for the key, in MiB: the scope's memory
    /// limit (the request's memory plus each unified device's claim
    /// memory).
    pub host_memory_mib: u64,
    /// The submit's maximum: at most the pin's.
    pub maximum_secs: u64,
    /// The boot and the boot-clock time of the launch commit; the prepare
    /// step arms the cutoff from them.
    pub boot_id: String,
    pub launch_boot_ns: u64,
}

/// What the unit's end step records, as root, after every process of the
/// unit is gone. The workload cannot write it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndRecord {
    /// The key from `launch.json`.
    pub key: String,
    /// The service manager's `$SERVICE_RESULT` (`success`, `exit-code`,
    /// `signal`, `timeout`, `oom-kill`, `core-dump`, ...).
    pub service_result: String,
    /// The service manager's `$EXIT_CODE` (`exited`, `killed`, `dumped`).
    #[serde(default)]
    pub exit_code: Option<String>,
    /// The service manager's `$EXIT_STATUS`: the exit status, or the signal.
    #[serde(default)]
    pub exit_status: Option<String>,
    pub boot_id: String,
    /// The boot-clock time of the end step: the end of occupancy.
    pub end_boot_ns: u64,
    /// Whether the cutoff timer stopped the unit.
    pub cutoff_fired: bool,
    /// Whether the workload's process ever existed. False means the prepare
    /// step or the launcher refused before it.
    pub workload_started: bool,
    /// Whether the unit's control group was empty when the step ran.
    pub cgroup_empty: bool,
    /// The prepare step's or the launcher's refusal, when the workload never
    /// started.
    #[serde(default)]
    pub refusal: Option<String>,
}

/// Reads the key's end record, if the end step wrote one.
///
/// # Errors
///
/// An end record that exists and cannot be read or parsed, or one written
/// for another key. Such a record is never read as "no end record".
pub fn read_end_record(control_dir: &Path, key: &str) -> io::Result<Option<EndRecord>> {
    let path = control_dir.join(END_RECORD_FILE_NAME);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut record: EndRecord = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    // The end step names no key it could not check: a launch file that named
    // another key than the unit's instance is refused before any workload,
    // and its record carries no key. In the key's own control directory such
    // a refusal is this key's (R3b review r3 R3-09).
    if record.key.is_empty() && !record.workload_started {
        record.key = key.to_owned();
    }
    if record.key != key {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} names another key", path.display()),
        ));
    }
    Ok(Some(record))
}

/// Writes `bytes` to `path` through a synced temporary file and a rename.
///
/// # Errors
///
/// The I/O error that stopped it.
pub fn write_file_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    let Some(dir) = path.parent() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a control file needs a directory",
        ));
    };
    std::fs::create_dir_all(dir)?;
    let mut staging_name = path
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    staging_name.push(".new");
    let staging = dir.join(staging_name);
    {
        let mut file = std::fs::File::create(&staging)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&staging, path)?;
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}
