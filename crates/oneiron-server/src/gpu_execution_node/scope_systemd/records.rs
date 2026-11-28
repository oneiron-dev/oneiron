//! The files the unit's steps hand each other, besides R3a's `launch.json`
//! and `ended.json` ([`crate::gpu_execution_node::jobs::LaunchFile`],
//! [`crate::gpu_execution_node::jobs::EndRecord`]):
//! - `exec.json` ([`ExecFile`]): the prepare step (root) writes it into the
//!   job's exchange directory; `job-exec` applies it and nothing else;
//! - the scope report ([`ScopeReport`]): `job-exec` sends it on its
//!   connection to the gate's socket before the workload exists;
//! - `prepared.json` ([`PreparedRecord`]), `scope.json` ([`ScopeRecord`])
//!   and `cutoff.json` ([`CutoffMark`]): root's records in the key's control
//!   directory, which the end step and the engine read.
//!
//! A bound is G1's [`ScopeBound`] (pass 34, section 2.2), and each report is
//! G1's [`BoundReport`]: its [`BoundStrength`] and one line of evidence.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::super::wire::{ScopeClass, ScopeFacts};
pub use oneiron::job_workload::{
    BoundReport, BoundRequirement, BoundStrength, ScopeBound, ScopeCapabilities,
};

/// The bounds `job-exec` proves from inside the unit before the workload
/// exists; the prepare step (root) judges every other bound from the unit's
/// effective properties.
pub const PROVED_INSIDE: [ScopeBound; 6] = [
    ScopeBound::DeviceClosure,
    ScopeBound::FileWall,
    ScopeBound::NetworkClosed,
    ScopeBound::ProcessesHidden,
    ScopeBound::MemoryCap,
    ScopeBound::WriteRateCap,
];

/// A bound the kernel enforces with no process of ours alive.
#[must_use]
pub fn enforced_by_kernel(evidence: impl Into<String>) -> BoundReport {
    BoundReport {
        strength: BoundStrength::Kernel,
        evidence: evidence.into(),
    }
}

/// A bound nothing enforces or proved.
#[must_use]
pub fn not_enforced(evidence: impl Into<String>) -> BoundReport {
    BoundReport {
        strength: BoundStrength::None,
        evidence: evidence.into(),
    }
}

/// Whether `report` gives its bound at all (kernel or supervised).
#[must_use]
pub fn is_enforced(report: &BoundReport) -> bool {
    report.strength.is_enforced()
}

/// The first of `required` that `proofs` does not give at the strength it
/// asks (a `:kernel` requirement needs the kernel's), in its written form.
#[must_use]
pub fn first_unmet(
    required: &[BoundRequirement],
    proofs: &BTreeMap<ScopeBound, BoundReport>,
) -> Option<BoundRequirement> {
    required.iter().copied().find(|requirement| {
        !proofs
            .get(&requirement.bound)
            .is_some_and(|report| requirement.is_met_by(report.strength))
    })
}

/// `job-exec`'s whole input, written by the prepare step (root) and readable
/// by the job account only. It names the workload's program exactly: the
/// template's interpreter, the entry inside the checkout, the pin's
/// arguments, and nothing from the engine's environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecFile {
    /// The job key.
    pub key: String,
    /// The unit's instance: the key's 32 hex digits.
    pub instance: String,
    /// `execution-node check`'s probe: report every bound, then exit, and
    /// never start a program.
    pub probe: bool,
    /// The program and its arguments: interpreter, entry, the pin's args.
    pub argv: Vec<String>,
    /// The workload's whole environment.
    pub env: BTreeMap<String, String>,
    /// The working directory: the key's payload directory.
    pub cwd: PathBuf,
    /// Paths the inner wall lets the job read and run.
    pub read: Vec<PathBuf>,
    /// Paths the inner wall lets the job write: out, tmp, log, and the
    /// template's write paths.
    pub write: Vec<PathBuf>,
    /// Paths the job must not be able to open: the vault's trees, the
    /// keystore, the state directory.
    pub protected: Vec<PathBuf>,
    /// The device files the unit's device policy allows.
    pub devices_allowed: Vec<PathBuf>,
    /// Device files outside the allow-list that exist on this machine: the
    /// proof tries to open one.
    pub devices_denied: Vec<PathBuf>,
    /// Processes the job must not see: process 1 and the engine's.
    pub hidden_pids: Vec<u32>,
    /// The machine's own network namespace, as `/proc/1/ns/net` names it
    /// (`net:[<inode>]`): the job's must be another (review r2 R2-06). Empty
    /// when root could not read it.
    pub host_network_namespace: String,
    /// The bounds the template requires (pass 34, 2.2).
    pub require: Vec<BoundRequirement>,
    /// The bytes each of the workload's log files keeps: the template's
    /// `log_max_mib` (pass 34, 7.2).
    #[serde(default = "log_max_bytes_default")]
    pub log_max_bytes: u64,
}

fn log_max_bytes_default() -> u64 {
    u64::from(super::super::node_settings::LOG_MAX_MIB_DEFAULT) << 20
}

/// What `job-exec` proved from inside the unit, before the workload exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeReport {
    pub instance: String,
    /// Each bound `job-exec` can prove from inside.
    pub proofs: BTreeMap<ScopeBound, BoundReport>,
    /// The first required bound that is not proved, or the wall that could
    /// not be applied; `None` when the workload may start.
    pub refusal: Option<String>,
}

/// What the prepare step applied before any workload process existed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedRecord {
    pub key: String,
    pub instance: String,
    /// Why the prepare step refused; the unit then fails before `job-exec`.
    pub refusal: Option<String>,
    pub boot_id: String,
    pub at_boot_ns: u64,
    /// The job account the unit runs as.
    pub account: String,
    /// The unit properties this step set on the unit, as `Name=value`.
    pub properties: Vec<String>,
    /// The device files the device policy admits.
    pub devices: Vec<String>,
    /// The cutoff: its timer unit and when it stops the job unit.
    pub cutoff: Option<CutoffPlan>,
    /// The sleep inhibitor's unit, when the step started one.
    pub awake_unit: Option<String>,
    /// Each bound as the effective unit properties and this kernel give it.
    pub configured: BTreeMap<ScopeBound, BoundReport>,
    /// The bounds the template required (pass 34, 2.2).
    pub required: Vec<BoundRequirement>,
    /// The inner file wall: `read <path>` and `write <path>`, one per path.
    pub fence: Vec<String>,
    /// The names of the credentials the service manager loaded for this run
    /// (FIX NODE-JOB-CREDENTIALS), never their values. Empty in a record
    /// written before credentials.
    #[serde(default)]
    pub credentials: Vec<String>,
    /// For a session template's run (pass 34, 2.5; row W1), the latest
    /// boot-clock time a renewal may move its cutoff to: the launch plus the
    /// template's `session_max_secs`. `None` for a job, whose cutoff never
    /// moves, and in a record written before sessions.
    #[serde(default)]
    pub session_until_boot_ns: Option<u64>,
}

/// The cutoff timer the prepare step armed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutoffPlan {
    /// The timer's unit, `oneiron-job-cutoff-<id>.timer`.
    pub unit: String,
    /// The boot-clock time the timer stops the unit at: launch plus the
    /// maximum less the stop grace, so the unit is empty by the maximum.
    pub stop_at_boot_ns: u64,
    /// The stop grace inside the maximum, in seconds.
    pub stop_grace_secs: u64,
}

/// The gate's record (root), written before it lets the workload start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeRecord {
    pub instance: String,
    /// `job-exec`'s report, as the gate read it; `None` when none came.
    pub report: Option<ScopeReport>,
    /// Whether the gate let the workload start. Written and synced before
    /// the gate writes its go, so a workload that started always has it.
    pub released: bool,
    pub refusal: Option<String>,
    /// Why the workload's `execve` failed after the go, in `job-exec`'s
    /// words on the gate connection (review r2 R2-02); the workload then never
    /// started.
    #[serde(default)]
    pub exec_failed: Option<String>,
    pub at_boot_ns: u64,
}

/// The cutoff's mark (root): the timer stopped the unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutoffMark {
    pub instance: String,
    pub fired_boot_ns: u64,
}

/// The receipt's scope facts for one key, from the root records: each bound
/// as `job-exec` proved it inside the unit before the workload existed, else
/// as the unit's effective properties gave it, else at none (unproven).
#[must_use]
pub fn scope_facts(prepared: &PreparedRecord, scope: Option<&ScopeRecord>) -> ScopeFacts {
    let proved = scope.and_then(|record| record.report.as_ref());
    let report = |bound: ScopeBound| -> BoundReport {
        proved
            .and_then(|report| report.proofs.get(&bound))
            .or_else(|| prepared.configured.get(&bound))
            .cloned()
            .unwrap_or_else(|| not_enforced("not reported"))
    };
    let namespaces = ["mount", "network", "ipc"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    ScopeFacts {
        kind: ScopeClass::Host,
        account: prepared.account.clone(),
        devices: prepared.devices.clone(),
        namespaces,
        fence: prepared.fence.clone(),
        required: prepared.required.clone(),
        bounds: scope_capabilities(report),
    }
}

/// G1's [`ScopeCapabilities`], one report per bound from `report`.
#[must_use]
pub fn scope_capabilities(report: impl Fn(ScopeBound) -> BoundReport) -> ScopeCapabilities {
    ScopeCapabilities {
        tree_kill: report(ScopeBound::TreeKill),
        cutoff_without_engine: report(ScopeBound::CutoffWithoutEngine),
        emptiness: report(ScopeBound::Emptiness),
        memory_cap: report(ScopeBound::MemoryCap),
        cpu_cap: report(ScopeBound::CpuCap),
        file_wall: report(ScopeBound::FileWall),
        network_closed: report(ScopeBound::NetworkClosed),
        device_closure: report(ScopeBound::DeviceClosure),
        processes_hidden: report(ScopeBound::ProcessesHidden),
        write_rate_cap: report(ScopeBound::WriteRateCap),
    }
}
