//! The files the unit's steps hand each other, besides R3a's `launch.json`
//! and `ended.json` ([`crate::gpu_execution_node::jobs::LaunchFile`],
//! [`crate::gpu_execution_node::jobs::EndRecord`]):
//! - `exec.json` ([`ExecFile`]): the prepare step (root) writes it into the
//!   job's exchange directory; `job-exec` applies it and nothing else;
//! - the scope report ([`ScopeReport`]): `job-exec` writes it into the gate
//!   pipe before the workload exists;
//! - `prepared.json` ([`PreparedRecord`]), `scope.json` ([`ScopeRecord`])
//!   and `cutoff.json` ([`CutoffMark`]): root's records in the key's control
//!   directory, which the end step and the engine read.
//!
//! A bound is named as pass 34 names it (section 2.2, `ScopeCapabilities`),
//! and its strength is `kernel`, `supervised` or `none`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::super::wire::{ScopeClass, ScopeFacts};

/// The bounds a scope reports, by pass 34's names (section 2.2).
pub mod bound {
    /// The whole process tree is killed (the minimum contract).
    pub const TREE_KILL: &str = "tree_kill";
    /// The cutoff holds with the engine stopped (the minimum contract).
    pub const CUTOFF_WITHOUT_ENGINE: &str = "cutoff_without_engine";
    /// The node knows when the tree is empty (the minimum contract).
    pub const EMPTINESS: &str = "emptiness";
    pub const MEMORY_CAP: &str = "memory_cap";
    pub const CPU_CAP: &str = "cpu_cap";
    pub const FILE_WALL: &str = "file_wall";
    pub const NETWORK_CLOSED: &str = "network_closed";
    pub const DEVICE_CLOSURE: &str = "device_closure";
    pub const PROCESSES_HIDDEN: &str = "processes_hidden";
    pub const WRITE_RATE_CAP: &str = "write_rate_cap";

    /// The three bounds without which a machine offers no jobs (pass 34,
    /// invariants I4 and I5).
    pub const MINIMUM_CONTRACT: [&str; 3] = [TREE_KILL, CUTOFF_WITHOUT_ENGINE, EMPTINESS];

    /// Every bound, in report order: the node file's list, which a
    /// template's `require` is checked against.
    pub use crate::gpu_execution_node::node_settings::SCOPE_BOUND_NAMES as ALL;

    /// The bounds a template requires when it names none (pass 34, 2.2):
    /// the two that keep a workload out of the vault and off the network.
    pub use crate::gpu_execution_node::node_settings::REQUIRED_BOUNDS_DEFAULT as REQUIRED_DEFAULT;
}

/// How strongly a bound holds: the operating system enforces it with no
/// process of ours alive (`Kernel`), a privileged process that is not the
/// engine does (`Supervised`), or nothing proved it (`None`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundStrength {
    None,
    Supervised,
    Kernel,
}

/// One bound's strength with one line of evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundProof {
    pub strength: BoundStrength,
    pub evidence: String,
}

impl BoundProof {
    #[must_use]
    pub fn kernel(evidence: impl Into<String>) -> Self {
        Self {
            strength: BoundStrength::Kernel,
            evidence: evidence.into(),
        }
    }

    #[must_use]
    pub fn none(evidence: impl Into<String>) -> Self {
        Self {
            strength: BoundStrength::None,
            evidence: evidence.into(),
        }
    }

    /// Whether the bound holds at all.
    #[must_use]
    pub fn holds(&self) -> bool {
        self.strength != BoundStrength::None
    }
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
    /// The bounds the template requires (pass 34, 2.2).
    pub require: Vec<String>,
}

/// What `job-exec` proved from inside the unit, before the workload exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeReport {
    pub instance: String,
    /// Each bound `job-exec` can prove from inside, by name.
    pub proofs: BTreeMap<String, BoundProof>,
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
    pub configured: BTreeMap<String, BoundProof>,
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
    pub at_boot_ns: u64,
}

/// The cutoff's mark (root): the timer stopped the unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutoffMark {
    pub instance: String,
    pub fired_boot_ns: u64,
}

/// The receipt's scope facts for one key, from the root records: the bounds
/// the template required as `job-exec` proved them inside the unit, the rest
/// as the unit's effective properties gave them, each with its strength
/// (`fence` lists `<bound>=<strength>` for every bound; a bound proved only
/// by configuration says `configured`).
#[must_use]
pub fn scope_facts(prepared: &PreparedRecord, scope: Option<&ScopeRecord>) -> ScopeFacts {
    let proved = scope.and_then(|record| record.report.as_ref());
    let mut fence = Vec::new();
    for name in bound::ALL {
        let inside = proved.and_then(|report| report.proofs.get(name));
        let line = match (inside, prepared.configured.get(name)) {
            (Some(proof), _) => format!("{name}={}", strength_word(proof.strength)),
            (None, Some(proof)) if proof.holds() => {
                format!("{name}={} configured", strength_word(proof.strength))
            }
            _ => format!("{name}=none"),
        };
        fence.push(line);
    }
    let namespaces = ["mount", "network", "ipc"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    ScopeFacts {
        kind: ScopeClass::Host,
        account: prepared.account.clone(),
        devices: prepared.devices.clone(),
        namespaces,
        fence,
    }
}

fn strength_word(strength: BoundStrength) -> &'static str {
    match strength {
        BoundStrength::Kernel => "kernel",
        BoundStrength::Supervised => "supervised",
        BoundStrength::None => "none",
    }
}
