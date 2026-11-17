//! Moved from `crates/oneiron/src/merge_queue/check_inputs.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::merge_queue::types::CheckPhase;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// The candidate-key prefix of a verdict a bound queue check recorded. An
/// older verdict, recorded by the low-level callback path, has none.
pub const QUEUE_CHECK_CANDIDATE_PREFIX: &str = "queue-check:v1:";

/// What one check runs on: the approved baseline, or one staged path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueueCheckTarget {
    Baseline {
        commit: String,
        tree: String,
        phase: CheckPhase,
    },
    /// A fast check names the speculative commit; a slow check the landed one.
    Candidate {
        batch: String,
        mask: u64,
        phase: CheckPhase,
        commit: String,
        tree: String,
    },
}

impl QueueCheckTarget {
    #[must_use]
    pub fn phase(&self) -> CheckPhase {
        match self {
            Self::Baseline { phase, .. } | Self::Candidate { phase, .. } => *phase,
        }
    }

    #[must_use]
    pub fn commit(&self) -> &str {
        match self {
            Self::Baseline { commit, .. } | Self::Candidate { commit, .. } => commit,
        }
    }

    #[must_use]
    pub fn tree(&self) -> &str {
        match self {
            Self::Baseline { tree, .. } | Self::Candidate { tree, .. } => tree,
        }
    }
}

/// One guest's resolved resource limits, as the executor applies them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueCheckLimits {
    pub memory_mib: u32,
    pub cpu_millis: u32,
    pub pids: u32,
    pub tmpfs_mib: u32,
}

/// The effective executor a check runs under, as the host resolved it:
/// actual values, inherited defaults included, never settings labels alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueCheckEnvironment {
    /// `isolated` or `host`: the setting the operator chose.
    pub backend: String,
    /// The executor the host selected: the isolated backend's own name, or
    /// `host`.
    pub executor: String,
    pub runtime: Option<String>,
    /// The pinned image, for an isolated executor.
    pub image: Option<String>,
    /// The trusted helper's argv.
    pub helper: Vec<String>,
    /// Immutable toolchain identities the operator pinned.
    pub toolchain: BTreeMap<String, String>,
    /// `None` on the host, which applies no guest limits.
    pub limits: Option<QueueCheckLimits>,
    pub network: String,
    pub os: String,
    pub arch: String,
}

/// One native command's actual result. A command a signal ended has no
/// exit status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(deserialize = "Exhaust: Deserialize<'de>"))]
pub struct QueueCommandReceipt<Exhaust = Vec<u8>> {
    pub argv: Vec<String>,
    pub status: Option<i32>,
    pub signal: Option<i32>,
    pub stdout: Exhaust,
    pub stderr: Exhaust,
    /// The bytes of each output file the command declared that it left,
    /// by its declared path (FIX 7235); a declared file it did not leave
    /// is absent.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub declared_outputs: BTreeMap<String, Exhaust>,
}

impl<Exhaust> QueueCommandReceipt<Exhaust> {
    /// Whether this phase command passed: it exited, with status zero.
    #[must_use]
    pub fn exited_zero(&self) -> bool {
        self.status == Some(0)
    }
}

/// What a completed execution observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueCheckRun<Exhaust = Vec<u8>> {
    /// The phase commands in plan order; the run stops after the first that
    /// does not exit zero.
    pub commands: Vec<QueueCommandReceipt<Exhaust>>,
    pub contract_outputs: BTreeMap<String, QueueCommandReceipt<Exhaust>>,
    /// The isolated session's manifest and fence proof; `None` on the host.
    pub session: Option<oneiron_container::SessionManifest>,
    /// The executor's digest of the input files before and after the
    /// commands ran. They must agree.
    pub input_before: String,
    pub input_after: String,
}

/// Why a check was held: no verdict, the work kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueCheckHoldReason {
    /// The executor stopped before a terminal status: the host stopped, the
    /// guest ended or its session was abandoned.
    Interrupted,
    /// The executor could not start on a provisioned host.
    ExecutorUnavailable,
    /// A command could not be satisfied offline: a tool or input the image
    /// lacks.
    MissingOfflineInput,
    /// The inputs changed while the check ran.
    UnstableInputs,
    /// The owner's queued approval no longer holds.
    Authority,
    /// The staged path this check needs is gone; rematerialization is G2 PR2.
    TreeUnavailable,
    /// The queue refused the work in its current state, as its own doors
    /// would: a changed batch, a moved head or a missing row.
    Refused,
}

/// A held check's typed reason and what it names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueCheckHold {
    pub reason: QueueCheckHoldReason,
    pub detail: String,
}

impl QueueCheckHold {
    #[must_use]
    pub fn new(reason: QueueCheckHoldReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }
}

/// Configuration a check needs before it can run: the setting keys it names
/// and why. The work is kept; nothing goes green.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueCheckNeed {
    pub keys: Vec<String>,
    pub reason: String,
}

impl QueueCheckNeed {
    #[must_use]
    pub fn new(keys: &[&str], reason: impl Into<String>) -> Self {
        Self {
            keys: keys.iter().map(|key| (*key).to_owned()).collect(),
            reason: reason.into(),
        }
    }
}

/// One immutable native artifact version holding an execution output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueCheckOutputRef {
    pub artifact_id: EntityId,
    pub version: u64,
    pub content_hash: [u8; 32],
}

/// One file of a pinned tree: its path bytes, Git mode and blob id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueCheckFile {
    pub path: Vec<u8>,
    pub mode: u32,
    pub oid: String,
}
