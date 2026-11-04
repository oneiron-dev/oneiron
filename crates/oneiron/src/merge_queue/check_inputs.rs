//! The exact inputs one queue check runs on, their one digest, the receipt a
//! run leaves and the host seam that runs it (FIX 6868).
//!
//! [`QueueCheckInputs::digest`] is the one canonical hash of everything a
//! check's result depends on: the store, the pinned target, the frozen plan,
//! the exact commands and the effective executor values, inherited defaults
//! included. It feeds both the stored receipt and the verdict's candidate
//! key ([`QueueCheckInputs::candidate_key`]); nothing hashes these inputs a
//! second way.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::CheckPhase;
use crate::EntityId;
use crate::attempt_queue::AttemptId;
use crate::contract_oracle::invalid;
use crate::error::Result;
use crate::memory::code_view_doors::CodeBuildSpec;

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

/// Everything one check's result depends on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueCheckInputs {
    /// The object store's hex identity.
    pub store: String,
    /// The CODE_ARTIFACT the queue serves.
    pub repo: EntityId,
    pub target: QueueCheckTarget,
    /// The contract baseline the verdict compares to; `None` while the
    /// baseline itself is checked.
    pub baseline_id: Option<String>,
    pub plan_digest: String,
    /// The phase's ordered native commands, exactly as the plan froze them.
    pub commands: Vec<CodeBuildSpec>,
    /// The shared contract-output commands, by contract name.
    pub contract_outputs: BTreeMap<String, CodeBuildSpec>,
    pub environment: QueueCheckEnvironment,
}

impl QueueCheckInputs {
    /// The one domain-separated canonical hash of these inputs.
    ///
    /// # Errors
    /// An encoding failure.
    pub fn digest(&self) -> Result<String> {
        let bytes = rmp_serde::to_vec_named(&("oneiron:queue-check-inputs:v1", self))
            .map_err(|_| invalid("queue check inputs encoding failed"))?;
        Ok(blake3::hash(&bytes).to_hex().to_string())
    }

    /// The verdict candidate these inputs bind: `queue-check:v1:<digest>`.
    ///
    /// # Errors
    /// An encoding failure.
    pub fn candidate_key(&self) -> Result<String> {
        Ok(format!("{QUEUE_CHECK_CANDIDATE_PREFIX}{}", self.digest()?))
    }

    /// Whether a completed receipt of the same digest may stand for a new
    /// run (CALL "new-plan validation"). A check on the host depends on the
    /// host's own state, so it is never reused; no freshness window exists.
    #[must_use]
    pub fn reusable(&self) -> bool {
        self.environment.backend == "isolated" && self.environment.network == "deny"
    }
}

/// One native command's actual result. A command a signal ended has no
/// exit status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueCommandReceipt {
    pub argv: Vec<String>,
    pub status: Option<i32>,
    pub signal: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// The bytes of each output file the command declared that it left,
    /// by its declared path (FIX 7235); a declared file it did not leave
    /// is absent.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub declared_outputs: BTreeMap<String, Vec<u8>>,
}

impl QueueCommandReceipt {
    /// Whether this phase command passed: it exited, with status zero.
    #[must_use]
    pub fn exited_zero(&self) -> bool {
        self.status == Some(0)
    }
}

/// What a completed execution observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueCheckRun {
    /// The phase commands in plan order; the run stops after the first that
    /// does not exit zero.
    pub commands: Vec<QueueCommandReceipt>,
    pub contract_outputs: BTreeMap<String, QueueCommandReceipt>,
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

/// What the host hands back. Only `Completed` carries results; a held or
/// unconfigured execution never manufactures a failed test.
#[derive(Debug, Clone)]
pub enum QueueCheckExecution {
    Completed(QueueCheckRun),
    Held(QueueCheckHold),
    NeedsConfiguration(QueueCheckNeed),
}

/// The receipt one check generation leaves: its inputs and digest, the
/// attempt lease it ran under, what it observed and the verdict it recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueCheckReceipt {
    pub inputs_digest: String,
    pub inputs: QueueCheckInputs,
    pub attempt: AttemptId,
    pub attempt_count: u32,
    pub lease_owner: String,
    pub generation: u32,
    pub run: Option<QueueCheckRun>,
    pub hold: Option<QueueCheckHold>,
    pub need: Option<QueueCheckNeed>,
    /// The earlier receipt digest this one reuses, when it ran nothing.
    pub reused_from: Option<String>,
    pub tests_passed: Option<bool>,
    pub verdict_ref: Option<String>,
}

/// One file of a pinned tree: its path bytes, Git mode and blob id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueCheckFile {
    pub path: Vec<u8>,
    pub mode: u32,
    pub oid: String,
}

/// The pinned tree a check runs on, read from Git objects by the engine:
/// never the live checkout, its `.git` link, config or hooks.
pub trait QueueCheckTreeSource {
    /// Every file of the tree, in path order. Submodule links are not files.
    ///
    /// # Errors
    /// An object store read failure.
    fn files(&self) -> Result<Vec<QueueCheckFile>>;

    /// One blob's exact bytes.
    ///
    /// # Errors
    /// An object store read failure.
    fn blob(&self, oid: &str) -> Result<Vec<u8>>;

    /// Hands `visit` each of `oids`' exact bytes in order, with its index;
    /// `visit` answers whether to read on. An object store reads them in
    /// bounded batches (FIX 7229); this default reads one at a time.
    /// `Ok(false)` when `visit` stopped the read.
    ///
    /// # Errors
    /// An object store read failure, or an error `visit` answered.
    fn blobs(
        &self,
        oids: &[&str],
        visit: &mut dyn FnMut(usize, &[u8]) -> Result<bool>,
    ) -> Result<bool> {
        for (index, oid) in oids.iter().enumerate() {
            if !visit(index, &self.blob(oid)?)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Hands `visit` the pinned `commit`'s commit object and every tree
    /// object under it, raw, each with its Git type: with the files' blobs,
    /// a fresh local-only object store for the guest (FIX 7228). `visit`
    /// answers whether to read on. The default ships none.
    ///
    /// # Errors
    /// An object store read failure, or a commit that names another tree.
    fn git_objects(
        &self,
        _commit: &str,
        _visit: &mut dyn FnMut(&str, &[u8]) -> Result<bool>,
    ) -> Result<bool> {
        Ok(true)
    }
}

/// One execution request: the target and its pinned tree.
pub struct QueueCheckInvocation<'a> {
    pub target: &'a QueueCheckTarget,
    pub tree: &'a dyn QueueCheckTreeSource,
}

/// The host seam that runs a queue check's commands. The isolated executor
/// is the default; the host child runs only on the operator's explicit
/// opt-in. Neither falls back to the other.
pub trait QueueCheckHost {
    /// The effective executor values a check would run under, or the
    /// configuration it needs first.
    ///
    /// # Errors
    /// A configuration need, naming its keys.
    fn environment(&mut self) -> std::result::Result<QueueCheckEnvironment, QueueCheckNeed>;

    /// Runs `inputs`' commands on the invocation's pinned tree. `stop` turns
    /// true when the host stops: the executor ends its guest or child and
    /// answers held.
    ///
    /// # Errors
    /// An engine failure; an executor that cannot run answers held or a
    /// configuration need instead.
    fn execute(
        &mut self,
        invocation: &QueueCheckInvocation<'_>,
        inputs: &QueueCheckInputs,
        stop: &dyn Fn() -> bool,
    ) -> Result<QueueCheckExecution>;
}
