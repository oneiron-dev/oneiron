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

use crate::EntityId;
use crate::build_cache::command_spec::CodeBuildSpec;
use crate::error::Result;
use crate::store::attempt_id::AttemptId;
use crate::store::contract_oracle::invalid;

#[doc(hidden)]
pub use oneiron_records::merge_queue::check_inputs::{
    QUEUE_CHECK_CANDIDATE_PREFIX, QueueCheckEnvironment, QueueCheckFile, QueueCheckHold,
    QueueCheckHoldReason, QueueCheckLimits, QueueCheckNeed, QueueCheckOutputRef, QueueCheckRun,
    QueueCheckTarget, QueueCommandReceipt,
};

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
    /// BEFORE-hostexecute snapshot of the served CODE's read scope: the
    /// repo row's actual raw bytes through `scope_for_blob`. `None` when
    /// the row is absent. Frozen at the `new_receipt` producer, ORIGINAL
    /// through finish; never re-read from CURRENT config. Skipped from
    /// the digest wire so the candidate key stays byte-stable.
    #[serde(skip)]
    pub(super) input_scope: Option<crate::federation::Scope>,
    /// BEFORE-hostexecute snapshot of the served CODE's forward taint
    /// refs (`exhaust_taint_refs_in_txn`); empty is Clean. Frozen at the
    /// `new_receipt` producer, ORIGINAL through finish. Refs only, never
    /// a derived state (S7: state is derived on every read). Skipped from
    /// the digest wire so the candidate key stays byte-stable.
    #[serde(skip)]
    pub(super) input_taint: Vec<crate::secret_lease::SecretTaintRef>,
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
pub struct QueueCheckReceipt<Exhaust = Vec<u8>> {
    pub inputs_digest: String,
    pub inputs: QueueCheckInputs,
    /// The original approver frozen with the configuration used for this run.
    /// Author data only; it grants no new command or content-write authority.
    pub recorded_actor: EntityId,
    /// Runtime-only proof from the exact configuration this execution used.
    /// The finish writer closes it over the actual returned outputs.
    #[serde(skip)]
    pub(super) completion_approval: Option<crate::consent::QueuedCheckApproval>,
    pub attempt: AttemptId,
    pub attempt_count: u32,
    pub lease_owner: String,
    pub generation: u32,
    pub run: Option<QueueCheckRun<Exhaust>>,
    pub hold: Option<QueueCheckHold>,
    pub need: Option<QueueCheckNeed>,
    /// The earlier receipt digest this one reuses, when it ran nothing.
    pub reused_from: Option<String>,
    pub tests_passed: Option<bool>,
    pub verdict_ref: Option<String>,
}

/// A persisted receipt retains output version references, never command bytes.
pub type StoredQueueCheckReceipt = QueueCheckReceipt<QueueCheckOutputRef>;

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
