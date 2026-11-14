//! The native check record (ARCH-0068 #rc5-check-reuse, FIX
//! [L4-30-CHECK-REUSE-RECORD]): one check a run recorded in its own checkout.
//!
//! An attempt receipt may carry a check record. It names the producer, the
//! native command and its output, and the observed pass. It also names the
//! request revision and the scoped input versions. The engine captures every
//! input version it can see before the command starts and compares them again
//! after it ends; the agent never supplies them. Reuse needs every input
//! pinned; this module only records (PR 3 reuses).
//!
//! Environment values are never stored: the record keeps the sorted names and
//! the digest of the whole map only. Toolchain values are stored. The record
//! states its limits through [`CHECK_RECORD_LIMITS`], shown by the owner read,
//! never stored.

pub(crate) mod tables;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::attempt_queue::AttemptId;
use crate::side_table::{Named, SideTable};
use crate::store::attempt_result::AttemptResultRef;
use crate::store::contract_oracle::invalid;

/// The four canon limits a check record states: shown by the owner read, never stored.
pub const CHECK_RECORD_LIMITS: [&str; 4] = [
    "undeclared_inputs",
    "outside_state",
    "transient_writes",
    "relocation",
];

/// What the producer states as declared: the toolchain and the environment names it named.
pub const CHECK_RECORD_DECLARED: [&str; 2] = ["toolchain", "environment"];

/// One native check a run recorded in its own checkout, by attempt then check id.
pub(crate) const CHECK_RECORDS: SideTable<(AttemptId, EntityId), AttemptCheckRecord, Named> =
    SideTable::new(&crate::side_table::ATTEMPT_CHECK_RECORD);

/// The run that produced a native check, stamp-style (as `RepoRunStamp`): the
/// leased try, the executor run, the TASK and the PROJECT. Evidence the finish
/// compares with its own binding, never a lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckProducer {
    pub attempt: AttemptId,
    pub generation: u32,
    pub executor_run: EntityId,
    pub task: EntityId,
    pub project: EntityId,
}

/// The input versions the engine captured around a native check: HEAD's tree
/// when the worktree was clean (else the tree is unpinned), the command,
/// toolchain and environment digests, and the TASK's request revision. Stored
/// in the record and answered as is by the run doors and the owner read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CheckInputVersions {
    /// HEAD's tree oid hex when the worktree was clean; `None` when the tree is not pinned.
    pub tree: Option<String>,
    /// The blake3 of the command argv.
    pub command_digest: String,
    /// The blake3 of the whole toolchain map.
    pub toolchain_digest: String,
    /// The blake3 of the whole environment map, values included.
    pub environment_digest: String,
    /// The TASK's revision when captured.
    pub request_revision: u64,
}

/// What `finish` captured again: the tree and the request revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CheckAfter {
    /// HEAD's tree oid hex when the worktree was clean; `None` when the tree is not pinned.
    pub tree: Option<String>,
    /// The TASK's revision when captured.
    pub request_revision: u64,
}

/// One native check a run recorded in its own checkout (ARCH-0068 RC5), minted by the engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptCheckRecord {
    /// The engine-minted check id.
    pub check: EntityId,
    pub producer: CheckProducer,
    /// The CODE anchor the run was admitted to.
    pub repo: EntityId,
    /// The full Git ref the run edits through this checkout.
    pub git_ref: String,
    /// The checkout id, 32 lower-hex characters.
    pub checkout: String,
    /// The live lease epoch.
    pub epoch: u64,
    /// The native command, argv in order.
    pub command: Vec<String>,
    /// The declared toolchain, names to stored values.
    pub toolchain: BTreeMap<String, String>,
    /// The declared environment names, sorted; values are never stored.
    pub environment_names: Vec<String>,
    /// Whether the check depends on the world outside the checkout; a world check is never reused.
    pub world: bool,
    /// The input versions captured before the command ran.
    pub inputs: CheckInputVersions,
    /// What the finish observed; `None` while the check runs.
    pub finish: Option<CheckFinish>,
}

/// What a finished check observed: the captured-again inputs, the exit status,
/// the output, and the observed pass and stability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckFinish {
    pub after: CheckAfter,
    /// The command's exit status; `None` when a signal ended it.
    pub exit_status: Option<i32>,
    /// The stored artifact version holding the command's output.
    pub output: AttemptResultRef,
    /// The observed pass: the command exited zero.
    pub passed: bool,
    /// The inputs held still: a pinned tree, unchanged across the run, on the
    /// same request revision.
    pub stable: bool,
}

impl CheckInputVersions {
    /// Captures the input versions: the tree as observed, the command,
    /// toolchain and environment digests, and the request revision.
    ///
    /// # Errors
    /// An encoding failure.
    pub(crate) fn capture(
        command: &[String],
        toolchain: &BTreeMap<String, String>,
        environment: &BTreeMap<String, String>,
        tree: Option<String>,
        request_revision: u64,
    ) -> crate::Result<Self> {
        Ok(Self {
            tree,
            command_digest: part_digest(COMMAND_DIGEST_TAG, command)?,
            toolchain_digest: part_digest(TOOLCHAIN_DIGEST_TAG, toolchain)?,
            environment_digest: part_digest(ENVIRONMENT_DIGEST_TAG, environment)?,
            request_revision,
        })
    }
}

impl CheckFinish {
    /// Observes a finished check: `passed` is exit zero; `stable` is a pinned
    /// tree unchanged across the run on the same request revision.
    pub(crate) fn observe(
        after: CheckAfter,
        exit_status: Option<i32>,
        output: AttemptResultRef,
        inputs: &CheckInputVersions,
    ) -> Self {
        Self {
            passed: exit_status == Some(0),
            stable: inputs.tree.is_some()
                && after.tree == inputs.tree
                && after.request_revision == inputs.request_revision,
            after,
            exit_status,
            output,
        }
    }
}

/// The digest tags: one domain per part, as `QueueCheckInputs::digest` separates its own.
const COMMAND_DIGEST_TAG: &str = "oneiron:check-record-command:v1";
const TOOLCHAIN_DIGEST_TAG: &str = "oneiron:check-record-toolchain:v1";
const ENVIRONMENT_DIGEST_TAG: &str = "oneiron:check-record-environment:v1";

/// The one domain-separated canonical hash of one inputs part.
fn part_digest(tag: &str, value: &impl Serialize) -> crate::Result<String> {
    let bytes = rmp_serde::to_vec_named(&(tag, value))
        .map_err(|_| invalid("check record digest encoding failed"))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}
