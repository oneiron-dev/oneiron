//! The run repo doors' closed inputs and per-row outputs (FIX 6867, G1 PR2a),
//! and the run stamp a run's own work keeps. No input names an actor, a
//! holder, a TASK, a session, a lease, a server path or a base: the host
//! binding supplies each of those.

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::attempt_queue::AttemptId;
use crate::memory::codebase_doors::{CodeSnapshotDefinition, CodeSnapshotFile};

/// `self.code.snapshots.get`: the manifest of one snapshot of the admitted
/// repo, at the commit its full ref names now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoSnapshotsGetInput {
    /// The CODE anchor the run's Grant admits.
    pub repo: EntityId,
    /// The full Git ref name (`refs/heads/main`).
    #[serde(rename = "ref")]
    pub git_ref: String,
    /// The snapshot's fork hash, 64 lower-hex characters. A selector, not
    /// authority: it names a snapshot of the ref's current commit or none.
    pub snapshot: String,
}

/// `self.code.snapshots.read`: one file of such a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoSnapshotsReadInput {
    pub repo: EntityId,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub snapshot: String,
    /// The normalized repo-relative path; a readable glob must match it.
    pub path: String,
}

/// `self.code.symbols.definitions`: exact-name Rust definitions in such a
/// snapshot, on readable paths only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoSymbolsDefinitionsInput {
    pub repo: EntityId,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub snapshot: String,
    /// The exact symbol name.
    pub name: String,
}

/// `self.code.views.get`: the run's own work, as it was opened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoViewsGetInput {
    /// The work id `self.code.work.open` returned to this run.
    pub work: EntityId,
}

/// `self.code.views.read`: one file of the run's own work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoViewsReadInput {
    pub work: EntityId,
    pub path: String,
}

/// `self.code.merge_queue.observe`: the queue its own work is pinned under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoMergeQueueObserveInput {
    pub work: EntityId,
}

/// `self.code.snapshots.ingest`: imports the commit the admitted repo's full
/// ref names now, readable paths only. The repo's folder is the stored
/// anchor's; no folder comes from the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoSnapshotsIngestInput {
    pub repo: EntityId,
    #[serde(rename = "ref")]
    pub git_ref: String,
}

/// `self.code.work.open`: a fresh private working set of the admitted repo
/// at its queue's green commit, readable paths only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoWorkOpenInput {
    pub repo: EntityId,
    #[serde(rename = "ref")]
    pub git_ref: String,
}

/// One snapshot of the admitted repo, filtered to the paths the run reads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoSnapshotView {
    /// The CODE anchor the run was admitted to.
    pub repo: EntityId,
    #[serde(rename = "ref")]
    pub git_ref: String,
    /// The commit the ref named, 40 lower-hex characters.
    pub commit: String,
    /// The snapshot's fork hash, 64 lower-hex characters.
    pub snapshot: String,
    /// The CODE_ARTIFACT that holds the snapshot.
    pub artifact: EntityId,
    pub files: Vec<CodeSnapshotFile>,
}

/// `self.code.snapshots.get`'s answer.
pub type RepoSnapshotsGetOutput = RepoSnapshotView;

/// `self.code.snapshots.ingest`'s answer: the snapshot it stored.
pub type RepoSnapshotsIngestOutput = RepoSnapshotView;

/// `self.code.snapshots.read`'s answer: one frozen file, read from its
/// stored blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoSnapshotsReadOutput {
    pub repo: EntityId,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub snapshot: String,
    pub file: CodeSnapshotFile,
    /// The file text, strict UTF-8.
    pub content: String,
    /// The SHA-256 of exactly these bytes, 64 lower-hex characters.
    pub text_sha256: String,
}

/// `self.code.symbols.definitions`'s answer, in manifest order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoSymbolsDefinitionsOutput {
    pub repo: EntityId,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub snapshot: String,
    pub definitions: Vec<CodeSnapshotDefinition>,
}

/// One work of the run's own: a private view at its queue's green commit.
/// No host path is shown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoWorkView {
    /// The work id: the view's own id, minted fresh at each open.
    pub work: EntityId,
    pub repo: EntityId,
    #[serde(rename = "ref")]
    pub git_ref: String,
    /// The green commit the work is pinned at, 40 lower-hex characters.
    pub base_green: String,
    /// The pinned base snapshot's hash, 64 lower-hex characters.
    pub base_snapshot: String,
    /// The view's fork hash over its files, 64 lower-hex characters.
    pub fork_hash: String,
    /// The files the work holds.
    pub files: Vec<RepoWorkFile>,
}

/// One file of a run's work: its path and its bytes' identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoWorkFile {
    pub path: String,
    /// The BLAKE3 hash of the file's bytes, 64 lower-hex characters.
    pub content_hash_blake3: String,
}

/// `self.code.work.open`'s answer.
pub type RepoWorkOpenOutput = RepoWorkView;

/// `self.code.views.get`'s answer.
pub type RepoViewsGetOutput = RepoWorkView;

/// `self.code.views.read`'s answer: the file's bytes in the run's work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoViewsReadOutput {
    pub work: EntityId,
    pub path: String,
    pub bytes: Vec<u8>,
    /// The SHA-256 of exactly these bytes, 64 lower-hex characters.
    pub sha256: String,
}

/// `self.code.merge_queue.observe`'s answer: the queue the work is pinned
/// under, as raw Git commits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoMergeQueueObserveOutput {
    pub work: EntityId,
    pub repo: EntityId,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub base_green: String,
    pub head_commit: String,
    pub green_commit: String,
    /// Whether the queue's green has moved past the work's pin.
    pub green_moved: bool,
}

/// The run a work belongs to, bound in the receipt's first write (PREMISE
/// 2): the leased try, the executor run, the TASK, the repo and ref the
/// Grant admitted, and the pinned base. Evidence a later door compares with
/// its own binding, never a lease: no door rebuilds a host binding from it.
/// The actor is the receipt's own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoRunStamp {
    pub attempt: AttemptId,
    pub lease_owner: String,
    pub generation: u32,
    pub executor_run: EntityId,
    pub task: EntityId,
    pub project: EntityId,
    pub repo: EntityId,
    pub grant: EntityId,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub base_green: String,
    /// The pinned base snapshot's hash.
    pub base_snapshot: [u8; 32],
    /// The work id: the view id the stamp was bound with.
    pub work: EntityId,
}
