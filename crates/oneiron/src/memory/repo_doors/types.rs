//! The run repo doors' closed inputs and per-row outputs (FIX 6867, G1 PR2a),
//! and the run stamp a run's own work keeps. No input names an actor, a
//! holder, a TASK, a session, a lease, a server path or a base: the host
//! binding supplies each of those.

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::attempt_queue::AttemptId;
use crate::memory::codebase_doors::{CodeSnapshotDefinition, CodeSnapshotFile};
use crate::merge_queue::{BatchState, QueueDriveStatus};
use crate::origin::RepoPortableId;
use crate::store::repo_proposal_record::RepoProposalStatus;

/// `self.code.snapshots.get`: the manifest of one snapshot of the admitted
/// repo, at the commit its full ref names now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoSnapshotsGetInput {
    /// The CODE anchor used when the portable selector is absent or unknown.
    pub repo: EntityId,
    /// Portable repo id (64 lowercase hex digits). Resolves before admission;
    /// an unknown id uses `repo` instead. The selector grants no authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub portable_repo: Option<RepoPortableId>,
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
    /// The CODE anchor used when the portable selector is absent or unknown.
    pub repo: EntityId,
    /// Portable repo id (64 lowercase hex digits). Resolves before admission;
    /// an unknown id uses `repo` instead. The selector grants no authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub portable_repo: Option<RepoPortableId>,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub snapshot: String,
    /// The normalized repo-relative path; a readable glob must match it.
    pub path: String,
    /// Why the caller needs this marked file's real bytes (FIX 7608,
    /// CALL 3): absent reads the masked copy as before; a why from a proven
    /// agent asks the owner for this file's stored bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

/// `self.code.symbols.definitions`: exact-name Rust definitions in such a
/// snapshot, on readable paths only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoSymbolsDefinitionsInput {
    /// The CODE anchor used when the portable selector is absent or unknown.
    pub repo: EntityId,
    /// Portable repo id (64 lowercase hex digits). Resolves before admission;
    /// an unknown id uses `repo` instead. The selector grants no authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub portable_repo: Option<RepoPortableId>,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub snapshot: String,
    /// The exact symbol name.
    pub name: String,
}

#[doc(hidden)]
pub use oneiron_verb_wire::memory::repo_doors::types::{
    RepoMergeQueueEnqueueInput, RepoMergeQueueObserveInput, RepoMergeQueueObserveOutput,
    RepoProposalResolveInput, RepoProposalSubmitInput, RepoProposalSubmitOutput,
    RepoQueueEntryView, RepoQueueSuccessor, RepoSnapshotView, RepoSnapshotsReadOutput,
    RepoSymbolDeclarationView, RepoSymbolsDeclareInput, RepoSymbolsDefinitionsOutput,
    RepoSymbolsObserveInput, RepoSymbolsReleaseInput, RepoSymbolsReleaseOutput,
    RepoSymbolsRenewInput, RepoViewsGetInput, RepoViewsReadInput, RepoViewsReadOutput,
    RepoWorkFile, RepoWorkView,
};

/// `self.code.snapshots.ingest`: imports the commit the admitted repo's full
/// ref names now, readable paths only. The repo's folder is the stored
/// anchor's; no folder comes from the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoSnapshotsIngestInput {
    /// The CODE anchor used when the portable selector is absent or unknown.
    pub repo: EntityId,
    /// Portable repo id (64 lowercase hex digits). Resolves before admission;
    /// an unknown id uses `repo` instead. The selector grants no authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub portable_repo: Option<RepoPortableId>,
    #[serde(rename = "ref")]
    pub git_ref: String,
}

/// `self.code.work.open`: a fresh private working set of the admitted repo
/// at its queue's green commit, readable paths only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoWorkOpenInput {
    /// The CODE anchor used when the portable selector is absent or unknown.
    pub repo: EntityId,
    /// Portable repo id (64 lowercase hex digits). Resolves before admission;
    /// an unknown id uses `repo` instead. The selector grants no authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub portable_repo: Option<RepoPortableId>,
    #[serde(rename = "ref")]
    pub git_ref: String,
}

/// `self.code.snapshots.get`'s answer.
pub type RepoSnapshotsGetOutput = RepoSnapshotView;

/// `self.code.snapshots.ingest`'s answer: the snapshot it stored.
pub type RepoSnapshotsIngestOutput = RepoSnapshotView;

/// `self.code.work.open`'s answer.
pub type RepoWorkOpenOutput = RepoWorkView;

/// `self.code.views.get`'s answer.
pub type RepoViewsGetOutput = RepoWorkView;

/// `self.code.merge_queue.enqueue`'s answer: the accepted entry.
pub type RepoMergeQueueEnqueueOutput = RepoQueueEntryView;

/// `self.code.symbols.declare`'s answer.
pub type RepoSymbolsDeclareOutput = RepoSymbolDeclarationView;

/// `self.code.symbols.renew`'s answer.
pub type RepoSymbolsRenewOutput = RepoSymbolDeclarationView;

/// `self.code.symbols.observe`'s answer: the declaration as it is stored,
/// its id and expiry unchanged by the read.
pub type RepoSymbolsObserveOutput = RepoSymbolDeclarationView;

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
    /// The run's symbol declaration a proposal was made under (FIX 6867,
    /// G1 PR2b): `None` on a work's own stamp and on a proposal made with
    /// none.
    pub symbol_fence: Option<EntityId>,
}
