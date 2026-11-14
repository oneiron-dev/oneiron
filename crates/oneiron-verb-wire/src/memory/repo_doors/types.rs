//! Moved from `crates/oneiron/src/memory/repo_doors/types.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::codebase_doors::types::CodeSnapshotDefinition;
use crate::memory::codebase_doors::types::CodeSnapshotFile;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::merge_queue::driver_types::QueueDriveStatus;
use oneiron_store::merge_queue::types::BatchState;
use oneiron_store::repo_proposal_record::RepoProposalStatus;
use serde::Deserialize;
use serde::Serialize;

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
    /// Why the caller needs this marked file's real bytes (FIX 7608,
    /// CALL 3): absent reads the masked copy as before; a why from a proven
    /// agent asks the owner for this file's stored bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

/// `self.code.merge_queue.observe`: the queue its own work is pinned under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoMergeQueueObserveInput {
    pub work: EntityId,
}

/// `self.code.symbols.declare` (FIX 6867, G1 PR2b): declares current
/// symbols of the run's own work's repo, on paths the Grant edits, for the
/// run's TASK, under a fresh declaration id. An overlap waits; it is never
/// refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoSymbolsDeclareInput {
    pub work: EntityId,
    /// Current CODE_SYMBOL ids of the repo's stored symbol manifest.
    pub symbols: Vec<EntityId>,
    /// The hold's lifetime in seconds: required, positive and a safe JS
    /// integer. There is no default.
    pub ttl_seconds: u64,
}

/// `self.code.symbols.renew`: extends the run's own declaration by its
/// declared lifetime, keeping its id and whether it is held.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoSymbolsRenewInput {
    pub work: EntityId,
    /// The declaration id `self.code.symbols.declare` returned.
    pub declaration: EntityId,
}

/// `self.code.symbols.release`: removes the run's own declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoSymbolsReleaseInput {
    pub work: EntityId,
    pub declaration: EntityId,
}

/// `self.code.symbols.observe`: reads the run's own current declaration for
/// its TASK, held or waiting, with what it waits behind now. It renews,
/// releases, declares and schedules nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoSymbolsObserveInput {
    pub work: EntityId,
}

/// `self.code.proposal_submit`: one whole-file change against the run's own
/// work, kept as an immutable Proposed proposal at the work's pinned base.
/// Nothing lands, is approved or is queued here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoProposalSubmitInput {
    pub work: EntityId,
    /// The normalized repo-relative path of the one file; an editable glob
    /// must match it.
    pub path: String,
    /// The new file bytes.
    pub content: Vec<u8>,
    pub message: String,
    /// The run's current declaration, when it names one. Its TASK's current
    /// declaration is bound either way; naming another is a stale lease.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declaration: Option<EntityId>,
    /// The failed proposal this change replaces (FIX 4364), if any: one the
    /// run's lane reads, of the same repository, that a terminal queue batch
    /// quarantined or rolled back, or whose standalone attempt failed. The
    /// new proposal is fresh and is reviewed and queued anew; the run needs
    /// no part in the source, and gains no authority from it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair_of: Option<EntityId>,
}

/// `self.code.proposal_resolve`: one file resolving a typed repo conflict,
/// proposed against the run's own pinned work. Review and landing are separate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoProposalResolveInput {
    pub work: EntityId,
    pub branch_subject: EntityId,
    pub conflict: EntityId,
    pub branch: String,
    /// The normalized repo-relative path of one conflicted file.
    pub path: String,
    pub content: Vec<u8>,
    pub message: String,
    /// The current run declaration, under the same rules as proposal_submit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declaration: Option<EntityId>,
}

/// `self.code.merge_queue.enqueue`: queues the run's own stored proposals
/// of one work as one batch, under the declaration they were made under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoMergeQueueEnqueueInput {
    pub work: EntityId,
    /// The proposal ids `self.code.proposal_submit` returned, in order.
    pub proposals: Vec<EntityId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declaration: Option<EntityId>,
}

/// One snapshot of the admitted repo, filtered to the paths the run reads.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
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

/// `self.code.snapshots.read`'s answer: one frozen file, read from its
/// stored blob.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoSymbolsDefinitionsOutput {
    pub repo: EntityId,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub snapshot: String,
    pub definitions: Vec<CodeSnapshotDefinition>,
}

/// One work of the run's own: a private view at its queue's green commit.
/// No host path is shown.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoWorkFile {
    pub path: String,
    /// The BLAKE3 hash of the file's bytes, 64 lower-hex characters.
    pub content_hash_blake3: String,
    /// How the work's copy differs from the stored blob it stands in for,
    /// as the snapshot doors name it (FIX 8965): absent for the stored
    /// bytes, and for every unmarked file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection: Option<crate::origin::secret_projection::types::RepoFileProjectionView>,
}

/// `self.code.views.read`'s answer: the file's bytes in the run's work.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoViewsReadOutput {
    pub work: EntityId,
    pub path: String,
    pub bytes: Vec<u8>,
    /// The SHA-256 of exactly these bytes, 64 lower-hex characters.
    pub sha256: String,
}

/// `self.code.merge_queue.observe`'s answer: the queue the work is pinned
/// under, as raw Git commits.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
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
    /// The queue entries accepted from this work, with what each waits
    /// behind now (FIX 6867, G1 PR2b). No other run's entry is shown.
    pub entries: Vec<RepoQueueEntryView>,
}

/// The green reconciliation successor that carried a run's superseded
/// queue entry, as the run reads it (QUEUE Q1 = A).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepoQueueSuccessor {
    /// The successor batch id, 64 lower-hex characters: the run's lane
    /// reads the successor's own completion receipt.
    Batch(String),
    /// Another batch, which the run's lane does not read; no id is shown.
    AnotherBatch,
}

/// One of the run's own queue entries: a batch of its exact proposals.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoQueueEntryView {
    /// The batch id, 64 lower-hex characters.
    pub batch: String,
    pub work: EntityId,
    pub proposals: Vec<EntityId>,
    /// The run's declaration it was accepted under, if any.
    pub declaration: Option<EntityId>,
    #[schemars(with = "String")]
    pub state: BatchState,
    /// Where the automatic driver stands on it, from the same stored batch
    /// as `state`: `unenrolled` on a queue no checked init enrolls, else a
    /// typed hold such as `waiting_symbols` or `held_needs_new_base`, or
    /// `driving` / `done` / `superseded`. Its last stored status, so it can
    /// trail the live `blockers` until the driver's next pass. No reason
    /// text, conflict or other run's proposal is shown.
    #[schemars(with = "String")]
    pub drive: QueueDriveStatus,
    /// Once `state` is `Superseded`: what carried its change, never landed
    /// itself (QUEUE Q1 = A). The green successor batch only when the run's
    /// lane reads that successor's own completion receipt, else
    /// `another_batch`.
    pub superseded_by: Option<RepoQueueSuccessor>,
    pub base_green: String,
    pub expected_head: String,
    pub landed_head: Option<String>,
    /// The TASKs whose live declarations it waits behind now; empty once it
    /// may stage. Order only, never a refusal.
    pub blockers: Vec<EntityId>,
    /// Its `repo.queue_admission` receipt (FIX 4338): the stored fact that
    /// the queue accepted this entry, a waiting one included. The batch id
    /// and the queue sequence are not it.
    pub admission_receipt: Option<EntityId>,
    /// Its `repo.queue_completion` receipt once terminal: green advanced,
    /// rolled back, quarantined, cancelled or superseded. A landed head is
    /// not one.
    pub completion_receipt: Option<EntityId>,
    /// The `repo.proposal_admission` receipt of each of its proposals the
    /// run's lane reads, in batch order, as its queue admission bound them.
    pub proposal_admission_receipts: Vec<EntityId>,
}

/// A run's symbol declaration, as the engine holds it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoSymbolDeclarationView {
    pub work: EntityId,
    /// The declaration id the run names it by: fresh at each declaration,
    /// kept by a renewal.
    pub declaration: EntityId,
    pub task: EntityId,
    pub symbols: Vec<EntityId>,
    /// Engine host time plus the declared lifetime, in Unix seconds.
    pub expires_at: u64,
    /// False while it waits behind an overlapping live declaration.
    pub held: bool,
    /// The TASKs whose live overlapping declarations it waits behind, as
    /// they hold at the call that answers; empty when held, and on a
    /// renewal. A waiting declaration whose blockers have all gone stays
    /// waiting until it is declared again.
    pub blockers: Vec<EntityId>,
}

/// `self.code.symbols.release`'s answer: the declaration it removed.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoSymbolsReleaseOutput {
    pub work: EntityId,
    pub declaration: EntityId,
    pub task: EntityId,
}

/// `self.code.proposal_submit`'s answer: the immutable proposal, as stored.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoProposalSubmitOutput {
    /// The engine-minted proposal id.
    pub proposal: EntityId,
    /// Its `repo.proposal_admission` receipt (FIX 4338): the stored fact
    /// that the engine admitted this candidate into custody. It is not a
    /// queue admission.
    pub admission_receipt: EntityId,
    pub work: EntityId,
    pub path: String,
    /// The green commit the proposal is pinned at, 40 lower-hex characters.
    pub base_green: String,
    /// The retained pre-action base hash, 64 lower-hex characters.
    pub base_snapshot: String,
    /// The actor's session and the gated `repo.provenance` claim the host
    /// minted for it: attribution, not authority.
    pub session: EntityId,
    pub provenance_claim: EntityId,
    /// The run's declaration bound with it, if it had one.
    pub declaration: Option<EntityId>,
    /// `Proposed` at submission.
    pub status: RepoProposalStatus,
}
