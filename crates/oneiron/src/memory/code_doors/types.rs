use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::code_document::CodeOpProvenance;
use crate::critic::LensCatalog;
use crate::repo_mutation::proposal::RepoProposalStatus;

/// Declares the code symbols one task will touch. The holder is the caller;
/// no request field names it, and the engine host clock sets the expiry.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeSymbolsDeclareRequest {
    /// An existing CODE_ARTIFACT, never a folder path.
    pub repo: EntityId,
    /// An existing TASK, the key the declaration is held under.
    pub task: EntityId,
    /// Current CODE_SYMBOL ids of the repository's stored symbol manifest.
    pub symbols: Vec<EntityId>,
    /// The lifetime of the hold, in seconds. Required: there is no default.
    pub ttl_seconds: u64,
}

/// One task's own symbol declaration. The task is the engine's lease key;
/// it is not a lease ref and carries no epoch.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeSymbolsTaskRequest {
    pub task: EntityId,
}

/// A stored symbol declaration, as the engine holds it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSymbolLeaseView {
    pub task: EntityId,
    /// The caller that declared it.
    pub holder: EntityId,
    pub symbols: Vec<EntityId>,
    /// Engine host time plus the declared lifetime, in Unix seconds.
    pub expires_at: u64,
    /// False while the declaration waits behind an overlapping live one.
    pub held: bool,
}

/// A declaration, granted or waiting. A waiting declaration is retained,
/// never refused; it grants no write, approval or landing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSymbolsDeclared {
    pub declaration: CodeSymbolLeaseView,
    /// The TASK ids whose live overlapping declarations it waits behind;
    /// empty when granted. Task refs, not proposal refs.
    pub blockers: Vec<EntityId>,
}

/// What a release did. It is not fenced by any lease generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSymbolsReleased {
    pub task: EntityId,
    /// False when the task held no declaration.
    pub released: bool,
}

/// Stages one ordinary file change of a repository as a proposal. Nothing
/// lands; review and the existing landing gate decide that later.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeProposalSubmitRequest {
    /// An existing CODE_ARTIFACT, whose stored repo_ref pins the base commit.
    pub repo: EntityId,
    /// An existing SESSION. Attribution, not authority.
    pub session: EntityId,
    /// An existing active `repo.provenance` CLAIM.
    pub provenance_claim: EntityId,
    /// Repository-relative path of the one file.
    pub path: String,
    /// The new file bytes.
    pub content: Vec<u8>,
    pub message: String,
    /// The turn, activity, intent and model behind the change, each a
    /// readable record when present. Absent fields stay unrecorded.
    pub op_provenance: CodeOpProvenance,
    /// The owner's review policy for this proposal: the lenses it must pass.
    /// A policy, not a verdict.
    pub catalog: LensCatalog,
}

/// The staged proposal, as the engine stored it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeProposalSubmitted {
    /// The engine-minted proposal id, the `repo.proposed_diff` claim. Not a
    /// queue entry or a receipt.
    pub proposal: EntityId,
    pub repo: EntityId,
    /// The caller, stamped by the engine.
    pub actor: EntityId,
    pub session: EntityId,
    pub provenance_claim: EntityId,
    /// The retained pre-action fork hash the proposal is reviewed against:
    /// 64 lower-hex BLAKE3, not a git commit.
    pub base: String,
    /// `Proposed` at submission.
    pub status: RepoProposalStatus,
}

/// One repository, by its CODE_ARTIFACT.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeRepoRequest {
    pub repo: EntityId,
}

/// The durable repository mutation log, in sequence order. It records
/// mutations the engine prepared or ran; a pending proposal is not in it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeMutationLog {
    pub repo: EntityId,
    pub entries: Vec<CodeMutationEntry>,
}

/// Where one mutation stands, as its oplog row records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeMutationState {
    Prepared,
    Applied,
    Failed,
}

/// One oplog row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeMutationEntry {
    /// The engine's canonical repo_ref.
    pub repo_ref: String,
    pub seq: u64,
    pub operation_kind: String,
    pub operation_subject: Option<String>,
    /// None when the engine recorded no actor, or once that actor was erased
    /// (FIX 3520).
    pub actor: Option<EntityId>,
    pub session: Option<EntityId>,
    pub started_at_ms: u64,
    pub finished_at_ms: Option<u64>,
    /// 64 lower-hex BLAKE3 fork hashes.
    pub pre_action_fork_hash: String,
    pub expected_post_action_fork_hash: Option<String>,
    pub status: CodeMutationState,
    pub failure: Option<String>,
}
