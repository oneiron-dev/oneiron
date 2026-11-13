//! Moved from `crates/oneiron/src/memory/code_doors/types.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::critic_lens::LensCatalog;
use oneiron_store::repo_proposal_record::RepoProposalStatus;
use serde::Deserialize;
use serde::Serialize;

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

/// Stages one ordinary file change of a repository as a proposal. Nothing
/// lands; review and the existing landing gate decide that later. The
/// engine binds the proposal's session (the owner's sitting on this
/// install) and its `repo.provenance` claim (the `owner_request` form, on
/// that sitting); the caller names neither.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeProposalSubmitRequest {
    /// An existing CODE_ARTIFACT, whose stored repo_ref pins the base commit.
    pub repo: EntityId,
    /// Repository-relative path of the one file.
    pub path: String,
    /// The new file bytes.
    pub content: Vec<u8>,
    pub message: String,
    /// The turn, activity, intent and model behind the change, each a
    /// readable record when present. Absent fields stay unrecorded.
    pub op_provenance: CodeOpProvenance,
    /// The owner's own review catalog for this proposal: the lenses it must
    /// pass, a policy and not a verdict. Omitted, it is held to the vault's
    /// review policy, and with none set the same checked queue lands it on
    /// green (FIX 8268).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog: Option<LensCatalog>,
    /// The failed proposal this change replaces (FIX 4364), if any: a
    /// stored proposal of the same repository that a terminal queue batch
    /// quarantined or rolled back, or whose standalone attempt failed. The
    /// new proposal is fresh, reviewed and queued anew; a failed proposal
    /// has one replacement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair_of: Option<EntityId>,
}

/// A fresh review of an approved ordinary file proposal. The nested change
/// supplies the message and policy; its content is filled by the engine,
/// and its attribution is the engine's, bound to that content.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeProposalRereviewRequest {
    pub original: EntityId,
    pub change: CodeProposalSubmitRequest,
}

/// The staged proposal, as the engine stored it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeProposalSubmitted {
    /// The engine-minted proposal id, the `repo.proposed_diff` claim. Not a
    /// queue entry or a receipt.
    pub proposal: EntityId,
    /// Its `repo.proposal_admission` receipt (FIX 4338): the stored fact
    /// that the engine admitted this candidate into custody. It is not a
    /// queue admission and not a landing.
    pub admission_receipt: EntityId,
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
