//! Moved from `crates/oneiron/src/origin/document_candidate_types.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The validated ref update a receive-pack landed: the proven object store,
/// the full ref and the old and new tips, never a request's own values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReceivedRefSource {
    /// The served object store's hex identity.
    pub object_store: String,
    pub ref_name: String,
    /// The tip the update replaced, 40 lower-hex; `None` for a new ref.
    pub old_oid: Option<String>,
    /// The tip it left, 40 lower-hex; `None` for a deleted ref.
    pub new_oid: Option<String>,
}

/// Where an accepted push's candidate stands. Held states keep the source
/// and the accepted push; matching never changes the receive result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodePushCandidateState {
    /// Received, not matched yet.
    Pending,
    /// No exact base, or more than one.
    HeldBase,
    /// The push it continues has no sealed tested revision yet.
    HeldPredecessor,
    /// No owner review catalog for this repository.
    HeldReviewPolicy,
    /// A shape the reviewed path does not carry: no change, a deleted or
    /// non-commit ref, a non-fast-forward, or binary entries.
    /// Gitlinks stay opaque; linked repositories are not traversed.
    HeldShape,
    /// One all-files proposal awaits review and an owner enqueue.
    Proposed,
    Rejected,
    /// Its proposal is in a merge stack.
    Queued,
    Quarantined,
    RolledBack,
    /// Its proposal applied.
    Landed,
    /// A tested revision binds its complete source.
    Sealed,
}

/// A candidate as the owner reads it: a projection of its saved source,
/// proposal, batch and seal rows, never a live head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodePushCandidateView {
    pub candidate: EntityId,
    pub state: CodePushCandidateState,
    /// The engine reason code of a hold.
    pub reason: Option<String>,
    pub base_revision: Option<EntityId>,
    pub fork_session: Option<EntityId>,
    pub proposal_refs: Vec<EntityId>,
    pub batch_refs: Vec<String>,
    pub check_work_refs: Vec<String>,
    pub revision_refs: Vec<EntityId>,
    /// The ruled status text of a masked copy's typed hold (FIX 7608,
    /// FIX 9237); none for every other candidate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}
