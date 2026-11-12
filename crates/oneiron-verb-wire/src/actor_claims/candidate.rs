//! Moved from `crates/oneiron/src/actor_claims/candidate.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::claim::ClaimApprovalStatus;
use serde::Deserialize;
use serde::Serialize;

/// The owner's verdict on one craft candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CraftVerdict {
    /// The note becomes the resident's learned craft.
    Approved,
    /// The note is set aside; a later dreaming may propose it again.
    Rejected,
}

impl CraftVerdict {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Rejected => "rejected",
        }
    }

    const fn approval(self) -> ClaimApprovalStatus {
        match self {
            Self::Approved => ClaimApprovalStatus::Approved,
            Self::Rejected => ClaimApprovalStatus::Rejected,
        }
    }
}

/// `vault.craft_candidates`'s input.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CraftCandidatesRequest {
    /// Only this resident's candidates (32 hex); every resident's when absent.
    #[serde(default)]
    pub resident: Option<String>,
}

/// `vault.craft_candidates.answer`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CraftCandidateAnswer {
    /// The candidate's claim id (32 hex), as its card names it.
    pub candidate_id: String,
    /// The content hash its card showed (64 hex); another refuses.
    pub content_hash: String,
    pub verdict: CraftVerdict,
}

/// One candidate as its card shows it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CraftCandidateView {
    pub candidate_id: String,
    /// What an answer pins (64 hex): the candidate's id, kind and words and
    /// the dreaming they came from.
    pub content_hash: String,
    /// The resident the note is about (32 hex).
    pub resident: String,
    /// `actor.lesson` or `actor.failure_mode`.
    pub predicate: String,
    pub text: String,
    /// The dreaming attempt that proposed it (32 hex).
    pub attempt: String,
    /// When it was proposed, on the vault clock.
    pub proposed_at: u64,
}

/// `vault.craft_candidates`'s answer, newest first.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CraftCandidatesView {
    pub candidates: Vec<CraftCandidateView>,
}

/// The owner's verdict as it landed.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CraftVerdictView {
    pub candidate_id: String,
    pub verdict: CraftVerdict,
    /// The verdict row (32 hex), which superseded the candidate.
    pub verdict_id: String,
    /// The decision's receipt (`gate:<hex>`).
    pub receipt_ref: String,
    /// When the owner decided, on the vault clock.
    pub decided_at: u64,
}
