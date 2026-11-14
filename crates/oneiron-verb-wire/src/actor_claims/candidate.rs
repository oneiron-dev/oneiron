//! Moved from `crates/oneiron/src/actor_claims/candidate.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// `vault.craft_candidates`'s input.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CraftCandidatesRequest {
    /// Only this resident's candidates (32 hex); every resident's when absent.
    #[serde(default)]
    pub resident: Option<String>,
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
