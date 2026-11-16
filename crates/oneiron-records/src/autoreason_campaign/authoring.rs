//! Moved from `crates/oneiron/src/autoreason_campaign/authoring.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::claim::ClaimApprovalStatus;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::attempt_id::AttemptId;
use serde::Deserialize;
use serde::Serialize;

/// The exact revision of the strategy skill the campaign runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimAuthoringSkillPin {
    pub skill: EntityId,
    pub version: String,
    /// Hex of the skill's content hash.
    pub content_hash: String,
}

/// The typed choice the strategy skill returns for one claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimAuthoringChoice {
    SinglePass,
    Tournament,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TournamentStop {
    Consensus,
    RoundCap,
    ExhaustedRounds,
    /// A round discarded every candidate: the run failed and landed no
    /// claim.
    AllDiscarded,
}

/// The winner a tournament run landed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoringWinner {
    pub claim: EntityId,
    pub candidate_ref: String,
    pub branch: AttemptId,
    pub score: u64,
    /// The winner claim's approval as the gate left it: rank never approves.
    pub approval: ClaimApprovalStatus,
}
