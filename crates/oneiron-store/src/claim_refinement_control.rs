//! A refinement candidate's content-free control row, the claim base's
//! reserved held-out labels and the offered shared-skill delta, with the
//! scope test and the erase a deletion makes of them. The skill hub
//! (`skill_hub::{refinement_admission, claim_refinement, shared_delta,
//! shared_gate, shared_merge_queue}`) writes and reads these rows; the
//! store's erase markers, replay, active store and deindex test and erase
//! them.
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_CLAIM;
use oneiron_base::registry::ENTITY_TYPE_SKILL;
use oneiron_contracts::entity_id::EntityId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefinementState {
    Pending,
    Refused,
    Admitted,
    Erased,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RefinementTarget {
    Skill { base: String, fork: String },
    Claim { base: String, proposal: String },
}
impl RefinementTarget {
    pub fn base(&self) -> &str {
        match self {
            Self::Skill { base, .. } | Self::Claim { base, .. } => base,
        }
    }
    pub fn kind(&self) -> u8 {
        match self {
            Self::Skill { .. } => ENTITY_TYPE_SKILL,
            Self::Claim { .. } => ENTITY_TYPE_CLAIM,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefinementControl {
    pub target: RefinementTarget,
    pub resident: Option<String>,
    pub base_binding: String,
    pub proposal_binding: String,
    pub state: RefinementState,
}
impl RefinementControl {
    pub fn claim(
        base: EntityId,
        candidate: EntityId,
        resident: EntityId,
        base_binding: String,
        proposal_binding: String,
    ) -> Self {
        Self {
            target: RefinementTarget::Claim {
                base: base.to_hex(),
                proposal: candidate.to_hex(),
            },
            resident: Some(resident.to_hex()),
            base_binding,
            proposal_binding,
            state: RefinementState::Pending,
        }
    }
    pub fn skill(
        base: EntityId,
        fork: EntityId,
        base_binding: String,
        proposal_binding: String,
    ) -> Self {
        Self {
            target: RefinementTarget::Skill {
                base: base.to_hex(),
                fork: fork.to_hex(),
            },
            resident: None,
            base_binding,
            proposal_binding,
            state: RefinementState::Pending,
        }
    }
}

/// Both lanes offer bytes to the receiving base. Neither grants access to the sender's vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SharedSkillLane {
    FederationMergeBack,
    CompanyPullRequest,
}
/// Durable offered delta; author and foreign fork are source assertions, never authority.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedSkillDelta {
    pub candidate: String,
    pub base: String,
    pub base_binding: String,
    pub content_hash: String,
    pub lane: SharedSkillLane,
    pub submitted_by: String,
    pub submitted_fork: String,
}
