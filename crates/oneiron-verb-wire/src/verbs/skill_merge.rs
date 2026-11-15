//! Wire types of the owner's ingress door for a shared-skill merge offer (FIX
//! [SKILL-HUB-PROMOTION-VERBS]): `vault.skills.merges.offer`. `oneiron`
//! re-exports each item.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

use crate::skill_hub::{SharedSkillDelta, SharedSkillLane};

/// `vault.skills.merges.offer`: a revision of an active shared skill, offered
/// as the package bytes a federation merge-back or a company pull request
/// carried to this vault. The door reads no other vault: the offer is the
/// bytes alone, and it lands as an untrusted Candidate the owner's merge
/// route rules on.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillMergeOfferRequest {
    /// The active shared skill the delta revises.
    pub base: EntityId,
    /// The offered package in its host transport encoding, standard base64.
    pub package_base64: String,
    /// The lane that carried it.
    pub lane: SharedSkillLane,
    /// Who offered it, as the carrying host names them, at most 512 bytes; a
    /// source assertion, never authority.
    pub submitted_by: String,
    /// The sender's fork the delta revises from; a source assertion.
    pub submitted_fork: EntityId,
}

/// The staged offer: `candidate` is the id the owner's merge route
/// (`POST /v1/owner/packs/skills/merges/{candidate}/approve`) rules on.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillMergeOffered {
    pub candidate: EntityId,
    /// The offer as stored.
    pub delta: SharedSkillDelta,
}
