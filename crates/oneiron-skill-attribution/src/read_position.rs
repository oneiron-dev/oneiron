//! The original discovery-proposal producer's requested native read placement.

use std::collections::BTreeSet;

use oneiron_authority::federation::Scope;
use oneiron_contracts::EntityId;
use oneiron_contracts::gate_read_anchors::GateReadAnchors;
use serde::{Deserialize, Deserializer, Serialize};

/// Placement data for a newly minted proposal, never a reader grant. Every
/// axis comes from that proposal's original producer request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillEditProposalReadPosition {
    pub scope: Scope,
    pub kind_band: u8,
    #[serde(deserialize_with = "deserialize_relationship")]
    pub relationship: Option<BTreeSet<EntityId>>,
    pub private: bool,
    pub body_worlds: Vec<EntityId>,
    pub body_facets: Vec<EntityId>,
    pub anchors: GateReadAnchors,
}

/// Placement data for a newly minted judgment, never a reader grant. Every
/// axis comes from that judgment's original producer request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributionJudgmentReadPosition {
    pub scope: Scope,
    pub kind_band: u8,
    #[serde(deserialize_with = "deserialize_relationship")]
    pub relationship: Option<BTreeSet<EntityId>>,
    pub private: bool,
    pub body_worlds: Vec<EntityId>,
    pub body_facets: Vec<EntityId>,
    pub anchors: GateReadAnchors,
}

fn deserialize_relationship<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<BTreeSet<EntityId>>, D::Error> {
    Option::<BTreeSet<EntityId>>::deserialize(deserializer)
}
