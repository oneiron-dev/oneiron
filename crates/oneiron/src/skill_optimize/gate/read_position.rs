//! The read placement a verdict producer supplies on its original request.

use crate::EntityId;
use crate::store::GateReadAnchors;
use oneiron_authority::federation::Scope;
use serde::{Deserialize, Serialize};

/// Native-row placement data, not an authority, supporting-entity grant or
/// custody certificate. No scope axis is inferred from the scoring job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillVerdictReadPosition {
    pub scope: Scope,
    pub kind_band: u8,
    #[serde(
        deserialize_with = "crate::write_envelope::claim_body::RelationshipScope::deserialize"
    )]
    pub relationship: crate::write_envelope::claim_body::RelationshipScope,
    pub private: bool,
    pub body_worlds: Vec<EntityId>,
    pub body_facets: Vec<EntityId>,
    pub anchors: GateReadAnchors,
}
