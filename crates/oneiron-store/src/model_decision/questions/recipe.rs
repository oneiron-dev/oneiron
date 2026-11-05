//! Graph-question identities and explicit evidence joins.

use oneiron_contracts::EntityId;
use serde::{Deserialize, Serialize};

/// A skill pins the definition, including its outcome binding and decision dial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphQuestionRef {
    #[serde(with = "super::super::codec::entity")]
    pub id: EntityId,
    pub version: u32,
}

/// The unit and the exact sources selected by the resident's recipe. Sources
/// are required: a missing contact, variant or signal means abstain, not no.
/// The same unit may occur with different evidence (for example, variants).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphQuestionInput {
    #[serde(with = "super::super::codec::entity")]
    #[schemars(with = "String")]
    pub unit: EntityId,
    #[serde(with = "super::super::codec::entities")]
    #[schemars(with = "Vec<String>")]
    pub evidence: Vec<EntityId>,
}
