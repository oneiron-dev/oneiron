//! Placement supplied by the original rule-outcome producer, never a reader grant.

use std::collections::BTreeSet;

use oneiron_authority::federation::Scope;
use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::store::GateReadAnchors;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuleOutcomeReadPosition {
    pub(crate) scope: Scope,
    pub(crate) kind_band: u8,
    pub(crate) relationship: Option<BTreeSet<EntityId>>,
    pub(crate) private: bool,
    pub(crate) body_worlds: Vec<EntityId>,
    pub(crate) body_facets: Vec<EntityId>,
    pub(crate) anchors: GateReadAnchors,
}
