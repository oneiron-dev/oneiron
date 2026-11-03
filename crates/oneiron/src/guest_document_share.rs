//! Guest document share input for the sync export door.
use crate::EntityId;
use crate::federation::SelectorRange;
use serde::{Deserialize, Serialize};

/// One named, locally authored world under the recipient's existing guest grant.
/// Empty requested axes leave the grant ceiling in force; they never widen it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestDocumentShareRequest {
    pub grant_ref: EntityId,
    pub world_ref: EntityId,
    pub window_key: String,
    #[serde(default)]
    pub facets: Vec<EntityId>,
    #[serde(default)]
    pub bands: Vec<SelectorRange>,
}
