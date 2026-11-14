//! Moved from `crates/oneiron/src/guest_document_share.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::federation::pact_scope::SelectorRange;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

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
