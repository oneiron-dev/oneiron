//! Moved from `crates/oneiron/src/verbs/pack_preview.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::verbs::host::PackFileInput;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// `vault.packs.preview`'s input: the folder `vault.packs.put` would take,
/// and the local world the owner would pick for a travelling agent held for
/// its world.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackPreviewRequest {
    pub files: Vec<PackFileInput>,
    /// The picked live local world; absent previews the one the agent's
    /// scope names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub world: Option<EntityId>,
}
