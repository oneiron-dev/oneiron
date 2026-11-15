//! Moved from `crates/oneiron/src/code_view/mod.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::code_view::VisibleFilePolicy;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ViewReceipt {
    #[serde(with = "entity_serde")]
    pub view_id: EntityId,
    #[serde(with = "entity_serde")]
    pub actor: EntityId,
    pub fork_hash: [u8; 32],
    pub base: Option<(EntityId, EntityId)>,
    pub files: BTreeMap<String, [u8; 32]>,
    /// The run this view is the work of (FIX 6867), bound in its first
    /// write; `None` for an owner's or trusted caller's view.
    pub run: Option<crate::memory::repo_doors::types::RepoRunStamp>,
    /// How each file a masked reader's copy holds differs from the stored
    /// blob it stands in for (FIX 8965): absent for the stored bytes.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub projections: BTreeMap<
        String,
        oneiron_verb_wire::origin::secret_projection::types::RepoFileProjectionView,
    >,
}

pub mod entity_serde {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        value: &EntityId,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_hex())
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<EntityId, D::Error> {
        let value = String::deserialize(deserializer)?;
        EntityId::from_hex(&value).map_err(serde::de::Error::custom)
    }
}
pub mod erase;
