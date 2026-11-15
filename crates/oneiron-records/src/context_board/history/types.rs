//! Moved from `crates/oneiron/src/context_board/history/types.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::revision_ref::RevisionRef;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnAnchor {
    #[serde(with = "entity_id_codec")]
    pub owner: EntityId,
    pub at: u64,
    pub learned_at: u64,
    pub source_revision_ref: RevisionRef,
    pub frontier: Vec<u8>,
}

pub mod entity_id_codec {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        value: &EntityId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value.as_bytes().serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<EntityId, D::Error> {
        let bytes = <[u8; 16]>::deserialize(deserializer)?;
        EntityId::from_bytes(bytes).map_err(serde::de::Error::custom)
    }
}
