//! Moved from `crates/oneiron/src/linear_sync/storage_codec.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub mod entity_ref {
    use oneiron_contracts::entity_id::EntityId;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(id: &EntityId, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&id.to_hex())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<EntityId, D::Error> {
        let text = String::deserialize(deserializer)?;
        EntityId::from_hex(&text).map_err(serde::de::Error::custom)
    }
}
