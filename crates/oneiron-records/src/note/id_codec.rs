//! Moved from `crates/oneiron/src/note/id_codec.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serializer;

pub fn serialize<S: Serializer>(id: &EntityId, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&id.to_hex())
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<EntityId, D::Error> {
    let hex = String::deserialize(deserializer)?;
    EntityId::from_hex(&hex).map_err(serde::de::Error::custom)
}
