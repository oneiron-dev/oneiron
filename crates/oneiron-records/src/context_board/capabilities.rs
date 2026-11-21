//! Moved from `crates/oneiron/src/context_board/capabilities.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;

/// A hit from the capability channel. Other entity types are ignored.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapabilityHit {
    #[serde(
        serialize_with = "serialize_capability_id",
        deserialize_with = "deserialize_capability_id"
    )]
    pub id: EntityId,
    pub entity_type: u8,
    pub label: String,
}

pub fn serialize_capability_id<S: serde::Serializer>(
    id: &EntityId,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&id.to_hex())
}

pub fn deserialize_capability_id<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<EntityId, D::Error> {
    let value = <String as serde::Deserialize>::deserialize(deserializer)?;
    EntityId::from_hex(&value).map_err(serde::de::Error::custom)
}
