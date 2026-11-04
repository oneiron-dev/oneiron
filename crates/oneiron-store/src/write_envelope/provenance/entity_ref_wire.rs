//! Validated hexadecimal entity references in provenance receipts.
use oneiron_contracts::entity_id::EntityId;
use serde::{Deserialize, Deserializer, Serializer};
pub fn serialize<S: Serializer>(id: &EntityId, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&id.to_hex())
}
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<EntityId, D::Error> {
    let value = String::deserialize(deserializer)?;
    EntityId::from_hex(&value).map_err(serde::de::Error::custom)
}
