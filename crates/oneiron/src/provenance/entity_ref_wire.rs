//! Validated hexadecimal entity references in provenance receipts.
use crate::EntityId;
use serde::{Deserialize, Deserializer, Serializer};
pub(super) fn serialize<S: Serializer>(id: &EntityId, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&id.to_hex())
}
pub(super) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<EntityId, D::Error> {
    let value = String::deserialize(deserializer)?;
    EntityId::from_hex(&value).map_err(serde::de::Error::custom)
}
