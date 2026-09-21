//! Canonical entity references in the private durable link codec.
pub(super) mod entity_ref {
    use crate::EntityId;
    use serde::{Deserialize, Deserializer, Serializer};
    pub(in crate::linear_sync) fn serialize<S: Serializer>(
        id: &EntityId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&id.to_hex())
    }
    pub(in crate::linear_sync) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<EntityId, D::Error> {
        let text = String::deserialize(deserializer)?;
        EntityId::from_hex(&text).map_err(serde::de::Error::custom)
    }
}
