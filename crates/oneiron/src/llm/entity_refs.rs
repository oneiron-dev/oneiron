//! Validated entity-reference wire encoding for model policy DTOs.
use crate::EntityId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
pub(crate) fn serialize<S: Serializer>(id: &EntityId, serializer: S) -> Result<S::Ok, S::Error> {
    id.as_bytes().serialize(serializer)
}
pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<EntityId, D::Error> {
    let bytes = <[u8; 16]>::deserialize(deserializer)?;
    EntityId::from_bytes(bytes).map_err(serde::de::Error::custom)
}
pub(super) mod list {
    use super::*;
    pub(crate) fn serialize<S: Serializer>(
        ids: &[EntityId],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ids.iter()
            .map(EntityId::as_bytes)
            .collect::<Vec<_>>()
            .serialize(serializer)
    }
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<EntityId>, D::Error> {
        Vec::<[u8; 16]>::deserialize(deserializer)?
            .into_iter()
            .map(|bytes| EntityId::from_bytes(bytes).map_err(serde::de::Error::custom))
            .collect()
    }
}
