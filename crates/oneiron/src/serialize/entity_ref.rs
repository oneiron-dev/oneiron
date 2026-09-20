//! Hex adapters for typed entity references in host-side serialized envelopes.
use crate::EntityId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
pub(crate) fn serialize<S: Serializer>(id: &EntityId, serializer: S) -> Result<S::Ok, S::Error> {
    id.to_hex().serialize(serializer)
}
pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<EntityId, D::Error> {
    EntityId::from_hex(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
}
pub(crate) mod optional {
    use super::*;
    pub(crate) fn serialize<S: Serializer>(
        id: &Option<EntityId>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        id.map(|value| value.to_hex()).serialize(serializer)
    }
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<EntityId>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|value| EntityId::from_hex(&value).map_err(serde::de::Error::custom))
            .transpose()
    }
}
pub(crate) mod sequence {
    use super::*;
    pub(crate) fn serialize<S: Serializer>(
        ids: &[EntityId],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ids.iter()
            .map(EntityId::to_hex)
            .collect::<Vec<_>>()
            .serialize(serializer)
    }
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<EntityId>, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .into_iter()
            .map(|value| EntityId::from_hex(&value).map_err(serde::de::Error::custom))
            .collect()
    }
}
