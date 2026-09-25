//! Validated entity-id representation for opt-in domain records.
use crate::EntityId;
use serde::{Deserialize, Deserializer, Serializer};
pub(crate) fn serialize<S: Serializer>(id: &EntityId, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&id.to_hex())
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
        match id {
            Some(id) => serializer.serialize_some(&id.to_hex()),
            None => serializer.serialize_none(),
        }
    }
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<EntityId>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|s| EntityId::from_hex(&s).map_err(serde::de::Error::custom))
            .transpose()
    }
}
