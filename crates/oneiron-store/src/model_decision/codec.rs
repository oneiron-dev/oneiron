//! Canonical entity references for typed-decision wire records.

use oneiron_contracts::EntityId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub mod entity {
    use super::*;
    pub fn serialize<S: Serializer>(id: &EntityId, serializer: S) -> Result<S::Ok, S::Error> {
        id.to_hex().serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<EntityId, D::Error> {
        parse(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}
pub mod entities {
    use super::*;
    pub fn serialize<S: Serializer>(ids: &[EntityId], serializer: S) -> Result<S::Ok, S::Error> {
        ids.iter()
            .map(EntityId::to_hex)
            .collect::<Vec<_>>()
            .serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<EntityId>, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .iter()
            .map(|s| parse(s).map_err(serde::de::Error::custom))
            .collect()
    }
}
pub mod optional_entity {
    use super::*;
    pub fn serialize<S: Serializer>(
        id: &Option<EntityId>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        id.map(|id| id.to_hex()).serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<EntityId>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|text| parse(&text).map_err(serde::de::Error::custom))
            .transpose()
    }
}
pub fn parse(text: &str) -> Result<EntityId, &'static str> {
    let id = EntityId::from_hex(text).map_err(|_| "invalid entity reference")?;
    if id.to_hex() != text {
        return Err("noncanonical entity reference");
    }
    Ok(id)
}
