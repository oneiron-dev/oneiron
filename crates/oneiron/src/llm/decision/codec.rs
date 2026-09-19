//! Canonical entity references for typed-decision wire records.

use crate::EntityId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub(in crate::llm::decision) mod entity {
    use super::*;
    pub(in crate::llm::decision) fn serialize<S: Serializer>(
        id: &EntityId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        id.to_hex().serialize(serializer)
    }
    pub(in crate::llm::decision) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<EntityId, D::Error> {
        parse(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}
pub(in crate::llm::decision) mod entities {
    use super::*;
    pub(in crate::llm::decision) fn serialize<S: Serializer>(
        ids: &[EntityId],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ids.iter()
            .map(EntityId::to_hex)
            .collect::<Vec<_>>()
            .serialize(serializer)
    }
    pub(in crate::llm::decision) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<EntityId>, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .iter()
            .map(|s| parse(s).map_err(serde::de::Error::custom))
            .collect()
    }
}
fn parse(text: &str) -> Result<EntityId, &'static str> {
    let id = EntityId::from_hex(text).map_err(|_| "invalid entity reference")?;
    if id.to_hex() != text {
        return Err("noncanonical entity reference");
    }
    Ok(id)
}
