//! Hex adapters for typed entity references in host-side serialized envelopes.
//!
//! `#[serde(with = ...)]` targets. Public so the serialized envelopes in `oneiron` and
//! `oneiron-model` share one encoding across the crate line; they only encode and parse ids.
use crate::EntityId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
pub fn serialize<S: Serializer>(id: &EntityId, serializer: S) -> Result<S::Ok, S::Error> {
    id.to_hex().serialize(serializer)
}
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<EntityId, D::Error> {
    EntityId::from_hex(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
}
pub mod optional {
    use super::*;
    pub fn serialize<S: Serializer>(
        id: &Option<EntityId>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        id.map(|value| value.to_hex()).serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<EntityId>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|value| EntityId::from_hex(&value).map_err(serde::de::Error::custom))
            .transpose()
    }
}
pub mod sequence {
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
            .into_iter()
            .map(|value| EntityId::from_hex(&value).map_err(serde::de::Error::custom))
            .collect()
    }
}
/// An optional set of ids as an optional list of hex refs: `None` stays
/// absent, `Some(empty)` is `[]`.
pub mod optional_set {
    use super::*;
    use std::collections::BTreeSet;
    pub fn serialize<S: Serializer>(
        ids: &Option<BTreeSet<EntityId>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ids.as_ref()
            .map(|ids| ids.iter().map(EntityId::to_hex).collect::<Vec<_>>())
            .serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<BTreeSet<EntityId>>, D::Error> {
        Option::<Vec<String>>::deserialize(deserializer)?
            .map(|ids| {
                ids.iter()
                    .map(|value| EntityId::from_hex(value).map_err(serde::de::Error::custom))
                    .collect()
            })
            .transpose()
    }
}
