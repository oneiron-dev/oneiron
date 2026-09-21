//! Strict hexadecimal entity references for the intake row codec.
use crate::EntityId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
fn parse<E: serde::de::Error>(value: String) -> Result<EntityId, E> {
    let id = EntityId::from_hex(&value).map_err(E::custom)?;
    if id.to_hex() != value {
        return Err(E::custom("noncanonical feedback entity ref"));
    }
    Ok(id)
}
pub(super) mod one {
    use super::*;
    pub(in crate::feedback::intake) fn serialize<S: Serializer>(
        id: &EntityId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        id.to_hex().serialize(serializer)
    }
    pub(in crate::feedback::intake) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<EntityId, D::Error> {
        parse(String::deserialize(deserializer)?)
    }
}
pub(super) mod many {
    use super::*;
    pub(in crate::feedback::intake) fn serialize<S: Serializer>(
        ids: &[EntityId],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ids.iter()
            .map(EntityId::to_hex)
            .collect::<Vec<_>>()
            .serialize(serializer)
    }
    pub(in crate::feedback::intake) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<EntityId>, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .into_iter()
            .map(parse)
            .collect()
    }
}
