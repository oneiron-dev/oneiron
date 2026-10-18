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
pub(in crate::llm::decision) mod optional_entity {
    use super::*;
    pub(in crate::llm::decision) fn serialize<S: Serializer>(
        id: &Option<EntityId>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        id.map(|id| id.to_hex()).serialize(serializer)
    }
    pub(in crate::llm::decision) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<EntityId>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|text| parse(&text).map_err(serde::de::Error::custom))
            .transpose()
    }
}
/// An [`AnswerActor`](crate::llm::decision::AnswerActor): the actor's canonical hex, or
/// [`ERASED_CALL_IDENTITY`](crate::receipt::ERASED_CALL_IDENTITY) once that
/// actor was erased (FIX 3520).
pub(in crate::llm::decision) mod answer_actor {
    use super::*;
    use crate::llm::decision::AnswerActor;
    use crate::receipt::ERASED_CALL_IDENTITY;
    pub(in crate::llm::decision) fn serialize<S: Serializer>(
        actor: &AnswerActor,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match actor {
            AnswerActor::Actor(id) => id.to_hex().serialize(serializer),
            AnswerActor::Erased => ERASED_CALL_IDENTITY.serialize(serializer),
        }
    }
    pub(in crate::llm::decision) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<AnswerActor, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text == ERASED_CALL_IDENTITY {
            return Ok(AnswerActor::Erased);
        }
        parse(&text)
            .map(AnswerActor::Actor)
            .map_err(serde::de::Error::custom)
    }
}
fn parse(text: &str) -> Result<EntityId, &'static str> {
    let id = EntityId::from_hex(text).map_err(|_| "invalid entity reference")?;
    if id.to_hex() != text {
        return Err("noncanonical entity reference");
    }
    Ok(id)
}
