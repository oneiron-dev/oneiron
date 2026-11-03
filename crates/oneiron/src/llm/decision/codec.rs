//! Canonical entity references for typed-decision wire records.

use crate::model_decision::codec::parse;
pub(in crate::llm::decision) use crate::model_decision::codec::{
    entities, entity, optional_entity,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

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
