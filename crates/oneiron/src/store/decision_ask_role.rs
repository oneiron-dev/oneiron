//! The role a human decision ask goes to, and the serde form of an answer's
//! actor. The decision ladder (`llm::decision`) builds and resolves asks;
//! the store-layer e-sign escalation and import audience read the role.
use crate::EntityId;
use crate::model_decision::RoleRank;
use serde::{Deserialize, Serialize};

/// An [`AnswerActor`](crate::model_decision::AnswerActor): the actor's canonical hex, or
/// [`ERASED_CALL_IDENTITY`](crate::store::receipt_identity::ERASED_CALL_IDENTITY) once that
/// actor was erased (FIX 3520).
pub(crate) mod answer_actor {
    use crate::model_decision::AnswerActor;
    use crate::model_decision::codec::parse;
    use crate::store::receipt_identity::ERASED_CALL_IDENTITY;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub(crate) fn serialize<S: Serializer>(
        actor: &AnswerActor,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match actor {
            AnswerActor::Actor(id) => id.to_hex().serialize(serializer),
            AnswerActor::Erased => ERASED_CALL_IDENTITY.serialize(serializer),
        }
    }
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
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

/// A role an ask can go to (Q3 by role). A role names authority, not a person: the host
/// resolves who holds it when the ask is queued, and the answer door rechecks it. The
/// model asks for escalation; it never names the role or the actor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum AskRole {
    /// The actor responsible for what the question is over (a schedule's, a question's or
    /// a unit's), as the caller binds it, and no one once it was erased (FIX 4588); with a
    /// project, the chain then walks that project's boards.
    Responsible {
        #[serde(with = "crate::store::decision_ask_role::answer_actor")]
        #[schemars(with = "String")]
        actor: crate::model_decision::AnswerActor,
        #[serde(default, with = "crate::model_decision::codec::optional_entity")]
        #[schemars(with = "Option<String>")]
        project: Option<EntityId>,
    },
    /// A project's effective board; the chain then walks its parents' boards.
    Board {
        #[serde(with = "crate::model_decision::codec::entity")]
        #[schemars(with = "String")]
        project: EntityId,
    },
    /// The vault's live owners, where every chain ends.
    Owner,
}

impl AskRole {
    /// Where the role sits on a chain.
    #[must_use]
    pub fn rank(&self) -> RoleRank {
        match self {
            Self::Responsible { .. } => RoleRank::Responsible,
            Self::Board { .. } => RoleRank::Board,
            Self::Owner => RoleRank::Owner,
        }
    }
}
