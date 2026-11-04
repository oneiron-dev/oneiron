//! An answer actor identity, including its erased state.

use super::invalid;
use oneiron_contracts::{EntityId, Result};

/// The actor an answer names (an ask's answerer, a rule row's writer, an
/// ask's principal or responsible actor), or no one once that actor was
/// erased (FIX 3520, 4588). It reads and writes as the actor's hex id, or as
/// `oneiron::receipt::ERASED_CALL_IDENTITY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerActor {
    Actor(EntityId),
    Erased,
}

impl schemars::JsonSchema for AnswerActor {
    fn schema_name() -> String {
        "AnswerActor".to_owned()
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        <String as schemars::JsonSchema>::json_schema(generator)
    }
}

impl AnswerActor {
    /// Whether this is `actor`.
    #[must_use]
    pub fn is(self, actor: EntityId) -> bool {
        self == Self::Actor(actor)
    }

    /// The actor, while it is not erased.
    #[must_use]
    pub const fn id(self) -> Option<EntityId> {
        match self {
            Self::Actor(id) => Some(id),
            Self::Erased => None,
        }
    }

    /// The actor, refused once it was erased: no live request is rebuilt
    /// for no one.
    pub fn live(self) -> Result<EntityId> {
        self.id()
            .ok_or_else(|| invalid("the decision ask names an erased actor"))
    }

    /// Makes this no one when it is `actor`; whether it was.
    pub fn forget(&mut self, actor: EntityId) -> bool {
        let named = self.is(actor);
        if named {
            *self = Self::Erased;
        }
        named
    }
}
