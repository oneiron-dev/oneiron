//! Moved from `crates/oneiron/src/skill_optimize/offer_switch.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::receipt_identity::ERASED_CALL_IDENTITY;
use serde::Deserialize;
use serde::Serialize;

/// The owner a switch or its undo names: an actor, or no one once that
/// actor was erased (FIX 3520). It reads and writes as the actor's hex id,
/// or as [`ERASED_CALL_IDENTITY`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchOwner {
    Actor(EntityId),
    Erased,
}

impl SwitchOwner {
    /// Whether this is `actor`.
    #[must_use]
    pub fn is(self, actor: EntityId) -> bool {
        self == Self::Actor(actor)
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

impl Serialize for SwitchOwner {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Actor(id) => serializer.serialize_str(&id.to_hex()),
            Self::Erased => serializer.serialize_str(ERASED_CALL_IDENTITY),
        }
    }
}

impl<'de> Deserialize<'de> for SwitchOwner {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value == ERASED_CALL_IDENTITY {
            return Ok(Self::Erased);
        }
        EntityId::from_hex(&value)
            .map(Self::Actor)
            .map_err(serde::de::Error::custom)
    }
}

/// Its schema is its wire form: the actor's hex id, or [`ERASED_CALL_IDENTITY`].
impl schemars::JsonSchema for SwitchOwner {
    fn schema_name() -> String {
        "SwitchOwner".to_owned()
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        <String as schemars::JsonSchema>::json_schema(generator)
    }
}
