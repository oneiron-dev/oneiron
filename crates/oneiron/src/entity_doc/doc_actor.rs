//! Whose act an entity-document row records, and the erase that forgets it
//! (FIX 3520).

use crate::error::Result;
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};

/// Whose act an entity-document row records: an actor, or no one once that
/// actor was erased (FIX 3520). It reads and writes as the actor's hex id, or
/// as [`ERASED_CALL_IDENTITY`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocActor {
    Actor(EntityId),
    Erased,
}

impl schemars::JsonSchema for DocActor {
    fn schema_name() -> String {
        "DocActor".to_owned()
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        <String as schemars::JsonSchema>::json_schema(generator)
    }
}

impl DocActor {
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

    /// Makes this no one when it is `actor`; whether it was.
    pub(super) fn forget(&mut self, actor: EntityId) -> bool {
        let named = self.is(actor);
        if named {
            *self = Self::Erased;
        }
        named
    }
}

impl Serialize for DocActor {
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

impl<'de> Deserialize<'de> for DocActor {
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

/// Whether `id`'s entity is no actor, so its erase has no one to take out of
/// the entity-document rows.
pub(super) fn names_no_actor(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    if let Some(raw) = vault.get_raw_in(txn, id)?
        && let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw)
    {
        return Ok(!matches!(
            header.entity_type,
            crate::registry::ENTITY_TYPE_PERSON
                | crate::registry::ENTITY_TYPE_MACHINE
                | crate::registry::ENTITY_TYPE_AGENT_DEF
        ));
    }
    Ok(false)
}
