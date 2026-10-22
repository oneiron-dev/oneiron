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
pub(super) use crate::deletion::names_no_actor;

#[cfg(feature = "sync")]
impl DocActor {
    /// This actor as this vault knows it: no one once this vault erased it,
    /// as the erase's own marker reads (FIX 4247).
    pub(crate) fn erased_here(self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Self> {
        if let Self::Actor(id) = self
            && vault.local_hard_delete_marker_exists_in_txn(txn, &id)?
        {
            return Ok(Self::Erased);
        }
        Ok(self)
    }
}

#[cfg(feature = "sync")]
impl super::CitationPin {
    /// This pin naming no one: the form a window keys it by, so a pin and
    /// its erased twin ride under one key (FIX 4247).
    pub(crate) fn actor_erased(&self) -> Self {
        Self {
            actor: DocActor::Erased,
            ..self.clone()
        }
    }

    /// ErasedWins (FIX 4247), the one rule wherever two copies of one pin
    /// meet: the copy that stands, or `None` when they conflict. Equal
    /// copies are one, and this one stands. Where one names an actor and the
    /// other no one, the erased one wins, so no carried copy undoes an
    /// erase. Two different live actors, or any other difference, conflict.
    pub(crate) fn erased_wins<'a>(&'a self, other: &'a Self) -> Option<&'a Self> {
        if self.actor_erased() != other.actor_erased() {
            None
        } else if self.actor == other.actor || self.actor == DocActor::Erased {
            Some(self)
        } else if other.actor == DocActor::Erased {
            Some(other)
        } else {
            None
        }
    }
}
