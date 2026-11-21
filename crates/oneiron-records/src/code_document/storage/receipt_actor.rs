//! Moved from `crates/oneiron/src/code_document/storage/receipt_actor.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::receipt_identity::ERASED_CALL_IDENTITY;
use serde::Deserialize;
use serde::Serialize;

/// Who made one operation: its actor, or no one once that actor was erased
/// (FIX 3520). It reads and writes as the actor's hex id, or as
/// [`ERASED_CALL_IDENTITY`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptActor {
    Actor(EntityId),
    Erased,
}

impl ReceiptActor {
    /// The actor, while it is not erased.
    pub const fn id(self) -> Option<EntityId> {
        match self {
            Self::Actor(id) => Some(id),
            Self::Erased => None,
        }
    }

    /// Makes this no one when it is `actor`; whether it was.
    pub fn forget(&mut self, actor: EntityId) -> bool {
        let named = *self == Self::Actor(actor);
        if named {
            *self = Self::Erased;
        }
        named
    }
}

impl Serialize for ReceiptActor {
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

impl<'de> Deserialize<'de> for ReceiptActor {
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
