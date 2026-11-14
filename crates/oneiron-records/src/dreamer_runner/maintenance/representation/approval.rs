//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/representation/approval.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::receipt_identity::ERASED_CALL_IDENTITY;
use serde::Deserialize;
use serde::Serialize;

/// The owner an arm or a plan's envelope names: an actor, or no one once
/// that actor was erased (FIX 3520, 4512), and then the arm stands on no
/// receipt and the plan reviews nothing. It reads and writes as the actor's
/// hex id, or as [`ERASED_CALL_IDENTITY`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalOwner {
    Actor(EntityId),
    Erased,
}

impl ApprovalOwner {
    /// Whether this is `actor`.
    pub fn is(self, actor: EntityId) -> bool {
        self == Self::Actor(actor)
    }
}

impl Serialize for ApprovalOwner {
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

impl<'de> Deserialize<'de> for ApprovalOwner {
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
