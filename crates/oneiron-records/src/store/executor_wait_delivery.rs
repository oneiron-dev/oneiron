//! Moved from `crates/oneiron/src/store/executor_wait_delivery.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// What one run holds of a wait's reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaitHolder {
    /// The reply, for `actor`'s run, when its run's stamps name one.
    Kept { actor: Option<EntityId> },
    /// A soft delete of `actor` took the reply (FIX 6591): it reads as
    /// erased for good, as Erased, and no retry keeps it again. The actor
    /// stays only so its later erase selects the membership; it is no live
    /// hold and no authority.
    Deleted { actor: EntityId },
    /// Its run's actor was erased: the reply reads as erased for it, for
    /// good.
    Erased,
}

impl WaitHolder {
    /// The actor whose erase selects this membership (FIX 6591): the one it
    /// keeps the reply for, or the one a soft delete took it from.
    pub const fn retirement_actor(self) -> Option<EntityId> {
        match self {
            Self::Kept { actor } => actor,
            Self::Deleted { actor } => Some(actor),
            Self::Erased => None,
        }
    }

    /// Whether a delete or an erase took the reply.
    pub const fn erased(self) -> bool {
        !matches!(self, Self::Kept { .. })
    }

    /// The membership `prior` once a soft delete of `actor` takes it (FIX
    /// 6591): an erased one stays erased, and one that names an actor keeps
    /// naming it.
    pub const fn deleted(prior: Option<Self>, actor: EntityId) -> Self {
        match prior {
            Some(Self::Erased) => Self::Erased,
            Some(Self::Deleted { actor } | Self::Kept { actor: Some(actor) }) => {
                Self::Deleted { actor }
            }
            Some(Self::Kept { actor: None }) | None => Self::Deleted { actor },
        }
    }
}
