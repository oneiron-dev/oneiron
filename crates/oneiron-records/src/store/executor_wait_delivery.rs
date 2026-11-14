//! Moved from `crates/oneiron/src/store/executor_wait_delivery.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::side_table::codec::CodecError;
use oneiron_store::side_table::codec::RawValue;
use serde::Deserialize;
use serde::Serialize;

/// The reply one wait was answered with, and when it was delivered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaitDelivery {
    /// The reply as JSON text.
    pub reply: String,
    pub delivered_at_ms: u64,
    /// The rows the reply was derived from, as its settler listed them
    /// (FIX 5455): the rows a connector call's passes picked. `None` when
    /// its settler listed none: the reply then adds no row to its run's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_rows: Option<Vec<EntityId>>,
    /// The origins of the reply as its settler served it (FIX 7083): the
    /// worlds and row scopes the settler froze in the writer that made the
    /// reply. `None` when they are unknown. An empty value is a proof that
    /// the reply has no origin. A copy of the delivery keeps them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origins: Option<crate::code_run::reader::origins::ResultOrigins>,
    /// Whether an erase of its holder's actor took the reply (FIX 5718):
    /// its text is gone, and when it came and its rows stay.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub erased: bool,
}

impl RawValue for WaitDelivery {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        serde_json::to_vec(self).map_err(|_| Error::CorruptedIndex("code-run wait delivery").into())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        serde_json::from_slice(bytes)
            .map_err(|_| Error::CorruptedIndex("code-run wait delivery").into())
    }
}

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
