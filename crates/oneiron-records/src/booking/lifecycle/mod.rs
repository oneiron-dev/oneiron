//! Moved from `crates/oneiron/src/booking/lifecycle/mod.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::booking::lifecycle::feed_move::BookingRevisionInvitePayload;
pub use crate::booking::lifecycle::token::HoldLeaseSpec;
pub use crate::booking::lifecycle::token::OpaqueCheckoutLeaseToken;
pub use crate::booking::lifecycle::token::OpaqueLifecycleToken;
pub use crate::booking::lifecycle::token::SessionKey;
pub use crate::booking::lifecycle::types::BOOKING_VERBS;
pub use crate::booking::lifecycle::types::BookingBookerContactValue;
pub use crate::booking::lifecycle::types::BookingEventTypeRefValue;
pub use crate::booking::lifecycle::types::BookingSourcePageValue;
pub use crate::booking::lifecycle::types::BookingStatus;
pub use crate::booking::lifecycle::types::BookingStatusValue;
pub use crate::booking::lifecycle::types::BookingVerb;
pub use crate::booking::lifecycle::types::CalendarRevision;
pub use crate::booking::lifecycle::types::CancelSpec;
pub use crate::booking::lifecycle::types::ConfirmReceipt;
pub use crate::booking::lifecycle::types::ConfirmSpec;
pub use crate::booking::lifecycle::types::LifecycleTokenScope;
pub use crate::booking::lifecycle::types::RevisionReceipt;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serializer;

pub mod entity_ref_serde {
    use super::{Deserialize, Deserializer, EntityId, Serializer};

    pub fn serialize<S: Serializer>(value: &EntityId, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_hex())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<EntityId, D::Error> {
        let hex = String::deserialize(deserializer)?;
        EntityId::from_hex(&hex).map_err(serde::de::Error::custom)
    }
}

pub mod entity_refs_serde {
    use super::{Deserialize, Deserializer, EntityId, Serializer};

    pub fn serialize<S: Serializer>(value: &[EntityId], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(value.iter().map(EntityId::to_hex))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<EntityId>, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .iter()
            .map(|hex| EntityId::from_hex(hex).map_err(serde::de::Error::custom))
            .collect()
    }
}
pub mod feed_move;
pub mod token;
pub mod types;
