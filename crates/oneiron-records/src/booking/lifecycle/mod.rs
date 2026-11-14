//! Moved from `crates/oneiron/src/booking/lifecycle/mod.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::booking::lifecycle::feed_move::BookingRevisionInvitePayload;
pub use crate::booking::lifecycle::token::HoldLeaseSpec;
pub use crate::booking::lifecycle::token::OpaqueCheckoutLeaseToken;
pub use crate::booking::lifecycle::token::OpaqueLifecycleToken;
pub use crate::booking::lifecycle::token::SessionKey;
pub(super) use crate::booking::lifecycle::token::digest_with;
pub use crate::booking::lifecycle::types::BOOKING_VERBS;
pub use crate::booking::lifecycle::types::BookingBookerContactValue;
pub use crate::booking::lifecycle::types::BookingEventTypeRefValue;
pub use crate::booking::lifecycle::types::BookingSourcePageValue;
pub use crate::booking::lifecycle::types::BookingStatus;
pub use crate::booking::lifecycle::types::BookingStatusValue;
pub use crate::booking::lifecycle::types::BookingVerb;
pub use crate::booking::lifecycle::types::BookingVerbReceipt;
pub use crate::booking::lifecycle::types::CalendarRevision;
pub use crate::booking::lifecycle::types::CancelSpec;
pub use crate::booking::lifecycle::types::ConfirmReceipt;
pub use crate::booking::lifecycle::types::ConfirmSpec;
pub use crate::booking::lifecycle::types::HoldReceipt;
pub use crate::booking::lifecycle::types::LifecycleTokenScope;
pub use crate::booking::lifecycle::types::RevisionReceipt;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::temporal::TimeRange;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

mod time_range_serde {
    use super::{Deserialize, Deserializer, Serialize, Serializer, TimeRange, TimeRangeWire};

    pub(super) fn serialize<S: Serializer>(
        value: &TimeRange,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        TimeRangeWire {
            start: value.start,
            end: value.end,
        }
        .serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<TimeRange, D::Error> {
        let wire = TimeRangeWire::deserialize(deserializer)?;
        Ok(TimeRange {
            start: wire.start,
            end: wire.end,
        })
    }
}

mod entity_ref_serde {
    use super::{Deserialize, Deserializer, EntityId, Serializer};

    pub(super) fn serialize<S: Serializer>(
        value: &EntityId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_hex())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<EntityId, D::Error> {
        let hex = String::deserialize(deserializer)?;
        EntityId::from_hex(&hex).map_err(serde::de::Error::custom)
    }
}

mod entity_refs_serde {
    use super::{Deserialize, Deserializer, EntityId, Serializer};

    pub(super) fn serialize<S: Serializer>(
        value: &[EntityId],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(value.iter().map(EntityId::to_hex))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
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
