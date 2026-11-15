//! Moved from `crates/oneiron/src/booking/emergency_reschedule.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::booking::emergency_reschedule::planning::EmergencyLocalBasis;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::temporal::TimeRange;
use oneiron_verb_wire::booking::constraint::BookingError;
use serde::Deserialize;
use serde::Serialize;

/// The owner chooses the action; discovery cannot silently change it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyActionPolicy {
    Cancel,
    RequestUpdate,
}

/// One logged instruction. This is a reference to durable evidence, not proof
/// by itself. The host must authenticate the owner before calling append.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerInstructionRecord {
    #[serde(with = "entity_ref_serde")]
    pub owner_ref: EntityId,
    pub request_hash: [u8; 32],
    pub recorded_at: u64,
}

/// Executing request. `affected_window` is inclusive, like core `TimeRange`;
/// booking occurrences exposed below are half-open, like booking's slot seam.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmergencyRescheduleRequest {
    #[serde(with = "entity_ref_serde")]
    pub owner_ref: EntityId,
    #[serde(with = "time_range_serde")]
    pub affected_window: TimeRange,
    pub reason: String,
    pub action_policy: EmergencyActionPolicy,
    pub authority: OwnerInstructionRecord,
}

pub fn content_hash(value: &impl Serialize) -> Result<[u8; 32], BookingError> {
    let bytes = serde_json::to_vec(value).map_err(storage_failure)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

pub mod time_range_serde {
    use super::*;
    pub fn serialize<S: serde::Serializer>(value: &TimeRange, s: S) -> Result<S::Ok, S::Error> {
        (value.start, value.end).serialize(s)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<TimeRange, D::Error> {
        let (start, end) = <(u64, u64)>::deserialize(d)?;
        Ok(TimeRange { start, end })
    }
}

pub fn refused(reason: &str) -> BookingError {
    BookingError::InvalidConfig(reason.to_owned())
}

pub fn storage_failure(error: impl std::fmt::Display) -> BookingError {
    BookingError::SlotOracle(format!("emergency reschedule: {error}"))
}

pub mod entity_ref_serde {
    use super::*;

    pub fn serialize<S: serde::Serializer>(value: &EntityId, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&value.to_hex())
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<EntityId, D::Error> {
        EntityId::from_hex(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
pub mod planning;
