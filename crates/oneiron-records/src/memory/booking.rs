//! Moved from `crates/oneiron/src/memory/booking.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::booking::emergency_reschedule::EmergencyActionPolicy;
use oneiron_verb_wire::calendar::query::requests::CalendarRangeDto;

/// The bound Memory actor is the owner; an input never names a replacement actor.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EmergencyInstructionInput {
    pub affected_window: CalendarRangeDto,
    pub reason: String,
    pub action_policy: EmergencyActionPolicy,
    pub recorded_at: u64,
}
