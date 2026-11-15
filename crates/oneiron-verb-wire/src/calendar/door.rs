//! Moved from `crates/oneiron/src/calendar/door.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::calendar::query::requests::CalendarRangeDto;
use serde::Deserialize;
use serde::Serialize;

/// The origin union forbids extraction evidence on native entries and requires
/// it on extracted entries. Recorded time and actor are always engine-stamped.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "origin", rename_all = "snake_case", deny_unknown_fields)]
pub enum CalendarEventCreateRequest {
    Native {
        summary: String,
        occurred_at: CalendarRangeDto,
    },
    Dreamer {
        summary: String,
        occurred_at: CalendarRangeDto,
        evidence_turn_ids: Vec<String>,
        source_frontiers: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalendarEventCreated {
    pub event_ref: String,
    pub origin: String,
    pub recorded_at: u64,
}
