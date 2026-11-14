//! Moved from `crates/oneiron/src/calendar/query/window.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::calendar::query::requests::CalendarRangeDto;
use serde::Deserialize;
use serde::Serialize;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarOccurrencesRequest {
    pub master_ref: String,
    /// Inclusive UTC seconds. An unbounded expansion is not a public call.
    pub range: CalendarRangeDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalendarOccurrenceView {
    pub event_ref: String,
    pub master_ref: String,
    pub uid: String,
    /// The occurrence's recurrence key: a UTC instant, or for an all-day or
    /// floating series its civil start read as UTC.
    pub original_start_utc: u64,
    /// Inclusive UTC bounds; for an all-day occurrence in a zone its
    /// calendar names, its days in that zone; for any other all-day or
    /// floating occurrence, the span it falls in across every zone. Its days
    /// or wall times are in [`Self::civil`].
    pub start_utc: u64,
    pub end_utc: u64,
    /// An all-day or floating occurrence's days or wall times (FIX 17869).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub civil: Option<super::civil::CalendarCivilSpan>,
}
