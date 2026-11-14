//! Moved from `crates/oneiron/src/verbs/calendar.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::calendar::query::requests::CalendarRangeDto;
use crate::calendar::query::requests::CalendarSel;
use serde::Deserialize;
use serde::Serialize;

/// The owner names an existing, configured booking page by its hex entity id.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BookingPageTokenRequest {
    pub page_ref: String,
}

/// The canonical opaque address, not publication or booking authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BookingPageTokenResponse {
    pub page_token: String,
}

/// A move proves authority with this booking's reschedule token only.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum BookingRescheduleRequest {
    Reschedule {
        page_token: String,
        input: crate::booking::agent_api::BookingRescheduleInput,
    },
}

/// A cancellation proves authority with this booking's cancel token only.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum BookingCancelRequest {
    Cancel {
        page_token: String,
        input: crate::booking::agent_api::BookingCancelInput,
    },
}

/// Source-redacted occupancy over an inclusive UTC-seconds window.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarFreebusyRequest {
    pub calendars: Vec<CalendarSel>,
    pub range: CalendarRangeDto,
}

/// One constraint-field turn, addressed by a live public booking-page token.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BookingConstraintTurnRequest {
    pub page_token: String,
    pub turn: BookingConstraintTurnInput,
}

/// The existing public constraint-turn body, shared by both transports.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BookingConstraintTurnInput {
    pub event_type: crate::booking::constraint::EventTypeKey,
    pub window: BookingConstraintTurnWindow,
    pub visitor_tz: String,
    pub free_text: String,
    pub session_ref: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BookingConstraintTurnWindow {
    pub start: u64,
    pub end: u64,
}
