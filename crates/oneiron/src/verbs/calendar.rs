//! Typed booking-page discovery, public lifecycle calls and calendar occupancy inputs.
use serde::{Deserialize, Serialize};

use crate::calendar::{CalendarRangeDto, CalendarSel};

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

/// Public availability, using the canonical booking operation envelope.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum BookingAvailabilityRequest {
    Availability {
        page_token: String,
        input: crate::booking::agent_api::BookingAvailabilityInput,
    },
}

/// The full two-stage book flow, not an implicit confirmation.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum BookingBookRequest {
    Book {
        page_token: String,
        input: crate::booking::agent_api::BookingBookInput,
    },
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
    pub event_type: crate::booking::EventTypeKey,
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

/// Offers, an email continuation, or a deflect; never booking authority.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum BookingConstraintTurnResponse {
    Slots {
        card: crate::lens::GeneratedUiCard,
        flex_used: bool,
        hold: BookingConstraintHoldContext,
    },
    ContinueByEmail {
        continuation: crate::booking::agent_front::ConstraintContinuation,
    },
    Deflect {
        card: crate::lens::GeneratedUiCard,
    },
}

/// The rest of an explicit slot selection's hold input, not a hold itself.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BookingConstraintHoldContext {
    pub event_type: crate::booking::EventTypeKey,
    pub visitor_tz: String,
    pub constraint: crate::booking::ConstraintObject,
    pub session_ref: String,
}
