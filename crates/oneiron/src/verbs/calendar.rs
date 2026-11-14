//! Typed booking-page discovery, public lifecycle calls and calendar occupancy inputs.
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::calendar::{
    BookingCancelRequest, BookingConstraintTurnInput, BookingConstraintTurnRequest,
    BookingConstraintTurnWindow, BookingPageTokenRequest, BookingPageTokenResponse,
    BookingRescheduleRequest, CalendarFreebusyRequest,
};

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
