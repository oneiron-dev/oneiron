//! Moved from `crates/oneiron/src/booking/agent_api.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::booking::constraint::RankedSlot;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

// -------------------------------------------------------------------------
// Instructions document
// -------------------------------------------------------------------------

/// The closed operation set a booking page advertises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BookingAgentOperation {
    Availability,
    Book,
    Reschedule,
    Cancel,
}

impl BookingAgentOperation {
    /// Canonical order: availability, book, reschedule, cancel. A block that
    /// listed them in any other order would hash differently for the same
    /// page, so the order is data, not presentation.
    pub const CANONICAL: [Self; 4] = [
        Self::Availability,
        Self::Book,
        Self::Reschedule,
        Self::Cancel,
    ];

    /// Stable machine identifier. It is the same string the `op`
    /// discriminator carries on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Availability => "availability",
            Self::Book => "book",
            Self::Reschedule => "reschedule",
            Self::Cancel => "cancel",
        }
    }
}

/// One concrete UTC slot the caller picked out of an availability answer.
/// Half-open `[start_utc, end_utc)`, the oracle's own convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectedSlot {
    pub start_utc: u64,
    pub end_utc: u64,
}

/// One answer to one configured intake field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BookingIntakeAnswer {
    pub field_key: String,
    pub value: String,
}

/// Stage two of booking: convert a live hold into a booking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BookingConfirmInput {
    pub hold_token: String,
    pub booker_email: String,
    pub intake: Vec<BookingIntakeAnswer>,
    pub session_ref: String,
    /// Replay hygiene only.
    pub idempotency_key: String,
}

/// Move a booking, proving authority with its action-scoped reschedule token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BookingRescheduleInput {
    pub reschedule_token: String,
    pub selected_slot: SelectedSlot,
    pub visitor_tz: String,
    /// Replay hygiene only.
    pub idempotency_key: String,
}

/// Cancel a booking, proving authority with its action-scoped cancel token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BookingCancelInput {
    pub cancel_token: String,
    /// Replay hygiene only.
    pub idempotency_key: String,
}

// -------------------------------------------------------------------------
// Operation results
// -------------------------------------------------------------------------

/// What one book stage decided.
///
/// `SlotTaken` is a result, not an error: the lifecycle transition ran,
/// decided nothing was writable, and returned the same oracle's nearest
/// alternatives.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "stage", content = "result", rename_all = "snake_case")]
pub enum BookingBookResult {
    Held {
        hold_token: String,
        selected_slot: SelectedSlot,
        /// Server-capped expiry. The caller never chose it.
        expires_at: u64,
    },
    Confirmed {
        reschedule_token: String,
        cancel_token: String,
    },
    SlotTaken {
        alternatives: Vec<RankedSlot>,
    },
}

/// The closed response union.
///
/// Availability projects ranked public slots and the flex flag and nothing
/// else — no titles, descriptions, attendees, busy sources, or free/busy
/// internals can be expressed here. Mutations project only action-safe opaque
/// tokens.
///
/// `Book` carries [`BookingBookResult`] directly, exactly as
/// [`BookingOperationRequest::Book`] carries [`BookingBookInput`] directly: one
/// `op`/`result` envelope around one `stage`/`result` envelope, so a request
/// and its answer nest to the same depth. A named field here would wrap the
/// stage union in a second `result` object the request side has no counterpart
/// for.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "op", content = "result", rename_all = "snake_case")]
pub enum BookingOperationResponse {
    Availability {
        slots: Vec<RankedSlot>,
        flex_used: bool,
    },
    Book(BookingBookResult),
    Reschedule {
        reschedule_token: String,
    },
    Cancel {
        cancel_token: String,
    },
}

impl BookingOperationResponse {
    /// Which advertised operation answered.
    #[must_use]
    pub const fn operation(&self) -> BookingAgentOperation {
        match self {
            Self::Availability { .. } => BookingAgentOperation::Availability,
            Self::Book(_) => BookingAgentOperation::Book,
            Self::Reschedule { .. } => BookingAgentOperation::Reschedule,
            Self::Cancel { .. } => BookingAgentOperation::Cancel,
        }
    }
}
