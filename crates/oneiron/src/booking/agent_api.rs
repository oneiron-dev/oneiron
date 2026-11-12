//! ONE-1819 [BK-08] the agent-readable booking wire.
//!
//! Provider-neutral, versioned data: the instructions document a booking page
//! embeds for machine consumers, and the four structured operation
//! request/response families the shared server executor speaks.
//!
//! Two properties are structural rather than reviewed:
//!
//! * **No `EntityId`.** Pages and bookings are addressed here only by opaque
//!   `String` tokens. There is no field of that type to carry one, so a public
//!   payload cannot leak or accept an internal identifier — resolution happens
//!   inside the server executor, against tokens whose preimage the caller does
//!   not hold.
//! * **No instruction prose.** Endpoint and operation identifiers are stable
//!   machine strings; every visitor-facing sentence is booking-page
//!   configuration, exactly as [`super::agent_front::ConstraintFrontCopy`]
//!   keeps host copy out of engine Rust.
//!
//! This module performs no IO and names no server type. It is the wire, and
//! the wire only.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::booking::{ConstraintObject, EventTypeKey, RankedSlot};
use crate::temporal::TimeRange;

/// Wire version of [`BookingAgentInstructionsBlock`]. A block carrying any
/// other version fails closed rather than being coerced.
pub const BOOKING_AGENT_INSTRUCTIONS_VERSION: u16 = 1;

/// Media type of the embedded instructions block and of the HTTP document it
/// is byte-equivalent to.
pub const BOOKING_AGENT_INSTRUCTIONS_MIME: &str = "application/vnd.oneiron.booking-agent+json";

// -------------------------------------------------------------------------
// TimeRange wire adapter
//
// `crate::temporal::TimeRange` is the ONE time range import path for booking
// and deliberately carries no serde derives, so each booking wire owns its own
// adapter rather than widening the shared temporal type. This mirrors the
// adapter in `super::constraint`.
// -------------------------------------------------------------------------

#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct TimeRangeWire {
    start: u64,
    end: u64,
}

#[doc(hidden)]
pub use oneiron_verb_wire::booking::agent_api::{
    BookingAgentOperation, BookingAvailabilityInput, BookingBookInput, BookingBookResult,
    BookingCancelInput, BookingConfirmInput, BookingConstraintInput, BookingHoldInput,
    BookingIntakeAnswer, BookingOperationResponse, BookingRescheduleInput, SelectedSlot,
};

/// One advertised operation endpoint. `path` is relative and same-origin: a
/// machine consumer resolves it against the origin it fetched the page from,
/// so the block can never redirect a booking to a third party.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingAgentEndpoint {
    pub operation: BookingAgentOperation,
    pub method: String,
    pub path: String,
}

/// The versioned instructions document.
///
/// It carries no credential, no grant, no private calendar data, no owner
/// email, no internal identifier, and no raw constraint sentence — only the
/// page's opaque token, its configured event-type keys, and the operation
/// table.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingAgentInstructionsBlock {
    pub version: u16,
    pub page_token: String,
    pub event_types: Vec<EventTypeKey>,
    pub operations: Vec<BookingAgentEndpoint>,
    pub constraint_schema_version: u16,
}

impl BookingAgentInstructionsBlock {
    /// Fails closed on an unsupported version, a blank page token, an
    /// operation list that is not the canonical four in canonical order, or a
    /// path that is not relative and same-origin.
    ///
    /// # Errors
    ///
    /// [`BookingAgentInstructionsDefect`] naming the first defect found.
    pub fn validate(&self) -> Result<(), BookingAgentInstructionsDefect> {
        if self.version != BOOKING_AGENT_INSTRUCTIONS_VERSION {
            return Err(BookingAgentInstructionsDefect::UnsupportedVersion);
        }
        if self.page_token.trim().is_empty() {
            return Err(BookingAgentInstructionsDefect::BlankPageToken);
        }
        if self.operations.len() != BookingAgentOperation::CANONICAL.len()
            || self
                .operations
                .iter()
                .zip(BookingAgentOperation::CANONICAL)
                .any(|(endpoint, expected)| endpoint.operation != expected)
        {
            return Err(BookingAgentInstructionsDefect::NonCanonicalOperations);
        }
        for endpoint in &self.operations {
            if endpoint.method.trim().is_empty() {
                return Err(BookingAgentInstructionsDefect::BlankMethod);
            }
            if !is_relative_same_origin_path(&endpoint.path) {
                return Err(BookingAgentInstructionsDefect::NonRelativePath);
            }
        }
        Ok(())
    }
}

/// Why one instructions block is unusable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BookingAgentInstructionsDefect {
    UnsupportedVersion,
    BlankPageToken,
    NonCanonicalOperations,
    BlankMethod,
    NonRelativePath,
}

impl BookingAgentInstructionsDefect {
    /// Stable machine reason string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedVersion => "booking agent instructions version is unsupported",
            Self::BlankPageToken => "booking agent instructions page token must not be blank",
            Self::NonCanonicalOperations => {
                "booking agent instructions must list availability, book, reschedule, cancel in that order"
            }
            Self::BlankMethod => "booking agent instructions method must not be blank",
            Self::NonRelativePath => {
                "booking agent instructions path must be relative and same-origin"
            }
        }
    }
}

/// A same-origin relative path starts at the origin root and names no scheme,
/// authority, or protocol-relative prefix.
fn is_relative_same_origin_path(path: &str) -> bool {
    path.starts_with('/') && !path.starts_with("//") && !path.contains("://")
}

/// The closed request union the shared executor accepts. HTTP routes and the
/// MCP tool both build this, so neither transport can grow an operation the
/// other does not have.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", content = "input", rename_all = "snake_case")]
pub enum BookingOperationRequest {
    Availability(BookingAvailabilityInput),
    Book(BookingBookInput),
    Reschedule(BookingRescheduleInput),
    Cancel(BookingCancelInput),
}

impl BookingOperationRequest {
    /// Which advertised operation this request is.
    #[must_use]
    pub const fn operation(&self) -> BookingAgentOperation {
        match self {
            Self::Availability(_) => BookingAgentOperation::Availability,
            Self::Book(_) => BookingAgentOperation::Book,
            Self::Reschedule(_) => BookingAgentOperation::Reschedule,
            Self::Cancel(_) => BookingAgentOperation::Cancel,
        }
    }
}
