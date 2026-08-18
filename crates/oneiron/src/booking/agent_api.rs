//! ONE-1819 [BK-08] agent-readable booking wire data.
//!
//! Provider-neutral, versioned data ONLY. This module owns the embedded
//! instructions document and the four structured booking operation
//! request/response families, and nothing else: no transport, no vault access,
//! no solver, no lifecycle, and no page copy.
//!
//! Two invariants are mechanical rather than editorial:
//!
//! * **No [`crate::EntityId`].** Public booking data addresses pages and
//!   bookings only by opaque `String` tokens the server resolves internally.
//!   The identifier type is deliberately absent from this file so a future
//!   edit cannot quietly widen the public surface into an internal handle.
//! * **No English prose.** Endpoint and operation identifiers are stable
//!   machine strings; every human- or agent-facing explanatory sentence is
//!   booking-page configuration supplied by the host, never a Rust constant.
//!
//! The seam types this module composes over — [`ConstraintObject`],
//! [`EventTypeKey`], [`RankedSlot`] — are ONE-1816's and are imported, never
//! redefined.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::booking::{ConstraintObject, EventTypeKey, RankedSlot};
use crate::temporal::TimeRange;

/// Wire version of the agent instructions document. A block carrying any other
/// version fails closed rather than being coerced.
pub const BOOKING_AGENT_INSTRUCTIONS_VERSION: u16 = 1;

/// Media type of the embedded instructions fragment and of the
/// `agent-instructions` endpoint's canonical document.
pub const BOOKING_AGENT_INSTRUCTIONS_MIME: &str = "application/vnd.oneiron.booking-agent+json";

// -------------------------------------------------------------------------
// TimeRange wire adapter
//
// `crate::temporal::TimeRange` is the ONE time range import path for booking
// and deliberately carries no serde derives. ONE-1816 owns its own private
// adapter for the seam types; this module owns this one for its own DTOs
// rather than widening the shared temporal type or forking the seam.
// -------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TimeRangeWire {
    start: u64,
    end: u64,
}

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

// -------------------------------------------------------------------------
// Instructions document
// -------------------------------------------------------------------------

/// The closed operation set one booking page exposes to an agent.
///
/// The catalog grows operations, never a fifth transport verb: the HTTP routes
/// and the single `oneiron.book` MCP tool both discriminate on exactly these
/// four values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BookingAgentOperation {
    Availability,
    Book,
    Reschedule,
    Cancel,
}

impl BookingAgentOperation {
    /// Canonical order: availability, book, reschedule, cancel. Every producer
    /// of an instructions block reads this constant instead of hand-listing the
    /// operations, so the advertised order cannot drift between transports.
    pub const CANONICAL_ORDER: [Self; 4] = [
        Self::Availability,
        Self::Book,
        Self::Reschedule,
        Self::Cancel,
    ];

    /// The stable machine identifier for this operation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Availability => "availability",
            Self::Book => "book",
            Self::Reschedule => "reschedule",
            Self::Cancel => "cancel",
        }
    }

    /// Parses a machine identifier. Unknown spellings fail closed.
    #[must_use]
    pub fn from_str_exact(value: &str) -> Option<Self> {
        match value {
            "availability" => Some(Self::Availability),
            "book" => Some(Self::Book),
            "reschedule" => Some(Self::Reschedule),
            "cancel" => Some(Self::Cancel),
            _ => None,
        }
    }
}

/// One advertised endpoint. `path` is same-origin and relative by contract; a
/// block carrying an absolute or cross-origin path is invalid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingAgentEndpoint {
    pub operation: BookingAgentOperation,
    pub method: String,
    pub path: String,
}

/// The versioned document a booking page embeds for visiting agents.
///
/// It carries no credential, grant, private calendar title, busy interval,
/// owner email, internal identifier, or raw constraint sentence — none of those
/// has a field to travel in.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingAgentInstructionsBlock {
    pub version: u16,
    pub page_token: String,
    pub event_types: Vec<EventTypeKey>,
    pub operations: Vec<BookingAgentEndpoint>,
    pub constraint_schema_version: u16,
}

/// Why an instructions block is not usable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BookingAgentInstructionsDefect {
    /// `version` is not [`BOOKING_AGENT_INSTRUCTIONS_VERSION`].
    UnsupportedVersion(u16),
    /// `page_token` is blank.
    BlankPageToken,
    /// `page_token` is shaped like a canonical 32-hex entity id.
    PageTokenLooksLikeEntityId,
    /// Operations are absent, duplicated, or not in canonical order.
    NonCanonicalOperations,
    /// An advertised path is absolute, cross-origin, or blank.
    NonRelativePath(String),
    /// A method is not one this contract advertises.
    UnsupportedMethod(String),
    /// `constraint_schema_version` is not ONE-1816's pinned version.
    UnsupportedConstraintSchemaVersion(u16),
}

impl core::fmt::Display for BookingAgentInstructionsDefect {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => write!(
                f,
                "booking agent instructions version must be {BOOKING_AGENT_INSTRUCTIONS_VERSION}, got {version}"
            ),
            Self::BlankPageToken => f.write_str("booking agent page token must not be blank"),
            Self::PageTokenLooksLikeEntityId => {
                f.write_str("booking agent page token must not be an internal entity id")
            }
            Self::NonCanonicalOperations => f.write_str(
                "booking agent operations must be availability, book, reschedule, cancel in that exact order",
            ),
            Self::NonRelativePath(path) => {
                write!(f, "booking agent endpoint path must be same-origin relative: {path}")
            }
            Self::UnsupportedMethod(method) => {
                write!(f, "booking agent endpoint method is not advertised: {method}")
            }
            Self::UnsupportedConstraintSchemaVersion(version) => write!(
                f,
                "booking agent constraint schema version must be {}, got {version}",
                crate::booking::constraint::CONSTRAINT_SCHEMA_VERSION
            ),
        }
    }
}

impl BookingAgentInstructionsBlock {
    /// Fails closed on an unsupported version, an entity-id-shaped page token,
    /// a non-canonical operation list, or a path that is not same-origin
    /// relative.
    ///
    /// # Errors
    ///
    /// [`BookingAgentInstructionsDefect`] naming the first defect found.
    pub fn validate(&self) -> Result<(), BookingAgentInstructionsDefect> {
        if self.version != BOOKING_AGENT_INSTRUCTIONS_VERSION {
            return Err(BookingAgentInstructionsDefect::UnsupportedVersion(
                self.version,
            ));
        }
        if self.page_token.trim().is_empty() {
            return Err(BookingAgentInstructionsDefect::BlankPageToken);
        }
        if is_entity_id_shaped(&self.page_token) {
            return Err(BookingAgentInstructionsDefect::PageTokenLooksLikeEntityId);
        }
        if self.operations.len() != BookingAgentOperation::CANONICAL_ORDER.len()
            || self
                .operations
                .iter()
                .zip(BookingAgentOperation::CANONICAL_ORDER)
                .any(|(endpoint, expected)| endpoint.operation != expected)
        {
            return Err(BookingAgentInstructionsDefect::NonCanonicalOperations);
        }
        for endpoint in &self.operations {
            if !matches!(endpoint.method.as_str(), "GET" | "POST") {
                return Err(BookingAgentInstructionsDefect::UnsupportedMethod(
                    endpoint.method.clone(),
                ));
            }
            if !is_same_origin_relative(&endpoint.path) {
                return Err(BookingAgentInstructionsDefect::NonRelativePath(
                    endpoint.path.clone(),
                ));
            }
        }
        if self.constraint_schema_version != crate::booking::constraint::CONSTRAINT_SCHEMA_VERSION {
            return Err(
                BookingAgentInstructionsDefect::UnsupportedConstraintSchemaVersion(
                    self.constraint_schema_version,
                ),
            );
        }
        Ok(())
    }
}

/// A canonical 32-character lowercase hex id — the shape a public token must
/// never take.
fn is_entity_id_shaped(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Same-origin relative: begins with a single `/`, and carries no scheme,
/// authority, backslash, or control character.
fn is_same_origin_relative(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && !path.contains("://")
        && !path.contains('\\')
        && !path.bytes().any(|byte| byte.is_ascii_control())
}

// -------------------------------------------------------------------------
// Operation inputs
// -------------------------------------------------------------------------

/// What an agent may send as a scheduling preference.
///
/// `FreeText` is bounded input for ONE-1816's parser, never solver input: the
/// executor replaces it with a canonical [`ConstraintObject`] before any solve,
/// and [`crate::booking::SolveRequest`] has no field a sentence could ride in.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum BookingConstraintInput {
    Object(ConstraintObject),
    FreeText(String),
}

/// `POST .../availability` input.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingAvailabilityInput {
    pub event_type: EventTypeKey,
    #[serde(with = "time_range_serde")]
    pub window: TimeRange,
    pub visitor_tz: String,
    pub constraint: Option<BookingConstraintInput>,
    pub session_ref: String,
}

/// One concrete UTC slot the agent chose from an availability answer.
///
/// Half-open `[start_utc, end_utc)`, matching the oracle's own convention. A
/// caller does not get to round, widen, or invent these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedSlot {
    pub start_utc: u64,
    pub end_utc: u64,
}

/// One intake answer. Field keys are host configuration; the engine pins none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingIntakeAnswer {
    pub field_key: String,
    pub value: String,
}

/// `book:hold` input.
///
/// There is no TTL field, by construction: a hold's lifetime is the server
/// default, or the cap a verified server-issued checkout lease allows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingHoldInput {
    pub event_type: EventTypeKey,
    pub selected_slot: SelectedSlot,
    pub visitor_tz: String,
    pub constraint: Option<ConstraintObject>,
    pub session_ref: String,
    pub checkout_lease_token: Option<String>,
    /// Replay hygiene only. Lifecycle revalidation on the home-node writer is
    /// what makes a confirm correct.
    pub idempotency_key: String,
}

/// `book:confirm` input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingConfirmInput {
    pub hold_token: String,
    pub booker_email: String,
    pub intake: Vec<BookingIntakeAnswer>,
    pub session_ref: String,
    pub idempotency_key: String,
}

/// The typed two-stage book flow.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "stage", content = "input", rename_all = "snake_case")]
pub enum BookingBookInput {
    Hold(BookingHoldInput),
    Confirm(BookingConfirmInput),
}

/// `POST .../reschedule` input. Authority is the action-scoped token, never an
/// internal booking identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingRescheduleInput {
    pub reschedule_token: String,
    pub selected_slot: SelectedSlot,
    pub visitor_tz: String,
    pub idempotency_key: String,
}

/// `POST .../cancel` input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingCancelInput {
    pub cancel_token: String,
    pub idempotency_key: String,
}

/// The closed request union both transports carry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", content = "input", rename_all = "snake_case")]
pub enum BookingOperationRequest {
    Availability(BookingAvailabilityInput),
    Book(BookingBookInput),
    Reschedule(BookingRescheduleInput),
    Cancel(BookingCancelInput),
}

impl BookingOperationRequest {
    /// Which operation this request is.
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

// -------------------------------------------------------------------------
// Operation results
// -------------------------------------------------------------------------

/// What the book flow returns.
///
/// `SlotTaken` is a result, not an error: the transition ran, decided nothing
/// was writable, and returned the same solver's nearest alternatives.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "stage", content = "result", rename_all = "snake_case")]
pub enum BookingBookResult {
    Held {
        hold_token: String,
        selected_slot: SelectedSlot,
        /// Server-capped expiry. No caller proposed it.
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

/// The closed response union both transports serialize.
///
/// Availability carries ranked slots and the flex flag and nothing else: there
/// is no field for an event title, description, attendee, busy source, or
/// free/busy internal. Mutations carry only action-scoped opaque tokens.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", content = "result", rename_all = "snake_case")]
pub enum BookingOperationResponse {
    Availability {
        slots: Vec<RankedSlot>,
        flex_used: bool,
    },
    Book {
        result: BookingBookResult,
    },
    Reschedule {
        reschedule_token: String,
    },
    Cancel {
        cancel_token: String,
    },
}

impl BookingOperationResponse {
    /// Which operation produced this response.
    #[must_use]
    pub const fn operation(&self) -> BookingAgentOperation {
        match self {
            Self::Availability { .. } => BookingAgentOperation::Availability,
            Self::Book { .. } => BookingAgentOperation::Book,
            Self::Reschedule { .. } => BookingAgentOperation::Reschedule,
            Self::Cancel { .. } => BookingAgentOperation::Cancel,
        }
    }
}
