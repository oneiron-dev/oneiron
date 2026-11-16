//! Moved from `crates/oneiron/src/booking/agent_api.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::booking::agent_api::BookingAgentOperation;
pub use oneiron_verb_wire::booking::agent_api::BookingBookResult;
pub use oneiron_verb_wire::booking::agent_api::BookingCancelInput;
pub use oneiron_verb_wire::booking::agent_api::BookingConfirmInput;
pub use oneiron_verb_wire::booking::agent_api::BookingIntakeAnswer;
pub use oneiron_verb_wire::booking::agent_api::BookingOperationResponse;
pub use oneiron_verb_wire::booking::agent_api::BookingRescheduleInput;
pub use oneiron_verb_wire::booking::agent_api::SelectedSlot;
use oneiron_verb_wire::booking::constraint::EventTypeKey;
use serde::Deserialize;
use serde::Serialize;

/// Wire version of [`BookingAgentInstructionsBlock`]. A block carrying any
/// other version fails closed rather than being coerced.
pub const BOOKING_AGENT_INSTRUCTIONS_VERSION: u16 = 1;

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
pub fn is_relative_same_origin_path(path: &str) -> bool {
    path.starts_with('/') && !path.starts_with("//") && !path.contains("://")
}
