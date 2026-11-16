//! Moved from `crates/oneiron/src/booking/lifecycle/types.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::booking::lifecycle::entity_ref_serde;
use crate::booking::lifecycle::entity_refs_serde;
use crate::booking::lifecycle::token::OpaqueLifecycleToken;
use crate::booking::lifecycle::token::SessionKey;
use oneiron_contracts::entity_id::EntityId;
use oneiron_verb_wire::booking::constraint::EventTypeKey;
use serde::Deserialize;
use serde::Serialize;

/// The closed verb table, sorted so the wire spellings live in one place.
pub const BOOKING_VERBS: [&str; 4] = [
    "booking.cancel",
    "booking.confirm",
    "booking.hold",
    "booking.reschedule",
];

/// The closed booking verb enum, mirroring `task_verb.rs`'s typed verb shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BookingVerb {
    Cancel,
    Confirm,
    Hold,
    Reschedule,
}

impl BookingVerb {
    /// The pinned wire spelling, read out of [`BOOKING_VERBS`] so the enum and
    /// the sorted table cannot drift apart.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cancel => BOOKING_VERBS[0],
            Self::Confirm => BOOKING_VERBS[1],
            Self::Hold => BOOKING_VERBS[2],
            Self::Reschedule => BOOKING_VERBS[3],
        }
    }

    /// Parses a wire spelling, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "booking.cancel" => Some(Self::Cancel),
            "booking.confirm" => Some(Self::Confirm),
            "booking.hold" => Some(Self::Hold),
            "booking.reschedule" => Some(Self::Reschedule),
            _ => None,
        }
    }
}

/// Ask to convert a live hold into a booking.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfirmSpec {
    pub hold_token: OpaqueLifecycleToken,
    pub session_key: SessionKey,
    #[serde(with = "entity_ref_serde")]
    pub booker_contact: EntityId,
    /// Short pre-confirm intake; persisted with the confirmation context so
    /// delivery and later progressive intake can read the same answers.
    #[serde(default)]
    pub intake: Vec<oneiron_verb_wire::booking::agent_api::BookingIntakeAnswer>,
    /// Retry hygiene only.
    pub idempotency_key: Option<String>,
}

/// Ask to cancel a booking, proving authority with its cancel token.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CancelSpec {
    pub token: OpaqueLifecycleToken,
    pub idempotency_key: Option<String>,
}

/// What one opaque token is allowed to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleTokenScope {
    Reschedule,
    Cancel,
}

impl LifecycleTokenScope {
    /// The scope's domain tag, so one booking's two credentials can never derive
    /// to the same value and a reschedule receipt can never alias a cancel one.
    pub const fn tag(self) -> &'static [u8] {
        match self {
            Self::Reschedule => b"reschedule\0",
            Self::Cancel => b"cancel\0",
        }
    }
}

/// A booking's live status. Changes go through supersession, never mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BookingStatus {
    Confirmed,
    Cancelled,
}

impl BookingStatus {
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Confirmed => b"confirmed",
            Self::Cancelled => b"cancelled",
        }
    }
}

/// The `{event_ref, uid, sequence}` triple a lifecycle receipt exposes. BK-03
/// turns this into `calendar.invite`; this ticket dispatches nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalendarRevision {
    #[serde(with = "entity_ref_serde")]
    pub event_ref: EntityId,
    pub uid: String,
    pub sequence: u32,
}

/// Value of a `booking.event_type_ref` claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingEventTypeRefValue {
    pub event_type: EventTypeKey,
}

/// Value of a `booking.booker_contact` claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingBookerContactValue {
    #[serde(with = "entity_ref_serde")]
    pub contact_ref: EntityId,
}

/// Value of a `booking.source_page` claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingSourcePageValue {
    #[serde(with = "entity_ref_serde")]
    pub page_ref: EntityId,
}

/// Value of a `booking.status` claim. Calendar UID and sequence are
/// deliberately absent: passport claims are their only home.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingStatusValue {
    pub status: BookingStatus,
    pub recorded_at: u64,
}

/// What a successful confirm returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmReceipt {
    pub calendar: CalendarRevision,
    pub reschedule_token: OpaqueLifecycleToken,
    pub cancel_token: OpaqueLifecycleToken,
    /// While the Gate holds this booking's confirm invite for the owner, the
    /// approve-once digest his one-time press must name to release it, 64
    /// lower-hex (FIX 6424), copied from the invite's dispatch result. The
    /// confirm stands either way. Absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_digest: Option<String>,
    /// The rows the confirm writer read (FIX 5483): every row its
    /// availability re-solve listed. A replay returns the first pass's.
    #[serde(default, with = "entity_refs_serde")]
    pub reads: Vec<EntityId>,
}

/// What a successful reschedule or cancel returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionReceipt {
    pub calendar: CalendarRevision,
    /// The rows the writer read (FIX 5483): the booking EVENT and every claim
    /// on it, and for a move every row its re-solve listed. A replay returns
    /// the first pass's.
    #[serde(default, with = "entity_refs_serde")]
    pub reads: Vec<EntityId>,
}
