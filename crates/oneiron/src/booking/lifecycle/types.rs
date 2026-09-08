//! The lifecycle's domain types: pinned constants and predicates, the verb
//! enum, the request specs, the hold row, token scope, claim values, receipts,
//! the attempt payload, and the request validators.

use serde::{Deserialize, Serialize};

use super::storage::refused;
use super::token::{HoldLeaseSpec, OpaqueLifecycleToken, SessionKey, TOKEN_RAW_BYTES};
use super::{digest_serde, entity_ref_serde, opt_digest_serde, time_range_serde};
use crate::EntityId;
use crate::booking::constraint::validate_visitor_tz;
use crate::booking::{BookingError, ConstraintObject, EventTypeKey, RankedSlot};
use crate::temporal::TimeRange;

/// Attempt kind the home-node lifecycle consumer claims.
pub const BOOKING_LIFECYCLE_ATTEMPT_KIND: &str = "booking.lifecycle.macro";

/// `vault_meta` prefix for session-keyed soft-hold rows.
pub const BOOKING_HOLD_META_PREFIX: &[u8] = b"booking.hold.v1:";

/// `vault_meta` prefix for opaque-token digest rows.
pub const BOOKING_TOKEN_META_PREFIX: &[u8] = b"booking.token.v1:";

/// `vault_meta` prefix for durable lifecycle receipts.
pub const BOOKING_RECEIPT_META_PREFIX: &[u8] = b"booking.lifecycle.receipt.v1:";

/// The ordinary hold lifetime, and its own server cap: a caller has no TTL
/// input at all, so this is both the default and the maximum for an ordinary
/// hold.
pub const DEFAULT_HOLD_TTL_SECS: u64 = 5 * 60;

/// Server cap on an extended (checkout) hold. An extension can only ever
/// shorten to its verified lease; it can never exceed this.
pub const MAX_CHECKOUT_HOLD_TTL_SECS: u64 = 30 * 60;

/// The closed verb table, sorted so the wire spellings live in one place.
pub const BOOKING_VERBS: [&str; 4] = [
    "booking.cancel",
    "booking.confirm",
    "booking.hold",
    "booking.reschedule",
];

/// Exact predicate: which host event type this booking realizes.
pub const BOOKING_EVENT_TYPE_REF_PREDICATE: &str = "booking.event_type_ref";

/// Exact predicate: who booked.
pub const BOOKING_BOOKER_CONTACT_PREDICATE: &str = "booking.booker_contact";

/// Exact predicate: which page the booking came from.
pub const BOOKING_SOURCE_PAGE_PREDICATE: &str = "booking.source_page";

/// Exact predicate: the booking's live status.
pub const BOOKING_STATUS_PREDICATE: &str = "booking.status";

/// The lifecycle claim family, as an exact table. A `booking.` prefix would
/// silently adopt every future booking predicate into this validator.
pub const BOOKING_LIFECYCLE_PREDICATES: [&str; 4] = [
    BOOKING_BOOKER_CONTACT_PREDICATE,
    BOOKING_EVENT_TYPE_REF_PREDICATE,
    BOOKING_SOURCE_PAGE_PREDICATE,
    BOOKING_STATUS_PREDICATE,
];

/// The passport `system` a booking's outbound calendar identity carries. One
/// live passport per `(system × UID)` is CAL-02's invariant; this is the
/// engine's own outbound system name.
pub const BOOKING_PASSPORT_SYSTEM: &str = "oneiron.booking";

/// Bound on an advisory idempotency key.
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;

/// Bound on the failure reason stamped onto a failed attempt row.
pub(super) const MAX_ATTEMPT_FAILURE_REASON_BYTES: usize = 512;

/// How far either side of a held slot confirm's re-solve looks.
///
/// Confirm must answer a taken slot with the SAME solver's nearest
/// alternatives, which a window equal to the held slot cannot contain. The
/// solver still clips every solve to the page's own booking horizon, so this
/// widens the ANSWER, never the work bound.
pub(super) const CONFIRM_ALTERNATIVES_PAD_SECS: u64 = 24 * 60 * 60;

/// Row-format byte on every lifecycle `vault_meta` value.
pub(super) const LIFECYCLE_ROW_VERSION: u8 = 1;

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

/// Ask to soft-hold one solved slot.
///
/// `slot` is the half-open UTC interval `[start, end)` the oracle emitted — the
/// solver's convention, carried in the one [`TimeRange`] import path booking
/// uses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HoldSpec {
    #[serde(with = "entity_ref_serde")]
    pub page_ref: EntityId,
    pub event_type: EventTypeKey,
    #[serde(with = "time_range_serde")]
    pub slot: TimeRange,
    pub session_key: SessionKey,
    pub visitor_tz: String,
    pub constraint: Option<ConstraintObject>,
    pub lease: HoldLeaseSpec,
    /// Retry hygiene only. It becomes the attempt-queue dedupe string and takes
    /// no part in mutual exclusion or in receipt identity.
    pub idempotency_key: Option<String>,
}

/// Ask to convert a live hold into a booking.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfirmSpec {
    pub hold_token: OpaqueLifecycleToken,
    pub session_key: SessionKey,
    #[serde(with = "entity_ref_serde")]
    pub booker_contact: EntityId,
    /// Retry hygiene only.
    pub idempotency_key: Option<String>,
}

/// Ask to move a booking, proving authority with its reschedule token.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RescheduleSpec {
    pub token: OpaqueLifecycleToken,
    #[serde(with = "time_range_serde")]
    pub new_slot: TimeRange,
    pub visitor_tz: String,
    pub constraint: Option<ConstraintObject>,
    pub idempotency_key: Option<String>,
}

/// Ask to cancel a booking, proving authority with its cancel token.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CancelSpec {
    pub token: OpaqueLifecycleToken,
    pub idempotency_key: Option<String>,
}

/// The closed request union one attempt carries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BookingVerbRequest {
    Hold(HoldSpec),
    Confirm(ConfirmSpec),
    Reschedule(RescheduleSpec),
    Cancel(CancelSpec),
}

impl BookingVerbRequest {
    /// Which verb this request is.
    #[must_use]
    pub const fn verb(&self) -> BookingVerb {
        match self {
            Self::Hold(_) => BookingVerb::Hold,
            Self::Confirm(_) => BookingVerb::Confirm,
            Self::Reschedule(_) => BookingVerb::Reschedule,
            Self::Cancel(_) => BookingVerb::Cancel,
        }
    }

    /// The advisory idempotency key, if the caller supplied one.
    #[must_use]
    pub fn idempotency_key(&self) -> Option<&str> {
        match self {
            Self::Hold(spec) => spec.idempotency_key.as_deref(),
            Self::Confirm(spec) => spec.idempotency_key.as_deref(),
            Self::Reschedule(spec) => spec.idempotency_key.as_deref(),
            Self::Cancel(spec) => spec.idempotency_key.as_deref(),
        }
    }
}

/// One session's active soft hold.
///
/// Stored under [`BOOKING_HOLD_META_PREFIX`] keyed by the session, so a new
/// hold for the same session replaces the prior row by construction. ONE-1817
/// owns HTTP/IP/email abuse policy; this row is only the storage invariant that
/// one active hold per session needs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SoftHoldRow {
    #[serde(with = "entity_ref_serde")]
    pub page_ref: EntityId,
    pub event_type: EventTypeKey,
    #[serde(with = "time_range_serde")]
    pub slot: TimeRange,
    pub session_key: SessionKey,
    pub visitor_tz: String,
    pub constraint: Option<ConstraintObject>,
    #[serde(with = "digest_serde")]
    pub token_hash: [u8; 32],
    pub expires_at: u64,
    #[serde(with = "opt_digest_serde")]
    pub checkout_lease_hash: Option<[u8; 32]>,
}

impl SoftHoldRow {
    /// Lazy expiry: `expires_at == now` is already dead. Nothing wakes to
    /// enforce this — a read that sees a dead row simply does not see a hold.
    #[must_use]
    pub const fn is_live_at(&self, now_utc: u64) -> bool {
        self.expires_at > now_utc
    }
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
    pub(super) const fn tag(self) -> &'static [u8] {
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
    pub(super) const fn as_bytes(self) -> &'static [u8] {
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

/// What a successful hold returns. The bearer token appears here and never
/// again.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HoldReceipt {
    pub token: OpaqueLifecycleToken,
    #[serde(with = "time_range_serde")]
    pub slot: TimeRange,
    pub expires_at: u64,
}

/// What a successful confirm returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmReceipt {
    pub calendar: CalendarRevision,
    pub reschedule_token: OpaqueLifecycleToken,
    pub cancel_token: OpaqueLifecycleToken,
}

/// What a successful reschedule or cancel returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionReceipt {
    pub calendar: CalendarRevision,
}

/// The closed receipt union.
///
/// `SlotTaken` is a receipt, not an error: the transition ran, decided nothing
/// was writable, and returned the same solver's nearest alternatives with no
/// EVENT, claim, or passport written.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BookingVerbReceipt {
    Held(HoldReceipt),
    Confirmed(ConfirmReceipt),
    Rescheduled(RevisionReceipt),
    Cancelled(RevisionReceipt),
    SlotTaken { alternatives: Vec<RankedSlot> },
}

/// The typed attempt payload the generic queue row carries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BookingLifecycleAttempt {
    pub request: BookingVerbRequest,
    pub requested_at: u64,
    /// Server-derived public snapshot. Persisted so delayed consumers cannot
    /// lose the requirement to recheck publication in their writer.
    #[serde(default)]
    pub public_authority: Option<crate::booking::publication::PublicBookingAuthority>,
}

pub(super) fn validate_request(request: &BookingVerbRequest) -> Result<(), BookingError> {
    validate_idempotency_key(request.idempotency_key())?;
    match request {
        BookingVerbRequest::Hold(spec) => validate_hold_spec(spec),
        BookingVerbRequest::Confirm(spec) => validate_token_shape(&spec.hold_token.0),
        BookingVerbRequest::Reschedule(spec) => {
            validate_token_shape(&spec.token.0)?;
            validate_visitor_tz(&spec.visitor_tz)?;
            validate_slot(spec.new_slot)?;
            validate_optional_constraint(spec.constraint.as_ref())
        }
        BookingVerbRequest::Cancel(spec) => validate_token_shape(&spec.token.0),
    }
}

fn validate_hold_spec(spec: &HoldSpec) -> Result<(), BookingError> {
    validate_visitor_tz(&spec.visitor_tz)?;
    validate_slot(spec.slot)?;
    validate_optional_constraint(spec.constraint.as_ref())?;
    if let HoldLeaseSpec::CheckoutExtension {
        server_issued_lease,
    } = &spec.lease
    {
        validate_token_shape(&server_issued_lease.0)?;
    }
    Ok(())
}

fn validate_optional_constraint(constraint: Option<&ConstraintObject>) -> Result<(), BookingError> {
    constraint.map_or(Ok(()), ConstraintObject::validate)
}

fn validate_idempotency_key(key: Option<&str>) -> Result<(), BookingError> {
    match key {
        Some(key) if key.is_empty() || key.len() > MAX_IDEMPOTENCY_KEY_BYTES => Err(refused(
            "idempotency key must be 1..=128 bytes when supplied",
        )),
        _ => Ok(()),
    }
}

/// A slot is a half-open UTC interval, so an empty or inverted one is refused
/// before it can become a hold nobody could confirm.
fn validate_slot(slot: TimeRange) -> Result<(), BookingError> {
    if slot.start >= slot.end {
        return Err(refused("booking slot must satisfy start < end"));
    }
    Ok(())
}

/// A bearer credential is exactly the lowercase hex of [`TOKEN_RAW_BYTES`]
/// random bytes. Anything else cannot have come from this module and is refused
/// before it reaches a digest lookup.
fn validate_token_shape(token: &str) -> Result<(), BookingError> {
    let well_formed = token.len() == TOKEN_RAW_BYTES * 2
        && token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if well_formed {
        Ok(())
    } else {
        Err(refused("opaque token is not a well-formed bearer value"))
    }
}
