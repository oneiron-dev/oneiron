//! Engine-generic booking module.
//!
//! Declarations, re-exports, and the `booking.*` claim-family aggregation.
//! Every seam type is defined in [`constraint`], which is the single home later
//! booking layers import from. This file defines no domain type and allocates no
//! entity byte.

pub mod agent_front;
pub mod config;
pub mod constraint;
pub mod disclosure_rung;
pub mod lifecycle;
pub mod solver;
#[cfg(test)]
mod tests;

pub use config::{
    BOOKING_EVENT_TYPE_META_PREFIX, BOOKING_EVENT_TYPE_PREDICATE,
    BOOKING_EVENT_TYPE_SCHEMA_VERSION, BookingEventTypeClaimValue, ClaimClassDescriptorRow,
    DEFAULT_INTRO_DURATION_MIN, DEFAULT_MIN_NOTICE_SECS, EventTypeConfig,
    HIGH_VALUE_MIN_NOTICE_SECS, HostAvailabilityConfig, MAX_BOOKING_WINDOW_SECS, RoutingMode,
    WeeklyWallWindow, decode_event_type_claim_value, encode_event_type_claim_value,
    event_type_index_key, is_booking_claim_predicate,
};
pub use constraint::{
    BookingError, ConstraintObject, EventTypeKey, RankedSlot, SlotMask, SlotOracle, SolveRequest,
    SolveResult,
};
pub use disclosure_rung::{
    BusyBlockRow, CalendarDisclosureDefault, DisclosureRung, EventDetailsRow, EventRow,
    RungProjection, SurfaceClass, TitledEventRow, default_disclosure_rung, project_at_rung,
    project_calendar_grant,
};
pub use lifecycle::{
    BOOKING_BOOKER_CONTACT_PREDICATE, BOOKING_EVENT_TYPE_REF_PREDICATE, BOOKING_HOLD_META_PREFIX,
    BOOKING_LIFECYCLE_ATTEMPT_KIND, BOOKING_LIFECYCLE_PREDICATES, BOOKING_PASSPORT_SYSTEM,
    BOOKING_RECEIPT_META_PREFIX, BOOKING_SOURCE_PAGE_PREDICATE, BOOKING_STATUS_PREDICATE,
    BOOKING_TOKEN_META_PREFIX, BOOKING_VERBS, BookingBookerContactValue, BookingEventTypeRefValue,
    BookingLifecycleAttempt, BookingLifecycleConsumerInput, BookingLifecycleTurn,
    BookingOracleRequest, BookingSourcePageValue, BookingStatus, BookingStatusValue, BookingVerb,
    BookingVerbReceipt, BookingVerbRequest, CalendarRevision, CancelSpec, ConfirmReceipt,
    ConfirmSpec, DEFAULT_HOLD_TTL_SECS, HoldLeaseSpec, HoldReceipt, HoldSpec, LifecycleTokenScope,
    MAX_CHECKOUT_HOLD_TTL_SECS, OpaqueCheckoutLeaseToken, OpaqueLifecycleToken, RescheduleSpec,
    RevisionReceipt, SessionKey, SoftHoldRow, VaultActiveHoldSource, enqueue_booking_verb,
    is_booking_lifecycle_claim_predicate, issue_checkout_lease, run_booking_lifecycle_once,
};
pub use solver::{
    ActiveHoldSource, BookingCountBucket, BookingCounts, BookingSolver, NoActiveHolds, slot_mask,
};

/// Whether `predicate` belongs to the `booking.*` claim family.
///
/// The family is the UNION of its per-layer exact tables — the host
/// configuration predicate ONE-1823 owns, plus the four lifecycle predicates
/// ONE-1813 owns. It is deliberately a table union and not a `booking.` prefix
/// test: a prefix would silently adopt every future booking predicate into
/// whichever validator happened to be listed first.
#[must_use]
pub fn is_booking_family_claim_predicate(predicate: &str) -> bool {
    config::is_booking_claim_predicate(predicate)
        || lifecycle::is_booking_lifecycle_claim_predicate(predicate)
}

/// Validates one `booking.*` claim body against its own family validator.
///
/// This is the booking-family door the shared validator chain calls: it routes
/// on the exact predicate tables above, so a body whose predicate is not an
/// exact member of any layer's table is rejected here rather than accepted
/// unvalidated.
///
/// # Errors
///
/// [`crate::Error::InvalidClaimBody`] naming the defect.
pub fn validate_booking_family_claim(body: &crate::claim::ClaimBody) -> crate::Result<()> {
    if config::is_booking_claim_predicate(&body.predicate) {
        return config::validate_event_type_claim(body);
    }
    if lifecycle::is_booking_lifecycle_claim_predicate(&body.predicate) {
        return lifecycle::validate_lifecycle_claim(body);
    }
    Err(crate::Error::InvalidClaimBody(
        "unknown booking claim predicate",
    ))
}

/// Every pure-data claim-class descriptor row the `booking.*` family ships.
///
/// The per-layer tables concatenated in family order: host configuration first,
/// then the lifecycle rows. No descriptor runtime or registry exists in engine
/// Rust (ARCH-0057 is design-only), so this is authoritative documentation until
/// one lands and is ready to register unchanged when it does.
#[must_use]
pub fn booking_claim_class_descriptors() -> Vec<ClaimClassDescriptorRow> {
    let mut rows = config::claim_class_descriptors();
    rows.extend(lifecycle::claim_class_descriptors());
    rows
}
