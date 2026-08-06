//! Engine-generic booking module.
//!
//! Declarations and re-exports only: every seam type is defined in
//! [`constraint`], which is the single home later booking layers import from.
//! This file defines no type and allocates no entity byte.

pub mod agent_front;
pub mod config;
pub mod constraint;
pub mod disclosure_rung;
pub mod solver;
#[cfg(test)]
mod tests;

pub use config::{
    BOOKING_EVENT_TYPE_META_PREFIX, BOOKING_EVENT_TYPE_PREDICATE,
    BOOKING_EVENT_TYPE_SCHEMA_VERSION, BookingEventTypeClaimValue, ClaimClassDescriptorRow,
    DEFAULT_INTRO_DURATION_MIN, DEFAULT_MIN_NOTICE_SECS, EventTypeConfig,
    HIGH_VALUE_MIN_NOTICE_SECS, HostAvailabilityConfig, RoutingMode, WeeklyWallWindow,
    claim_class_descriptors, decode_event_type_claim_value, encode_event_type_claim_value,
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
pub use solver::{
    ActiveHoldSource, BookingCountBucket, BookingCounts, BookingSolver, NoActiveHolds, slot_mask,
};
