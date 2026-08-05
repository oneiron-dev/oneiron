//! Calendar module home (CAL-00).
//!
//! Owns the `calendar.*` claim family and the single calendar error home. The
//! family is claims-on-EVENT: this layer allocates no entity type byte, no
//! `EdgeKind`, and no serialization profile change. Series, exception,
//! successor, passport, and outcome relations are all claim values.

pub mod claims;

/// Single calendar error home. Uninhabited at CAL-00; later stack layers append variants.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CalendarError {}

pub use claims::{
    CALENDAR_CLAIM_PREDICATES, CalendarBusyTransparency, CalendarOrigin, CalendarPassportDirection,
    CalendarPassportPresence, CalendarPassportValue, CalendarSeriesExceptionValue,
    CalendarSeriesMasterValue, CalendarStatus, CalendarStatusBasis, CalendarStatusValue,
    CalendarSuccessorValue, CalendarTimeKind, CalendarTimeKindValue, ClaimClassDescriptorRow,
    claim_class_descriptors, is_calendar_claim_predicate,
};
