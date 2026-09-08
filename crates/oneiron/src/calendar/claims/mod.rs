//! The `calendar.*` claim family (CAL-00).
//!
//! Mirrors the `comm.rs` constants/table/matcher/structural-validator pattern.
//! Every predicate in this family is a claim ON an EVENT entity: no entity type
//! byte, no `EdgeKind`, and no serialization profile is minted here.
//!
//! Two validation halves live in this module, because the engine's claim
//! chokepoints sit at two different layers:
//!
//! * `validate_calendar_claim_structure` is the byte-level half, wired into
//!   the write-only validator chain in `crate::claim`. It sees a decoded
//!   [`ClaimBody`] and no storage, so it enforces the subject *shape*
//!   (`ClaimSubject::Entity`) plus the exact value shapes.
//! * [`require_event_subject`] is the store-aware half, mirroring the
//!   `comm.rs` PERSON-subject precedent. Subject *existence* is already
//!   enforced generically at both write doors; this adds the EVENT type
//!   assertion for calendar writers without reopening the shared write path.
//!
//! Timezone resolution (CAL-01), RRULE parsing/expansion (CAL-03), and the
//! passport UID index plus feed diff (CAL-02) are deliberately out of scope:
//! this layer stores structure verbatim.

mod codec;
mod predicates;
mod values;

#[cfg(test)]
mod tests;

pub use self::codec::require_event_subject;
pub use self::predicates::{
    CALENDAR_CLAIM_PREDICATES, ClaimClassDescriptorRow, ICS_TRANSP_OPAQUE, ICS_TRANSP_TRANSPARENT,
    PREDICATE_CALENDAR_ATTENDEE, PREDICATE_CALENDAR_MEETING_LINK, PREDICATE_CALENDAR_ORIGIN,
    PREDICATE_CALENDAR_PASSPORT, PREDICATE_CALENDAR_RRULE, PREDICATE_CALENDAR_SERIES_EXCEPTION,
    PREDICATE_CALENDAR_SERIES_MASTER, PREDICATE_CALENDAR_STATUS, PREDICATE_CALENDAR_SUCCESSOR,
    PREDICATE_CALENDAR_TIME_KIND, PREDICATE_CALENDAR_TZ, PREDICATE_CALENDAR_WALL_TIME,
    claim_class_descriptors, is_calendar_claim_predicate,
};
pub use self::values::{
    CalendarAttendeeValue, CalendarBusyTransparency, CalendarOrigin, CalendarPassportDirection,
    CalendarPassportPresence, CalendarPassportValue, CalendarSeriesExceptionValue,
    CalendarSeriesMasterValue, CalendarStatus, CalendarStatusBasis, CalendarStatusValue,
    CalendarSuccessorValue, CalendarTimeKind, CalendarTimeKindValue, CalendarWallTimeValue,
};

pub(crate) use self::codec::{
    decode_attendee_value, decode_event_outcome_value, decode_passport_value, decode_status_value,
    decode_time_kind_value, encode_event_outcome_value, validate_calendar_claim_structure,
};

// These four decoders are named only by sibling test modules (`series` and
// `tz`); the re-export exists in test builds so those paths keep resolving,
// and is absent otherwise so the non-test build carries no unused import.
#[cfg(test)]
pub(crate) use self::codec::{
    decode_series_exception_value, decode_series_master_value, decode_successor_value,
    decode_wall_time_value,
};

// The flat claims.rs module used to provide these names to the inline test
// module through `use super::*`: its own private crate/std import header, and
// every claims-internal item the tests name bare. After the directory split
// the seam re-imports both so `tests.rs` resolves exactly as it did before.
// `values::*` adds nothing here: every value type is `pub` and already
// re-exported above, so the glob would be an unused import.
#[cfg(test)]
use self::{codec::*, predicates::*};
#[cfg(test)]
use super::outcome::{EventOutcome, EventOutcomeBasis, PREDICATE_CALENDAR_EVENT_OUTCOME};
#[cfg(test)]
use crate::claim::{ClaimBody, ClaimSubject};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::registry::ENTITY_TYPE_EVENT;
#[cfg(test)]
use rmpv::Value;
