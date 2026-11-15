//! Moved from `crates/oneiron/src/booking/config.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_verb_wire::booking::constraint::BookingError;
use oneiron_verb_wire::booking::constraint::EventTypeKey;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

/// The one booking-page configuration predicate. Matching is exact everywhere:
/// no `booking.` prefix is ever accepted as family membership.
pub const BOOKING_EVENT_TYPE_PREDICATE: &str = "booking.event_type";

/// Wire version of a [`BookingEventTypeClaimValue`]. Any other version fails
/// closed rather than being coerced.
pub const BOOKING_EVENT_TYPE_SCHEMA_VERSION: u64 = 1;

/// The furthest ahead a page may open.
///
/// The horizon is what bounds ONE solve: the solver reaches over it to ask CAL
/// for a busy union and to walk each host's local days, so an unbounded horizon
/// is an unbounded read and an unbounded loop. A year and a day is far past any
/// real booking page — the ratified deployment default is this week and next —
/// and keeps the day walk under four hundred iterations per host.
pub const MAX_BOOKING_WINDOW_SECS: u64 = 366 * 24 * 3_600;

/// Exclusive upper bound for a civil minute-of-day. `1440` is admissible as an
/// *end* minute and denotes the following midnight.
pub const MINUTES_PER_DAY: u16 = 1_440;

/// Weekday axis width. Rows are `0 = Monday ..= 6 = Sunday`.
pub const DAYS_PER_WEEK: u8 = 7;

/// How a multi-host event type turns per-host availability into offered slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingMode {
    /// Any one host suffices: the union of the hosts' slots.
    Either,
    /// Every host must attend: the intersection of the hosts' slots.
    Both,
}

/// The digest [`event_type_index_key`] spells, for the typed
/// [`EVENT_TYPE_SHORTCUT`] table's own key.
pub fn event_type_index_digest(page_ref: EntityId, key: &EventTypeKey) -> [u8; 32] {
    let mut material = Vec::with_capacity(page_ref.as_bytes().len() + key.0.len());
    material.extend_from_slice(page_ref.as_bytes());
    material.extend_from_slice(key.0.as_bytes());
    *blake3::hash(&material).as_bytes()
}

pub fn storage_failure<E>(_: E) -> BookingError {
    BookingError::SlotOracle("booking configuration lookup failed to read the vault".to_owned())
}
