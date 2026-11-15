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

/// One recurring civil window in a host's zone.
///
/// Half-open `[start_minute, end_minute)` minutes from local midnight, so
/// `end_minute == MINUTES_PER_DAY` means "to the following midnight" and two
/// adjacent rows never double-count the boundary minute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeeklyWallWindow {
    /// `0 = Monday ..= 6 = Sunday`.
    pub weekday: u8,
    /// Inclusive, `0..MINUTES_PER_DAY`.
    pub start_minute: u16,
    /// Exclusive, `start_minute < end_minute <= MINUTES_PER_DAY`.
    pub end_minute: u16,
}

impl WeeklyWallWindow {
    fn defect(&self) -> Option<&'static str> {
        if self.weekday >= DAYS_PER_WEEK {
            return Some("booking.event_type weekday must be 0 (Monday) through 6 (Sunday)");
        }
        if self.start_minute >= self.end_minute || self.end_minute > MINUTES_PER_DAY {
            return Some("booking.event_type wall window must satisfy 0 <= start < end <= 1440");
        }
        None
    }
}

/// One host's availability configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostAvailabilityConfig {
    #[serde(with = "entity_ref_serde")]
    pub host_ref: EntityId,
    /// The calendars whose busy union occupies this host's time.
    #[serde(with = "entity_refs_serde")]
    pub calendar_refs: Vec<EntityId>,
    /// IANA zone the wall windows below are written in.
    pub host_tz: String,
    /// When this host is bookable at all.
    pub working_hours: Vec<WeeklyWallWindow>,
    /// A subset of bookable time this host would rather be booked in. Ranking
    /// only: a preferred window never widens availability.
    pub preferred_hours: Vec<WeeklyWallWindow>,
}

impl HostAvailabilityConfig {
    fn defect(&self) -> Option<&'static str> {
        if self.host_tz.is_empty() {
            return Some("booking.event_type host_tz must name an IANA zone");
        }
        if self.calendar_refs.is_empty() {
            return Some("booking.event_type host must bind at least one calendar");
        }
        self.working_hours
            .iter()
            .chain(&self.preferred_hours)
            .find_map(WeeklyWallWindow::defect)
    }
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

// -------------------------------------------------------------------------
// serde adapters
//
// `EntityId` carries no serde impl, so configuration values cross the wire as
// lowercase hex — the same `serde(with = ...)` shape ONE-1812 uses in
// `crate::booking::disclosure_rung`.
// -------------------------------------------------------------------------

pub mod entity_ref_serde {
    use super::{Deserialize, Deserializer, EntityId, Serializer};

    pub fn serialize<S: Serializer>(value: &EntityId, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_hex())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<EntityId, D::Error> {
        let hex = String::deserialize(deserializer)?;
        EntityId::from_hex(&hex).map_err(serde::de::Error::custom)
    }
}

pub mod entity_refs_serde {
    use super::{Deserialize, Deserializer, EntityId, Serialize, Serializer};

    pub fn serialize<S: Serializer>(value: &[EntityId], serializer: S) -> Result<S::Ok, S::Error> {
        value
            .iter()
            .map(EntityId::to_hex)
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<EntityId>, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .into_iter()
            .map(|hex| EntityId::from_hex(&hex).map_err(serde::de::Error::custom))
            .collect()
    }
}
