//! Moved from `crates/oneiron/src/booking/constraint.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::temporal::TimeRange;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use std::fmt;

/// Wire version of [`ConstraintObject`]. A payload carrying any other version
/// fails closed rather than being coerced.
pub const CONSTRAINT_SCHEMA_VERSION: u16 = 1;

/// Exclusive upper bound for a local-minute-of-day.
pub const MINUTES_PER_DAY: u16 = 1440;

/// Host-configured event type. Configuration for the type (duration, pool,
/// flex policy) is ONE-1823's `EventTypeConfig`; the key alone lives here.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, schemars::JsonSchema)]
#[serde(transparent)]
pub struct EventTypeKey(pub String);

/// Booking error taxonomy. `Display` and `std::error::Error` are implemented
/// by hand so the derive list stays exactly the seam's five traits.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum BookingError {
    /// Host configuration is missing or unusable — including an unresolvable
    /// parse tier. Never a silent fallback to an ungoverned model.
    InvalidConfig(String),
    /// A normalized constraint failed validation or canonical ordering.
    InvalidConstraint(String),
    /// The bounded parse pass failed or returned an unusable payload.
    ConstraintParse(String),
    /// The per-session turn or model-call dial is spent.
    SessionCapExhausted,
    /// The oracle refused or failed to solve.
    SlotOracle(String),
    /// Surface assembly (lens atoms, controls, card) failed.
    Surface(String),
    /// A typed existing facade/engine boundary failure.
    Boundary(Box<oneiron_contracts::memory::MemoryError>),
}

impl fmt::Display for BookingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(detail) => write!(f, "booking invalid config: {detail}"),
            Self::InvalidConstraint(detail) => write!(f, "booking invalid constraint: {detail}"),
            Self::ConstraintParse(detail) => write!(f, "booking constraint parse failed: {detail}"),
            Self::SessionCapExhausted => f.write_str("booking session cap exhausted"),
            Self::SlotOracle(detail) => write!(f, "booking slot oracle failed: {detail}"),
            Self::Surface(detail) => write!(f, "booking surface assembly failed: {detail}"),
            Self::Boundary(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for BookingError {}

mod opt_time_range_serde {
    use super::{Deserialize, Deserializer, Serialize, Serializer, TimeRange, TimeRangeWire};

    pub(super) fn serialize<S: Serializer>(
        value: &Option<TimeRange>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value
            .as_ref()
            .map(TimeRangeWire::from)
            .serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<TimeRange>, D::Error> {
        Ok(Option::<TimeRangeWire>::deserialize(deserializer)?.map(TimeRange::from))
    }
}

// -------------------------------------------------------------------------
// Normalized constraint
// -------------------------------------------------------------------------

/// Weekday axis of a normalized constraint.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintWeekday {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

/// Half-open local-minute-of-day window.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct LocalMinuteWindow {
    /// Inclusive, `0..1440`.
    pub start_minute: u16,
    /// Exclusive, `start < end <= 1440`.
    pub end_minute: u16,
}

/// The deterministic, serializable constraint. This is pure data: it holds no
/// source text and no model explanation, so free text cannot ride it into a
/// solve. An empty weekday or window vector means "no restriction on that
/// axis".
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConstraintObject {
    pub schema_version: u16,
    #[serde(default)]
    pub weekdays: Vec<ConstraintWeekday>,
    #[serde(default)]
    pub local_time_windows: Vec<LocalMinuteWindow>,
    #[serde(with = "opt_time_range_serde")]
    #[schemars(with = "Option<TimeRangeWire>")]
    pub utc_window: Option<TimeRange>,
    pub allow_flex_pool: bool,
}

impl ConstraintObject {
    /// Sort and de-duplicate every axis, then validate. Two semantically
    /// identical payloads that differ only in weekday/window order canonicalize
    /// to the same value, and therefore to the same bytes and hash.
    pub fn canonicalize(mut self) -> Result<Self, BookingError> {
        self.weekdays.sort_unstable();
        self.weekdays.dedup();
        self.local_time_windows.sort_unstable();
        self.local_time_windows.dedup();
        self.validate()?;
        Ok(self)
    }

    /// Fail closed on an unsupported schema version, an out-of-bounds minute
    /// window, an inverted UTC window, or a vector that is not in canonical
    /// (strictly ascending) order. A constraint carries any number of local
    /// windows (ABC row 74); the solve door measures them.
    pub fn validate(&self) -> Result<(), BookingError> {
        if self.schema_version != CONSTRAINT_SCHEMA_VERSION {
            return Err(BookingError::InvalidConstraint(format!(
                "constraint schema version must be {CONSTRAINT_SCHEMA_VERSION}, got {}",
                self.schema_version
            )));
        }
        for window in &self.local_time_windows {
            if window.start_minute >= window.end_minute || window.end_minute > MINUTES_PER_DAY {
                return Err(BookingError::InvalidConstraint(format!(
                    "local minute window must satisfy 0 <= start < end <= {MINUTES_PER_DAY}"
                )));
            }
        }
        if let Some(window) = &self.utc_window
            && window.start >= window.end
        {
            return Err(BookingError::InvalidConstraint(
                "utc window must satisfy start < end".to_owned(),
            ));
        }
        if !is_strictly_ascending(&self.weekdays) {
            return Err(BookingError::InvalidConstraint(
                "constraint weekdays must be sorted and de-duplicated".to_owned(),
            ));
        }
        if !is_strictly_ascending(&self.local_time_windows) {
            return Err(BookingError::InvalidConstraint(
                "constraint local time windows must be sorted and de-duplicated".to_owned(),
            ));
        }
        Ok(())
    }

    /// Canonical JSON bytes. Validation runs first, so a non-canonical object
    /// can never produce bytes: field order is the declaration order and every
    /// vector is proven strictly ascending.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BookingError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| {
            BookingError::InvalidConstraint(format!("constraint serialization failed: {error}"))
        })
    }

    /// BLAKE3 over [`Self::canonical_bytes`].
    pub fn canonical_hash(&self) -> Result<[u8; 32], BookingError> {
        Ok(*blake3::hash(&self.canonical_bytes()?).as_bytes())
    }
}

pub fn is_strictly_ascending<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

/// One slot the oracle chose. UTC times are the oracle's; no caller rewrites,
/// rounds, or invents them.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, schemars::JsonSchema)]
pub struct RankedSlot {
    pub start_utc: u64,
    pub end_utc: u64,
    pub rank: f32,
}
