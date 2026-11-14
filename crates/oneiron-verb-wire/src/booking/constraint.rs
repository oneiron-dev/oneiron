//! Moved from `crates/oneiron/src/booking/constraint.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
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
