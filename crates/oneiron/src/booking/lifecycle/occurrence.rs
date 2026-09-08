//! Interval algebra between the engine's inclusive [`TimeRange`] and the
//! half-open convention the solver and claim writes use.

use super::storage::refused;
use super::types::CONFIRM_ALTERNATIVES_PAD_SECS;
use crate::booking::{BookingError, RankedSlot};
use crate::temporal::TimeRange;

/// Half-open `[start, end)` → the engine's inclusive occurrence row.
pub(super) fn inclusive_occurrence(slot: TimeRange) -> Result<TimeRange, BookingError> {
    let end = slot
        .end
        .checked_sub(1)
        .filter(|end| *end >= slot.start)
        .ok_or_else(|| refused("booking slot must satisfy start < end"))?;
    Ok(TimeRange {
        start: slot.start,
        end,
    })
}

/// The inclusive solve window confirm asks over: the held slot padded far
/// enough on both sides to carry nearest alternatives.
pub(super) fn confirm_solve_window(slot: TimeRange) -> Result<TimeRange, BookingError> {
    let held = inclusive_occurrence(slot)?;
    Ok(TimeRange {
        start: held.start.saturating_sub(CONFIRM_ALTERNATIVES_PAD_SECS),
        end: held.end.saturating_add(CONFIRM_ALTERNATIVES_PAD_SECS),
    })
}

/// The engine's inclusive occurrence row → half-open `[start, end)`.
pub(super) const fn half_open_occurrence(start: u64, end: u64) -> TimeRange {
    TimeRange {
        start,
        end: end.saturating_add(1),
    }
}

pub(super) const fn at(now: u64) -> TimeRange {
    TimeRange {
        start: now,
        end: now,
    }
}

/// Whether the solver still offers exactly this interval. Equality, not
/// containment: the oracle's UTC bounds are authoritative, and nothing here
/// rounds or widens them.
pub(super) fn offers_slot(slots: &[RankedSlot], slot: TimeRange) -> bool {
    slots
        .iter()
        .any(|ranked| ranked.start_utc == slot.start && ranked.end_utc == slot.end)
}
