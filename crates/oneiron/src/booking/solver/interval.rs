//! Half-open interval algebra and the public slot-mask projection.

use crate::booking::{BookingError, SlotMask, SolveRequest, SolveResult};
use crate::temporal::TimeRange;

// -------------------------------------------------------------------------
// Slot mask
// -------------------------------------------------------------------------

/// Projects a solve into the seam's public availability mask.
///
/// The mask carries the event type, the half-open window, the ranked UTC slots,
/// and whether the flex pool answered — and nothing else. No event title, body,
/// attendee, raw busy interval, or calendar identity has a field to travel in.
#[must_use]
pub fn slot_mask(req: &SolveRequest, solved: SolveResult) -> SlotMask {
    SlotMask {
        event_type: req.event_type.clone(),
        window_start_utc: req.window.start,
        window_end_utc: req.window.end.saturating_add(1),
        slots: solved.slots,
        flex_used: solved.flex_used,
    }
}

// -------------------------------------------------------------------------
// Interval algebra (half-open)
// -------------------------------------------------------------------------

/// Inclusive engine range → half-open solver range.
pub(super) fn half_open(range: TimeRange) -> Result<TimeRange, BookingError> {
    let end = range.end.checked_add(1).ok_or_else(|| {
        BookingError::InvalidConstraint(
            "solve window ends at the last representable second".to_owned(),
        )
    })?;
    Ok(TimeRange {
        start: range.start,
        end,
    })
}

/// Half-open solver range → inclusive engine range, for the CAL call.
pub(super) const fn inclusive(range: TimeRange) -> TimeRange {
    TimeRange {
        start: range.start,
        end: range.end.saturating_sub(1),
    }
}

pub(super) fn intersect(left: TimeRange, right: TimeRange) -> Option<TimeRange> {
    let start = left.start.max(right.start);
    let end = left.end.min(right.end);
    if start < end {
        Some(TimeRange { start, end })
    } else {
        None
    }
}

pub(super) const fn overlaps(left: TimeRange, right: TimeRange) -> bool {
    left.start < right.end && right.start < left.end
}

/// Sorts and merges overlapping or touching ranges.
pub(super) fn normalize(ranges: &mut Vec<TimeRange>) {
    ranges.retain(|range| range.start < range.end);
    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    let mut merged: Vec<TimeRange> = Vec::with_capacity(ranges.len());
    for range in ranges.iter().copied() {
        match merged.last_mut() {
            Some(open) if range.start <= open.end => open.end = open.end.max(range.end),
            _ => merged.push(range),
        }
    }
    *ranges = merged;
}

/// Removes every blocker from `mask`, returning the normalized remainder.
pub(super) fn subtract(mask: Vec<TimeRange>, blockers: &[TimeRange]) -> Vec<TimeRange> {
    let mut remaining = mask;
    for blocker in blockers {
        let mut next = Vec::with_capacity(remaining.len());
        for range in remaining {
            if !overlaps(range, *blocker) {
                next.push(range);
                continue;
            }
            if range.start < blocker.start {
                next.push(TimeRange {
                    start: range.start,
                    end: blocker.start,
                });
            }
            if blocker.end < range.end {
                next.push(TimeRange {
                    start: blocker.end,
                    end: range.end,
                });
            }
        }
        remaining = next;
    }
    normalize(&mut remaining);
    remaining
}
