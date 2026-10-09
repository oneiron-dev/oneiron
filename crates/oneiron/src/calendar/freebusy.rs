//! Busy-only freebusy projection (CAL-09, C5).
//!
//! This is the one place the Busy-only law is applied: free/transparent and
//! cancelled occurrences are excluded here, so BK-00 and every other consumer
//! receive occupancy and never re-filter. The projection is deliberately
//! detail-free — a [`BusyInterval`] carries no name, description, attendee, or
//! meeting link, and external MCP/SDK DTOs drop even the internal `source`.
//!
//! Interval algebra: the engine's [`TimeRange`] is inclusive on both ends, and
//! a `BusyInterval` is half-open `[start_utc, end_utc)`. All clipping happens
//! in the inclusive domain, and the conversion happens once, in `half_open`,
//! on the clipped result — so an occurrence that runs to `u64::MAX` still
//! projects normally against any window that ends earlier, and the checked
//! conversion fails typed only when the interval actually emitted has no
//! half-open representation.
//!
//! Recurrence is a deferred leg. ONE-1785 (CAL-03) lands after this ticket, so
//! on the 1791 baseline the union covers non-recurring busy occurrences only;
//! when `expand_window` exists, series masters expand inside the query range
//! before `normalize_busy` runs and its typed `CalendarError` propagates —
//! an expansion failure must never degrade to a silently empty union.

use super::query::{
    CalendarRead, CalendarSel, matches_selectors, validate_selectors, visit_calendar_events,
};
use crate::claim::{ScopedRead, ScopedReadResult};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// One busy occupancy interval, half-open `[start_utc, end_utc)`.
///
/// Internal-only: serde is deliberately absent because [`EntityId`] carries no
/// serde impl and because `source` is redacted from every external DTO, which
/// carries no source field at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusyInterval {
    /// Inclusive half-open start, Unix seconds.
    pub start_utc: u64,
    /// Exclusive half-open end, Unix seconds.
    pub end_utc: u64,
    /// Deterministic representative EVENT of this interval's merged component.
    pub source: EntityId,
}

/// Normalized, merged, sorted busy union.
pub type BusyUnion = Vec<BusyInterval>;

/// Projects the busy union over `range` through the internal lane.
///
/// This is C5's pinned signature and BK-00's step-2 input.
pub fn freebusy(vault: &Vault, calendars: &[CalendarSel], range: TimeRange) -> Result<BusyUnion> {
    freebusy_in(&CalendarRead::Vault(vault), calendars, range)
}

/// Projects the busy union over `range` through an actor's scoped-read lane.
///
/// Claims the actor may not read never enter the union, so an actor's freebusy
/// is always a subset of the internal projection — filtering happens before the
/// merge, never after it. The receipt counts the claims the lane withheld.
pub fn freebusy_scoped(
    read: &ScopedRead<'_>,
    calendars: &[CalendarSel],
    range: TimeRange,
) -> Result<ScopedReadResult<BusyUnion>> {
    super::query::receipted(read, |lane| freebusy_in(lane, calendars, range))
}

fn freebusy_in(
    read: &CalendarRead<'_>,
    calendars: &[CalendarSel],
    range: TimeRange,
) -> Result<BusyUnion> {
    // Selection on `CalendarSel.system` is deferred to CAL-02's passport index
    // (ONE-1784 lands after this ticket); a well-formed selector must not empty
    // the union in the meantime, so only structural validation runs here.
    validate_selectors(calendars)?;

    let bounds = ordered(range);
    let mut rows = Vec::new();
    visit_calendar_events(read, |row| {
        rows.push(row);
        Ok(())
    })?;
    let exceptions: Vec<_> = rows
        .iter()
        .filter_map(|row| row.facts.exception().cloned())
        .collect();
    let withheld_exception = read.withheld_exception_series()?;
    let mut intervals = Vec::new();
    for row in rows {
        if !matches_selectors(row.facts.systems(), calendars)
            || !row.facts.blocks_time()
            || row.facts.is_cancelled()
            || row.facts.series_withheld()
        {
            continue;
        }
        let occurrences =
            super::query::occurrences(&row, bounds, &exceptions, &withheld_exception)?;
        for occurrence in occurrences {
            if let Some(clipped) = clip(occurrence, bounds) {
                let (start_utc, end_utc) = half_open(clipped)?;
                intervals.push(BusyInterval {
                    start_utc,
                    end_utc,
                    source: row.id,
                });
            }
        }
    }

    Ok(normalize_busy(intervals))
}

/// Sorts, then merges overlapping *and* touching intervals.
///
/// Inputs are already clipped to the query bounds by [`clip`], so this pass
/// only drops empties, sorts, and coalesces. The merged component keeps the
/// lowest `EntityId` as its representative: a single-source field cannot
/// retain every overlapping EVENT, and a deterministic representative keeps the
/// ratified internal ABI stable while full provenance stays queryable from the
/// underlying EVENTs.
fn normalize_busy(mut intervals: Vec<BusyInterval>) -> BusyUnion {
    intervals.retain(|interval| interval.start_utc < interval.end_utc);
    intervals.sort_unstable_by(|left, right| {
        (left.start_utc, left.end_utc, left.source).cmp(&(
            right.start_utc,
            right.end_utc,
            right.source,
        ))
    });

    let mut union: BusyUnion = Vec::with_capacity(intervals.len());
    for interval in intervals {
        match union.last_mut() {
            Some(open) if interval.start_utc <= open.end_utc => {
                open.end_utc = open.end_utc.max(interval.end_utc);
                open.source = open.source.min(interval.source);
            }
            _ => union.push(interval),
        }
    }
    union
}

/// Checked inclusive → half-open conversion of an already-clipped interval.
///
/// Clipping first is load-bearing, not stylistic: an occurrence whose inclusive
/// end is `u64::MAX` has no half-open successor, but its intersection with an
/// ordinary query window almost always does. Converting before clipping fails
/// the *whole* query on one open-ended EVENT — even one the window never
/// touches — so the overflow is raised only when the interval that would
/// actually be emitted is unrepresentable.
fn half_open(range: TimeRange) -> Result<(u64, u64)> {
    let end = range.end.checked_add(1).ok_or(Error::ArithmeticOverflow(
        "calendar freebusy interval ends at the last representable second",
    ))?;
    Ok((range.start, end))
}

/// Orders a possibly-inverted range, matching the retrieval layer's tolerance
/// for reversed anchors.
const fn ordered(range: TimeRange) -> TimeRange {
    if range.start <= range.end {
        range
    } else {
        TimeRange {
            start: range.end,
            end: range.start,
        }
    }
}

/// Intersects two inclusive intervals, dropping a disjoint result.
///
/// Inclusive on both ends, so a one-second overlap (`start == end`) survives;
/// the half-open conversion happens after, on the clipped result only.
const fn clip(interval: TimeRange, bounds: TimeRange) -> Option<TimeRange> {
    let start = if interval.start > bounds.start {
        interval.start
    } else {
        bounds.start
    };
    let end = if interval.end < bounds.end {
        interval.end
    } else {
        bounds.end
    };
    if start <= end {
        Some(TimeRange { start, end })
    } else {
        None
    }
}
