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
//! in the inclusive domain, and the conversion happens once, in [`half_open`],
//! on the clipped result — so an occurrence that runs to `u64::MAX` still
//! projects normally against any window that ends earlier, and the checked
//! conversion fails typed only when the interval actually emitted has no
//! half-open representation.
//!
//! Recurrence is a deferred leg. ONE-1785 (CAL-03) lands after this ticket, so
//! on the 1791 baseline the union covers non-recurring busy occurrences only;
//! when `expand_window` exists, series masters expand inside the query range
//! before [`normalize_busy`] runs and its typed `CalendarError` propagates —
//! an expansion failure must never degrade to a silently empty union.

use super::query::{CalendarRead, CalendarSel, validate_selectors, visit_calendar_events};
use crate::claim::ScopedRead;
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
/// merge, never after it.
pub fn freebusy_scoped(
    read: &ScopedRead<'_>,
    calendars: &[CalendarSel],
    range: TimeRange,
) -> Result<BusyUnion> {
    freebusy_in(&CalendarRead::Scoped(read), calendars, range)
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
    let mut intervals = Vec::new();
    visit_calendar_events(read, |row| {
        if !row.facts.blocks_time() || row.facts.is_cancelled() {
            return Ok(());
        }
        // An EVENT that stores no occurrence is undated, not epoch-anchored; it
        // occupies no availability at all.
        let Some(occurrence) = row.occurred else {
            return Ok(());
        };
        // CAL-03's `expand_window` slots in here once ONE-1785 merges: a series
        // master contributes one interval per expanded occurrence inside
        // `bounds`, and its typed CalendarError propagates unchanged.
        let Some(clipped) = clip(occurrence, bounds) else {
            return Ok(());
        };
        let (start_utc, end_utc) = half_open(clipped)?;
        intervals.push(BusyInterval {
            start_utc,
            end_utc,
            source: row.id,
        });
        Ok(())
    })?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calendar::claims::CalendarBusyTransparency;
    use crate::calendar::test_support::{CalendarEventFixture, open_calendar_vault};
    use crate::test_util::entity;

    fn window(start: u64, end: u64) -> TimeRange {
        TimeRange { start, end }
    }

    #[test]
    fn freebusy_excludes_free_events_by_busy_transparency() {
        let (_dir, vault) = open_calendar_vault();
        CalendarEventFixture::new(0x61, "Focus block", 1_000, 1_099).store(&vault);
        CalendarEventFixture::new(0x62, "Out of office", 2_000, 2_099)
            .transparency(CalendarBusyTransparency::Free)
            .store(&vault);

        let union = freebusy(&vault, &[], window(0, 10_000)).expect("freebusy");
        assert_eq!(union.len(), 1, "only the busy occurrence occupies time");
        assert_eq!(union[0].start_utc, 1_000);
        assert_eq!(union[0].end_utc, 1_100);
    }

    #[test]
    fn freebusy_excludes_cancelled_events() {
        let (_dir, vault) = open_calendar_vault();
        CalendarEventFixture::new(0x63, "Cancelled sync", 3_000, 3_099)
            .cancelled()
            .store(&vault);

        assert!(
            freebusy(&vault, &[], window(0, 10_000))
                .expect("freebusy")
                .is_empty(),
            "A1 never deletes a cancelled EVENT, so freebusy must not bill it"
        );
    }

    #[test]
    fn freebusy_checked_converts_inclusive_range_to_half_open() {
        let (_dir, vault) = open_calendar_vault();
        CalendarEventFixture::new(0x64, "Inclusive", 100, 199).store(&vault);

        // The stored occurrence is inclusive `[100, 199]`; the projection is
        // half-open `[100, 200)`.
        let union = freebusy(&vault, &[], window(0, 1_000)).expect("freebusy");
        assert_eq!((union[0].start_utc, union[0].end_utc), (100, 200));

        // The query window converts the same way: an inclusive end of 149 keeps
        // the second at 149 and stops at 150.
        let clipped = freebusy(&vault, &[], window(120, 149)).expect("freebusy");
        assert_eq!((clipped[0].start_utc, clipped[0].end_utc), (120, 150));

        // An unbounded window is not itself an overflow. Nothing that clips out
        // of it needs a successor for `u64::MAX`, so the conversion never runs
        // on the window — only on the interval actually emitted.
        let unbounded = freebusy(&vault, &[], window(0, u64::MAX)).expect("freebusy");
        assert_eq!((unbounded[0].start_utc, unbounded[0].end_utc), (100, 200));
    }

    #[test]
    fn freebusy_clips_before_the_half_open_conversion() {
        let (_dir, vault) = open_calendar_vault();
        // Admitted, busy, and open-ended: this occurrence's inclusive end has
        // no half-open successor, but it is wholly disjoint from the window.
        CalendarEventFixture::new(0x65, "Open ended", 200, u64::MAX).store(&vault);

        assert!(
            freebusy(&vault, &[], window(0, 100))
                .expect("a disjoint occurrence cannot fail the whole query")
                .is_empty()
        );

        // Overlapping an open-ended occurrence clips to a representable
        // interval instead of overflowing: `[0, u64::MAX]` ∩ `[0, 100]` is
        // `[0, 100]`, which is `[0, 101)` half-open.
        CalendarEventFixture::new(0x66, "From epoch", 0, u64::MAX).store(&vault);
        let clipped = freebusy(&vault, &[], window(0, 100)).expect("freebusy");
        assert_eq!(clipped.len(), 1);
        assert_eq!((clipped[0].start_utc, clipped[0].end_utc), (0, 101));

        // The typed overflow survives exactly where it is real: the clipped
        // interval itself ends at the last representable second.
        assert!(
            matches!(
                freebusy(&vault, &[], window(0, u64::MAX)),
                Err(Error::ArithmeticOverflow(_))
            ),
            "an unrepresentable half-open end fails typed, never as an empty union"
        );
    }

    #[test]
    fn freebusy_excludes_events_with_no_stored_occurrence() {
        let (_dir, vault) = open_calendar_vault();
        CalendarEventFixture::new(0x67, "Undated", 0, 0).store(&vault);
        CalendarEventFixture::new(0x68, "Dated", 500, 599).store(&vault);

        let union = freebusy(&vault, &[], window(0, 1_000)).expect("freebusy");
        assert_eq!(union.len(), 1, "an undated EVENT bills no availability");
        assert_eq!((union[0].start_utc, union[0].end_utc), (500, 600));

        assert!(
            freebusy(&vault, &[], window(0, 0))
                .expect("freebusy")
                .is_empty(),
            "an undated EVENT does not occupy Unix second zero"
        );
    }

    #[test]
    fn freebusy_sorts_clips_and_merges_touching_intervals() {
        let (_dir, vault) = open_calendar_vault();
        // Stored out of order; [300,399] and [400,449] touch at 400.
        CalendarEventFixture::new(0x71, "Late", 400, 449).store(&vault);
        CalendarEventFixture::new(0x72, "Early", 300, 399).store(&vault);
        CalendarEventFixture::new(0x73, "Overlapping", 350, 379).store(&vault);
        CalendarEventFixture::new(0x74, "Far future", 9_000, 9_100).store(&vault);

        let union = freebusy(&vault, &[], window(0, 1_000)).expect("freebusy");
        assert_eq!(union.len(), 1, "touching and overlapping runs coalesce");
        assert_eq!((union[0].start_utc, union[0].end_utc), (300, 450));

        let clipped = freebusy(&vault, &[], window(320, 359)).expect("freebusy");
        assert_eq!((clipped[0].start_utc, clipped[0].end_utc), (320, 360));
    }

    #[test]
    fn freebusy_merge_uses_deterministic_source_representative() {
        let (_dir, vault) = open_calendar_vault();
        let high = CalendarEventFixture::new(0x7A, "High id", 500, 549).store(&vault);
        let low = CalendarEventFixture::new(0x75, "Low id", 520, 599).store(&vault);
        assert!(low < high, "fixture seeds order as the test expects");

        let union = freebusy(&vault, &[], window(0, 1_000)).expect("freebusy");
        assert_eq!(union.len(), 1);
        assert_eq!(
            union[0].source, low,
            "the merged component keeps the lowest EntityId as its representative"
        );
    }

    #[test]
    fn freebusy_ignores_events_without_the_calendar_family() {
        let (_dir, vault) = open_calendar_vault();
        vault
            .put_entity(
                &entity(0x76),
                crate::registry::ENTITY_TYPE_EVENT,
                window(700, 799),
                1,
                b"plain event",
            )
            .expect("put plain event");

        assert!(
            freebusy(&vault, &[], window(0, 1_000))
                .expect("freebusy")
                .is_empty()
        );
    }
}
