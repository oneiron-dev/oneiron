//! Busy-only freebusy projection (CAL-09, C5).
//!
//! This is the one place the Busy-only law is applied: free/transparent and
//! cancelled occurrences are excluded here, so BK-00 and every other consumer
//! receive occupancy and never re-filter. The projection is deliberately
//! detail-free — a [`BusyInterval`] carries no name, description, attendee, or
//! meeting link, and external MCP/SDK DTOs drop even the internal `source`.
//!
//! Interval algebra: the engine's [`TimeRange`] is inclusive on both ends, and
//! a `BusyInterval` is half-open `[start_utc, end_utc)`. The conversion happens
//! once, in [`half_open`], and is checked: an inclusive end of `u64::MAX` has
//! no half-open representation and fails typed rather than wrapping to an empty
//! interval.
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

    let bounds = half_open(ordered(range))?;
    let mut intervals = Vec::new();
    visit_calendar_events(read, |row| {
        if !row.facts.blocks_time() || row.facts.is_cancelled() {
            return Ok(());
        }
        // CAL-03's `expand_window` slots in here once ONE-1785 merges: a series
        // master contributes one interval per expanded occurrence inside
        // `bounds`, and its typed CalendarError propagates unchanged.
        let occurrence = half_open(row.occurred)?;
        if let Some(clipped) = clip(occurrence, bounds) {
            intervals.push(BusyInterval {
                start_utc: clipped.0,
                end_utc: clipped.1,
                source: row.id,
            });
        }
        Ok(())
    })?;

    Ok(normalize_busy(intervals, bounds))
}

/// Sorts, then merges overlapping *and* touching intervals.
///
/// Inputs are already clipped to the query bounds. The merged component keeps
/// the lowest `EntityId` as its representative: a single-source field cannot
/// retain every overlapping EVENT, and a deterministic representative keeps the
/// ratified internal ABI stable while full provenance stays queryable from the
/// underlying EVENTs.
fn normalize_busy(mut intervals: Vec<BusyInterval>, bounds: (u64, u64)) -> BusyUnion {
    intervals.retain(|interval| {
        interval.start_utc < interval.end_utc
            && interval.start_utc >= bounds.0
            && interval.end_utc <= bounds.1
    });
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

/// Checked inclusive → half-open conversion.
fn half_open(range: TimeRange) -> Result<(u64, u64)> {
    let end = range.end.checked_add(1).ok_or(Error::ArithmeticOverflow(
        "calendar freebusy inclusive range end has no half-open successor",
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

/// Clips a half-open interval to half-open bounds, dropping empty results.
const fn clip(interval: (u64, u64), bounds: (u64, u64)) -> Option<(u64, u64)> {
    let start = if interval.0 > bounds.0 {
        interval.0
    } else {
        bounds.0
    };
    let end = if interval.1 < bounds.1 {
        interval.1
    } else {
        bounds.1
    };
    if start < end { Some((start, end)) } else { None }
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

        assert!(
            matches!(
                freebusy(&vault, &[], window(0, u64::MAX)),
                Err(Error::ArithmeticOverflow(_))
            ),
            "an unrepresentable half-open end fails typed, never as an empty union"
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
