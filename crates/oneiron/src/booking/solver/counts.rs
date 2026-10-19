//! Confirmed-booking tallies per visitor-local day and week.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use serde::{Deserialize, Serialize};

use super::civil_date::{local_day, visitor_zone_error, week_of};
use crate::booking::{BookingError, EventTypeKey};
use crate::entity_id::EntityId;
use crate::temporal::TimeRange;
use crate::vault::Vault;

// -------------------------------------------------------------------------
// Confirmed-booking counts
// -------------------------------------------------------------------------

/// Confirmed bookings inside one visitor-local period.
///
/// The bucket's own UTC span is what a caller reads; which cap it is charged
/// against is decided from `window_start_utc`'s visitor-local day, so a table
/// built in one zone cannot be silently applied in another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookingCountBucket {
    pub window_start_utc: u64,
    /// Half-open `[window_start_utc, window_end_utc)`.
    pub window_end_utc: u64,
    pub confirmed: u16,
}

/// The typed cap input. Sparse by construction: a period with no bucket has no
/// confirmed bookings, which is zero, not unknown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookingCounts {
    pub daily: Vec<BookingCountBucket>,
    pub weekly: Vec<BookingCountBucket>,
}

/// Loads confirmed-booking counts for `(page_ref, event_type)` over `window`.
///
/// `window` is the bookable extent — the caller's window already clipped to the
/// page's horizon — so it is bounded, not caller-controlled. A cap is charged
/// over a whole visitor-local period, so the read widens `window` to every
/// visitor-local week it touches: a booking earlier on a candidate's day, or
/// earlier in its week, counts even though it lies outside `window`.
///
/// Each bucket holds one period's bookings and spans exactly them, from the
/// first one's start to just past the last one's, so its `window_start_utc`
/// falls on the period it is charged to. `moving` is a booking being moved,
/// which never charges against its own move.
///
/// `listed`, when given, receives the rows each charged booking was decided
/// from (FIX 4777): its EVENT and the claims on it.
///
/// # Errors
///
/// [`BookingError::SlotOracle`] when committed state cannot be read;
/// [`BookingError::InvalidConstraint`] when a booking's start has no
/// visitor-local date in `visitor_tz`.
pub(super) fn load_booking_counts(
    vault: &Vault,
    page_ref: EntityId,
    event_type: &EventTypeKey,
    window: TimeRange,
    visitor_tz: &str,
    moving: Option<EntityId>,
    mut listed: Option<&mut Vec<EntityId>>,
) -> Result<BookingCounts, BookingError> {
    let first_week = week_of(local_day(window.start, visitor_tz).map_err(visitor_zone_error)?);
    let last_week = week_of(local_day(window.end, visitor_tz).map_err(visitor_zone_error)?);
    // A visitor-local week starts at most seven days plus the widest zone
    // offset before any instant in it, and ends as far after: eight days
    // either side reads every booking those weeks hold, whatever the zone.
    let scan = TimeRange {
        start: window.start.saturating_sub(SCAN_MARGIN_SECS),
        end: window.end.saturating_add(SCAN_MARGIN_SECS),
    };
    let starts: Vec<(u64, Vec<EntityId>)> = if listed.is_some() {
        crate::booking::lifecycle::confirmed_booking_starts_listed(
            vault, page_ref, event_type, scan, moving,
        )?
    } else {
        crate::booking::lifecycle::confirmed_booking_starts(
            vault, page_ref, event_type, scan, moving,
        )?
        .into_iter()
        .map(|start| (start, Vec::new()))
        .collect()
    };
    let mut daily: BTreeMap<i64, BookingCountBucket> = BTreeMap::new();
    let mut weekly: BTreeMap<i64, BookingCountBucket> = BTreeMap::new();
    for (start, rows) in starts {
        let day = local_day(start, visitor_tz).map_err(visitor_zone_error)?;
        let week = week_of(day);
        if week < first_week || week > last_week {
            continue;
        }
        if let Some(listed) = listed.as_deref_mut() {
            listed.extend(rows);
        }
        charge(daily.entry(day), start);
        charge(weekly.entry(week), start);
    }
    Ok(BookingCounts {
        daily: daily.into_values().collect(),
        weekly: weekly.into_values().collect(),
    })
}

/// Eight days, in seconds: one week plus more than any zone's UTC offset.
const SCAN_MARGIN_SECS: u64 = 8 * 86_400;

/// Adds one booking starting at `start` to its period's bucket.
fn charge(entry: Entry<'_, i64, BookingCountBucket>, start: u64) {
    let end = start.saturating_add(1);
    let bucket = entry.or_insert(BookingCountBucket {
        window_start_utc: start,
        window_end_utc: end,
        confirmed: 0,
    });
    bucket.window_start_utc = bucket.window_start_utc.min(start);
    bucket.window_end_utc = bucket.window_end_utc.max(end);
    bucket.confirmed = bucket.confirmed.saturating_add(1);
}
