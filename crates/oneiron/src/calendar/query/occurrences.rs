//! Windowed occurrences from lane-admitted calendar facts.
use super::facts::CalendarEventRow;
use crate::calendar::claims::CalendarSeriesExceptionValue;
use crate::{Error, Result, TimeRange};
pub(in crate::calendar) fn occurrences(
    row: &CalendarEventRow,
    window: TimeRange,
    exceptions: &[CalendarSeriesExceptionValue],
    withheld: &std::collections::BTreeSet<(crate::EntityId, String)>,
) -> Result<Vec<TimeRange>> {
    if row.facts.series_withheld() || row.facts.exception_withheld() {
        return Ok(Vec::new());
    }
    let Some(occurrence) = row.occurred else {
        // A lone floating or all-day EVENT falls within its civil span; a
        // series of them steps its civil starts on the UTC carrier.
        return match row.facts.series() {
            None => Ok(row.wall_span.into_iter().collect()),
            Some(master) => civil_occurrences(row, master, window, exceptions, withheld),
        };
    };
    let Some(master) = row.facts.series() else {
        return Ok(vec![occurrence]);
    };
    if row
        .facts
        .uids()
        .iter()
        .any(|uid| withheld.contains(&(row.id, uid.clone())))
    {
        return Ok(Vec::new());
    }
    let duration = occurrence.end.saturating_sub(occurrence.start);
    let expanded = TimeRange {
        start: window.start.saturating_sub(duration),
        end: window.end,
    };
    let mut starts = crate::calendar::series::expand_window(&master.rrule, master.into(), expanded)
        .map_err(|_| Error::InvalidConfig("calendar recurrence projection failed".into()))?;
    for uid in row.facts.uids() {
        starts = crate::calendar::series::mask_master_exceptions(row.id, uid, starts, exceptions);
    }
    Ok(starts
        .into_iter()
        .map(|start| TimeRange {
            start,
            end: start.saturating_add(duration),
        })
        .collect())
}

/// The occurrences of an all-day or floating series that meet `window` (FIX
/// 16568). Its master steps on the UTC carrier, where its date and floating
/// exceptions key too, and each start spans the civil envelope its first
/// occurrence spans: wherever that civil time falls in some zone. A master
/// seeded in a zone (a dated `DTSTART` with a `TZID`) has its starts read
/// back to their civil times first.
fn civil_occurrences(
    row: &CalendarEventRow,
    master: &crate::calendar::claims::CalendarSeriesMasterValue,
    window: TimeRange,
    exceptions: &[CalendarSeriesExceptionValue],
    withheld: &std::collections::BTreeSet<(crate::EntityId, String)>,
) -> Result<Vec<TimeRange>> {
    let Some(first) = row.wall_span else {
        return Ok(Vec::new());
    };
    if row
        .facts
        .uids()
        .iter()
        .any(|uid| withheld.contains(&(row.id, uid.clone())))
    {
        return Ok(Vec::new());
    }
    let failed = || Error::InvalidConfig("calendar recurrence projection failed".into());
    let (_, length) = super::facts::civil_bounds(first);
    let (east, west) = super::facts::CIVIL_REACH_SECS;
    // A zone's starts sit up to a day of offsets off their civil times.
    let zoned = !master.tz.eq_ignore_ascii_case("UTC");
    let slack = if zoned { east + west } else { 0 };
    let expanded = TimeRange {
        start: window
            .start
            .saturating_sub(length.saturating_add(west).saturating_add(slack)),
        end: window.end.saturating_add(east).saturating_add(slack),
    };
    let mut starts = crate::calendar::series::expand_window(&master.rrule, master.into(), expanded)
        .map_err(|_| failed())?;
    for uid in row.facts.uids() {
        starts = crate::calendar::series::mask_master_exceptions(row.id, uid, starts, exceptions);
    }
    let mut spans = Vec::with_capacity(starts.len());
    for start in starts {
        let civil = if zoned {
            let wall = crate::calendar::utc_to_wall(start, &master.tz).map_err(|_| failed())?;
            carrier_seconds(&wall).ok_or_else(failed)?
        } else {
            start
        };
        let span = super::facts::civil_envelope(civil, length);
        if span.start <= window.end && window.start <= span.end {
            spans.push(span);
        }
    }
    Ok(spans)
}

/// A zone's wall time read on the UTC carrier: its civil fields as UTC.
fn carrier_seconds(wall: &crate::calendar::WallTime) -> Option<u64> {
    let at = chrono::NaiveDate::from_ymd_opt(wall.y, u32::from(wall.mo), u32::from(wall.d))?
        .and_hms_opt(u32::from(wall.h), u32::from(wall.mi), u32::from(wall.s))?;
    u64::try_from(at.and_utc().timestamp()).ok()
}
