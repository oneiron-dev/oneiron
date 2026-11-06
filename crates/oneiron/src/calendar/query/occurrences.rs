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
/// exceptions key too, and each start spans the civil envelope of its first
/// occurrence's civil length: wherever that civil time falls in some zone.
fn civil_occurrences(
    row: &CalendarEventRow,
    master: &crate::calendar::claims::CalendarSeriesMasterValue,
    window: TimeRange,
    exceptions: &[CalendarSeriesExceptionValue],
    withheld: &std::collections::BTreeSet<(crate::EntityId, String)>,
) -> Result<Vec<TimeRange>> {
    let Some((_, length)) = row.facts.civil_extent() else {
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
    Ok(civil_starts(row, master, window, exceptions, length)?
        .into_iter()
        .map(|(_, civil)| super::facts::civil_envelope(civil, length))
        .collect())
}

/// The starts of an all-day or floating series whose civil envelope meets
/// `window`, each as its recurrence key and its civil start on the UTC
/// carrier, its exceptions masked; `length` is its civil length. A master
/// seeded in a zone (a dated `DTSTART` with a `TZID`) keys its starts as
/// instants, read back to their civil times here.
pub(in crate::calendar) fn civil_starts(
    row: &CalendarEventRow,
    master: &crate::calendar::claims::CalendarSeriesMasterValue,
    window: TimeRange,
    exceptions: &[CalendarSeriesExceptionValue],
    length: u64,
) -> Result<Vec<(u64, u64)>> {
    let failed = || Error::InvalidConfig("calendar recurrence projection failed".into());
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
    let mut kept = Vec::with_capacity(starts.len());
    for start in starts {
        let civil = if zoned {
            let wall = crate::calendar::utc_to_wall(start, &master.tz).map_err(|_| failed())?;
            carrier_seconds(&wall).ok_or_else(failed)?
        } else {
            start
        };
        let span = super::facts::civil_envelope(civil, length);
        if span.start <= window.end && window.start <= span.end {
            kept.push((start, civil));
        }
    }
    Ok(kept)
}

/// Each occurrence of a floating or all-day EVENT that meets `window`, its
/// envelope with its civil span (FIX 17869); `None` for an EVENT anchored at
/// an instant. A lone one is its own one occurrence.
pub(in crate::calendar) fn civil_occurrences_named(
    row: &CalendarEventRow,
    window: TimeRange,
    exceptions: &[CalendarSeriesExceptionValue],
    withheld: &std::collections::BTreeSet<(crate::EntityId, String)>,
) -> Result<Option<Vec<(TimeRange, super::civil::CalendarCivilSpan)>>> {
    if row.occurred.is_some() {
        return Ok(None);
    }
    let Some((first, length)) = row.facts.civil_extent() else {
        return Ok(None);
    };
    if row.facts.series_withheld() || row.facts.exception_withheld() {
        return Ok(Some(Vec::new()));
    }
    let starts = match row.facts.series() {
        None => vec![first],
        Some(_)
            if row
                .facts
                .uids()
                .iter()
                .any(|uid| withheld.contains(&(row.id, uid.clone()))) =>
        {
            Vec::new()
        }
        Some(master) => civil_starts(row, master, window, exceptions, length)?
            .into_iter()
            .map(|(_, civil)| civil)
            .collect(),
    };
    let all_day = row.facts.civil_all_day();
    Ok(Some(
        starts
            .into_iter()
            .filter_map(|start| {
                super::civil::civil_span(all_day, start, length)
                    .map(|named| (super::facts::civil_envelope(start, length), named))
            })
            .collect(),
    ))
}

/// A zone's wall time read on the UTC carrier: its civil fields as UTC.
fn carrier_seconds(wall: &crate::calendar::WallTime) -> Option<u64> {
    let at = chrono::NaiveDate::from_ymd_opt(wall.y, u32::from(wall.mo), u32::from(wall.d))?
        .and_hms_opt(u32::from(wall.h), u32::from(wall.mi), u32::from(wall.s))?;
    u64::try_from(at.and_utc().timestamp()).ok()
}
