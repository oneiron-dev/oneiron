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
/// exceptions key too, and each start spans its first occurrence's civil
/// length as the EVENT's projector places it: its days in its zone, or
/// wherever that civil time falls in some zone (fix list row 17868).
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
    Ok(
        civil_starts(row, master, window, exceptions, row.facts.uids(), length)?
            .into_iter()
            .map(|(_, _, span)| span)
            .collect(),
    )
}

/// The starts of an all-day or floating series whose span meets `window`,
/// each as its recurrence key, its civil start on the UTC carrier and its
/// span as the EVENT's projector places it (fix list row 17868), the
/// exceptions of `uids` masked; `length` is its civil length. Candidates
/// are taken across every zone's reach, a superset of any one zone's days.
/// A master seeded in a zone (a dated `DTSTART` with a `TZID`) keys its
/// starts as instants, read back to their civil times here.
pub(in crate::calendar) fn civil_starts(
    row: &CalendarEventRow,
    master: &crate::calendar::claims::CalendarSeriesMasterValue,
    window: TimeRange,
    exceptions: &[CalendarSeriesExceptionValue],
    uids: &[String],
    length: u64,
) -> Result<Vec<(u64, u64, TimeRange)>> {
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
    for uid in uids {
        starts = crate::calendar::series::mask_master_exceptions(row.id, uid, starts, exceptions);
    }
    let projector = row.facts.civil_projector();
    let mut kept = Vec::with_capacity(starts.len());
    for start in starts {
        let civil = if zoned {
            let wall = crate::calendar::utc_to_wall(start, &master.tz).map_err(|_| failed())?;
            carrier_seconds(&wall).ok_or_else(failed)?
        } else {
            start
        };
        if let Some(span) = projector.span(civil, length)
            && span.start <= window.end
            && window.start <= span.end
        {
            kept.push((start, civil, span));
        }
    }
    Ok(kept)
}

/// Each occurrence of a floating or all-day EVENT that meets `window`, its
/// UTC span with its civil span (FIX 17869): its days in its zone, or its
/// envelope (fix list row 17868). `None` for an EVENT anchored at an
/// instant. A lone one is its own one occurrence.
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
    let starts: Vec<(u64, TimeRange)> = match row.facts.series() {
        None => row
            .facts
            .civil_projector()
            .span(first, length)
            .map(|span| (first, span))
            .into_iter()
            .collect(),
        Some(_)
            if row
                .facts
                .uids()
                .iter()
                .any(|uid| withheld.contains(&(row.id, uid.clone()))) =>
        {
            Vec::new()
        }
        Some(master) => civil_starts(row, master, window, exceptions, row.facts.uids(), length)?
            .into_iter()
            .map(|(_, civil, span)| (civil, span))
            .collect(),
    };
    let all_day = row.facts.civil_all_day();
    let duration = row.facts.civil_duration();
    Ok(Some(
        starts
            .into_iter()
            .filter_map(|(start, span)| {
                super::civil::civil_span(all_day, start, duration).map(|named| (span, named))
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
