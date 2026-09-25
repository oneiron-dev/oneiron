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
        return Ok(Vec::new());
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
