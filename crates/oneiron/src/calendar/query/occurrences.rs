//! Windowed occurrences from lane-admitted calendar facts.
use std::collections::BTreeMap;

use super::facts::CalendarEventRow;
use crate::calendar::CalendarError;
use crate::calendar::claims::{CalendarSeriesExceptionValue, CalendarSeriesMasterValue};
use crate::calendar::series::{ExpansionCursor, expand_window_carried};
use crate::{EntityId, Error, Result, TimeRange};

/// Where each series' expansion stood when the last slice of a page ended
/// (FIX 16174), so the next slice resumes a counted rule's walk there
/// instead of walking it again from its DTSTART: its prefix is walked once
/// per page. Kept for one page, by the series' EVENT, with the rule and
/// start it was walked on; a cursor whose series changed, or whose slice
/// does not continue it, is dropped.
#[derive(Default)]
pub(in crate::calendar) struct SeriesCursors {
    kept: BTreeMap<EntityId, KeptCursor>,
}

/// One series' kept cursor and the rule and start it walks.
struct KeptCursor {
    master: CalendarSeriesMasterValue,
    cursor: ExpansionCursor,
}

impl SeriesCursors {
    /// The starts `master` (the series of EVENT `id`) has in `window`,
    /// resumed at the cursor the slice before left for it, keeping the
    /// cursor for the slice after, which expands from `next_from`.
    ///
    /// # Errors
    ///
    /// As [`crate::calendar::expand_window`].
    pub(in crate::calendar) fn expand(
        &mut self,
        id: EntityId,
        master: &CalendarSeriesMasterValue,
        window: TimeRange,
        next_from: Option<u64>,
    ) -> std::result::Result<Vec<u64>, CalendarError> {
        let carried = self
            .kept
            .get(&id)
            .filter(|kept| kept.master == *master && kept.cursor.continues(window))
            .map(|kept| kept.cursor);
        let (starts, carry) =
            expand_window_carried(&master.rrule, master.into(), window, carried, next_from)?;
        let Some(carry) = carry else {
            self.kept.remove(&id);
            return Ok(starts);
        };
        if let Some(kept) = self.kept.get_mut(&id).filter(|kept| kept.master == *master) {
            kept.cursor = carry;
        } else {
            self.kept.insert(
                id,
                KeptCursor {
                    master: master.clone(),
                    cursor: carry,
                },
            );
        }
        Ok(starts)
    }
}

/// `row`'s occurrences that can meet `window`. A series expands under
/// `cursors`, which a page's slices share so a counted rule's walk carries
/// from each slice to the next.
pub(in crate::calendar) fn occurrences(
    row: &CalendarEventRow,
    window: TimeRange,
    exceptions: &[CalendarSeriesExceptionValue],
    withheld: &std::collections::BTreeSet<(crate::EntityId, String)>,
    cursors: &mut SeriesCursors,
) -> Result<Vec<TimeRange>> {
    if row.facts.series_withheld() || row.facts.exception_withheld() {
        return Ok(Vec::new());
    }
    let Some(occurrence) = row.occurred else {
        // A lone floating or all-day EVENT falls within its civil span; a
        // series of them steps its civil starts on the UTC carrier.
        return match row.facts.series() {
            None => Ok(row.wall_span.into_iter().collect()),
            Some(master) => civil_occurrences(row, master, window, exceptions, withheld, cursors),
        };
    };
    let Some(master) = row.facts.series() else {
        // A row under the busy hold whose kind, held, is floating or
        // all-day keeps both its header's interval and its civil span.
        return Ok(std::iter::once(occurrence).chain(row.wall_span).collect());
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
    // The slice after starts the second after this one, and its expansion
    // as far before that as an occurrence lasts.
    let next_from = window
        .end
        .checked_add(1)
        .map(|next| next.saturating_sub(duration));
    let mut starts = cursors
        .expand(row.id, master, expanded, next_from)
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
/// wherever that civil time falls in some zone (fix list row 17868). The
/// series expands under `cursors`, as a timed one does.
fn civil_occurrences(
    row: &CalendarEventRow,
    master: &crate::calendar::claims::CalendarSeriesMasterValue,
    window: TimeRange,
    exceptions: &[CalendarSeriesExceptionValue],
    withheld: &std::collections::BTreeSet<(crate::EntityId, String)>,
    cursors: &mut SeriesCursors,
) -> Result<Vec<TimeRange>> {
    let Some((_, length)) = row.facts.placed_extent() else {
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
    Ok(civil_starts(
        row,
        master,
        window,
        exceptions,
        row.facts.uids(),
        length,
        cursors,
    )?
    .into_iter()
    .map(|(_, _, span)| span)
    .collect())
}

/// The starts of an all-day or floating series whose span meets `window`,
/// each as its recurrence key, its civil start on the UTC carrier and its
/// span as the EVENT's projector places it (fix list row 17868), the
/// exceptions of `uids` masked; `length` is its civil length. Candidates
/// are taken across every zone's reach, a superset of any one zone's days.
/// A master seeded in a zone (a dated `DTSTART` with a `TZID`) keys its
/// starts as instants, read back to their civil times here. The series
/// expands under `cursors`, which a page's slices share (FIX 16174).
pub(in crate::calendar) fn civil_starts(
    row: &CalendarEventRow,
    master: &crate::calendar::claims::CalendarSeriesMasterValue,
    window: TimeRange,
    exceptions: &[CalendarSeriesExceptionValue],
    uids: &[String],
    length: u64,
    cursors: &mut SeriesCursors,
) -> Result<Vec<(u64, u64, TimeRange)>> {
    let failed = || Error::InvalidConfig("calendar recurrence projection failed".into());
    let (east, west) = super::facts::CIVIL_REACH_SECS;
    // A zone's starts sit up to a day of offsets off their civil times.
    let zoned = !master.tz.eq_ignore_ascii_case("UTC");
    let slack = if zoned { east + west } else { 0 };
    let reach_before = length.saturating_add(west).saturating_add(slack);
    let expanded = TimeRange {
        start: window.start.saturating_sub(reach_before),
        end: window.end.saturating_add(east).saturating_add(slack),
    };
    // The slice after starts the second after this one, and its expansion
    // as far before that as this one's.
    let next_from = window
        .end
        .checked_add(1)
        .map(|next| next.saturating_sub(reach_before));
    let mut starts = cursors
        .expand(row.id, master, expanded, next_from)
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
/// instant. A lone one is its own one occurrence; a series expands under
/// `cursors`, which a page's slices share (FIX 16174).
pub(in crate::calendar) fn civil_occurrences_named(
    row: &CalendarEventRow,
    window: TimeRange,
    exceptions: &[CalendarSeriesExceptionValue],
    withheld: &std::collections::BTreeSet<(crate::EntityId, String)>,
    cursors: &mut SeriesCursors,
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
        Some(master) => civil_starts(
            row,
            master,
            window,
            exceptions,
            row.facts.uids(),
            length,
            cursors,
        )?
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
