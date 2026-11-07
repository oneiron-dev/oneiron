//! Bounded, scoped series occurrences with stable original-instance identities.
use std::time::Instant;

use serde::{Deserialize, Serialize};

use super::facts::{CalendarRead, event_row, receipted, visit_calendar_events};
use super::pages::{CalendarOccurrencesPage, Slices};
use super::requests::CalendarRangeDto;
use crate::calendar::claims::{CalendarSeriesExceptionValue, CalendarSeriesMasterValue};
use crate::calendar::{expand_master_window, mask_master_exceptions};
use crate::claim::{ClaimReadStatus, ScopedRead, ScopedReadResult};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::{EntityId, Error, Result, TimeRange};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarOccurrencesRequest {
    pub master_ref: String,
    /// Inclusive UTC seconds. An unbounded expansion is not a public call.
    pub range: CalendarRangeDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalendarOccurrenceView {
    pub event_ref: String,
    pub master_ref: String,
    pub uid: String,
    pub original_start_utc: u64,
    pub start_utc: u64,
    pub end_utc: u64,
}

impl Memory<'_> {
    pub fn calendar_occurrences(
        &self,
        request: &CalendarOccurrencesRequest,
    ) -> MemoryResult<ScopedReadResult<Vec<CalendarOccurrenceView>>> {
        if !request.range.is_ordered() {
            return Err(MemoryError::bad_request(
                "calendar range start must not exceed end",
            ));
        }
        let lane = self.read_lane(ClaimReadStatus::Surfaceable)?;
        Ok(read_occurrences_scoped(&lane, request)?)
    }
}

/// Reads the stored master, never a caller-supplied recurrence rule. Exception
/// admission and withholding are the same ones search/freebusy already use.
pub fn read_occurrences_scoped(
    read: &ScopedRead<'_>,
    request: &CalendarOccurrencesRequest,
) -> Result<ScopedReadResult<Vec<CalendarOccurrenceView>>> {
    if !request.range.is_ordered() {
        return Err(Error::InvalidKey);
    }
    let master_id = EntityId::from_hex(&request.master_ref)?;
    receipted(read, |lane| occurrences_in(lane, master_id, request.range))
}

fn occurrences_in(
    lane: &CalendarRead<'_>,
    master_id: EntityId,
    range: CalendarRangeDto,
) -> Result<Vec<CalendarOccurrenceView>> {
    match prepare_occurrences(lane, master_id)? {
        Some(prepared) => prepared.within(range),
        None => Ok(Vec::new()),
    }
}

/// [`read_occurrences_scoped`] as one page (FIX 11998): the range from
/// `resume_from` (or its start) in time slices, each whole, until the
/// range's end or `deadline` (see `super::pages`). Each occurrence starts in
/// exactly one slice, so the page keeps today's order.
pub(super) fn read_occurrences_page_scoped(
    read: &ScopedRead<'_>,
    request: &CalendarOccurrencesRequest,
    resume_from: Option<u64>,
    deadline: Option<Instant>,
) -> Result<ScopedReadResult<CalendarOccurrencesPage>> {
    if !request.range.is_ordered() {
        return Err(Error::InvalidKey);
    }
    let master_id = EntityId::from_hex(&request.master_ref)?;
    receipted(read, |lane| {
        let mut slices = Slices::new(
            resume_from.unwrap_or(request.range.start),
            request.range.end,
            deadline,
            false,
        );
        let prepared = prepare_occurrences(lane, master_id)?;
        let mut occurrences = Vec::new();
        while let Some(slice) = slices.next_slice() {
            if let Some(prepared) = &prepared {
                occurrences.extend(prepared.within(CalendarRangeDto {
                    start: slice.start,
                    end: slice.end,
                })?);
            }
        }
        Ok(CalendarOccurrencesPage {
            occurrences,
            complete: slices.resume_from().is_none(),
            resume_from: slices.resume_from(),
        })
    })
}

/// One admitted series master with the detached exceptions that mask it,
/// read once and expanded over a window or one slice of it at a time.
struct PreparedOccurrences {
    master_id: EntityId,
    series: CalendarSeriesMasterValue,
    uids: Vec<String>,
    duration: u64,
    exceptions: Vec<(EntityId, Option<TimeRange>, CalendarSeriesExceptionValue)>,
}

/// The master `master_id` and its exceptions, or `None` when it is no
/// admitted series this lane may expand.
fn prepare_occurrences(
    lane: &CalendarRead<'_>,
    master_id: EntityId,
) -> Result<Option<PreparedOccurrences>> {
    let Some(master) = event_row(lane, master_id)? else {
        return Ok(None);
    };
    if master.facts.series_withheld() || master.facts.exception_withheld() {
        return Ok(None);
    }
    let Some(series) = master.facts.series() else {
        return Ok(None);
    };
    let Some(at) = master.occurred else {
        return Ok(None);
    };
    let withheld = lane.withheld_exception_series()?;
    if master
        .facts
        .uids()
        .iter()
        .any(|uid| withheld.contains_key(&(master_id, uid.clone())))
    {
        return Ok(None);
    }
    let mut exceptions = Vec::new();
    visit_calendar_events(lane, |row| {
        if !row.facts.exception_withheld()
            && let Some(key) = row.facts.exception()
            && key.master_ref == master_id
        {
            exceptions.push((row.id, row.occurred, key.clone()));
        }
        Ok(())
    })?;
    Ok(Some(PreparedOccurrences {
        master_id,
        series: series.clone(),
        uids: master.facts.uids().to_vec(),
        duration: at.end.saturating_sub(at.start),
        exceptions,
    }))
}

impl PreparedOccurrences {
    /// The occurrences that start in `range`, by actual start, then end,
    /// UID, original start and EVENT.
    fn within(&self, range: CalendarRangeDto) -> Result<Vec<CalendarOccurrenceView>> {
        let master_id = self.master_id;
        let keys: Vec<_> = self
            .exceptions
            .iter()
            .map(|(_, _, key)| key.clone())
            .collect();
        let starts = expand_master_window(&self.series, range.to_time_range())
            .map_err(|_| Error::InvalidConfig("calendar recurrence projection failed".into()))?;
        let mut result = Vec::new();
        for uid in &self.uids {
            for start in mask_master_exceptions(master_id, uid, starts.clone(), &keys) {
                result.push(CalendarOccurrenceView {
                    event_ref: master_id.to_hex(),
                    master_ref: master_id.to_hex(),
                    uid: uid.clone(),
                    original_start_utc: start,
                    start_utc: start,
                    end_utc: start.saturating_add(self.duration),
                });
            }
            for (event, occurred, key) in &self.exceptions {
                if key.uid == *uid
                    && let Some(at) = occurred
                    && range.start <= at.start
                    && at.start <= range.end
                {
                    result.push(CalendarOccurrenceView {
                        event_ref: event.to_hex(),
                        master_ref: master_id.to_hex(),
                        uid: uid.clone(),
                        original_start_utc: key.original_start_utc,
                        start_utc: at.start,
                        end_utc: at.end,
                    });
                }
            }
        }
        result.sort_unstable_by(|a, b| {
            (
                a.start_utc,
                a.end_utc,
                &a.uid,
                a.original_start_utc,
                &a.event_ref,
            )
                .cmp(&(
                    b.start_utc,
                    b.end_utc,
                    &b.uid,
                    b.original_start_utc,
                    &b.event_ref,
                ))
        });
        Ok(result)
    }
}

impl Memory<'_> {
    /// Whether the caller can act on this stored master's original instance.
    pub(crate) fn calendar_instance_admitted(
        &self,
        master_id: EntityId,
        uid: &str,
        original: u64,
    ) -> MemoryResult<bool> {
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let checked = receipted(&read, |lane| {
            let Some(row) = event_row(lane, master_id)? else {
                return Ok(false);
            };
            if row.facts.series_withheld()
                || row.facts.exception_withheld()
                || !row.facts.uids().iter().any(|value| value == uid)
                || lane
                    .withheld_exception_series()?
                    .contains_key(&(master_id, uid.to_owned()))
            {
                return Ok(false);
            }
            let Some(series) = row.facts.series() else {
                return Ok(false);
            };
            Ok(expand_master_window(
                series,
                crate::TimeRange {
                    start: original,
                    end: original,
                },
            )
            .map_err(|_| Error::InvalidConfig("calendar recurrence projection failed".into()))?
            .contains(&original))
        })?;
        Ok(checked.value)
    }
}
