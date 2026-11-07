//! Bounded, scoped series occurrences with stable original-instance identities.
use std::time::Instant;

use serde::{Deserialize, Serialize};

use super::facts::{CalendarEventRow, CalendarRead, event_row, receipted, visit_calendar_events};
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
    /// The occurrence's recurrence key: a UTC instant, or for an all-day or
    /// floating series its civil start read as UTC.
    pub original_start_utc: u64,
    /// Inclusive UTC bounds; for an all-day or floating occurrence, the
    /// span it falls in across every zone, its days or wall times in
    /// [`Self::civil`].
    pub start_utc: u64,
    pub end_utc: u64,
    /// An all-day or floating occurrence's days or wall times (FIX 17869).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub civil: Option<super::civil::CalendarCivilSpan>,
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
        Some(prepared) => prepared.within(range, None),
        None => Ok(Vec::new()),
    }
}

/// [`read_occurrences_scoped`] as one page (FIX 11998): the range from
/// `resume_from` (or its start) in time slices, each whole, until the
/// range's end or `deadline` (see `super::pages`). Each occurrence starts in
/// exactly one slice, so the page keeps today's order: a floating or all-day
/// occurrence that starts before the range and still meets it belongs to
/// the first page's first slice (FIX 17869).
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
        let mut lookback = resume_from.is_none();
        while let Some(slice) = slices.next_slice() {
            let owned_from = (!lookback).then_some(slice.start);
            lookback = false;
            if let Some(prepared) = &prepared {
                occurrences.extend(prepared.within(
                    CalendarRangeDto {
                        start: slice.start,
                        end: slice.end,
                    },
                    owned_from,
                )?);
            }
        }
        Ok(CalendarOccurrencesPage {
            occurrences,
            complete: slices.resume_from().is_none(),
            resume_from: slices.resume_from(),
        })
    })
}

/// A detached exception of a prepared master: its EVENT, its instant or
/// civil envelope, its days or wall times when it is floating or all-day,
/// and its recurrence key.
type PreparedException = (
    EntityId,
    Option<TimeRange>,
    Option<super::civil::CalendarCivilSpan>,
    CalendarSeriesExceptionValue,
);

/// One admitted series master with the detached exceptions that mask it,
/// read once and expanded over a window or one slice of it at a time.
struct PreparedOccurrences {
    master_id: EntityId,
    master: CalendarEventRow,
    series: CalendarSeriesMasterValue,
    exceptions: Vec<PreparedException>,
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
    let Some(series) = master.facts.series().cloned() else {
        return Ok(None);
    };
    // A floating or all-day master has no instant: its occurrences step on
    // the UTC carrier and name their days (FIX 17869).
    if master.occurred.is_none() && master.facts.civil_extent().is_none() {
        return Ok(None);
    }
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
            let named = row.facts.civil_extent().and_then(|(start, _)| {
                super::civil::civil_span(
                    row.facts.civil_all_day(),
                    start,
                    row.facts.civil_duration(),
                )
            });
            exceptions.push((row.id, row.occurred.or(row.wall_span), named, key.clone()));
        }
        Ok(())
    })?;
    Ok(Some(PreparedOccurrences {
        master_id,
        master,
        series,
        exceptions,
    }))
}

impl PreparedOccurrences {
    /// The occurrences that meet `range`, by actual start, then end, UID,
    /// original start and EVENT: a timed one by its start, a floating or
    /// all-day one by its envelope (FIX 17869). With `owned_from`, only the
    /// ones that start at or after it: a slice past a first page's first
    /// owns only the starts it holds.
    fn within(
        &self,
        range: CalendarRangeDto,
        owned_from: Option<u64>,
    ) -> Result<Vec<CalendarOccurrenceView>> {
        let master_id = self.master_id;
        let master = &self.master;
        let series = &self.series;
        let civil = master.facts.civil_extent();
        let keys: Vec<_> = self
            .exceptions
            .iter()
            .map(|(_, _, _, key)| key.clone())
            .collect();
        let window = range.to_time_range();
        // A master expands once, before any UID, as a timed one always did;
        // each UID then masks its own exceptions.
        let timed = match master.occurred {
            Some(at) => Some((
                at,
                expand_master_window(series, window).map_err(|_| {
                    Error::InvalidConfig("calendar recurrence projection failed".into())
                })?,
            )),
            None => None,
        };
        let civil_all = match (master.occurred, civil) {
            (None, Some((_, length))) => {
                super::occurrences::civil_starts(master, series, window, &keys, &[], length)?
            }
            _ => Vec::new(),
        };
        let mut result = Vec::new();
        for uid in master.facts.uids() {
            match (&timed, civil) {
                (Some((at, starts)), _) => {
                    let duration = at.end.saturating_sub(at.start);
                    for start in mask_master_exceptions(master_id, uid, starts.clone(), &keys) {
                        result.push(CalendarOccurrenceView {
                            event_ref: master_id.to_hex(),
                            master_ref: master_id.to_hex(),
                            uid: uid.clone(),
                            original_start_utc: start,
                            start_utc: start,
                            end_utc: start.saturating_add(duration),
                            civil: None,
                        });
                    }
                }
                (None, Some((_, length))) => {
                    let all_day = master.facts.civil_all_day();
                    let duration = master.facts.civil_duration();
                    let kept: std::collections::BTreeSet<u64> = mask_master_exceptions(
                        master_id,
                        uid,
                        civil_all.iter().map(|&(key, _)| key).collect(),
                        &keys,
                    )
                    .into_iter()
                    .collect();
                    for &(key, start) in civil_all.iter().filter(|(key, _)| kept.contains(key)) {
                        let span = super::facts::civil_envelope(start, length);
                        result.push(CalendarOccurrenceView {
                            event_ref: master_id.to_hex(),
                            master_ref: master_id.to_hex(),
                            uid: uid.clone(),
                            original_start_utc: key,
                            start_utc: span.start,
                            end_utc: span.end,
                            civil: super::civil::civil_span(all_day, start, duration),
                        });
                    }
                }
                (None, None) => {}
            }
            for (event, at, named, key) in &self.exceptions {
                // A civil replacement meets the range by its envelope, a timed
                // one by its start.
                if key.uid == *uid
                    && let Some(at) = at
                    && if named.is_some() {
                        at.start <= range.end && range.start <= at.end
                    } else {
                        range.start <= at.start && at.start <= range.end
                    }
                {
                    result.push(CalendarOccurrenceView {
                        event_ref: event.to_hex(),
                        master_ref: master_id.to_hex(),
                        uid: uid.clone(),
                        original_start_utc: key.original_start_utc,
                        start_utc: at.start,
                        end_utc: at.end,
                        civil: named.clone(),
                    });
                }
            }
        }
        if let Some(from) = owned_from {
            result.retain(|occurrence| occurrence.start_utc >= from);
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
