//! Which occurrences a series owes: the row the projector consumes, the
//! quota slots of one pass, and an rrule series' next start through the
//! calendar layer's one expander.

use crate::calendar::SeriesDtStart;
use crate::calendar::series::expand_window_shifting_gaps_page;
use crate::calendar::tz::MAX_SUPPORTED_UTC;
use crate::claim::ClaimBody;
use crate::commitment_schedule::{
    COMMITMENT_QUOTA_SLOTS_PER_PASS, CommitmentDueEntry, CommitmentDuePhase, CommitmentOccurrence,
    CommitmentSchedulePayload, QuotaWindow, Schedule, ScheduleError, ScheduleHistoryEntry,
    ScheduleResult, iso_week_window, validate_quota_count,
};
use crate::entity_id::EntityId;
use crate::temporal::TimeRange;

/// The first window an rrule due search expands, in seconds; each empty window
/// doubles the next. One day keeps a dense rule's first answer small, and the
/// doubling reaches a yearly rule's next start in about nine expansions.
const RRULE_DUE_SEARCH_FIRST_SPAN: u64 = 86_400;

/// The `Project` row for one series and one computed due instant.
///
/// A quota projects at the START of its window and is owed at the window's
/// inclusive end; everything else projects one lead ahead of its due instant.
pub(super) fn project_row(
    series_ref: &EntityId,
    payload: &CommitmentSchedulePayload,
    due_at: u64,
) -> ScheduleResult<CommitmentDueEntry> {
    let (at, occurrence) = match &payload.schedule {
        Schedule::Quota { window, .. } => {
            let QuotaWindow::IsoWeek { tz } = window;
            let window = iso_week_window(due_at, tz)?;
            (
                window.start,
                CommitmentOccurrence::new(window.end, window, 0)?,
            )
        }
        _ => (
            due_at.saturating_sub(payload.lead_seconds()),
            point_occurrence(due_at)?,
        ),
    };
    Ok(CommitmentDueEntry {
        at,
        phase: CommitmentDuePhase::Project,
        series_ref: *series_ref,
        instance_ref: None,
        occurrence,
    })
}

/// The occurrences a due `Project` row owes: the one it NAMES, never one
/// recomputed from the instant the projector happens to run (FIX 9729).
///
/// A pass that runs late still mints the occurrence that fell due while
/// nothing ran, at its own stable time, and its deterministic instance id
/// keeps a delayed retry from minting it twice. A quota row names its window
/// and the first slot still unminted in it, and owes up to
/// [`COMMITMENT_QUOTA_SLOTS_PER_PASS`] slots from there. A row the series has
/// already moved past owes nothing.
pub(super) fn occurrences_named(
    payload: &CommitmentSchedulePayload,
    named: &CommitmentOccurrence,
    history: &[ScheduleHistoryEntry],
) -> ScheduleResult<Vec<CommitmentOccurrence>> {
    match &payload.schedule {
        Schedule::Quota { count, .. } => {
            if history
                .iter()
                .any(|entry| entry.window.start > named.window.start)
            {
                return Ok(Vec::new());
            }
            quota_window_slots(*count, named.window, named.ordinal)
        }
        _ => {
            if history.iter().any(|entry| entry.due_at > named.due_at) {
                return Ok(Vec::new());
            }
            Ok(vec![point_occurrence(named.due_at)?])
        }
    }
}

/// One pass's slots of a quota window: ordinals `first..`, at most
/// [`COMMITMENT_QUOTA_SLOTS_PER_PASS`] of them and none at or past `count`.
///
/// Every slot shares the window's inclusive end as its due instant, because a
/// promise of "three times this week" is one commitment with three openings,
/// not three commitments discovered one at a time.
pub(super) fn quota_window_slots(
    count: u32,
    window: TimeRange,
    first: u32,
) -> ScheduleResult<Vec<CommitmentOccurrence>> {
    validate_quota_count(count)?;
    let end = first
        .saturating_add(COMMITMENT_QUOTA_SLOTS_PER_PASS)
        .min(count);
    (first..end)
        .map(|ordinal| CommitmentOccurrence::new(window.end, window, ordinal))
        .collect()
}

/// A non-quota occurrence covers exactly its due instant: the window is the
/// point, so the membership key round-trips it without loss.
pub(super) fn point_occurrence(due_at: u64) -> ScheduleResult<CommitmentOccurrence> {
    CommitmentOccurrence::new(
        due_at,
        TimeRange {
            start: due_at,
            end: due_at,
        },
        0,
    )
}

/// Where an rrule series' next start is searched from: the instant after the
/// greatest occurrence it already has, else `now`. The same rule as an
/// interval's: an overdue occurrence after the last one is still owed, and a
/// series with none owes nothing from before it was indexed.
pub(super) fn rrule_search_from(now: u64, history: &[ScheduleHistoryEntry]) -> ScheduleResult<u64> {
    match history.iter().map(|entry| entry.due_at).max() {
        Some(last) => last.checked_add(1).ok_or(ScheduleError::ArithmeticOverflow),
        None => Ok(now),
    }
}

/// The rule's DTSTART: the series claim's valid-time start, which every
/// commitment claim carries.
pub(super) fn rrule_dtstart(series: &ClaimBody) -> ScheduleResult<u64> {
    series.valid_from.ok_or(ScheduleError::Invalid(
        "commitment rrule series carries no valid-time start",
    ))
}

/// The first start of an rrule series at or after `from`, or `None` once the
/// rule has none left before the calendar's last supported instant (its
/// `COUNT` or `UNTIL` is spent).
///
/// Searched in disjoint windows that double from
/// [`RRULE_DUE_SEARCH_FIRST_SPAN`], so a dense rule answers from a small
/// window and a sparse one in a few expansions. Each window is walked as one
/// deadline-bound page due at once (FIX 11998): the page ends soon after its
/// first start, the only one this search needs, so a dense window is never
/// walked to its end. A start a spring-forward gap removed is owed at its
/// RFC 5545 shifted instant, never dropped.
pub(super) fn next_rrule_due(
    rrule: &str,
    tz: &str,
    dtstart_utc: u64,
    from: u64,
) -> ScheduleResult<Option<u64>> {
    let dtstart = SeriesDtStart { dtstart_utc, tz };
    let mut start = from;
    let mut span = RRULE_DUE_SEARCH_FIRST_SPAN;
    while start <= MAX_SUPPORTED_UTC {
        let end = start.saturating_add(span - 1).min(MAX_SUPPORTED_UTC);
        let page = expand_window_shifting_gaps_page(
            rrule,
            dtstart,
            TimeRange { start, end },
            None,
            std::time::Instant::now(),
        )?;
        if let Some(due) = page.starts.first() {
            return Ok(Some(*due));
        }
        if end == MAX_SUPPORTED_UTC {
            break;
        }
        start = end + 1;
        span = span.saturating_mul(2);
    }
    Ok(None)
}
