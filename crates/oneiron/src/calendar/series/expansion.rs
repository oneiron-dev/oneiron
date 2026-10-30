//! Windowed recurrence expansion over the tz border.

use std::time::Instant;

use chrono::{DateTime, Datelike, TimeDelta, TimeZone, Timelike};
use rrule::{RRule, RRuleSet, Tz, Unvalidated};

use super::SeriesDtStart;
use crate::calendar::CalendarError;
use crate::calendar::claims::CalendarSeriesMasterValue;
use crate::calendar::tz::{WallTime, utc_to_wall, wall_to_utc};
use crate::temporal::TimeRange;

/// Recurrence steps one expansion takes before it says, once, that it is still
/// walking (rule 5: an advisory scan check, never a refusal).
///
/// The walk is bounded by the window, and a rule without `COUNT` starts at the
/// last whole period before it (see [`super::reseed`]), so only a dense
/// window or a counted rule seeded long before its window walks this far.
const EXPANSION_SCAN_CHECK_STEPS: usize = 100_000;

/// Recurrence steps a deadline-bound walk takes between reads of the clock
/// (FIX 11998).
const EXPANSION_DEADLINE_CHECK_STEPS: usize = 1_024;

/// One deadline-bound page of a window's occurrence starts (FIX 11998).
///
/// A page that carries at least one occurrence ends at its deadline; one
/// that has walked to the window's end, or the series', ends there. The walk
/// up to a page's first occurrence is not cut, so each page moves the
/// expansion on and a resumed walk always reaches the window's end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpansionPage {
    /// The occurrence starts this page walked: ascending, unique, inside
    /// the window.
    pub starts: Vec<u64>,
    /// Where the walk resumes when the deadline ended the page: the same
    /// window from this instant on. `None` once the window is walked.
    pub resume_from: Option<u64>,
}

/// Wall-clock slack on the `UNTIL` bound the recurrence engine is given.
///
/// RFC 5545 pins `UNTIL` to an instant while the engine stops on a wall clock,
/// and inside a fall-back fold no wall time is equal to that instant: the last
/// occurrence of the series can stand *later* on the clock than its bound and
/// still be earlier than it. So the engine gets a bound loose enough that it
/// cannot end the series early — no post-epoch IANA transition rewinds a clock
/// by a day — and [`expand_window`] enforces the instant itself.
const UNTIL_WALL_SLACK_SECS: u64 = 86_400;

/// The one RFC 5545 content-line property this door reads.
const RRULE_PROPERTY: &str = "RRULE";

/// Expands a recurrence rule into the occurrence starts inside `window`.
///
/// `rrule` is RFC 5545 recurrence text (`FREQ=WEEKLY;BYDAY=MO`, with or without
/// the `RRULE:` prefix). Output is normalized: ascending, unique UTC seconds,
/// each inside the inclusive `window`.
///
/// The rule is stepped on `dtstart`'s wall clock and each occurrence crosses
/// the [`tz`](crate::calendar::tz) border once, so a recurring local hour survives a DST
/// transition instead of drifting by the offset change.
///
/// # Errors
///
/// - [`CalendarError::InvalidRecurrenceWindow`] — `window.start > window.end`,
///   answered before any recurrence work. A one-instant window
///   (`start == end`) is valid.
/// - [`CalendarError::InvalidRecurrenceRule`] — the text is not a rule this
///   engine supports, it is some other content line, it names both `COUNT` and
///   `UNTIL`, or it can never fire (a zero `INTERVAL` or `COUNT`, or an `UNTIL`
///   before its own start). A rule that is merely dense is walked to the end
///   of the window, never truncated and never refused for its size.
/// - [`CalendarError::UnknownTimeZone`] — `dtstart.tz` is not an IANA zone.
/// - [`CalendarError::NonexistentWallTime`] — an occurrence the window asked
///   for falls in a spring-forward gap and has no instant. The caller decides
///   skip-vs-shift; this door will not choose for it
///   ([`expand_window_shifting_gaps_page`] is the RFC 5545 shift).
/// - [`CalendarError::TimestampOutOfRange`] — `dtstart_utc` or a window bound
///   is past the border's supported range.
///
/// A fall-back fold is not an error: it resolves to the earliest offset, the
/// same way [`wall_to_utc`](crate::calendar::wall_to_utc) resolves it everywhere else.
pub fn expand_window(
    rrule: &str,
    dtstart: SeriesDtStart<'_>,
    window: TimeRange,
) -> Result<Vec<u64>, CalendarError> {
    expand(rrule, dtstart, window, GapPolicy::Refuse, None).map(|page| page.starts)
}

/// [`expand_window`] walked under `deadline`: one [`ExpansionPage`], and
/// where the next resumes when the deadline ended it. The pages a caller
/// walks from `window.start` to the window's end name exactly the starts
/// [`expand_window`] names; none is refused or cut for its size.
///
/// # Errors
///
/// As [`expand_window`], for the part of the window this page walks.
pub fn expand_window_page(
    rrule: &str,
    dtstart: SeriesDtStart<'_>,
    window: TimeRange,
    deadline: Instant,
) -> Result<ExpansionPage, CalendarError> {
    expand(rrule, dtstart, window, GapPolicy::Refuse, Some(deadline))
}

/// [`expand_window_page`] with RFC 5545 §3.3.5's reading of a spring-forward
/// gap: an occurrence whose wall time the zone skips is read with the UTC
/// offset in force before the gap, so it lands as far past the transition as
/// it stood past the gap's start on the clock.
///
/// For a caller that must owe every occurrence (a commitment schedule), where
/// dropping one or refusing the whole window would both lose an obligation.
///
/// # Errors
///
/// As [`expand_window_page`], except [`CalendarError::NonexistentWallTime`],
/// which remains only when the day before the gap has no instant at that wall
/// time either.
pub(crate) fn expand_window_shifting_gaps_page(
    rrule: &str,
    dtstart: SeriesDtStart<'_>,
    window: TimeRange,
    deadline: Instant,
) -> Result<ExpansionPage, CalendarError> {
    expand(
        rrule,
        dtstart,
        window,
        GapPolicy::ShiftForward,
        Some(deadline),
    )
}

/// What the walk does with an occurrence a spring-forward gap removed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum GapPolicy {
    /// Answer [`CalendarError::NonexistentWallTime`].
    Refuse,
    /// Read it with the offset in force before the gap (RFC 5545 §3.3.5).
    ShiftForward,
}

fn expand(
    rrule: &str,
    dtstart: SeriesDtStart<'_>,
    window: TimeRange,
    gaps: GapPolicy,
    deadline: Option<Instant>,
) -> Result<ExpansionPage, CalendarError> {
    if window.start > window.end {
        return Err(CalendarError::InvalidRecurrenceWindow);
    }
    let tz = dtstart.tz;
    let seed = wall_clock_at(dtstart.dtstart_utc, tz)?;
    let first = wall_clock_at(window.start, tz)?;

    let (parsed, until_utc) = parse_rule(rrule, tz)?;
    let rule = parsed
        .clone()
        .validate(seed)
        .map_err(|_| invalid_rule(rrule))?;
    // RFC 5545 makes `INTERVAL` and `COUNT` positive integers and puts `UNTIL`
    // no earlier than the start, and the engine answers each of these three by
    // finishing before it produces anything. An empty vector is a statement
    // about the window; a rule that can never fire is a defect in the rule, and
    // saying so is the whole point of not returning one silently.
    if rule.get_interval() == 0
        || rule.get_count() == Some(0)
        || until_utc.is_some_and(|until| until < dtstart.dtstart_utc)
    {
        return Err(invalid_rule(rrule));
    }
    // The series ends at the earlier of the two instants bounding it: the
    // caller's window and the rule's own `UNTIL`. Both are instants because
    // both are stated as instants — translating either onto the wall clock and
    // stopping there loses a fold's last occurrence, which stands after the
    // bound on the clock and before it on the timeline.
    let end = until_utc.map_or(window.end, |until| until.min(window.end));
    let last = wall_clock_at(end, tz)?;
    // The engine's own `limit` keeps a rule that never fires from cycling; the
    // walk itself is bounded by the window and never by a step count.
    let (seed, rule) = super::reseed::reseeded(&parsed, rule, seed, first);
    let series = RRuleSet::new(seed).rrule(rule).limit();

    let mut starts = Vec::new();
    // The latest start this page walked, and where the next page resumes
    // once the deadline ends this one.
    let mut latest = None;
    let mut resume_from = None;
    for (step, occurrence) in (&series).into_iter().enumerate() {
        if let (Some(deadline), Some(walked)) = (deadline, latest)
            && step % EXPANSION_DEADLINE_CHECK_STEPS == 0
            && Instant::now() >= deadline
        {
            resume_from = walked.checked_add(1).filter(|_| walked < end);
            break;
        }
        if step == EXPANSION_SCAN_CHECK_STEPS {
            tracing::warn!(
                rule = rrule,
                steps = step,
                window_start = window.start,
                window_end = window.end,
                "recurrence expansion passed its scan check and walks on"
            );
        }
        // Below the window's wall clock is below the window: the border is
        // increasing, so no earlier wall time can recover into it. Skipping
        // before the conversion also keeps gap errors scoped to occurrences the
        // caller actually asked about.
        if occurrence < first {
            continue;
        }
        // Inside the series' own wall clock a gap is the caller's verdict to
        // make. Past it the walk only continues because a fold can map a later
        // wall clock onto an earlier instant — and a wall time the zone never
        // observes has no instant at all, so out there it ends the walk instead
        // of becoming an error about occurrences nobody asked for.
        let start = match wall_to_utc(&wall_clock_of(&occurrence), tz) {
            Ok(start) => start,
            Err(CalendarError::NonexistentWallTime { .. })
                if gaps == GapPolicy::ShiftForward && occurrence <= last =>
            {
                shifted_past_gap(&occurrence, tz)?
            }
            Err(error) if occurrence <= last => return Err(error),
            Err(_) => break,
        };
        // The recovered instants ascend, so the first one past the end is the
        // last one worth walking to.
        if start > end {
            break;
        }
        if start >= window.start {
            starts.push(start);
            latest = latest.max(Some(start));
        }
    }
    // Normalization is a guarantee this door makes, not one it inherits: the
    // engine's yield order and multiplicity are its own business, and the two
    // consumers of this API read the output as a set of instants.
    starts.sort_unstable();
    starts.dedup();
    Ok(ExpansionPage {
        starts,
        resume_from,
    })
}

/// Expands a stored `calendar.series_master` value over `window`.
///
/// # Errors
///
/// As [`expand_window`], which this delegates to.
pub fn expand_master_window(
    master: &CalendarSeriesMasterValue,
    window: TimeRange,
) -> Result<Vec<u64>, CalendarError> {
    expand_window(&master.rrule, SeriesDtStart::from(master), window)
}

fn invalid_rule(rrule: &str) -> CalendarError {
    CalendarError::InvalidRecurrenceRule {
        rule: rrule.to_owned(),
    }
}

/// Lifts civil fields into the datetime type the recurrence engine steps.
///
/// The carrier zone is UTC and that is the point: it has no transitions, so the
/// engine does civil arithmetic and only civil arithmetic. Which instant each
/// resulting wall time names is the border's decision, made once, in
/// [`expand_window`].
fn wall_clock(wall: WallTime) -> Option<DateTime<Tz>> {
    Tz::UTC
        .with_ymd_and_hms(
            wall.y,
            u32::from(wall.mo),
            u32::from(wall.d),
            u32::from(wall.h),
            u32::from(wall.mi),
            u32::from(wall.s),
        )
        .single()
}

/// The civil fields a carrier datetime stands for.
fn wall_clock_of(dt: &DateTime<Tz>) -> WallTime {
    // Every cast is lossless: the accessors are documented as 1-12, 1-31, 0-23,
    // 0-59 and 0-59. The carrier zone is UTC, so these fields are the wall
    // clock the rule stepped to, not an instant's UTC rendering.
    WallTime {
        y: dt.year(),
        mo: dt.month() as u8,
        d: dt.day() as u8,
        h: dt.hour() as u8,
        mi: dt.minute() as u8,
        s: dt.second() as u8,
    }
}

/// Crosses the CAL-01 border and lifts the result onto the carrier clock.
fn wall_clock_at(utc: u64, tz: &str) -> Result<DateTime<Tz>, CalendarError> {
    let wall = utc_to_wall(utc, tz)?;
    wall_clock(wall).ok_or(CalendarError::TimestampOutOfRange { utc })
}

/// The instant RFC 5545 §3.3.5 gives a wall time a spring-forward gap removed:
/// the same clock reading under the offset in force before the gap, taken from
/// the same wall time one day earlier.
fn shifted_past_gap(occurrence: &DateTime<Tz>, tz: &str) -> Result<u64, CalendarError> {
    let out_of_range = || CalendarError::TimestampOutOfRange {
        utc: u64::try_from(occurrence.timestamp()).unwrap_or(0),
    };
    let day_before = occurrence
        .checked_sub_signed(TimeDelta::try_days(1).ok_or_else(out_of_range)?)
        .ok_or_else(out_of_range)?;
    let before =
        i64::try_from(wall_to_utc(&wall_clock_of(&day_before), tz)?).map_err(|_| out_of_range())?;
    // On the carrier clock a timestamp is the wall time read as UTC, so this
    // difference is the zone's offset before the gap.
    let offset = day_before.timestamp() - before;
    u64::try_from(occurrence.timestamp() - offset).map_err(|_| out_of_range())
}

/// Reads recurrence text into a rule the engine steps, plus the instant its
/// `UNTIL` names.
///
/// Two RFC 5545 verdicts the vetted parser does not reach on its own, both
/// answered on the text rather than by stepping it. It accepts any content line
/// and then ignores the property name it read, so `EXDATE:FREQ=DAILY` — a line
/// whose job is to *remove* occurrences — arrives as a plausible daily series;
/// only an `RRULE` is a rule. And it accepts `COUNT` and `UNTIL` together,
/// which the RFC makes mutually exclusive: a rule naming two endings names
/// none, and choosing one of them for its author is not this door's call.
///
/// The `UNTIL` the rule carries away is the engine's stopping wall clock, held
/// deliberately loose (see [`UNTIL_WALL_SLACK_SECS`]); the exact instant is
/// returned alongside for [`expand_window`] to end the series on.
fn parse_rule(rrule: &str, tz: &str) -> Result<(RRule<Unvalidated>, Option<u64>), CalendarError> {
    if let Some((property, _)) = rrule.split_once(':')
        && !property.eq_ignore_ascii_case(RRULE_PROPERTY)
    {
        return Err(invalid_rule(rrule));
    }
    let parsed: RRule<Unvalidated> = rrule.parse().map_err(|_| invalid_rule(rrule))?;
    let Some(until) = parsed.get_until() else {
        return Ok((parsed, None));
    };
    if parsed.get_count().is_some() {
        return Err(invalid_rule(rrule));
    }
    // An `UNTIL` without the `Z` is machine-local, which is both RFC-invalid
    // against a zoned start and environment-dependent. Leave it for validation
    // to reject rather than laundering it into a UTC instant here.
    if until.timezone().is_local() {
        return Ok((parsed, None));
    }
    let Ok(until_utc) = u64::try_from(until.timestamp()) else {
        // Pre-epoch, so outside the engine's model and before any start it
        // could bound. Validation rejects it as an `UNTIL` before the start.
        return Ok((parsed, None));
    };
    let bound = utc_to_wall(until_utc.saturating_add(UNTIL_WALL_SLACK_SECS), tz)
        .ok()
        .and_then(wall_clock)
        .ok_or_else(|| invalid_rule(rrule))?;
    Ok((parsed.until(bound), Some(until_utc)))
}
