//! Windowed recurrence expansion over the tz border.

use chrono::{DateTime, Datelike, TimeZone, Timelike};
use rrule::{RRule, RRuleSet, Tz, Unvalidated};

use super::SeriesDtStart;
use crate::calendar::CalendarError;
use crate::calendar::claims::CalendarSeriesMasterValue;
use crate::calendar::tz::{WallTime, utc_to_wall, wall_to_utc};
use crate::temporal::TimeRange;

/// Recurrence steps one window may cost before the rule counts as unsupported.
///
/// The walk is bounded by the window, but reaching the window is not free: a
/// rule whose `dtstart_utc` predates the window still has to be stepped up to
/// it. This budget covers both halves, so neither a dense rule inside the
/// window nor a long fast-forward to it can run away.
const MAX_EXPANSION_STEPS: usize = 100_000;

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
/// the [`super::tz`] border once, so a recurring local hour survives a DST
/// transition instead of drifting by the offset change.
///
/// # Errors
///
/// - [`CalendarError::InvalidRecurrenceWindow`] — `window.start > window.end`,
///   answered before any recurrence work. A one-instant window
///   (`start == end`) is valid.
/// - [`CalendarError::InvalidRecurrenceRule`] — the text is not a rule this
///   engine supports, it is some other content line, it names both `COUNT` and
///   `UNTIL`, it can never fire (a zero `INTERVAL` or `COUNT`, or an `UNTIL`
///   before its own start), or expanding it over `window` would cost more than
///   the supported number of steps. A rule that is merely dense is reported,
///   never silently truncated.
/// - [`CalendarError::UnknownTimeZone`] — `dtstart.tz` is not an IANA zone.
/// - [`CalendarError::NonexistentWallTime`] — an occurrence the window asked
///   for falls in a spring-forward gap and has no instant. The caller decides
///   skip-vs-shift; this layer will not choose for it.
/// - [`CalendarError::TimestampOutOfRange`] — `dtstart_utc` or a window bound
///   is past the border's supported range.
///
/// A fall-back fold is not an error: it resolves to the earliest offset, the
/// same way [`super::tz::wall_to_utc`] resolves it everywhere else.
pub fn expand_window(
    rrule: &str,
    dtstart: SeriesDtStart<'_>,
    window: TimeRange,
) -> Result<Vec<u64>, CalendarError> {
    if window.start > window.end {
        return Err(CalendarError::InvalidRecurrenceWindow);
    }
    let tz = dtstart.tz;
    let seed = wall_clock_at(dtstart.dtstart_utc, tz)?;
    let first = wall_clock_at(window.start, tz)?;

    let (parsed, until_utc) = parse_rule(rrule, tz)?;
    let rule = parsed.validate(seed).map_err(|_| invalid_rule(rrule))?;
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
    let series = RRuleSet::new(seed).rrule(rule).limit();

    let mut starts = Vec::new();
    for (step, occurrence) in (&series).into_iter().enumerate() {
        if step == MAX_EXPANSION_STEPS {
            return Err(invalid_rule(rrule));
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
        }
    }
    // Normalization is a guarantee this door makes, not one it inherits: the
    // engine's yield order and multiplicity are its own business, and the two
    // consumers of this API read the output as a set of instants.
    starts.sort_unstable();
    starts.dedup();
    Ok(starts)
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
