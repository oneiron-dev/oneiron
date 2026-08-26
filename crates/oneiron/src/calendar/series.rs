//! Recurrence series machinery (CAL-03).
//!
//! A recurring meeting is one master EVENT plus a rule. This module turns that
//! pair into concrete occurrence starts for a caller-chosen window, and nothing
//! else: it stores nothing, schedules nothing, and mints no graph.
//!
//! # Series links are claims
//!
//! Master, exception and successor are all EVENTs, related through the CAL-00
//! claim values in [`super::claims`] — `calendar.series_master`,
//! `calendar.series_exception`, `calendar.successor`. No `EdgeKind` and no
//! registry byte exists for any of them. "This and all following" is a
//! truncated master rule plus a new master whose replacement EVENT carries
//! `calendar.successor`; this module never writes either side.
//!
//! # Windowed, or not at all
//!
//! [`expand_window`] is the only expansion door and it always takes the
//! caller's inclusive [`TimeRange`]. There is no unbounded variant to reach
//! for: a recurrence rule without `COUNT` or `UNTIL` names infinitely many
//! occurrences, so "expand this series" is not a question with an answer.
//!
//! # The recurrence steps a wall clock
//!
//! RFC 5545 recurrence is civil arithmetic — "every Tuesday at 09:00" is a
//! statement about a wall clock, not about a fixed number of seconds. So the
//! rule is stepped over civil fields, and the IANA zone is applied exactly once
//! per occurrence, at the [`super::tz`] border. A weekly London series keeps
//! its 09:00 local hour across the March transition and moves an hour in UTC,
//! which is what its owner meant and what adding 604800 seconds would get
//! wrong.
//!
//! Handing the recurrence engine the zone itself instead would give it that
//! second job, and it discharges it by sliding a nonexistent local time into
//! the adjacent hour — the one outcome the border exists to prevent. Stepping
//! the wall clock and letting CAL-01 decide the instant is what keeps a
//! spring-forward gap a typed [`CalendarError::NonexistentWallTime`] and a
//! fall-back fold a resolved earliest-offset `Ok`.
//!
//! # Failure is never silence
//!
//! A malformed or unsupported rule, an inverted window, an unknown zone and a
//! gap are all typed errors. None of them is an empty vector: a caller that
//! cannot tell "this series has no occurrences here" from "this series could
//! not be expanded" will happily double-book the owner.
//!
//! The `rrule` crate and every chrono type stay private to this file. The
//! public surface is engine-owned scalars.

use std::collections::BTreeSet;

use chrono::{DateTime, Datelike, TimeZone, Timelike};
use rrule::{RRule, RRuleSet, Tz, Unvalidated};

use super::CalendarError;
use super::claims::{CalendarSeriesExceptionValue, CalendarSeriesMasterValue};
use super::tz::{WallTime, utc_to_wall, wall_to_utc};
use crate::entity_id::EntityId;
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

/// The two fields a recurrence needs from its master, without the claim.
///
/// Carries exactly `dtstart_utc` and the IANA zone name, borrowed, so callers
/// that hold a decoded [`CalendarSeriesMasterValue`] and callers that hold the
/// two scalars can both reach the same door.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeriesDtStart<'a> {
    /// Series start instant, UTC seconds.
    pub dtstart_utc: u64,
    /// IANA zone the recurrence's wall clock belongs to.
    pub tz: &'a str,
}

impl<'a> From<&'a CalendarSeriesMasterValue> for SeriesDtStart<'a> {
    fn from(master: &'a CalendarSeriesMasterValue) -> Self {
        Self {
            dtstart_utc: master.dtstart_utc,
            tz: &master.tz,
        }
    }
}

/// The full identity of a series exception: `(uid, original_start_utc)`.
///
/// Both fields are borrowed from the [`CalendarSeriesExceptionValue`] that
/// carries them, never sourced separately. The pair is the identity because a
/// start alone is not one — two unrelated series can begin at the same instant,
/// and masking on the start would delete one series' occurrence because another
/// series had an exception.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SeriesExceptionKey<'a> {
    /// Series UID, as the source expressed it.
    pub uid: &'a str,
    /// The occurrence start this exception replaces.
    pub original_start_utc: u64,
}

impl<'a> From<&'a CalendarSeriesExceptionValue> for SeriesExceptionKey<'a> {
    fn from(exception: &'a CalendarSeriesExceptionValue) -> Self {
        Self {
            uid: &exception.uid,
            original_start_utc: exception.original_start_utc,
        }
    }
}

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

/// Borrows an exception's full identity out of the claim value carrying it.
#[must_use]
pub fn exception_identity(exception: &CalendarSeriesExceptionValue) -> SeriesExceptionKey<'_> {
    SeriesExceptionKey::from(exception)
}

/// Removes this master's overridden occurrences from a generated start stream.
///
/// Exceptions are scoped to `master_ref` first, then matched on the full
/// `(uid, original_start_utc)` key. A coincident start belonging to another
/// series survives, because only its own exception can remove it.
///
/// The removed occurrences do not vanish from the calendar: an exception is its
/// own EVENT with its own temporal rows, which ordinary event retrieval returns.
/// This only stops the master from generating a second, stale copy of it.
#[must_use]
pub fn mask_master_exceptions(
    master_ref: EntityId,
    series_uid: &str,
    starts: Vec<u64>,
    exceptions: &[CalendarSeriesExceptionValue],
) -> Vec<u64> {
    let masked: BTreeSet<SeriesExceptionKey<'_>> = exceptions
        .iter()
        .filter(|exception| exception.master_ref == master_ref)
        .map(SeriesExceptionKey::from)
        .collect();

    starts
        .into_iter()
        .filter(|start| {
            let key = SeriesExceptionKey {
                uid: series_uid,
                original_start_utc: *start,
            };
            !masked.contains(&key)
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use rmpv::Value;

    use super::{
        SeriesDtStart, SeriesExceptionKey, exception_identity, expand_master_window, expand_window,
        mask_master_exceptions,
    };
    use crate::calendar::CalendarError;
    use crate::calendar::claims::{
        CalendarSeriesExceptionValue, CalendarSeriesMasterValue,
        PREDICATE_CALENDAR_SERIES_EXCEPTION, PREDICATE_CALENDAR_SERIES_MASTER,
        PREDICATE_CALENDAR_SUCCESSOR, decode_series_exception_value, decode_series_master_value,
        decode_successor_value,
    };
    use crate::calendar::tz::{WallTime, utc_to_wall};
    use crate::claim::{
        ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, encode_claim_body,
        validate_claim_body_bytes,
    };
    use crate::entity_id::EntityId;
    use crate::temporal::TimeRange;
    use crate::test_util::entity;

    const LONDON: &str = "Europe/London";
    const DAY: u64 = 86_400;

    /// `2026-01-05T09:00 Europe/London` — GMT, nowhere near a transition.
    const JAN_05_0900_LONDON: u64 = 1_767_603_600;
    /// `2026-03-22T09:00 Europe/London` — the Sunday before spring forward.
    const MAR_22_0900_LONDON: u64 = 1_774_170_000;
    /// `2026-03-29T09:00 Europe/London` — BST: same wall hour, an hour earlier
    /// in UTC.
    const MAR_29_0900_LONDON: u64 = 1_774_771_200;
    /// `2026-04-05T09:00 Europe/London` — BST.
    const APR_05_0900_LONDON: u64 = 1_775_376_000;
    /// `2026-03-27T01:30 Europe/London` — two days before the gap swallows
    /// this wall clock.
    const MAR_27_0130_LONDON: u64 = 1_774_575_000;
    /// `2026-03-28T01:30 Europe/London`.
    const MAR_28_0130_LONDON: u64 = 1_774_661_400;
    /// `2026-10-23T01:30 Europe/London` — BST, before the fold.
    const OCT_23_0130_LONDON: u64 = 1_792_715_400;
    /// `2026-10-24T01:30 Europe/London` — BST.
    const OCT_24_0130_LONDON: u64 = 1_792_801_800;
    /// `2026-10-25T01:30 Europe/London`, the *earlier* of the fold's two
    /// instants (BST).
    const OCT_25_0130_LONDON_EARLIEST: u64 = 1_792_888_200;
    /// The same wall clock an hour later, under GMT. The border never picks it.
    const OCT_25_0130_LONDON_LATEST: u64 = 1_792_891_800;
    /// `2026-10-26T01:30 Europe/London` — GMT, after the fold.
    const OCT_26_0130_LONDON: u64 = 1_792_978_200;
    /// `2026-10-23T01:45 Europe/London` — BST.
    const OCT_23_0145_LONDON: u64 = 1_792_716_300;
    /// `2026-10-24T01:45 Europe/London` — BST.
    const OCT_24_0145_LONDON: u64 = 1_792_802_700;
    /// `2026-10-25T01:45 Europe/London`, earliest leg (BST). Later on the wall
    /// clock than [`OCT_25_0130_LONDON_LATEST`], earlier as an instant.
    const OCT_25_0145_LONDON_EARLIEST: u64 = 1_792_889_100;
    /// `2026-10-25T01:15:00Z`. Inside the London fold, so its wall clock reads
    /// 01:15 GMT — *earlier* on the clock than the fold's 01:30 occurrence and
    /// 45 minutes *later* than it as an instant.
    const OCT_25_0115_UTC: u64 = 1_792_890_900;

    fn london(dtstart_utc: u64) -> SeriesDtStart<'static> {
        SeriesDtStart {
            dtstart_utc,
            tz: LONDON,
        }
    }

    fn wall_of(utc: u64) -> WallTime {
        utc_to_wall(utc, LONDON).expect("fixture instant converts")
    }

    fn map(entries: &[(&str, Value)]) -> Value {
        Value::Map(
            entries
                .iter()
                .map(|(key, value)| (Value::from(*key), value.clone()))
                .collect(),
        )
    }

    /// Round-trips a claim through the same codec storage uses and then the
    /// write-only validator chokepoint, exactly as CAL-00's own tests do.
    fn through_chokepoint(predicate: &str, subject: EntityId, value: &Value) {
        let body = ClaimBody::new(
            predicate,
            ClaimSubject::Entity(subject),
            value.clone(),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        let bytes = encode_claim_body(&body).expect("encode calendar claim");
        validate_claim_body_bytes(&bytes, false).expect("calendar claim passes the chokepoint");
    }

    #[test]
    fn expand_window_bounds_unbounded_daily_rule() {
        // No COUNT, no UNTIL: the rule names infinitely many occurrences, and
        // only the window makes the answer finite.
        let window = TimeRange {
            start: JAN_05_0900_LONDON + 2 * DAY,
            end: JAN_05_0900_LONDON + 4 * DAY,
        };
        let starts = expand_window("FREQ=DAILY", london(JAN_05_0900_LONDON), window)
            .expect("daily series expands");

        assert_eq!(
            starts,
            vec![
                JAN_05_0900_LONDON + 2 * DAY,
                JAN_05_0900_LONDON + 3 * DAY,
                JAN_05_0900_LONDON + 4 * DAY,
            ]
        );
        assert!(
            starts
                .iter()
                .all(|start| *start >= window.start && *start <= window.end),
            "occurrences before or after the window leaked out: {starts:?}"
        );

        // The window is the only bound, so moving it moves the answer — the
        // occurrences before it are neither returned nor an error.
        let later = TimeRange {
            start: JAN_05_0900_LONDON + 400 * DAY,
            end: JAN_05_0900_LONDON + 401 * DAY,
        };
        assert_eq!(
            expand_window("FREQ=DAILY", london(JAN_05_0900_LONDON), later)
                .expect("daily series expands far from its start")
                .len(),
            2
        );
    }

    #[test]
    fn expand_window_rejects_inverted_window() {
        // Inverted by one second is still inverted, and it is answered before
        // any recurrence work: the rule text below never even parses.
        assert_eq!(
            expand_window(
                "this is not a recurrence rule",
                london(JAN_05_0900_LONDON),
                TimeRange {
                    start: JAN_05_0900_LONDON + 1,
                    end: JAN_05_0900_LONDON,
                },
            ),
            Err(CalendarError::InvalidRecurrenceWindow)
        );

        // The inclusive one-instant window is not inverted, and it holds the
        // occurrence standing on it.
        assert_eq!(
            expand_window(
                "FREQ=DAILY",
                london(JAN_05_0900_LONDON),
                TimeRange {
                    start: JAN_05_0900_LONDON,
                    end: JAN_05_0900_LONDON,
                },
            ),
            Ok(vec![JAN_05_0900_LONDON])
        );
    }

    #[test]
    fn expand_window_sorts_and_deduplicates() {
        // Ascending and unique is what this door promises, and the promise is
        // kept here rather than borrowed from the recurrence engine's yield
        // order — which is its own business, and which grows a merge queue the
        // moment a rule carries more than one generator.
        //
        // Strictly ascending says both halves at once: sorted, and no repeat.
        for (rule, dtstart_utc, window) in [
            // Names the same hour twice.
            (
                "FREQ=DAILY;BYHOUR=9,9",
                JAN_05_0900_LONDON,
                TimeRange {
                    start: JAN_05_0900_LONDON,
                    end: JAN_05_0900_LONDON + 2 * DAY,
                },
            ),
            // Crosses the fold, where a naive expansion collides two instants
            // onto one wall clock.
            (
                "FREQ=DAILY",
                OCT_23_0130_LONDON,
                TimeRange {
                    start: OCT_23_0130_LONDON,
                    end: OCT_26_0130_LONDON,
                },
            ),
            // Several generators inside one day.
            (
                "FREQ=HOURLY;BYMINUTE=0;BYSECOND=0",
                JAN_05_0900_LONDON,
                TimeRange {
                    start: JAN_05_0900_LONDON,
                    end: JAN_05_0900_LONDON + DAY,
                },
            ),
        ] {
            let starts = expand_window(rule, london(dtstart_utc), window)
                .unwrap_or_else(|error| panic!("{rule} expands: {error}"));

            assert!(!starts.is_empty(), "{rule} produced nothing to normalize");
            assert!(
                starts.windows(2).all(|pair| pair[0] < pair[1]),
                "{rule} is not strictly ascending: {starts:?}"
            );
        }

        // The first case above, spelled out: three days, one occurrence each.
        assert_eq!(
            expand_window(
                "FREQ=DAILY;BYHOUR=9,9",
                london(JAN_05_0900_LONDON),
                TimeRange {
                    start: JAN_05_0900_LONDON,
                    end: JAN_05_0900_LONDON + 2 * DAY,
                },
            ),
            Ok(vec![
                JAN_05_0900_LONDON,
                JAN_05_0900_LONDON + DAY,
                JAN_05_0900_LONDON + 2 * DAY,
            ])
        );
    }

    #[test]
    fn expand_window_preserves_london_wall_hour_across_dst() {
        let window = TimeRange {
            start: MAR_22_0900_LONDON,
            end: APR_05_0900_LONDON,
        };
        let starts = expand_window("FREQ=WEEKLY;BYDAY=SU", london(MAR_22_0900_LONDON), window)
            .expect("weekly London series expands");

        assert_eq!(
            starts,
            vec![MAR_22_0900_LONDON, MAR_29_0900_LONDON, APR_05_0900_LONDON]
        );

        // The wall clock is what stayed put, and CAL-01 is what says so.
        for start in &starts {
            let wall = wall_of(*start);
            assert_eq!((wall.h, wall.mi, wall.s), (9, 0, 0), "at {start}");
        }

        // The UTC instant is what moved. Fixed-second arithmetic would have put
        // the 29th an hour late, at 09:00Z, and every occurrence after it too.
        assert_eq!(MAR_29_0900_LONDON - MAR_22_0900_LONDON, 7 * DAY - 3600);
        assert_eq!(APR_05_0900_LONDON - MAR_29_0900_LONDON, 7 * DAY);
    }

    #[test]
    fn expand_window_malformed_rule_is_typed_error() {
        for rule in [
            "",
            "this is not a recurrence rule",
            "FREQ=NEVER",
            "FREQ=DAILY;COUNT=every-so-often",
            // RFC 5545 makes INTERVAL and COUNT positive integers. The
            // recurrence engine takes a zero and finishes before producing
            // anything, so these two are precisely the rules that would arrive
            // as a quiet empty calendar rather than as a defect.
            "FREQ=DAILY;INTERVAL=0",
            "FREQ=DAILY;COUNT=0",
            // Ends a day before it starts, which is the same defect written a
            // third way.
            "FREQ=DAILY;UNTIL=20260104T090000Z",
        ] {
            let expanded = expand_window(
                rule,
                london(JAN_05_0900_LONDON),
                TimeRange {
                    start: JAN_05_0900_LONDON,
                    end: JAN_05_0900_LONDON + DAY,
                },
            );
            assert_eq!(
                expanded,
                Err(CalendarError::InvalidRecurrenceRule {
                    rule: rule.to_owned()
                }),
                "{rule:?} must be reported, never answered with an empty series"
            );
        }
    }

    #[test]
    fn expand_window_invalid_zone_is_typed_error() {
        // Including a case-mangled real zone: CAL-01 owns this verdict, and a
        // near-miss is an error there rather than a silent UTC fallback.
        for tz in ["Mars/Olympus_Mons", "europe/london", ""] {
            assert_eq!(
                expand_window(
                    "FREQ=DAILY",
                    SeriesDtStart {
                        dtstart_utc: JAN_05_0900_LONDON,
                        tz,
                    },
                    TimeRange {
                        start: JAN_05_0900_LONDON,
                        end: JAN_05_0900_LONDON + DAY,
                    },
                ),
                Err(CalendarError::UnknownTimeZone { tz: tz.to_owned() })
            );
        }
    }

    #[test]
    fn expand_window_dst_gap_is_typed_error() {
        // London springs forward 2026-03-29 at 01:00, so a daily 01:30 series
        // has an occurrence that never happens. Skipping it silently loses a
        // meeting; shifting it silently moves one. Both are the caller's call.
        let expanded = expand_window(
            "FREQ=DAILY",
            london(MAR_27_0130_LONDON),
            TimeRange {
                start: MAR_27_0130_LONDON,
                end: MAR_27_0130_LONDON + 3 * DAY,
            },
        );

        assert_eq!(
            expanded,
            Err(CalendarError::NonexistentWallTime {
                wall: WallTime {
                    y: 2026,
                    mo: 3,
                    d: 29,
                    h: 1,
                    mi: 30,
                    s: 0,
                },
                tz: LONDON.to_owned(),
            })
        );

        // The two occurrences before the gap are ordinary, so the rejection is
        // the gap itself and not the series.
        assert_eq!(
            expand_window(
                "FREQ=DAILY",
                london(MAR_27_0130_LONDON),
                TimeRange {
                    start: MAR_27_0130_LONDON,
                    end: MAR_28_0130_LONDON,
                },
            ),
            Ok(vec![MAR_27_0130_LONDON, MAR_28_0130_LONDON])
        );
    }

    #[test]
    fn expand_window_dst_fold_uses_earliest_offset() {
        // London falls back 2026-10-25 at 02:00 BST -> 01:00 GMT, so a daily
        // 01:30 series has an occurrence that happens twice.
        let starts = expand_window(
            "FREQ=DAILY",
            london(OCT_23_0130_LONDON),
            TimeRange {
                start: OCT_23_0130_LONDON,
                end: OCT_26_0130_LONDON,
            },
        )
        .expect("series across the fold expands");

        assert_eq!(
            starts,
            vec![
                OCT_23_0130_LONDON,
                OCT_24_0130_LONDON,
                OCT_25_0130_LONDON_EARLIEST,
                OCT_26_0130_LONDON,
            ]
        );

        // The fold is genuine — both instants really are 01:30 local — and the
        // later one is the one the border declines to pick.
        assert_eq!(
            wall_of(OCT_25_0130_LONDON_LATEST),
            wall_of(OCT_25_0130_LONDON_EARLIEST)
        );
        assert!(!starts.contains(&OCT_25_0130_LONDON_LATEST));

        // Ambiguity resolves to an `Ok`, not to a verdict the caller must make.
        assert_eq!(
            expand_window(
                "FREQ=DAILY;COUNT=3",
                london(OCT_23_0130_LONDON),
                TimeRange {
                    start: OCT_25_0130_LONDON_EARLIEST,
                    end: OCT_25_0130_LONDON_EARLIEST,
                },
            ),
            Ok(vec![OCT_25_0130_LONDON_EARLIEST])
        );
    }

    #[test]
    fn expand_window_keeps_a_folded_occurrence_past_the_window_wall_clock() {
        // The one case where the wall clock and the instant disagree about
        // membership. The window ends at 01:30 GMT — the *later* leg of the
        // London fold — while the occurrence stands at 01:45 BST, which is
        // 00:45Z and comfortably inside it. A walk that stopped at the window's
        // own wall clock would drop a busy hour and let the owner be
        // double-booked in it.
        let window = TimeRange {
            start: OCT_23_0145_LONDON,
            end: OCT_25_0130_LONDON_LATEST,
        };
        assert!(
            wall_of(window.end).h == 1 && wall_of(window.end).mi == 30,
            "the window has to end inside the fold for this to test anything"
        );

        assert_eq!(
            expand_window("FREQ=DAILY", london(OCT_23_0145_LONDON), window)
                .expect("series into the fold expands"),
            vec![
                OCT_23_0145_LONDON,
                OCT_24_0145_LONDON,
                OCT_25_0145_LONDON_EARLIEST,
            ]
        );
        // And it really is later on the wall clock than the window's own end.
        assert!(OCT_25_0145_LONDON_EARLIEST < window.end);
    }

    #[test]
    fn expand_window_refuses_to_truncate_an_unsupported_rule() {
        // A per-second rule a year ahead of its window cannot be walked to
        // within the step budget. The honest answer is the owner enum's
        // "unsupported" arm; a short vector would read as a quiet calendar.
        let window = TimeRange {
            start: JAN_05_0900_LONDON + 365 * DAY,
            end: JAN_05_0900_LONDON + 365 * DAY + 60,
        };
        assert_eq!(
            expand_window("FREQ=SECONDLY", london(JAN_05_0900_LONDON), window),
            Err(CalendarError::InvalidRecurrenceRule {
                rule: "FREQ=SECONDLY".to_owned()
            })
        );
    }

    #[test]
    fn expand_window_ends_an_until_series_on_the_zone_clock() {
        // UNTIL is a UTC instant while the rule steps a London wall clock, so
        // the two disagree by the offset. The series must end where its author
        // said, not an hour of BST away.
        let until = MAR_29_0900_LONDON;
        let rule = "FREQ=WEEKLY;BYDAY=SU;UNTIL=20260329T080000Z";
        let starts = expand_window(
            rule,
            london(MAR_22_0900_LONDON),
            TimeRange {
                start: MAR_22_0900_LONDON,
                end: APR_05_0900_LONDON,
            },
        )
        .expect("bounded weekly series expands");

        assert_eq!(starts, vec![MAR_22_0900_LONDON, until]);
    }

    #[test]
    fn expand_window_ends_an_until_series_on_the_utc_instant() {
        // Inside a fold no wall clock equals the UNTIL instant, so translating
        // the bound onto the clock is not enough. The bound reads 01:15 GMT;
        // the 25th's occurrence stands an hour later on the clock at 01:30 BST
        // and 45 minutes *earlier* as an instant, at 00:30Z. It is inside the
        // series its author bounded, and a walk that ends on the wall clock
        // drops it — leaving the owner free in an hour they are booked.
        let rule = "FREQ=DAILY;UNTIL=20261025T011500Z";
        let starts = expand_window(
            rule,
            london(OCT_23_0130_LONDON),
            TimeRange {
                start: OCT_23_0130_LONDON,
                end: OCT_26_0130_LONDON,
            },
        )
        .expect("bounded daily series across the fold expands");

        assert_eq!(
            starts,
            vec![
                OCT_23_0130_LONDON,
                OCT_24_0130_LONDON,
                OCT_25_0130_LONDON_EARLIEST,
            ]
        );

        // The bound really does read differently on the two clocks: the last
        // occurrence kept precedes it as an instant and follows it on the same
        // day's wall clock, while the first one dropped is past it either way.
        const { assert!(OCT_25_0130_LONDON_EARLIEST < OCT_25_0115_UTC) };
        const { assert!(OCT_26_0130_LONDON > OCT_25_0115_UTC) };
        let bound = wall_of(OCT_25_0115_UTC);
        let kept = wall_of(OCT_25_0130_LONDON_EARLIEST);
        assert_eq!((bound.d, bound.h, bound.mi), (25, 1, 15));
        assert_eq!((kept.d, kept.h, kept.mi), (25, 1, 30));
        assert!((kept.h, kept.mi) > (bound.h, bound.mi));
    }

    #[test]
    fn expand_window_does_not_report_a_gap_after_the_series_ended() {
        // The window reaches past London's spring-forward gap, but the series
        // stopped a day before it. A gap the series never reaches is not the
        // caller's skip-vs-shift verdict to make, so it ends the walk instead
        // of turning a completed series into an error.
        assert_eq!(
            expand_window(
                "FREQ=DAILY;UNTIL=20260328T013000Z",
                london(MAR_27_0130_LONDON),
                TimeRange {
                    start: MAR_27_0130_LONDON,
                    end: MAR_27_0130_LONDON + 3 * DAY,
                },
            ),
            Ok(vec![MAR_27_0130_LONDON, MAR_28_0130_LONDON])
        );
    }

    #[test]
    fn expand_window_rejects_text_the_dependency_alone_accepts() {
        for rule in [
            // RFC 5545 makes COUNT and UNTIL mutually exclusive. A rule naming
            // two endings names none, and picking one of them for its author
            // is a guess this door has no standing to make.
            "FREQ=DAILY;COUNT=2;UNTIL=20260131T090000Z",
            // Content lines that are not an RRULE. The parser defaults a
            // nameless line to RRULE and then ignores the name it did read, so
            // an EXDATE — whose whole job is to *remove* occurrences — arrives
            // as a plausible daily series and books the owner instead.
            "DTSTART:FREQ=DAILY",
            "EXRULE:FREQ=DAILY",
            "EXDATE:FREQ=DAILY",
            "RDATE:FREQ=DAILY",
        ] {
            assert_eq!(
                expand_window(
                    rule,
                    london(JAN_05_0900_LONDON),
                    TimeRange {
                        start: JAN_05_0900_LONDON,
                        end: JAN_05_0900_LONDON + DAY,
                    },
                ),
                Err(CalendarError::InvalidRecurrenceRule {
                    rule: rule.to_owned()
                }),
                "{rule:?} is not a recurrence rule and must not expand into one"
            );
        }

        // The spellings this door does take, including the RFC's
        // case-insensitive property name.
        for rule in [
            "FREQ=DAILY;COUNT=1",
            "RRULE:FREQ=DAILY;COUNT=1",
            "rrule:FREQ=DAILY;COUNT=1",
        ] {
            assert_eq!(
                expand_window(
                    rule,
                    london(JAN_05_0900_LONDON),
                    TimeRange {
                        start: JAN_05_0900_LONDON,
                        end: JAN_05_0900_LONDON + DAY,
                    },
                ),
                Ok(vec![JAN_05_0900_LONDON]),
                "{rule:?} is the same rule spelled three ways"
            );
        }
    }

    #[test]
    fn series_surface_is_reachable_from_the_crate_root() {
        // Two consumers import this API — CAL-09 freebusy and ONE-1539/CMT-2 —
        // and they write `oneiron::calendar::expand_window`. Naming the signatures rather
        // than the paths alone also pins the shared-consumer contract: engine
        // scalars in, `Result<Vec<u64>, CalendarError>` out, no wrapper.
        let _: fn(&str, SeriesDtStart<'_>, TimeRange) -> Result<Vec<u64>, CalendarError> =
            crate::calendar::expand_window;
        let _: fn(&CalendarSeriesMasterValue, TimeRange) -> Result<Vec<u64>, CalendarError> =
            crate::calendar::expand_master_window;
        let _: fn(&CalendarSeriesExceptionValue) -> crate::calendar::SeriesExceptionKey<'_> =
            crate::calendar::exception_identity;
        let _: fn(EntityId, &str, Vec<u64>, &[CalendarSeriesExceptionValue]) -> Vec<u64> =
            crate::calendar::mask_master_exceptions;
        let _: crate::calendar::SeriesDtStart<'_> = london(JAN_05_0900_LONDON);
    }

    #[test]
    fn series_exception_identity_is_view_of_claim_value() {
        let exception = CalendarSeriesExceptionValue {
            master_ref: entity(0x71),
            uid: "uid-1@example.com".to_owned(),
            original_start_utc: MAR_29_0900_LONDON,
        };
        let key = exception_identity(&exception);

        assert_eq!(
            key,
            SeriesExceptionKey {
                uid: "uid-1@example.com",
                original_start_utc: MAR_29_0900_LONDON,
            }
        );
        // Borrowed, not re-sourced: the key points into the claim value's own
        // string, so no second reader can supply a different UID for it.
        assert!(
            std::ptr::eq(key.uid.as_ptr(), exception.uid.as_ptr()),
            "the key copied the UID instead of viewing it"
        );
    }

    #[test]
    fn mask_master_exceptions_uses_full_key() {
        let master = entity(0x72);
        let other_master = entity(0x73);
        let starts = vec![OCT_23_0130_LONDON, OCT_24_0130_LONDON, OCT_26_0130_LONDON];
        let exceptions = vec![
            // This master's own exception: the one occurrence that must go.
            CalendarSeriesExceptionValue {
                master_ref: master,
                uid: "series-a".to_owned(),
                original_start_utc: OCT_24_0130_LONDON,
            },
            // Same master, unrelated UID, coincident start. Matching on the
            // start alone would delete an occurrence nobody overrode.
            CalendarSeriesExceptionValue {
                master_ref: master,
                uid: "series-z".to_owned(),
                original_start_utc: OCT_23_0130_LONDON,
            },
            // Another master entirely: out of scope before the key is even
            // compared.
            CalendarSeriesExceptionValue {
                master_ref: other_master,
                uid: "series-b".to_owned(),
                original_start_utc: OCT_26_0130_LONDON,
            },
        ];

        assert_eq!(
            mask_master_exceptions(master, "series-a", starts.clone(), &exceptions),
            vec![OCT_23_0130_LONDON, OCT_26_0130_LONDON]
        );

        // The other series shares two starts with the first and keeps both:
        // only its own exception can remove one of them.
        assert_eq!(
            mask_master_exceptions(other_master, "series-b", starts.clone(), &exceptions),
            vec![OCT_23_0130_LONDON, OCT_24_0130_LONDON]
        );

        // A master with no exceptions of its own keeps every start.
        assert_eq!(
            mask_master_exceptions(master, "series-untouched", starts.clone(), &exceptions),
            starts
        );
    }

    #[test]
    fn series_claims_round_trip_without_edges() {
        let master_event = entity(0x74);
        let exception_event = entity(0x75);

        let master_value = map(&[
            ("rrule", Value::from("FREQ=WEEKLY;BYDAY=SU")),
            ("dtstart_utc", Value::from(MAR_22_0900_LONDON)),
            ("tz", Value::from(LONDON)),
        ]);
        through_chokepoint(
            PREDICATE_CALENDAR_SERIES_MASTER,
            master_event,
            &master_value,
        );
        let master = decode_series_master_value(&master_value).expect("decode series master");
        assert_eq!(
            master,
            CalendarSeriesMasterValue {
                rrule: "FREQ=WEEKLY;BYDAY=SU".to_owned(),
                dtstart_utc: MAR_22_0900_LONDON,
                tz: LONDON.to_owned(),
            }
        );

        // The stored claim is sufficient to expand: nothing else has to be read
        // to know when this series happens.
        let occurrences = expand_master_window(
            &master,
            TimeRange {
                start: MAR_22_0900_LONDON,
                end: APR_05_0900_LONDON,
            },
        )
        .expect("stored master expands");
        assert_eq!(
            occurrences,
            vec![MAR_22_0900_LONDON, MAR_29_0900_LONDON, APR_05_0900_LONDON]
        );

        let exception_value = map(&[
            ("master_ref", Value::from(master_event.to_hex())),
            ("uid", Value::from("uid-1@example.com")),
            ("original_start_utc", Value::from(MAR_29_0900_LONDON)),
        ]);
        through_chokepoint(
            PREDICATE_CALENDAR_SERIES_EXCEPTION,
            exception_event,
            &exception_value,
        );
        let exception =
            decode_series_exception_value(&exception_value).expect("decode series exception");
        assert_eq!(exception.master_ref, master_event);
        assert_eq!(exception.uid, "uid-1@example.com");

        // Master and exception are two EVENTs joined by claim values alone: the
        // link travels in the exception's `master_ref` field, and the identity
        // it masks with is the `uid` the same claim carries.
        assert_eq!(
            mask_master_exceptions(
                master_event,
                &exception.uid,
                occurrences,
                std::slice::from_ref(&exception),
            ),
            vec![MAR_22_0900_LONDON, APR_05_0900_LONDON]
        );
    }

    #[test]
    fn successor_claim_points_from_replacement_to_predecessor() {
        let predecessor = entity(0x76);
        let replacement = entity(0x77);

        // The claim lives on the replacement and names what it supersedes, so
        // split-series provenance reads forward from the new master.
        let value = map(&[("predecessor_ref", Value::from(predecessor.to_hex()))]);
        through_chokepoint(PREDICATE_CALENDAR_SUCCESSOR, replacement, &value);

        let successor = decode_successor_value(&value).expect("decode successor");
        assert_eq!(successor.predecessor_ref, predecessor);
        assert_ne!(successor.predecessor_ref, replacement);
    }
}
