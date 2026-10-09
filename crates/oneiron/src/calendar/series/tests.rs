//! Expansion, masking, and claim round-trip tests.

use super::{SeriesDtStart, expand_window, mask_master_exceptions};
use crate::calendar::CalendarError;
use crate::calendar::claims::CalendarSeriesExceptionValue;
use crate::calendar::tz::{WallTime, utc_to_wall};
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
/// `2026-10-26T01:30 Europe/London` — GMT, after the fold.
const OCT_26_0130_LONDON: u64 = 1_792_978_200;
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
