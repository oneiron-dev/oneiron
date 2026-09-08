//! Stage-by-stage and end-to-end pipeline tests for the solver.

use super::*;
use crate::booking::config::{
    DEFAULT_INTRO_DURATION_MIN, HostAvailabilityConfig, WeeklyWallWindow,
};
use crate::booking::constraint::LocalMinuteWindow;
use crate::test_util::entity as id;

const HOST_A: u8 = 0x52;
const HOST_B: u8 = 0x55;
const CALENDAR: u8 = 0x53;

/// `2026-03-02T00:00:00Z`, a Monday.
const MONDAY: u64 = 1_772_409_600;

fn window(weekday: u8, start_hour: u16, end_hour: u16) -> WeeklyWallWindow {
    WeeklyWallWindow {
        weekday,
        start_minute: start_hour * 60,
        end_minute: end_hour * 60,
    }
}

fn host(seed: u8, tz: &str, working: Vec<WeeklyWallWindow>) -> HostAvailabilityConfig {
    HostAvailabilityConfig {
        host_ref: id(seed),
        calendar_refs: vec![id(CALENDAR)],
        host_tz: tz.to_owned(),
        working_hours: working,
        preferred_hours: Vec::new(),
    }
}

fn config(hosts: Vec<HostAvailabilityConfig>) -> EventTypeConfig {
    EventTypeConfig {
        key: EventTypeKey("intro-call".to_owned()),
        duration_min: DEFAULT_INTRO_DURATION_MIN,
        slot_step_min: 30,
        pre_buffer_min: 0,
        post_buffer_min: 0,
        min_notice_secs: 0,
        booking_window_secs: 30 * 24 * 3_600,
        daily_cap: None,
        weekly_cap: None,
        routing: RoutingMode::Either,
        hosts,
        flex_windows: Vec::new(),
    }
}

fn utc_host_config() -> EventTypeConfig {
    config(vec![host(HOST_A, "UTC", vec![window(0, 9, 11)])])
}

/// The whole Monday, half-open.
const fn monday() -> TimeRange {
    TimeRange {
        start: MONDAY,
        end: MONDAY + 86_400,
    }
}

fn empty_counts() -> BookingCounts {
    BookingCounts {
        daily: Vec::new(),
        weekly: Vec::new(),
    }
}

fn starts(masks: &[(EntityId, Vec<TimeRange>)]) -> Vec<(u64, u64)> {
    masks
        .iter()
        .flat_map(|(_, ranges)| ranges.iter().map(|range| (range.start, range.end)))
        .collect()
}

#[test]
fn civil_date_arithmetic_round_trips_and_names_weekdays() {
    assert_eq!(days_from_civil(1970, 1, 1), 0);
    assert_eq!(civil_from_days(0), (1970, 1, 1));
    assert_eq!(weekday_of(0), 3, "1970-01-01 was a Thursday");
    for days in [-100_000_i64, -1, 0, 1, 20_000, 100_000] {
        let (y, mo, d) = civil_from_days(days);
        assert_eq!(days_from_civil(y, mo, d), days, "{y}-{mo}-{d}");
    }
    // 2026-03-02 is a Monday, and the week index is Monday-anchored.
    let monday = days_from_civil(2026, 3, 2);
    assert_eq!(weekday_of(monday), 0);
    assert_eq!(week_of(monday), week_of(monday + 6));
    assert_ne!(week_of(monday), week_of(monday + 7));
    assert_ne!(week_of(monday), week_of(monday - 1));
}

#[test]
fn working_hours_convert_wall_windows_through_the_border() {
    let masks = working_hours_mask(&utc_host_config(), monday()).expect("mask");
    assert_eq!(starts(&masks), [(MONDAY + 9 * 3_600, MONDAY + 11 * 3_600)]);

    // The same civil window in a zone with an offset lands elsewhere in UTC,
    // so the conversion is real rather than an identity.
    let shifted = config(vec![host(HOST_A, "Asia/Tokyo", vec![window(0, 9, 11)])]);
    let masks = working_hours_mask(&shifted, monday()).expect("mask");
    assert_eq!(starts(&masks), [(MONDAY, MONDAY + 2 * 3_600)]);

    // A window ending at midnight carries into the next civil day.
    let midnight = config(vec![host(
        HOST_A,
        "UTC",
        vec![WeeklyWallWindow {
            weekday: 0,
            start_minute: 23 * 60,
            end_minute: MINUTES_PER_DAY,
        }],
    )]);
    let masks = working_hours_mask(&midnight, monday()).expect("mask");
    assert_eq!(starts(&masks), [(MONDAY + 23 * 3_600, MONDAY + 86_400)]);

    // A window on another weekday contributes nothing.
    let tuesday_only = config(vec![host(HOST_A, "UTC", vec![window(1, 9, 11)])]);
    assert!(starts(&working_hours_mask(&tuesday_only, monday()).expect("mask")).is_empty());
}

#[test]
fn nonexistent_wall_boundary_skips_the_occurrence_without_shifting() {
    // Europe/London springs forward 2026-03-29 at 01:00 local; 01:00-02:00
    // does not exist. A window anchored inside the gap has no instants and
    // is skipped; the neighbouring hour converts normally.
    let sunday = MONDAY + 27 * 86_400; // 2026-03-29
    let gap_window = TimeRange {
        start: sunday,
        end: sunday + 86_400,
    };
    let gapped = config(vec![host(HOST_A, "Europe/London", vec![window(6, 1, 2)])]);
    assert!(
        starts(&working_hours_mask(&gapped, gap_window).expect("mask")).is_empty(),
        "a skipped hour is never shifted into the adjacent one"
    );

    let ordinary = config(vec![host(HOST_A, "Europe/London", vec![window(6, 3, 4)])]);
    assert_eq!(
        starts(&working_hours_mask(&ordinary, gap_window).expect("mask")).len(),
        1,
        "the rejection is the gap, not the whole day"
    );
}

#[test]
fn unresolvable_host_zone_is_a_typed_config_error() {
    let bogus = config(vec![host(
        HOST_A,
        "Mars/Olympus_Mons",
        vec![window(0, 9, 11)],
    )]);
    assert!(matches!(
        working_hours_mask(&bogus, monday()),
        Err(BookingError::InvalidConfig(_))
    ));
}

#[test]
fn attach_busy_union_refuses_a_host_with_no_projection() {
    let masks = vec![(id(HOST_A), vec![monday()])];
    assert!(matches!(
        attach_busy_union(masks.clone(), Vec::new()),
        Err(BookingError::InvalidConfig(_))
    ));
    assert!(attach_busy_union(masks, vec![(id(HOST_A), Vec::new())]).is_ok());
}

#[test]
fn buffers_expand_existing_and_candidate_meetings() {
    let busy = vec![crate::calendar::BusyInterval {
        start_utc: MONDAY + 10 * 3_600,
        end_utc: MONDAY + 11 * 3_600,
        source: id(0x56),
    }];
    let mask = vec![TimeRange {
        start: MONDAY + 9 * 3_600,
        end: MONDAY + 12 * 3_600,
    }];
    let apply = |pre: u16, post: u16| {
        let mut config = utc_host_config();
        config.pre_buffer_min = pre;
        config.post_buffer_min = post;
        starts(&apply_buffers(
            vec![(id(HOST_A), mask.clone(), busy.clone())],
            &config,
        ))
    };

    // No buffers: the busy hour alone is removed.
    assert_eq!(
        apply(0, 0),
        [
            (MONDAY + 9 * 3_600, MONDAY + 10 * 3_600),
            (MONDAY + 11 * 3_600, MONDAY + 12 * 3_600)
        ]
    );
    // The required gap either side is one meeting's post-buffer plus the
    // other's pre-buffer, so pre-only and post-only shrink both sides.
    assert_eq!(
        apply(15, 0),
        [
            (MONDAY + 9 * 3_600, MONDAY + 10 * 3_600 - 900),
            (MONDAY + 11 * 3_600 + 900, MONDAY + 12 * 3_600)
        ]
    );
    assert_eq!(apply(0, 15), apply(15, 0), "the gap is pre + post");
    assert_eq!(
        apply(15, 15),
        [
            (MONDAY + 9 * 3_600, MONDAY + 10 * 3_600 - 1_800),
            (MONDAY + 11 * 3_600 + 1_800, MONDAY + 12 * 3_600)
        ]
    );
    // A buffer wide enough to reach the mask edges clips rather than
    // underflowing, and adjacent busy runs coalesce.
    assert!(apply(180, 180).is_empty());
}

#[test]
fn notice_24h_and_48h_presets_clip_candidates() {
    let mask = vec![(id(HOST_A), vec![monday()])];
    let clip = |notice: u64, horizon: u64| {
        let mut config = utc_host_config();
        config.min_notice_secs = notice;
        config.booking_window_secs = horizon;
        starts(&enforce_notice_and_window(
            mask.clone(),
            MONDAY,
            monday(),
            &config,
        ))
    };
    assert_eq!(clip(0, 30 * 86_400), [(MONDAY, MONDAY + 86_400)]);
    assert_eq!(
        clip(24 * 3_600, 30 * 86_400),
        [],
        "a 24h notice consumes the whole first day"
    );
    assert_eq!(
        clip(12 * 3_600, 30 * 86_400),
        [(MONDAY + 12 * 3_600, MONDAY + 86_400)]
    );
    assert_eq!(clip(48 * 3_600, 30 * 86_400), []);
}

#[test]
fn constrained_booking_window_clips_far_future_slots() {
    let far = TimeRange {
        start: MONDAY,
        end: MONDAY + 30 * 86_400,
    };
    let mut config = utc_host_config();
    config.booking_window_secs = 7 * 86_400;
    let clipped = enforce_notice_and_window(vec![(id(HOST_A), vec![far])], MONDAY, far, &config);
    assert_eq!(starts(&clipped), [(MONDAY, MONDAY + 7 * 86_400)]);
}

#[test]
fn duration_and_step_cut_candidates_on_the_epoch_grid() {
    let mask = vec![(
        id(HOST_A),
        vec![TimeRange {
            start: MONDAY + 9 * 3_600,
            end: MONDAY + 10 * 3_600 + 1_800,
        }],
    )];
    let config = utc_host_config();
    assert_eq!(config.duration_min, 30);
    let slots = apply_event_type_knobs(mask, &config, "UTC", &empty_counts());
    assert_eq!(
        starts(&slots),
        [
            (MONDAY + 9 * 3_600, MONDAY + 9 * 3_600 + 1_800),
            (MONDAY + 9 * 3_600 + 1_800, MONDAY + 10 * 3_600),
            (MONDAY + 10 * 3_600, MONDAY + 10 * 3_600 + 1_800),
        ]
    );

    // An unaligned mask start snaps forward onto the shared grid, so two
    // hosts always propose the same instants.
    let ragged = vec![(
        id(HOST_A),
        vec![TimeRange {
            start: MONDAY + 9 * 3_600 + 300,
            end: MONDAY + 10 * 3_600 + 1_800,
        }],
    )];
    assert_eq!(
        starts(&apply_event_type_knobs(
            ragged,
            &config,
            "UTC",
            &empty_counts()
        ))[0]
            .0,
        MONDAY + 9 * 3_600 + 1_800
    );
}

#[test]
fn visitor_local_daily_and_weekly_caps_use_typed_booking_counts() {
    let mask = vec![(
        id(HOST_A),
        vec![TimeRange {
            start: MONDAY + 9 * 3_600,
            end: MONDAY + 10 * 3_600,
        }],
    )];
    let mut config = utc_host_config();
    config.daily_cap = Some(1);

    // One confirmed booking on the visitor's Monday fills the daily cap.
    let counts = BookingCounts {
        daily: vec![BookingCountBucket {
            window_start_utc: MONDAY + 3_600,
            window_end_utc: MONDAY + 86_400,
            confirmed: 1,
        }],
        weekly: Vec::new(),
    };
    assert!(
        apply_event_type_knobs(mask.clone(), &config, "UTC", &counts)
            .iter()
            .all(|(_, slots)| slots.is_empty())
    );

    // The SAME table, read in a zone eight hours behind. There the bucket's
    // 01:00Z start is the previous local day while the 09:00Z candidates are
    // this one, so the bucket charges a different day and the candidates
    // survive. In UTC both fall on one day and the cap binds — which is what
    // proves the cap is the VISITOR's, not UTC's.
    assert_eq!(
        starts(&apply_event_type_knobs(
            mask.clone(),
            &config,
            "America/Los_Angeles",
            &counts
        ))
        .len(),
        2
    );

    // Sparse table: a period with no bucket has zero confirmed bookings.
    assert_eq!(
        starts(&apply_event_type_knobs(
            mask.clone(),
            &config,
            "UTC",
            &empty_counts()
        ))
        .len(),
        2
    );

    // Weekly caps aggregate every bucket in the Monday-anchored week.
    let mut weekly = config;
    weekly.daily_cap = None;
    weekly.weekly_cap = Some(3);
    let spread = BookingCounts {
        daily: Vec::new(),
        weekly: vec![
            BookingCountBucket {
                window_start_utc: MONDAY + 3_600,
                window_end_utc: MONDAY + 86_400,
                confirmed: 2,
            },
            BookingCountBucket {
                window_start_utc: MONDAY + 3 * 86_400,
                window_end_utc: MONDAY + 4 * 86_400,
                confirmed: 1,
            },
        ],
    };
    assert!(
        apply_event_type_knobs(mask.clone(), &weekly, "UTC", &spread)
            .iter()
            .all(|(_, slots)| slots.is_empty()),
        "2 + 1 confirmed reaches a weekly cap of 3"
    );
    // A bucket in the FOLLOWING week does not charge this one.
    let next_week = BookingCounts {
        daily: Vec::new(),
        weekly: vec![BookingCountBucket {
            window_start_utc: MONDAY + 8 * 86_400,
            window_end_utc: MONDAY + 9 * 86_400,
            confirmed: 3,
        }],
    };
    assert_eq!(
        starts(&apply_event_type_knobs(mask, &weekly, "UTC", &next_week)).len(),
        2
    );
}

#[test]
fn live_hold_fixture_removes_only_unexpired_overlap() {
    let slots = vec![(
        id(HOST_A),
        vec![
            TimeRange {
                start: MONDAY + 9 * 3_600,
                end: MONDAY + 9 * 3_600 + 1_800,
            },
            TimeRange {
                start: MONDAY + 10 * 3_600,
                end: MONDAY + 10 * 3_600 + 1_800,
            },
        ],
    )];
    let hold = TimeRange {
        start: MONDAY + 9 * 3_600 + 900,
        end: MONDAY + 9 * 3_600 + 1_200,
    };
    assert_eq!(
        starts(&subtract_live_holds(slots.clone(), &[hold])),
        [(MONDAY + 10 * 3_600, MONDAY + 10 * 3_600 + 1_800)],
        "a partially held candidate is not bookable"
    );
    // A hold that merely touches a candidate boundary does not take it.
    let touching = TimeRange {
        start: MONDAY + 9 * 3_600 + 1_800,
        end: MONDAY + 10 * 3_600,
    };
    assert_eq!(starts(&subtract_live_holds(slots, &[touching])).len(), 2);
    // The layer-1 source holds nothing; the confirming session's own hold is
    // excludable through the same door ONE-1813 implements.
    assert_eq!(
        NoActiveHolds
            .active_holds(id(0x57), monday(), MONDAY, Some(&[7_u8; 32]))
            .expect("empty source"),
        Vec::new()
    );
}

#[test]
fn routing_either_is_union_and_both_is_intersection() {
    let slot = |hour: u64| TimeRange {
        start: MONDAY + hour * 3_600,
        end: MONDAY + hour * 3_600 + 1_800,
    };
    let a = (id(HOST_A), vec![slot(9), slot(10)]);
    let b = (id(HOST_B), vec![slot(10), slot(11)]);
    let c = (id(0x58), vec![slot(11)]);

    let flat =
        |routed: Vec<SlotHostBinding>| routed.into_iter().map(|r| r.start_utc).collect::<Vec<_>>();
    assert_eq!(
        flat(route_host_masks(
            vec![a.clone(), b.clone()],
            RoutingMode::Either
        )),
        [slot(9).start, slot(10).start, slot(11).start],
        "union is sorted and duplicate-free"
    );
    assert_eq!(
        flat(route_host_masks(
            vec![a.clone(), b.clone()],
            RoutingMode::Both
        )),
        [slot(10).start]
    );
    // Disjoint hosts, three hosts, and an empty host.
    assert!(
        flat(route_host_masks(
            vec![(id(HOST_A), vec![slot(9)]), (id(HOST_B), vec![slot(11)])],
            RoutingMode::Both
        ))
        .is_empty()
    );
    assert!(flat(route_host_masks(vec![a.clone(), b, c], RoutingMode::Both)).is_empty());
    let empty_host = (id(HOST_B), Vec::new());
    assert!(
        flat(route_host_masks(
            vec![a.clone(), empty_host.clone()],
            RoutingMode::Both
        ))
        .is_empty()
    );
    assert_eq!(
        flat(route_host_masks(vec![a, empty_host], RoutingMode::Either)).len(),
        2
    );
    assert!(flat(route_host_masks(Vec::new(), RoutingMode::Both)).is_empty());
    assert!(flat(route_host_masks(Vec::new(), RoutingMode::Either)).is_empty());
}

#[test]
fn ranked_emit_is_deterministic() {
    let slot = |hour: u64| TimeRange {
        start: MONDAY + hour * 3_600,
        end: MONDAY + hour * 3_600 + 1_800,
    };
    let mut config = utc_host_config();
    config.hosts[0].preferred_hours = vec![window(0, 11, 12)];
    let result = rank_and_emit(
        route_host_masks(
            vec![(id(HOST_A), vec![slot(11), slot(9), slot(10)])],
            RoutingMode::Either,
        ),
        &config,
        None,
        "UTC",
        &empty_counts(),
    );
    assert!(result.slots.iter().all(|slot| slot.rank.is_finite()));
    assert_eq!(
        result
            .slots
            .iter()
            .map(|slot| slot.start_utc)
            .collect::<Vec<_>>(),
        [slot(11).start, slot(9).start, slot(10).start],
        "preferred first, then ascending UTC start"
    );
    assert!((result.slots[0].rank - PREFERRED_RANK).abs() < f32::EPSILON);
    assert!(!result.flex_used);

    // Identical inputs serialize byte-identically.
    let again = rank_and_emit(
        route_host_masks(
            vec![(id(HOST_A), vec![slot(10), slot(11), slot(9)])],
            RoutingMode::Either,
        ),
        &config,
        None,
        "UTC",
        &empty_counts(),
    );
    assert_eq!(
        serde_json::to_vec(&result).expect("serialize"),
        serde_json::to_vec(&again).expect("serialize")
    );
}

#[test]
fn constraint_object_masks_deterministically() {
    let slot = |day: u64, hour: u64| TimeRange {
        start: MONDAY + day * 86_400 + hour * 3_600,
        end: MONDAY + day * 86_400 + hour * 3_600 + 1_800,
    };
    let all = vec![slot(0, 9), slot(0, 15), slot(1, 9)];
    let emit = |constraint: Option<&ConstraintObject>, tz: &str| {
        rank_and_emit(
            route_host_masks(vec![(id(HOST_A), all.clone())], RoutingMode::Either),
            &utc_host_config(),
            constraint,
            tz,
            &empty_counts(),
        )
        .slots
        .into_iter()
        .map(|slot| slot.start_utc)
        .collect::<Vec<_>>()
    };
    assert_eq!(emit(None, "UTC").len(), 3);

    let weekday_only = ConstraintObject {
        schema_version: 1,
        weekdays: vec![ConstraintWeekday::Tuesday],
        local_time_windows: Vec::new(),
        utc_window: None,
        allow_flex_pool: false,
    }
    .canonicalize()
    .expect("canonical");
    assert_eq!(emit(Some(&weekday_only), "UTC"), [slot(1, 9).start]);

    let mornings = ConstraintObject {
        schema_version: 1,
        weekdays: Vec::new(),
        local_time_windows: vec![LocalMinuteWindow {
            start_minute: 8 * 60,
            end_minute: 12 * 60,
        }],
        utc_window: None,
        allow_flex_pool: false,
    }
    .canonicalize()
    .expect("canonical");
    assert_eq!(
        emit(Some(&mornings), "UTC"),
        [slot(0, 9).start, slot(1, 9).start]
    );
    // The same constraint in a zone five hours behind selects the 15:00Z
    // slot instead, because there it IS 10:00 local. The window is the
    // VISITOR's local time, never UTC.
    assert_eq!(
        emit(Some(&mornings), "America/New_York"),
        [slot(0, 15).start]
    );

    let utc_window = ConstraintObject {
        schema_version: 1,
        weekdays: Vec::new(),
        local_time_windows: Vec::new(),
        // Inclusive at the seam; the slot must fit inside it.
        utc_window: Some(TimeRange {
            start: slot(0, 9).start,
            end: slot(0, 9).end - 1,
        }),
        allow_flex_pool: false,
    }
    .canonicalize()
    .expect("canonical");
    assert_eq!(emit(Some(&utc_window), "UTC"), [slot(0, 9).start]);
}

#[test]
fn slot_mask_carries_the_half_open_window_and_nothing_else() {
    let req = SolveRequest {
        event_type: EventTypeKey("intro-call".to_owned()),
        window: TimeRange {
            start: MONDAY,
            end: MONDAY + 86_399,
        },
        constraint: None,
        visitor_tz: "UTC".to_owned(),
    };
    let solved = SolveResult {
        slots: vec![RankedSlot {
            start_utc: MONDAY + 9 * 3_600,
            end_utc: MONDAY + 9 * 3_600 + 1_800,
            rank: ORDINARY_RANK,
        }],
        flex_used: true,
        host_bindings: Vec::new(),
    };
    let mask = slot_mask(&req, solved);
    assert_eq!(mask.window_start_utc, MONDAY);
    assert_eq!(
        mask.window_end_utc,
        MONDAY + 86_400,
        "the inclusive request window becomes a half-open mask window"
    );
    assert!(mask.flex_used);
    let json = serde_json::to_value(&mask).expect("serialize");
    assert_eq!(
        json.as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "event_type",
            "window_start_utc",
            "window_end_utc",
            "slots",
            "flex_used"
        ]
    );
}
