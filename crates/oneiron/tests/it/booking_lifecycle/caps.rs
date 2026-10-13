//! engine-core-03: the daily and weekly caps count confirmed bookings.

use super::{
    Fixture, HOST_SEED, NOW, expect_confirmed, expect_held, expect_revision, expect_slot_taken,
    fixture_config, hold_spec, hour, session, test_id,
};
use oneiron::booking::{
    BookingError, BookingLifecycleTurn, BookingSolver, BookingVerbReceipt, BookingVerbRequest,
    CancelSpec, ConfirmSpec, DEFAULT_INTRO_DURATION_MIN, EventTypeConfig, RescheduleSpec,
    SessionKey, SlotOracle, SolveRequest, SolveResult, VaultActiveHoldSource, WeeklyWallWindow,
    enqueue_booking_verb, run_booking_lifecycle_once,
};
use oneiron::{EntityId, TimeRange};

/// The fixture's event type, open Monday and Tuesday 09:00–14:00 UTC.
fn capped(daily_cap: Option<u16>, weekly_cap: Option<u16>) -> EventTypeConfig {
    let mut config = fixture_config();
    config.daily_cap = daily_cap;
    config.weekly_cap = weekly_cap;
    config.hosts[0].working_hours.push(WeeklyWallWindow {
        weekday: 1,
        start_minute: 9 * 60,
        end_minute: 14 * 60,
    });
    config
}

fn slot(start: u64) -> TimeRange {
    TimeRange {
        start,
        end: start + u64::from(DEFAULT_INTRO_DURATION_MIN) * 60,
    }
}

/// The production solver over `config`, forwarding a move the way the
/// server's oracle does.
struct CappedSolver<'a> {
    fixture: &'a Fixture,
    exclude: Option<SessionKey>,
    config: &'a EventTypeConfig,
}

impl CappedSolver<'_> {
    fn with<T>(&self, run: impl FnOnce(&BookingSolver<'_>) -> T) -> T {
        let holds = match self.exclude {
            Some(key) => VaultActiveHoldSource::excluding(&self.fixture.vault, key),
            None => VaultActiveHoldSource::new(&self.fixture.vault),
        };
        let calendars = vec![(
            test_id(HOST_SEED),
            vec![oneiron::CalendarSel { system: None }],
        )];
        run(&BookingSolver {
            vault: &self.fixture.vault,
            page_ref: self.fixture.page,
            calendars_by_host: &calendars,
            holds: &holds,
            now_utc: NOW,
            synthetic_config: Some(self.config.clone()),
        })
    }
}

impl SlotOracle for CappedSolver<'_> {
    fn solve(&self, req: &SolveRequest) -> Result<SolveResult, BookingError> {
        self.with(|solver| solver.solve(req))
    }

    fn solve_moving(
        &self,
        req: &SolveRequest,
        moving: EntityId,
    ) -> Result<SolveResult, BookingError> {
        self.with(|solver| solver.solve_moving(req, moving))
    }
}

fn run(
    fixture: &Fixture,
    config: &EventTypeConfig,
    request: BookingVerbRequest,
) -> BookingVerbReceipt {
    enqueue_booking_verb(&fixture.vault, request, NOW).expect("enqueue");
    match run_booking_lifecycle_once(
        &fixture.vault,
        |oracle_request| {
            Ok(CappedSolver {
                fixture,
                exclude: oracle_request.exclude_session_key,
                config,
            })
        },
        &fixture.consumer_input(NOW),
    )
    .expect("turn")
    {
        BookingLifecycleTurn::Executed(receipt) => receipt,
        other => panic!("the home node must execute the queued attempt, got {other:?}"),
    }
}

fn hold(fixture: &Fixture, config: &EventTypeConfig, who: &[u8], start: u64) -> ConfirmSpec {
    let key = session(who);
    let held = expect_held(run(
        fixture,
        config,
        BookingVerbRequest::Hold(hold_spec(fixture, key, slot(start))),
    ));
    ConfirmSpec {
        hold_token: held.token,
        session_key: key,
        booker_contact: fixture.booker,
        intake: Vec::new(),
        idempotency_key: None,
    }
}

/// Daily cap 1: a second booking that day is refused at confirm, the first
/// booking can still move within its day, and cancelling it frees the day.
#[test]
fn a_daily_cap_binds_at_confirm_and_a_move_never_charges_itself() {
    let fixture = Fixture::open();
    let config = capped(Some(1), None);
    let first = hold(&fixture, &config, b"first", hour(9));
    let second = hold(&fixture, &config, b"second", hour(11));

    let booked = expect_confirmed(run(&fixture, &config, BookingVerbRequest::Confirm(first)));
    expect_slot_taken(run(
        &fixture,
        &config,
        BookingVerbRequest::Confirm(second.clone()),
    ));

    expect_revision(run(
        &fixture,
        &config,
        BookingVerbRequest::Reschedule(RescheduleSpec {
            token: booked.reschedule_token,
            new_slot: slot(hour(12)),
            visitor_tz: "UTC".to_owned(),
            constraint: None,
            idempotency_key: None,
        }),
    ));
    expect_revision(run(
        &fixture,
        &config,
        BookingVerbRequest::Cancel(CancelSpec {
            token: booked.cancel_token,
            idempotency_key: None,
        }),
    ));
    expect_confirmed(run(&fixture, &config, BookingVerbRequest::Confirm(second)));
}

/// Weekly cap 1: a Monday booking closes Tuesday too, even for a request
/// that asks about Tuesday alone, and moving it to Tuesday is still allowed.
#[test]
fn a_weekly_cap_counts_the_whole_visitor_week() {
    let fixture = Fixture::open();
    let config = capped(None, Some(1));
    let first = hold(&fixture, &config, b"first", hour(9));
    let booked = expect_confirmed(run(&fixture, &config, BookingVerbRequest::Confirm(first)));

    let tuesday = SolveRequest {
        event_type: config.key.clone(),
        window: TimeRange {
            start: hour(24 + 9),
            end: hour(24 + 14) - 1,
        },
        constraint: None,
        visitor_tz: "UTC".to_owned(),
    };
    let solver = CappedSolver {
        fixture: &fixture,
        exclude: None,
        config: &config,
    };
    assert_eq!(
        solver.solve(&tuesday).expect("solve").slots,
        Vec::new(),
        "Monday's booking fills the week's one place"
    );

    expect_revision(run(
        &fixture,
        &config,
        BookingVerbRequest::Reschedule(RescheduleSpec {
            token: booked.reschedule_token,
            new_slot: slot(hour(24 + 10)),
            visitor_tz: "UTC".to_owned(),
            constraint: None,
            idempotency_key: None,
        }),
    ));
    assert_eq!(solver.solve(&tuesday).expect("solve").slots, Vec::new());
}
