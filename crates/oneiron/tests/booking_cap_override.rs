//! BK-MEETING-CAPS PR B: the owner may book past a meeting cap with a reason
//! (owner rulings: an explicit "full" marker, per event type, and the owner
//! may oversell with a reason; RULING BK-CAP-OVERRIDE-WHO = B).
//!
//! A hold that carries a [`BookingCapOverride`] is confirmed past the event
//! type's daily and weekly caps, and the booking it makes keeps the reason as
//! a `booking.cap_override` claim. A hold without one is held to the caps as
//! before. Who may set the override is the server's owner door; this target
//! drives the engine's lifecycle door directly.
//!
//! The fixture is `tests/it/booking_lifecycle.rs`'s (vault, page, host,
//! booker, home node) with `tests/it/booking_lifecycle/caps.rs`'s capped
//! solver. Run: `cargo test -p oneiron --all-features --test
//! booking_cap_override`.
#![cfg(feature = "test-support")]

mod common;

use common::entity as test_id;
use oneiron::booking::{
    BOOKING_CAP_OVERRIDE_PREDICATE, BookingCapOverride, BookingCapOverrideValue, BookingError,
    BookingLifecycleConsumerInput, BookingLifecycleTurn, BookingSolver, BookingVerbReceipt,
    BookingVerbRequest, ConfirmReceipt, ConfirmSpec, DEFAULT_INTRO_DURATION_MIN, EventTypeConfig,
    EventTypeKey, HoldLeaseSpec, HoldSpec, HostAvailabilityConfig, RankedSlot, RoutingMode,
    SessionKey, SlotOracle, SolveRequest, SolveResult, VaultActiveHoldSource, WeeklyWallWindow,
    enqueue_booking_verb, run_booking_lifecycle_once,
};
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::{
    ClaimLifecycleStatus, DreamerHomeNodeCandidate, DreamerRunnerStore, EntityId, TimeRange, Vault,
    VaultConfig,
};

/// Monday 2 March 2026, 00:00 UTC.
const MONDAY: u64 = 1_772_409_600;
const NOW: u64 = MONDAY + 8 * 3_600;

const PAGE_SEED: u8 = 0x51;
const HOST_SEED: u8 = 0x52;
const ACTOR_SEED: u8 = 0x56;
const BOOKER_SEED: u8 = 0x57;
const BUSY_SEED: u8 = 0x61;
const HOME_NODE_ID: u64 = 9;

const REASON: &str = "Board review moved; owen asked for this slot himself.";

const fn at(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

const fn hour(hours: u64) -> u64 {
    MONDAY + hours * 3_600
}

fn slot(start: u64) -> TimeRange {
    TimeRange {
        start,
        end: start + u64::from(DEFAULT_INTRO_DURATION_MIN) * 60,
    }
}

/// A vault with a booking page, a host, a booker contact and an elected home
/// node.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    page: EntityId,
    booker: EntityId,
}

impl Fixture {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
        let actor = test_id(ACTOR_SEED);
        vault
            .put_entity(&actor, ENTITY_TYPE_PERSON, at(1), 1, b"booking actor")
            .expect("put actor");
        let page = test_id(PAGE_SEED);
        vault
            .put_entity(&page, ENTITY_TYPE_ASSET, at(1), 1, b"booking page")
            .expect("put booking page");
        vault
            .put_entity(&test_id(HOST_SEED), ENTITY_TYPE_PERSON, at(1), 1, b"host")
            .expect("put host");
        let booker = test_id(BOOKER_SEED);
        vault
            .put_entity(
                &booker,
                ENTITY_TYPE_PERSON,
                at(1),
                1,
                b"visitor@example.test",
            )
            .expect("put booker");
        DreamerRunnerStore::new(&vault)
            .elect_home_node(
                &[DreamerHomeNodeCandidate::always_on_local(HOME_NODE_ID)],
                1,
            )
            .expect("elect home node");
        oneiron::calendar::transcript::permit_imported_calendar_source_for_test(&vault, actor)
            .expect("authorize the fixture actor's Imported source");
        Self {
            _dir: dir,
            vault,
            page,
            booker,
        }
    }

    fn consumer_input(&self) -> BookingLifecycleConsumerInput {
        BookingLifecycleConsumerInput {
            local_node_id: HOME_NODE_ID,
            lease_owner: "booking-lifecycle-worker".to_owned(),
            now_utc: NOW,
        }
    }

    /// The live values of `predicate` on `event_ref`.
    fn live_claim_values(&self, event_ref: EntityId, predicate: &str) -> Vec<rmpv::Value> {
        self.vault
            .claims_for_subject(&event_ref)
            .expect("claims for subject")
            .into_iter()
            .filter_map(|id| self.vault.get_claim(&id).expect("read claim"))
            .filter(|body| {
                body.predicate == predicate && body.lifecycle == ClaimLifecycleStatus::Active
            })
            .map(|body| body.value)
            .collect()
    }
}

/// Monday 09:00-14:00 UTC, 30-minute slots, a daily cap of one booking.
fn capped_config() -> EventTypeConfig {
    EventTypeConfig {
        key: EventTypeKey("intro-call".to_owned()),
        duration_min: DEFAULT_INTRO_DURATION_MIN,
        slot_step_min: 30,
        pre_buffer_min: 0,
        post_buffer_min: 0,
        min_notice_secs: 0,
        booking_window_secs: 7 * 24 * 3_600,
        daily_cap: Some(1),
        weekly_cap: None,
        routing: RoutingMode::Either,
        hosts: vec![HostAvailabilityConfig {
            host_ref: test_id(HOST_SEED),
            calendar_refs: vec![test_id(BUSY_SEED)],
            host_tz: "UTC".to_owned(),
            working_hours: vec![WeeklyWallWindow {
                weekday: 0,
                start_minute: 9 * 60,
                end_minute: 14 * 60,
            }],
            preferred_hours: Vec::new(),
        }],
        flex_windows: Vec::new(),
    }
}

/// The production solver over `config`, forwarding every solve the way the
/// server's oracle does, the solve past the caps included.
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

    fn solve_past_caps(&self, req: &SolveRequest) -> Result<SolveResult, BookingError> {
        self.with(|solver| solver.solve_past_caps(req))
    }
}

/// Enqueues `request` and runs one home-node turn over the capped solver.
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
        &fixture.consumer_input(),
    )
    .expect("turn")
    {
        BookingLifecycleTurn::Executed(receipt) => receipt,
        other => panic!("the home node must execute the queued attempt, got {other:?}"),
    }
}

fn hold_spec(
    fixture: &Fixture,
    session_key: SessionKey,
    start: u64,
    cap_override: Option<BookingCapOverride>,
) -> HoldSpec {
    HoldSpec {
        page_ref: fixture.page,
        event_type: EventTypeKey("intro-call".to_owned()),
        slot: slot(start),
        session_key,
        visitor_tz: "UTC".to_owned(),
        constraint: None,
        lease: HoldLeaseSpec::Ordinary,
        idempotency_key: None,
        cap_override,
    }
}

/// Holds `start` for session `who` and answers the confirm for it.
fn hold(
    fixture: &Fixture,
    config: &EventTypeConfig,
    who: &[u8],
    start: u64,
    cap_override: Option<BookingCapOverride>,
) -> ConfirmSpec {
    let session_key = SessionKey::derive(who);
    let held = match run(
        fixture,
        config,
        BookingVerbRequest::Hold(hold_spec(fixture, session_key, start, cap_override)),
    ) {
        BookingVerbReceipt::Held(held) => held,
        other => panic!("expected a hold receipt, got {other:?}"),
    };
    ConfirmSpec {
        hold_token: held.token,
        session_key,
        booker_contact: fixture.booker,
        intake: Vec::new(),
        idempotency_key: None,
    }
}

fn expect_confirmed(receipt: BookingVerbReceipt) -> ConfirmReceipt {
    match receipt {
        BookingVerbReceipt::Confirmed(confirmed) => confirmed,
        other => panic!("expected a confirm receipt, got {other:?}"),
    }
}

fn expect_slot_taken(receipt: BookingVerbReceipt) -> Vec<RankedSlot> {
    match receipt {
        BookingVerbReceipt::SlotTaken { alternatives } => alternatives,
        other => panic!("expected SlotTaken, got {other:?}"),
    }
}

fn reason() -> BookingCapOverride {
    BookingCapOverride {
        reason: REASON.to_owned(),
    }
}

/// Daily cap 1, one booking already that day: the owner's hold with a reason
/// is confirmed past the cap, and its booking keeps the reason. The booking
/// under the cap records none.
#[test]
fn an_owner_override_books_a_full_day_and_records_its_reason() {
    let fixture = Fixture::open();
    let config = capped_config();
    let first = hold(&fixture, &config, b"first", hour(9), None);
    let under_cap = expect_confirmed(run(&fixture, &config, BookingVerbRequest::Confirm(first)));

    let past = hold(&fixture, &config, b"owner", hour(11), Some(reason()));
    let past_cap = expect_confirmed(run(&fixture, &config, BookingVerbRequest::Confirm(past)));

    let recorded =
        fixture.live_claim_values(past_cap.calendar.event_ref, BOOKING_CAP_OVERRIDE_PREDICATE);
    assert_eq!(recorded.len(), 1, "one cap override claim: {recorded:?}");
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &recorded[0]).expect("re-encode the claim value");
    let value: BookingCapOverrideValue =
        rmp_serde::from_slice(&bytes).expect("the pinned value schema");
    assert_eq!(value.reason, REASON, "the reason is kept verbatim");
    assert_eq!(value.recorded_at, NOW);
    assert!(
        fixture
            .live_claim_values(under_cap.calendar.event_ref, BOOKING_CAP_OVERRIDE_PREDICATE)
            .is_empty(),
        "a booking under the cap records no override"
    );
}

/// Daily cap 1: a hold with no override on the full day is refused at the
/// confirm, as before.
#[test]
fn without_an_override_a_full_day_stays_full() {
    let fixture = Fixture::open();
    let config = capped_config();
    let first = hold(&fixture, &config, b"first", hour(9), None);
    expect_confirmed(run(&fixture, &config, BookingVerbRequest::Confirm(first)));

    let second = hold(&fixture, &config, b"second", hour(11), None);
    expect_slot_taken(run(&fixture, &config, BookingVerbRequest::Confirm(second)));
}

/// A blank or oversized reason never reaches the queue.
#[test]
fn a_blank_or_oversized_cap_override_reason_is_refused() {
    let fixture = Fixture::open();
    for reason in [
        String::new(),
        " \n\t".to_owned(),
        "x".repeat(oneiron::booking::MAX_CAP_OVERRIDE_REASON_BYTES + 1),
    ] {
        let spec = hold_spec(
            &fixture,
            SessionKey::derive(b"owner"),
            hour(11),
            Some(BookingCapOverride { reason }),
        );
        assert!(
            matches!(
                enqueue_booking_verb(&fixture.vault, BookingVerbRequest::Hold(spec), NOW),
                Err(BookingError::InvalidConstraint(_))
            ),
            "a malformed reason is refused at the door"
        );
    }
}
