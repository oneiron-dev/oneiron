//! When a reschedule token can no longer move its booking.
//!
//! A booking whose calendar provider cancelled it cannot be moved (FIX 22385).
//! An inbound provider cancellation lands as a `calendar.status = cancelled`
//! head on the booking's EVENT and need not change `booking.status`. The cap
//! and the reminder already read it; the reschedule read only
//! `booking.status`, so a token still moved the cancelled booking onto a new
//! slot and attested a Confirmed passport over it.
//!
//! A booking whose start has come cannot be moved either (FIX
//! BOOKING-RESCHEDULE-AFTER-START). The reschedule refused only a cancelled
//! booking, so a token moved a meeting in progress, a held meeting or a
//! no-show onto any open slot. The line is the start second itself: a move
//! one second before it still lands. The host may let visitors move a started
//! booking (`booking.reschedule.after_start`, default off; the lead's
//! amendment of BOOKING-RESCHEDULE-AFTER-START = A, 16 Nov 22:40).
//!
//! A standalone file with a trimmed copy of the `it` booking fixture
//! (`tests/it/booking_lifecycle.rs`), because the `it` target does not compile
//! on main today. The imported-source permit is test-support only.
#![cfg(feature = "test-support")]

use oneiron::booking::{
    BookingError, BookingLifecycleConsumerInput, BookingLifecycleTurn, BookingSolver,
    BookingVerbReceipt, BookingVerbRequest, ConfirmReceipt, ConfirmSpec,
    DEFAULT_INTRO_DURATION_MIN, EventTypeConfig, EventTypeKey, HoldLeaseSpec, HoldReceipt,
    HoldSpec, HostAvailabilityConfig, RankedSlot, RescheduleSpec, RoutingMode, SessionKey,
    SlotOracle, SolveRequest, SolveResult, VaultActiveHoldSource, WeeklyWallWindow,
    enqueue_booking_verb, run_booking_lifecycle_once,
};
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::{
    CalendarSel, ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject,
    DreamerHomeNodeCandidate, DreamerRunnerStore, EdgeActorClass, EntityId, TimeRange, Vault,
    VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
};
use rmpv::Value;
use serde_json::json;

const MONDAY: u64 = 1_772_409_600;
const NOW: u64 = MONDAY + 8 * 3_600;

const PAGE_SEED: u8 = 0x51;
const HOST_SEED: u8 = 0x52;
const ACTOR_SEED: u8 = 0x56;
const BOOKER_SEED: u8 = 0x57;
const BUSY_SEED: u8 = 0x61;
const HOME_NODE_ID: u64 = 9;

const fn at(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

/// `[seed; 16]`, as the shared integration helper builds it; every seed here
/// is outside the production-pinned id bytes.
fn test_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("fixture id")
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    page: EntityId,
    booker: EntityId,
    actor: EntityId,
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
            .expect("authorize this CAL ingest actor's Imported source");
        Self {
            _dir: dir,
            vault,
            page,
            booker,
            actor,
        }
    }

    fn run(
        &self,
        request: BookingVerbRequest,
        now: u64,
    ) -> Result<BookingVerbReceipt, BookingError> {
        enqueue_booking_verb(&self.vault, request, now)?;
        let turn = run_booking_lifecycle_once(
            &self.vault,
            |oracle_request| {
                let page = oracle_request
                    .page_ref
                    .expect("the consumer only builds an oracle for a resolved page");
                Ok(LifecycleSolver {
                    page,
                    exclude: oracle_request.exclude_session_key,
                    vault: &self.vault,
                })
            },
            &BookingLifecycleConsumerInput {
                local_node_id: HOME_NODE_ID,
                lease_owner: "booking-lifecycle-worker".to_owned(),
                now_utc: now,
            },
        )?;
        match turn {
            BookingLifecycleTurn::Executed(receipt) => Ok(receipt),
            other => panic!("the home node must execute the queued attempt, got {other:?}"),
        }
    }

    fn offered_slots(&self) -> Vec<RankedSlot> {
        LifecycleSolver {
            page: self.page,
            exclude: None,
            vault: &self.vault,
        }
        .solve(&SolveRequest {
            event_type: event_type(),
            window: TimeRange {
                start: MONDAY,
                end: MONDAY + 86_399,
            },
            constraint: None,
            visitor_tz: "UTC".to_owned(),
        })
        .expect("solve the fixture day")
        .slots
    }

    /// Admits a live Auto `calendar.status = cancelled` head on `event_ref`
    /// with an imported-cancel basis, as calendar ingest does when the
    /// provider cancels the event: through the public candidate door, under
    /// the CAL actor's Imported source permit.
    fn admit_provider_cancellation(&self, event_ref: EntityId) {
        let envelope = WriteEnvelope::new(
            WriteActor::new(self.actor, EdgeActorClass::Human),
            ClaimSource::Imported,
            WriteProvenance::new(Value::from("fix-22385-provider-cancel")).expect("provenance"),
            ClaimApprovalStatus::Auto,
        );
        self.vault
            .batch()
            .claim_candidate(
                &test_id(0xC5),
                ClaimCandidate::new(
                    "calendar.status",
                    ClaimSubject::Entity(event_ref),
                    Value::Map(vec![
                        (Value::from("status"), Value::from("cancelled")),
                        (Value::from("basis"), Value::from("imported_cancel")),
                        (Value::from("recorded_at"), Value::from(NOW + 30)),
                    ]),
                    1.0,
                ),
                &envelope,
                at(NOW + 30),
                1,
            )
            .commit()
            .expect("the provider's cancellation is admitted");
    }
}

struct LifecycleSolver<'a> {
    page: EntityId,
    exclude: Option<SessionKey>,
    vault: &'a Vault,
}

impl SlotOracle for LifecycleSolver<'_> {
    fn solve(&self, req: &SolveRequest) -> Result<SolveResult, BookingError> {
        let holds = match self.exclude {
            Some(key) => VaultActiveHoldSource::excluding(self.vault, key),
            None => VaultActiveHoldSource::new(self.vault),
        };
        let calendars = vec![(test_id(HOST_SEED), vec![CalendarSel { system: None }])];
        BookingSolver {
            vault: self.vault,
            page_ref: self.page,
            calendars_by_host: &calendars,
            holds: &holds,
            now_utc: NOW,
            synthetic_config: Some(fixture_config()),
        }
        .solve(req)
    }
}

fn event_type() -> EventTypeKey {
    EventTypeKey("intro-call".to_owned())
}

fn fixture_config() -> EventTypeConfig {
    EventTypeConfig {
        key: event_type(),
        duration_min: DEFAULT_INTRO_DURATION_MIN,
        slot_step_min: 30,
        pre_buffer_min: 0,
        post_buffer_min: 0,
        min_notice_secs: 0,
        booking_window_secs: 7 * 24 * 3_600,
        daily_cap: None,
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
        flex_with_ordinary: false,
        flex_windows: Vec::new(),
    }
}

fn slot_of(ranked: &RankedSlot) -> TimeRange {
    TimeRange {
        start: ranked.start_utc,
        end: ranked.end_utc,
    }
}

fn book(fixture: &Fixture, session_key: SessionKey, slot: TimeRange) -> ConfirmReceipt {
    let hold: HoldReceipt = match fixture
        .run(
            BookingVerbRequest::Hold(HoldSpec {
                page_ref: fixture.page,
                event_type: event_type(),
                slot,
                session_key,
                visitor_tz: "UTC".to_owned(),
                constraint: None,
                lease: HoldLeaseSpec::Ordinary,
                idempotency_key: None,
                cap_override: None,
            }),
            NOW,
        )
        .expect("hold")
    {
        BookingVerbReceipt::Held(hold) => hold,
        other => panic!("expected a hold receipt, got {other:?}"),
    };
    match fixture
        .run(
            BookingVerbRequest::Confirm(ConfirmSpec {
                hold_token: hold.token.clone(),
                session_key,
                booker_contact: fixture.booker,
                intake: Vec::new(),
                idempotency_key: None,
            }),
            NOW,
        )
        .expect("confirm")
    {
        BookingVerbReceipt::Confirmed(confirmed) => confirmed,
        other => panic!("expected a confirm receipt, got {other:?}"),
    }
}

#[test]
fn a_provider_cancelled_booking_cannot_be_rescheduled() {
    let fixture = Fixture::open();
    let slots = fixture.offered_slots();
    let booked = book(
        &fixture,
        SessionKey::derive(b"provider-cancel"),
        slot_of(&slots[0]),
    );
    fixture.admit_provider_cancellation(booked.calendar.event_ref);

    let moved = fixture.run(
        BookingVerbRequest::Reschedule(RescheduleSpec {
            token: booked.reschedule_token,
            new_slot: slot_of(&slots[4]),
            visitor_tz: "UTC".to_owned(),
            constraint: None,
            idempotency_key: None,
        }),
        NOW + 60,
    );

    assert!(
        matches!(moved, Err(BookingError::InvalidConstraint(_))),
        "a booking its calendar provider cancelled must not move; got {moved:?}"
    );
}

/// The earliest and the latest slot the fixture day offers: a booking at the
/// first, and a free target well after it.
fn earliest_and_latest(slots: &[RankedSlot]) -> (TimeRange, TimeRange) {
    let earliest = slots
        .iter()
        .min_by_key(|slot| slot.start_utc)
        .expect("the fixture day offers a slot");
    let latest = slots
        .iter()
        .max_by_key(|slot| slot.start_utc)
        .expect("the fixture day offers a slot");
    assert!(
        latest.start_utc >= earliest.end_utc,
        "the fixture day offers two disjoint slots"
    );
    (slot_of(earliest), slot_of(latest))
}

fn move_booking(
    fixture: &Fixture,
    booked: &ConfirmReceipt,
    new_slot: TimeRange,
    now: u64,
) -> Result<BookingVerbReceipt, BookingError> {
    fixture.run(
        BookingVerbRequest::Reschedule(RescheduleSpec {
            token: booked.reschedule_token.clone(),
            new_slot,
            visitor_tz: "UTC".to_owned(),
            constraint: None,
            idempotency_key: None,
        }),
        now,
    )
}

fn refused_as_started(moved: &Result<BookingVerbReceipt, BookingError>) -> bool {
    matches!(moved, Err(BookingError::InvalidConstraint(detail)) if detail.contains("has started"))
}

#[test]
fn a_booking_cannot_be_rescheduled_at_its_start_second() {
    let fixture = Fixture::open();
    let (first, last) = earliest_and_latest(&fixture.offered_slots());
    let booked = book(&fixture, SessionKey::derive(b"start-second"), first);

    let moved = move_booking(&fixture, &booked, last, first.start);

    assert!(
        refused_as_started(&moved),
        "a booking whose start second has come must not move; got {moved:?}"
    );
}

#[test]
fn a_booking_cannot_be_rescheduled_after_it_ended() {
    let fixture = Fixture::open();
    let (first, last) = earliest_and_latest(&fixture.offered_slots());
    let booked = book(&fixture, SessionKey::derive(b"after-end"), first);

    // A held meeting or a no-show, an hour after its end.
    let moved = move_booking(&fixture, &booked, last, first.end + 3_600);

    assert!(
        refused_as_started(&moved),
        "a meeting that is over must not move; got {moved:?}"
    );
}

#[test]
fn a_booking_still_moves_one_second_before_its_start() {
    let fixture = Fixture::open();
    let (first, last) = earliest_and_latest(&fixture.offered_slots());
    let booked = book(&fixture, SessionKey::derive(b"one-second-before"), first);

    let moved = move_booking(&fixture, &booked, last, first.start - 1);

    assert!(
        matches!(moved, Ok(BookingVerbReceipt::Rescheduled(_))),
        "a booking whose start has not come still moves; got {moved:?}"
    );
}

#[test]
fn a_started_booking_moves_once_the_host_lets_visitors_reschedule_after_the_start() {
    let fixture = Fixture::open();
    let (first, last) = earliest_and_latest(&fixture.offered_slots());
    let booked = book(&fixture, SessionKey::derive(b"after-start-allowed"), first);
    let owner = fixture
        .vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let proof = fixture
        .vault
        .authenticate_owner(owner, "principal:owner", true, GateDecisionId::now())
        .expect("owner proof");
    let outcome = fixture
        .vault
        .set_setting(
            SettingCaller::Owner(&proof),
            SetSetting::vault_value("booking.reschedule.after_start", json!(true)),
        )
        .expect("set the key");
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "the owner's set applies: {outcome:?}"
    );

    // A no-show, an hour after its end, moved by the visitor's token.
    let moved = move_booking(&fixture, &booked, last, first.end + 3_600);

    assert!(
        matches!(moved, Ok(BookingVerbReceipt::Rescheduled(_))),
        "with the key on a started booking moves; got {moved:?}"
    );
}
