//! A calendar feed's move of a booking's EVENT goes through the booking
//! (FIX 22385; Engine ruling BOOKING-FEED-DRIFT = B, 12 Nov).
//!
//! When the host moves the booked event in their own calendar, the feed's
//! update lands. It lands as a booking revision: the booking passport takes
//! its next SEQUENCE, the revision receipt is recorded, and the booker's
//! revised invite is queued. Main let the feed rewrite the EVENT on its own,
//! with no passport, no receipt and no notice. The echo of the slot the
//! booking already sits at writes nothing, and a feed update of an EVENT that
//! carries no booking still moves it as before.
//!
//! The booking fixture is a trimmed copy of the `it` booking fixture
//! (`tests/it/booking_lifecycle.rs`), as in
//! `tests/booking_calendar_cancel_reschedule.rs`, because the `it` target does
//! not compile on main today. The feed is a scripted ICS fetcher, as in
//! `tests/it/calendar_ics_ingest_adapter.rs`. Only public paths, so main plus
//! this file builds for the red run.
#![cfg(feature = "test-support")]

use std::sync::Mutex;

use oneiron::attempt_queue::{AttemptQueue, ClaimAttempt, ClaimOutcome};
use oneiron::booking::{
    BOOKING_PASSPORT_SYSTEM, BookingError, BookingLifecycleConsumerInput, BookingLifecycleTurn,
    BookingSolver, BookingVerbReceipt, BookingVerbRequest, ConfirmReceipt, ConfirmSpec,
    DEFAULT_INTRO_DURATION_MIN, EventTypeConfig, EventTypeKey, HoldLeaseSpec, HoldReceipt,
    HoldSpec, HostAvailabilityConfig, RankedSlot, RescheduleSpec, RoutingMode, SessionKey,
    SlotOracle, SolveRequest, SolveResult, VaultActiveHoldSource, WeeklyWallWindow,
    enqueue_booking_verb, run_booking_lifecycle_once,
};
use oneiron::calendar::CalendarError;
use oneiron::calendar::ingest::{
    IcsFeedFetcher, IcsFeedPollConfig, IcsFetchResponse, run_ics_feed_poll,
};
use oneiron::calendar::passport::{live_passports_for_event, resolve_event_by_uid};
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::{
    CalendarSel, DreamerHomeNodeCandidate, DreamerRunnerStore, EntityId, TimeRange, Vault,
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

/// The host's own calendar, as its feed system names it.
const HOST_FEED_SYSTEM: &str = "host-calendar";

/// The attempt kind the booker's revised invite is queued under.
const REVISION_INVITE_KIND: &str = "booking.revision_invite";

const fn at(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

/// `[seed; 16]`, as the shared integration helper builds it; every seed here
/// is outside the production-pinned id bytes.
fn test_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("fixture id")
}

/// The engine's inclusive occurrence row for a half-open slot.
const fn inclusive(slot: TimeRange) -> TimeRange {
    TimeRange {
        start: slot.start,
        end: slot.end - 1,
    }
}

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
        // The feed's import actor writes as an enrolled engine machine.
        let issuer =
            oneiron::authority::HostSlipIssuer::from_secret(b"oneiron integration test host")
                .expect("host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .put_entity(
                &test_id(ACTOR_SEED),
                ENTITY_TYPE_PERSON,
                at(1),
                1,
                b"booking actor",
            )
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
        Self {
            _dir: dir,
            vault,
            page,
            booker,
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

    /// One complete poll of the host's calendar feed carrying `events`.
    fn poll_host_feed(&self, events: &[FeedEvent<'_>], etag: &str, now: u64) {
        let fetcher = ScriptedFeed(Mutex::new(Some(IcsFetchResponse::Complete {
            etag: Some(etag.to_owned()),
            body: feed(events),
        })));
        let config = IcsFeedPollConfig {
            secret_ref: format!("ics-feed:{HOST_FEED_SYSTEM}"),
            system: HOST_FEED_SYSTEM.to_owned(),
            cadence_min_seconds: 300,
            cadence_max_seconds: 900,
        };
        run_ics_feed_poll(&self.vault, &fetcher, &config, now, 7).expect("host feed poll");
    }

    /// The booking's outbound passport SEQUENCE: its one live head of the
    /// booking system.
    fn booking_sequence(&self, event: &EntityId) -> u32 {
        let heads: Vec<u32> = live_passports_for_event(&self.vault, event)
            .expect("passports of the booking EVENT")
            .into_iter()
            .filter(|(_, value)| value.system == BOOKING_PASSPORT_SYSTEM)
            .map(|(_, value)| value.last_sequence)
            .collect();
        match heads.as_slice() {
            [sequence] => *sequence,
            other => panic!("one live booking passport, got {other:?}"),
        }
    }

    /// Every queued revised-invite row's payload, claimed off the queue.
    fn queued_revision_invites(&self) -> Vec<serde_json::Value> {
        let queue = AttemptQueue::new(&self.vault);
        let mut payloads = Vec::new();
        loop {
            let claimed = queue
                .claim_kind(
                    REVISION_INVITE_KIND,
                    ClaimAttempt {
                        lease_owner: "fix-22385-test".to_owned(),
                        now: u64::MAX,
                    },
                )
                .expect("claim a revised-invite row");
            let ClaimOutcome::Claimed(row) = claimed else {
                return payloads;
            };
            payloads.push(serde_json::from_slice(&row.payload).expect("payload is JSON"));
        }
    }
}

/// One VEVENT of the host's feed.
struct FeedEvent<'a> {
    uid: &'a str,
    sequence: u32,
    slot: TimeRange,
    summary: &'a str,
}

/// A fetcher that answers one scripted response.
struct ScriptedFeed(Mutex<Option<IcsFetchResponse>>);

impl IcsFeedFetcher for ScriptedFeed {
    fn fetch(
        &self,
        _secret_ref: &str,
        _if_none_match: Option<&str>,
    ) -> Result<IcsFetchResponse, CalendarError> {
        self.0
            .lock()
            .expect("scripted response")
            .take()
            .ok_or_else(|| CalendarError::IcsFetch {
                reason: "the scripted feed has no response left".to_owned(),
            })
    }
}

/// A UTC instant on the fixture Monday as an ICS DATE-TIME.
fn ics_utc(ts: u64) -> String {
    assert!(
        (MONDAY..MONDAY + 86_400).contains(&ts),
        "fixture times stay on the fixture Monday"
    );
    let secs = ts - MONDAY;
    format!(
        "20260302T{:02}{:02}{:02}Z",
        secs / 3_600,
        secs / 60 % 60,
        secs % 60
    )
}

/// A complete VCALENDAR with a fixed DTSTAMP.
fn feed(events: &[FeedEvent<'_>]) -> Vec<u8> {
    let mut out = String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//test//EN\r\n");
    for event in events {
        out.push_str("BEGIN:VEVENT\r\n");
        out.push_str(&format!("UID:{}\r\n", event.uid));
        out.push_str("DTSTAMP:20260302T070000Z\r\n");
        out.push_str(&format!("DTSTART:{}\r\n", ics_utc(event.slot.start)));
        out.push_str(&format!("DTEND:{}\r\n", ics_utc(event.slot.end)));
        out.push_str(&format!("SEQUENCE:{}\r\n", event.sequence));
        out.push_str(&format!("SUMMARY:{}\r\n", event.summary));
        out.push_str("END:VEVENT\r\n");
    }
    out.push_str("END:VCALENDAR\r\n");
    out.into_bytes()
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

/// Books the fixture's first offered slot, and lets the host's feed report
/// the booked event as the booking's own invite placed it.
fn book_seen_by_the_host_feed(fixture: &Fixture, session: &[u8]) -> (ConfirmReceipt, TimeRange) {
    let booked_slot = slot_of(&fixture.offered_slots()[0]);
    let booked = book(fixture, SessionKey::derive(session), booked_slot);
    fixture.poll_host_feed(
        &[FeedEvent {
            uid: &booked.calendar.uid,
            sequence: 0,
            slot: booked_slot,
            summary: "intro-call",
        }],
        "v1",
        NOW + 60,
    );
    (booked, booked_slot)
}

#[test]
fn a_feed_move_of_a_booking_revises_it_and_queues_the_booker_notice() {
    let fixture = Fixture::open();
    let (booked, _) = book_seen_by_the_host_feed(&fixture, b"feed-move");
    let event = booked.calendar.event_ref;
    // 16:00, outside the host's working hours: no solve offers it.
    let moved = TimeRange {
        start: MONDAY + 16 * 3_600,
        end: MONDAY + 16 * 3_600 + u64::from(DEFAULT_INTRO_DURATION_MIN) * 60,
    };

    fixture.poll_host_feed(
        &[FeedEvent {
            uid: &booked.calendar.uid,
            sequence: 1,
            slot: moved,
            summary: "intro-call",
        }],
        "v2",
        NOW + 120,
    );

    assert_eq!(
        fixture.booking_sequence(&event),
        1,
        "the feed move takes the booking passport's next SEQUENCE"
    );
    assert_eq!(
        fixture
            .vault
            .get_occurred(&event)
            .expect("booking occurrence"),
        inclusive(moved),
        "the move lands at the feed's slot"
    );
    assert_eq!(
        fixture.queued_revision_invites(),
        vec![serde_json::json!({
            "event_ref": event.to_hex(),
            "uid": booked.calendar.uid,
            "sequence": 1,
        })],
        "one revised invite to the booker is queued for the move's SEQUENCE"
    );
    // The revision receipt: a token reschedule to the slot the booking now
    // sits at answers the feed move's revision and increments nothing.
    let replay = fixture.run(
        BookingVerbRequest::Reschedule(RescheduleSpec {
            token: booked.reschedule_token,
            new_slot: moved,
            visitor_tz: "UTC".to_owned(),
            constraint: None,
            idempotency_key: None,
        }),
        NOW + 180,
    );
    match replay {
        Ok(BookingVerbReceipt::Rescheduled(receipt)) => {
            assert_eq!(
                receipt.calendar.sequence, 1,
                "the recorded revision answers"
            );
        }
        other => {
            panic!("the move's revision receipt answers a reschedule to its slot; got {other:?}")
        }
    }
    assert_eq!(fixture.booking_sequence(&event), 1);
}

#[test]
fn the_feed_echo_of_the_booked_slot_writes_nothing() {
    let fixture = Fixture::open();
    let (booked, booked_slot) = book_seen_by_the_host_feed(&fixture, b"feed-echo");
    let event = booked.calendar.event_ref;

    // The host's calendar re-saves the event at the slot the booking sits at:
    // a new SEQUENCE and SUMMARY, the same times.
    fixture.poll_host_feed(
        &[FeedEvent {
            uid: &booked.calendar.uid,
            sequence: 1,
            slot: booked_slot,
            summary: "intro-call (host copy)",
        }],
        "v2",
        NOW + 120,
    );

    assert_eq!(
        fixture
            .vault
            .get_occurred(&event)
            .expect("booking occurrence"),
        inclusive(booked_slot),
        "the echo leaves the booking's slot where it is"
    );
    assert_eq!(
        fixture.booking_sequence(&event),
        0,
        "the echo takes no SEQUENCE"
    );
    assert_eq!(
        fixture.queued_revision_invites(),
        Vec::<serde_json::Value>::new(),
        "the echo queues no notice"
    );
}

#[test]
fn a_feed_update_of_an_event_with_no_booking_still_moves_it() {
    let fixture = Fixture::open();
    let uid = "standup@host.example";
    let first = TimeRange {
        start: MONDAY + 10 * 3_600,
        end: MONDAY + 10 * 3_600 + 900,
    };
    let moved = TimeRange {
        start: MONDAY + 11 * 3_600,
        end: MONDAY + 11 * 3_600 + 900,
    };
    fixture.poll_host_feed(
        &[FeedEvent {
            uid,
            sequence: 0,
            slot: first,
            summary: "standup",
        }],
        "v1",
        NOW + 60,
    );

    fixture.poll_host_feed(
        &[FeedEvent {
            uid,
            sequence: 1,
            slot: moved,
            summary: "standup",
        }],
        "v2",
        NOW + 120,
    );

    let event = resolve_event_by_uid(&fixture.vault, uid)
        .expect("resolve the feed's UID")
        .expect("the feed's EVENT");
    assert_eq!(
        fixture
            .vault
            .get_occurred(&event)
            .expect("event occurrence"),
        moved,
        "a plain EVENT follows the feed as before"
    );
    assert_eq!(
        fixture.queued_revision_invites(),
        Vec::<serde_json::Value>::new(),
        "no booking, no notice"
    );
}
