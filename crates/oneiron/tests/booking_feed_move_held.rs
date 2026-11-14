//! A calendar feed's move of a booking waits while an emergency delivery for
//! that booking is pending (FIX 22385 part 3; FIX-LIST
//! [FEED-MOVE-HOLD-UNTESTED-AND-INCREMENTAL-CURSOR], parts a and c).
//!
//! The ruling's hold (Engine 12 Nov 16:1x, "GO on part 3 as you designed
//! it"): a pending emergency delivery fences the booking's revision, so the
//! feed holds that one item back, "the feed keeps this item's update owed and
//! reads it again on its next poll, and every other item of the pass lands".
//! Part a runs that path end to end, green on main and on the head: the
//! held pass moves the plain EVENT and leaves the booking, its EVENT and its
//! passport as they were; the poll keeps no ETag, so the next poll reads the
//! whole feed again; once the delivery completes, that poll moves the
//! booking. Part c is the owner's one-shot ICS upload of the same moved
//! booking: its receipt now says the move was held (`owed_booking_moves`),
//! where main's receipt had no such field (red on main).
//!
//! The booking fixture is `tests/booking_feed_move.rs`'s, whose lifecycle
//! solver answers from the page's event-type config. The pending emergency
//! is the crate's own fixture (`booking/emergency_reschedule/tests/mod.rs`,
//! `executable_with_invite_config` with no initial invite) rebuilt on public
//! paths: an owner-logged RequestUpdate instruction, which keeps the booking
//! confirmed at its slot, planned and executed on the lifecycle home node
//! with a sink that fails the first delivery. Only public paths, so main
//! plus this file builds for the red run.
#![cfg(feature = "test-support")]

mod common;

use std::sync::Mutex;

use oneiron::attempt_queue::{AttemptQueue, ClaimAttempt, ClaimOutcome};
use oneiron::booking::{
    BOOKING_EVENT_TYPE_PREDICATE, BOOKING_EVENT_TYPE_SCHEMA_VERSION, BOOKING_PASSPORT_SYSTEM,
    BookingError, BookingEventTypeClaimValue, BookingLifecycleConsumerInput, BookingLifecycleTurn,
    BookingSolver, BookingVerbReceipt, BookingVerbRequest, ConfirmReceipt, ConfirmSpec,
    DEFAULT_INTRO_DURATION_MIN, EmergencyActionPolicy, EmergencyPlan, EmergencyRescheduleRequest,
    EventTypeConfig, EventTypeKey, HoldLeaseSpec, HoldReceipt, HoldSpec, HostAvailabilityConfig,
    PublishBookingPageGrantRequest, RoutingMode, SessionKey, SlotOracle, SolveRequest, SolveResult,
    VaultActiveHoldSource, WeeklyWallWindow, encode_event_type_claim_value, enqueue_booking_verb,
    execute_emergency_plan, mint_publish_page_invite_grant, plan_emergency_reschedule,
    run_booking_lifecycle_once,
};
use oneiron::calendar::CalendarError;
use oneiron::calendar::ingest::door::{CalendarIcsImportRequest, import_ics_as_owner};
use oneiron::calendar::ingest::{
    IcsFeedFetcher, IcsFeedPollConfig, IcsFetchResponse, run_ics_feed_poll,
};
use oneiron::calendar::passport::live_passports_for_event;
use oneiron::calendar::query::CalendarRangeDto;
use oneiron::channel_identity::{ChannelIdentityBinding, ChannelIdentityState, SelfHeldShape};
use oneiron::memory::{BlobArtifactInput, BlobVersionAppendOutcome, EmergencyInstructionInput};
use oneiron::outbound::{
    OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink,
};
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::{
    CalendarSel, ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject,
    DreamerRunnerStore, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
};

/// Monday 2 March 2026, 00:00 UTC.
const MONDAY: u64 = 1_772_409_600;
const NOW: u64 = MONDAY + 8 * 3_600;

const PAGE_SEED: u8 = 0x51;
const HOST_SEED: u8 = 0x52;
const BOOKER_SEED: u8 = 0x57;
const BUSY_SEED: u8 = 0x61;
const IDENTITY_SEED: u8 = 0x79;
const POLICY_SEED: u8 = 0x7a;

/// The host's own calendar, as its feed system names it.
const HOST_FEED_SYSTEM: &str = "host-calendar";

/// The attempt kind the booker's revised invite is queued under.
const REVISION_INVITE_KIND: &str = "booking.revision_invite";

/// The plain EVENT the host's feed carries beside the booking.
const STANDUP_UID: &str = "standup@host.example.test";

const fn at(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

/// `[seed; 16]`; every seed here is outside the production-pinned id bytes.
fn test_id(seed: u8) -> EntityId {
    common::entity(seed)
}

/// The engine's inclusive occurrence row for a half-open slot.
const fn inclusive(slot: TimeRange) -> TimeRange {
    TimeRange {
        start: slot.start,
        end: slot.end - 1,
    }
}

/// A slot of the intro call's length starting `hour` on the fixture Monday.
fn slot_at(hour: u64) -> TimeRange {
    let start = MONDAY + hour * 3_600;
    TimeRange {
        start,
        end: start + u64::from(DEFAULT_INTRO_DURATION_MIN) * 60,
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: oneiron::authority::HostSlipIssuer,
    page: EntityId,
    host: EntityId,
    booker: EntityId,
    /// This install's client id, elected the lifecycle home node: the
    /// emergency writer runs only there.
    node_id: u64,
}

impl Fixture {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
        // Signing doors load this install's keys from a keystore (P6c).
        vault.install_device_keystore(std::sync::Arc::new(
            oneiron_keystore::MemoryKeystore::default(),
        ));
        let page = test_id(PAGE_SEED);
        let host = test_id(HOST_SEED);
        let booker = test_id(BOOKER_SEED);
        vault
            .put_entity(&page, ENTITY_TYPE_ASSET, at(1), 1, b"booking page")
            .expect("put booking page");
        vault
            .put_entity(&host, ENTITY_TYPE_PERSON, at(1), 1, b"host")
            .expect("put host");
        vault
            .put_entity(
                &booker,
                ENTITY_TYPE_PERSON,
                at(1),
                1,
                b"visitor@example.test",
            )
            .expect("put booker");
        // A raw claim put is born in its subject's substrate FACET, which
        // only a PERSON's put stores, so the birth gate refuses a claim about
        // the page ASSET (InvalidFacet, #4389) until that FACET is stored.
        vault
            .put_entity(
                &oneiron::claim::substrate_facet_id(page).expect("the page's facet id"),
                oneiron::registry::ENTITY_TYPE_FACET,
                at(1),
                1,
                &rmp_serde::to_vec_named(&serde_json::json!({"name": "booking page facet"}))
                    .expect("facet body"),
            )
            .expect("store the page's facet");
        // The page's event type, which the emergency planner solves its
        // proposals from.
        let event_type_claim = ClaimBody::new(
            BOOKING_EVENT_TYPE_PREDICATE,
            ClaimSubject::Entity(page),
            encode_event_type_claim_value(&BookingEventTypeClaimValue {
                schema_version: BOOKING_EVENT_TYPE_SCHEMA_VERSION,
                page_ref: page,
                config: fixture_config(),
            })
            .expect("encode the event type"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
        .expect("event type claim");
        vault
            .put_claim(&EntityId::now(), &event_type_claim, at(1), 1)
            .expect("put the page's event type");
        // The feed's import actor writes as an enrolled engine machine.
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        let runner = DreamerRunnerStore::new(&vault);
        let local = runner
            .local_home_node_candidate(true, true, true)
            .expect("local home node candidate");
        let node_id = local.node_id;
        runner
            .elect_home_node(&[local], 1)
            .expect("elect home node");
        Self {
            _dir: dir,
            vault,
            issuer,
            page,
            host,
            booker,
            node_id,
        }
    }

    fn consumer(&self, now: u64) -> BookingLifecycleConsumerInput {
        BookingLifecycleConsumerInput {
            local_node_id: self.node_id,
            lease_owner: "booking-lifecycle-worker".to_owned(),
            now_utc: now,
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
            &self.consumer(now),
        )?;
        match turn {
            BookingLifecycleTurn::Executed(receipt) => Ok(receipt),
            other => panic!("the home node must execute the queued attempt, got {other:?}"),
        }
    }

    /// One complete poll of the host's calendar feed carrying `events`.
    /// Returns the `If-None-Match` the poll sent.
    fn poll_host_feed(&self, events: &[FeedEvent<'_>], etag: &str, now: u64) -> Option<String> {
        let fetcher = RecordingFeed {
            response: Mutex::new(Some(IcsFetchResponse::Complete {
                etag: Some(etag.to_owned()),
                body: feed(events),
            })),
            if_none_match: Mutex::new(Vec::new()),
        };
        let config = IcsFeedPollConfig {
            secret_ref: format!("ics-feed:{HOST_FEED_SYSTEM}"),
            system: HOST_FEED_SYSTEM.to_owned(),
            cadence_min_seconds: 300,
            cadence_max_seconds: 900,
        };
        run_ics_feed_poll(&self.vault, &fetcher, &config, now, 7).expect("host feed poll");
        let sent = fetcher.if_none_match.into_inner().expect("sent validators");
        assert_eq!(sent.len(), 1, "one fetch per poll");
        sent.into_iter().next().flatten()
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
                        lease_owner: "fix-22385-held-test".to_owned(),
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

    /// The calendars the emergency planner reads per host.
    fn calendars(&self) -> Vec<(EntityId, Vec<CalendarSel>)> {
        vec![(self.host, vec![CalendarSel { system: None }])]
    }
}

/// One VEVENT of the host's feed.
struct FeedEvent<'a> {
    uid: &'a str,
    sequence: u32,
    slot: TimeRange,
    summary: &'a str,
}

/// A fetcher that answers one scripted response and records the validator
/// it was sent.
struct RecordingFeed {
    response: Mutex<Option<IcsFetchResponse>>,
    if_none_match: Mutex<Vec<Option<String>>>,
}

impl IcsFeedFetcher for RecordingFeed {
    fn fetch(
        &self,
        _secret_ref: &str,
        if_none_match: Option<&str>,
    ) -> Result<IcsFetchResponse, CalendarError> {
        self.if_none_match
            .lock()
            .expect("sent validators")
            .push(if_none_match.map(str::to_owned));
        self.response
            .lock()
            .expect("scripted response")
            .take()
            .ok_or_else(|| CalendarError::IcsFetch {
                reason: "the scripted feed has no response left".to_owned(),
            })
    }
}

/// A sink whose first delivery fails definitely and whose later ones land.
#[derive(Default)]
struct FailFirstDelivery {
    calls: usize,
}

impl OutboundExecutionSink for FailFirstDelivery {
    fn execute(&mut self, _request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.calls += 1;
        if self.calls == 1 {
            OutboundExecutionOutcome::failed("definite fixture non-delivery")
        } else {
            OutboundExecutionOutcome::delivered_to_channel("provider:message:fixture")
        }
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

/// The booking at 09:00, the standup at 13:00, and where the host's feed
/// moves each: the booking to 16:00 (outside the host's working hours, so no
/// solve offers it) and the standup to 13:30.
struct Moves {
    booked: TimeRange,
    booking_moved: TimeRange,
    standup: TimeRange,
    standup_moved: TimeRange,
}

fn feed_moves() -> Moves {
    Moves {
        booked: slot_at(9),
        booking_moved: slot_at(16),
        standup: slot_at(13),
        standup_moved: TimeRange {
            start: slot_at(13).start + 1_800,
            end: slot_at(13).end + 1_800,
        },
    }
}

/// The host feed after the host moved both events.
fn moved_feed<'a>(uid: &'a str, moves: &Moves) -> [FeedEvent<'a>; 2] {
    [
        FeedEvent {
            uid,
            sequence: 1,
            slot: moves.booking_moved,
            summary: "intro-call",
        },
        FeedEvent {
            uid: STANDUP_UID,
            sequence: 1,
            slot: moves.standup_moved,
            summary: "standup",
        },
    ]
}

/// The emergency the owner logged, and its one plan.
struct PendingEmergency {
    request: EmergencyRescheduleRequest,
    plan: EmergencyPlan,
}

/// Books the 09:00 intro call, lets the host's feed see it beside the
/// standup, then leaves an emergency RequestUpdate on the booking whose first
/// delivery failed: the delivery is pending, so it fences the booking's
/// revision.
fn booking_fenced_by_a_pending_emergency(fixture: &Fixture) -> (ConfirmReceipt, PendingEmergency) {
    let moves = feed_moves();
    let booked = book(fixture, SessionKey::derive(b"feed-move-held"), moves.booked);
    assert_eq!(
        fixture.poll_host_feed(
            &[
                FeedEvent {
                    uid: &booked.calendar.uid,
                    sequence: 0,
                    slot: moves.booked,
                    summary: "intro-call",
                },
                FeedEvent {
                    uid: STANDUP_UID,
                    sequence: 0,
                    slot: moves.standup,
                    summary: "standup",
                },
            ],
            "v1",
            NOW + 60,
        ),
        None,
        "the first poll has no validator"
    );

    // The owner's delivery seat, policy and page grant, as the crate's own
    // emergency fixture installs them.
    let identity = common::self_held_identity_in_state(
        "email",
        "host@example.test",
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::agent(fixture.host),
        ChannelIdentityState::Active,
        NOW,
    );
    fixture
        .vault
        .create_channel_identity(&test_id(IDENTITY_SEED), &identity)
        .expect("the host's email identity");
    let effect_scope = oneiron::test_support::effect_preset();
    let policy = rmp_serde::to_vec_named(&serde_json::json!({
        "schema_version": "1.2", "pack_id": "feed-move-held-tests", "pack_version": "v1",
        "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": { "criticality": "normal", "sensitivity": "normal" }, "rules": [],
        "actor_ceilings": [
            { "actor_class": "agent", "actor_ref": fixture.host.to_hex(), "ceiling": "auto" },
            { "actor_class": "first_party", "ceiling": "auto" },
            { "actor_class": "human", "ceiling": "auto" }
        ],
        "scoped_grants": [
            { "actor_ref": fixture.host.to_hex(), "effector": "external:calendar.invite",
              "scope": effect_scope, "selectors": { "channel": "calendar" } },
            { "actor_ref": fixture.host.to_hex(), "effector": "external:send",
              "scope": effect_scope, "selectors": { "channel": "email" } }
        ]
    }))
    .expect("encode the policy manifest");
    oneiron::test_support::put_policy_manifest_bytes(&fixture.vault, test_id(POLICY_SEED), &policy)
        .expect("put the policy manifest");
    mint_publish_page_invite_grant(
        &fixture.vault,
        &PublishBookingPageGrantRequest {
            page_ref: fixture.page,
            publisher_principal: fixture.host,
            issued_at: NOW,
        },
    )
    .expect("the page's invite grant");
    oneiron::test_support::bind_host_owner(&fixture.vault, &fixture.issuer, fixture.host)
        .expect("bind the host as the owner");
    // The apology goes out on `email`, which a seeded vault refuses until its
    // built-in pack is installed and checked (OF-519): "the channel's
    // built-in pack is not installed". The pack is not what this test
    // covers, so the vault drops the seed marker, as an unseeded open has none.
    oneiron::test_doors::builtin_pack_seed::remove_builtin_pack_seed_marker(&fixture.vault)
        .expect("remove the built-in pack seed marker");

    // The owner's RequestUpdate instruction over the booked slot: it keeps
    // the booking confirmed at its slot and revision, and proposes others.
    let window = inclusive(moves.booked);
    let memory = fixture.vault.memory(fixture.host, EdgeActorClass::Human);
    let authority = memory
        .record_emergency_instruction(&EmergencyInstructionInput {
            affected_window: CalendarRangeDto {
                start: window.start,
                end: window.end,
            },
            reason: "unavailable".to_owned(),
            action_policy: EmergencyActionPolicy::RequestUpdate,
            recorded_at: NOW + 90,
        })
        .expect("the owner logs the emergency instruction");
    let request = EmergencyRescheduleRequest {
        owner_ref: fixture.host,
        affected_window: window,
        reason: "unavailable".to_owned(),
        action_policy: EmergencyActionPolicy::RequestUpdate,
        authority,
    };
    let batch = plan_emergency_reschedule(&fixture.vault, &request, &fixture.calendars(), NOW + 90)
        .expect("plan the emergency");
    assert!(batch.refusals.is_empty(), "{:?}", batch.refusals);
    let [plan] = <[EmergencyPlan; 1]>::try_from(batch.plans).expect("one plan, for the booking");
    assert_eq!(plan.booking().calendar.event_ref, booked.calendar.event_ref);
    assert!(
        execute_emergency_plan(
            &fixture.vault,
            &request,
            &plan,
            &fixture.calendars(),
            &fixture.consumer(NOW + 90),
            &mut FailFirstDelivery::default(),
        )
        .is_err(),
        "the first delivery fails, so the emergency stays pending"
    );
    (booked, PendingEmergency { request, plan })
}

#[test]
fn a_held_feed_move_lands_the_rest_of_the_pass_and_moves_the_booking_once_the_delivery_completes() {
    let fixture = Fixture::open();
    let moves = feed_moves();
    let (booked, pending) = booking_fenced_by_a_pending_emergency(&fixture);
    let event = booked.calendar.event_ref;
    let standup = oneiron::calendar::passport::resolve_event_by_uid(&fixture.vault, STANDUP_UID)
        .expect("resolve the standup")
        .expect("the standup EVENT");

    // The held pass: the standup moves, the booking stays as it was.
    assert_eq!(
        fixture.poll_host_feed(&moved_feed(&booked.calendar.uid, &moves), "v2", NOW + 120),
        Some("v1".to_owned()),
        "the poll before the hold sends the validator it kept"
    );
    assert_eq!(
        fixture
            .vault
            .get_occurred(&standup)
            .expect("standup occurrence"),
        moves.standup_moved,
        "every other item of the held pass lands"
    );
    assert_eq!(
        fixture
            .vault
            .get_occurred(&event)
            .expect("booking occurrence"),
        inclusive(moves.booked),
        "the held booking's EVENT keeps its slot"
    );
    assert_eq!(
        fixture.booking_sequence(&event),
        0,
        "the held booking's passport takes no SEQUENCE"
    );
    assert!(
        fixture.queued_revision_invites().is_empty(),
        "a held move queues no revised invite"
    );

    // The delivery completes.
    let item = execute_emergency_plan(
        &fixture.vault,
        &pending.request,
        &pending.plan,
        &fixture.calendars(),
        &fixture.consumer(NOW + 150),
        &mut FailFirstDelivery { calls: 1 },
    )
    .expect("the emergency delivery completes");
    assert!(item.calendar_delivered && item.apology_delivered);

    // The next poll reads the whole feed again (the held pass kept no ETag,
    // so a server cannot answer not-modified), and the booking moves.
    assert_eq!(
        fixture.poll_host_feed(&moved_feed(&booked.calendar.uid, &moves), "v2", NOW + 180),
        None,
        "the poll after a held move sends no validator"
    );
    assert_eq!(
        fixture.booking_sequence(&event),
        1,
        "the owed move takes the booking passport's next SEQUENCE"
    );
    assert_eq!(
        fixture
            .vault
            .get_occurred(&event)
            .expect("booking occurrence"),
        inclusive(moves.booking_moved),
        "the owed move lands at the feed's slot"
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
}

#[test]
fn the_owners_upload_of_a_held_booking_move_says_it_was_held() {
    let fixture = Fixture::open();
    let moves = feed_moves();
    let (booked, _pending) = booking_fenced_by_a_pending_emergency(&fixture);
    let event = booked.calendar.event_ref;

    // The vault's owner uploads the host calendar's file with both events
    // moved. The upload door asks for this vault's owner, the embedded owner
    // a self-hosted root binds; the fixture bound the host key to the page's
    // host for the emergency, so it binds the owner back first.
    let owner_id = fixture
        .vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    oneiron::test_support::bind_host_owner(&fixture.vault, &fixture.issuer, owner_id)
        .expect("bind the host key to the vault's owner again");
    let memory = fixture.vault.memory(owner_id, EdgeActorClass::Human);
    let owner = fixture
        .vault
        .authenticate_owner(owner_id, "principal:owner", true, GateDecisionId::now())
        .expect("owner proof");
    let artifact = memory
        .put_blob_artifact(&BlobArtifactInput {
            id: None,
            name: "host-calendar.ics".to_owned(),
            media_type: "text/calendar".to_owned(),
            occurred_at: NOW + 120,
            learned_at: None,
        })
        .expect("the upload's artifact");
    let BlobVersionAppendOutcome::Landed(version) = memory
        .append_blob_version(
            &artifact.id_hex,
            &feed(&moved_feed(&booked.calendar.uid, &moves)),
            None,
            NOW + 120,
            None,
        )
        .expect("the upload's bytes")
    else {
        panic!("an owner upload lands at once");
    };
    let receipt = import_ics_as_owner(
        &memory,
        &owner,
        &CalendarIcsImportRequest {
            system: HOST_FEED_SYSTEM.to_owned(),
            source_blob_ref: artifact.id_hex.clone(),
            source_version: version.version,
        },
        None,
    )
    .expect("the owner's upload imports");

    assert_eq!(
        fixture
            .vault
            .get_occurred(&event)
            .expect("booking occurrence"),
        inclusive(moves.booked),
        "the upload holds the booking's move back"
    );
    assert_eq!(fixture.booking_sequence(&event), 0);
    let receipt = serde_json::to_value(&receipt).expect("receipt JSON");
    assert_eq!(
        receipt["owed_booking_moves"],
        serde_json::json!(1),
        "the upload's receipt says one booking move was held (main: no such field): {receipt}"
    );
}
