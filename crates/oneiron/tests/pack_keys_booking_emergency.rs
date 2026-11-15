//! PACK-SETTINGS-ALL W1: the emergency reschedule's proposal count, floor and search
//! span are owner Setting keys, and each default is today's behaviour.
//!
//! - `booking.emergency.max_proposals` (default 3): how many replacement times
//!   one plan offers. Default: 3 proposals. Owner sets 5: 5 proposals.
//! - `booking.emergency.min_proposals` (default 2): the fewest live times a plan
//!   may offer before it refuses. Default: 2 proposals plan. Owner sets 3 with
//!   only 2 free: the booking is in refusals with "fewer than 3".
//! - `booking.emergency.search_span_secs` (default 604800, seven days): how far
//!   past the affected window a plan searches. Default: no free slots in seven
//!   days refuses. Owner sets 864000 (ten days): the days 9-10 slots plan.
//!
//! On the base (the Setting primitive branch without this head) the owner's set
//! fails with `no setting key is named ...`: that is its red. The defaults
//! still plan (the head only replaces the literals 3, 2 and 7 * 86_400), so the
//! red is the set, not the first half.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test pack_keys_booking_emergency`
#![cfg(feature = "test-support")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Mutex;

use oneiron::booking::emergency_reschedule::{
    EmergencyActionPolicy, EmergencyBatchPlan, EmergencyRescheduleRequest,
    plan_emergency_reschedule,
};
use oneiron::booking::{
    BOOKING_EVENT_TYPE_PREDICATE, BOOKING_EVENT_TYPE_SCHEMA_VERSION, BookingEventTypeClaimValue,
    BookingLifecycleConsumerInput, BookingLifecycleTurn, BookingVerbReceipt, BookingVerbRequest,
    ConfirmReceipt, ConfirmSpec, EventTypeConfig, EventTypeKey, HoldLeaseSpec, HoldSpec,
    HostAvailabilityConfig, RankedSlot, RoutingMode, SessionKey, SlotHostBinding, SlotOracle,
    SolveRequest, SolveResult, WeeklyWallWindow, encode_event_type_claim_value,
    enqueue_booking_verb, run_booking_lifecycle_once,
};
use oneiron::calendar::CalendarError;
use oneiron::calendar::ingest::{
    IcsFeedFetcher, IcsFeedPollConfig, IcsFetchResponse, run_ics_feed_poll,
};
use oneiron::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityStep,
    SelfHeldShape,
};
use oneiron::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::EmergencyInstructionInput;
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::{
    CalendarRangeDto, CalendarSel, DreamerRunnerStore, EdgeActorClass, EntityId, TimeRange, Vault,
    VaultConfig,
};

/// Monday 2 March 2026, 00:00 UTC.
const MONDAY: u64 = 1_772_409_600;
/// 08:00 on that Monday: the host clock for every plan.
const NOW: u64 = MONDAY + 8 * 3_600;
/// The booked slot: 09:00-09:30 that Monday.
const BOOKED_START: u64 = MONDAY + 9 * 3_600;
const BOOKED_END: u64 = BOOKED_START + 1_800;
/// The affected window: 09:00-09:59:59 that Monday, covering the booking.
const AFFECTED_START: u64 = BOOKED_START;
const AFFECTED_END: u64 = BOOKED_START + 3_599;
/// The replacement search starts here: the affected window's end + 1.
const SEARCH_START: u64 = AFFECTED_END + 1;

const OWNER_SEED: u8 = 0x51;
const PAGE_SEED: u8 = 0x52;
const BOOKER_SEED: u8 = 0x53;
const IDENTITY_SEED: u8 = 0x79;

/// The host's own calendar, as its feed system names it.
const HOST_FEED_SYSTEM: &str = "host-calendar";

const MAX_KEY: &str = "booking.emergency.max_proposals";
const MIN_KEY: &str = "booking.emergency.min_proposals";
const SPAN_KEY: &str = "booking.emergency.search_span_secs";

const FOURTEEN_DAYS: u64 = 14 * 86_400;
const TEN_DAYS: u64 = 864_000;

const fn at(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

fn test_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("fixture id")
}

fn booked_slot() -> TimeRange {
    TimeRange {
        start: BOOKED_START,
        end: BOOKED_END,
    }
}

fn affected_window() -> TimeRange {
    TimeRange {
        start: AFFECTED_START,
        end: AFFECTED_END,
    }
}

fn event_type() -> EventTypeKey {
    EventTypeKey("intro".to_owned())
}

fn base_config(
    owner: EntityId,
    working_hours: Vec<WeeklyWallWindow>,
    booking_window_secs: u64,
) -> EventTypeConfig {
    EventTypeConfig {
        key: event_type(),
        duration_min: 30,
        slot_step_min: 30,
        pre_buffer_min: 0,
        post_buffer_min: 0,
        min_notice_secs: 0,
        booking_window_secs,
        daily_cap: None,
        weekly_cap: None,
        routing: RoutingMode::Either,
        hosts: vec![HostAvailabilityConfig {
            host_ref: owner,
            calendar_refs: vec![owner],
            host_tz: "UTC".to_owned(),
            working_hours,
            preferred_hours: Vec::new(),
        }],
        flex_windows: Vec::new(),
    }
}

/// Every weekday open all day: many free slots in any span.
fn all_open_hours() -> Vec<WeeklyWallWindow> {
    (0..7)
        .map(|weekday| WeeklyWallWindow {
            weekday,
            start_minute: 0,
            end_minute: 1440,
        })
        .collect()
}

/// Exactly two slots in a seven-day span: Tuesday 09:00-10:00 only.
fn two_slot_hours() -> Vec<WeeklyWallWindow> {
    vec![WeeklyWallWindow {
        weekday: 1,
        start_minute: 9 * 60,
        end_minute: 10 * 60,
    }]
}

/// Two slots a day at 10:00-11:00: the busy feed blocks days 0-8, day 9 stays.
fn daily_ten_to_eleven_hours() -> Vec<WeeklyWallWindow> {
    (0..7)
        .map(|weekday| WeeklyWallWindow {
            weekday,
            start_minute: 10 * 60,
            end_minute: 11 * 60,
        })
        .collect()
}

/// The availability answer is a fixture; the hold, confirm, EVENT, passport
/// and receipts use the real writer.
struct Offered {
    slot: TimeRange,
    host: EntityId,
}

impl SlotOracle for Offered {
    fn solve(&self, _req: &SolveRequest) -> Result<SolveResult, oneiron::booking::BookingError> {
        Ok(SolveResult {
            slots: vec![RankedSlot {
                start_utc: self.slot.start,
                end_utc: self.slot.end,
                rank: 1.0,
            }],
            flex_used: false,
            host_bindings: vec![SlotHostBinding {
                start_utc: self.slot.start,
                end_utc: self.slot.end,
                host_refs: vec![self.host.to_hex()],
                host_zones: vec!["UTC".to_owned()],
            }],
        })
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    page: EntityId,
    owner: EntityId,
    booker: EntityId,
    owner_proof: AuthenticatedOwner,
    home_node_id: u64,
}

impl Fixture {
    fn open(config: EventTypeConfig) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        let owner = test_id(OWNER_SEED);
        let page = test_id(PAGE_SEED);
        let booker = test_id(BOOKER_SEED);
        vault
            .put_entity(&owner, ENTITY_TYPE_PERSON, at(1), 1, b"owen")
            .expect("put owner");
        vault
            .put_entity(&page, ENTITY_TYPE_ASSET, at(1), 1, b"booking page")
            .expect("put booking page");
        vault
            .put_entity(&booker, ENTITY_TYPE_PERSON, at(1), 1, b"yuki")
            .expect("put booker");
        oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("bind owner");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        let candidate = DreamerRunnerStore::new(&vault)
            .local_home_node_candidate(true, true, true)
            .expect("local home candidate");
        let home_node_id = candidate.node_id;
        DreamerRunnerStore::new(&vault)
            .elect_home_node(&[candidate], 1)
            .expect("elect home node");
        let body = ClaimBody::new(
            BOOKING_EVENT_TYPE_PREDICATE,
            ClaimSubject::Entity(page),
            encode_event_type_claim_value(&BookingEventTypeClaimValue {
                schema_version: BOOKING_EVENT_TYPE_SCHEMA_VERSION,
                page_ref: page,
                config,
            })
            .expect("encode event type"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
        .expect("event type claim");
        vault
            .put_claim(&EntityId::now(), &body, at(1), 1)
            .expect("put event type");
        let requested = ChannelIdentity::requested(
            "email",
            "owen@example.com",
            SelfHeldShape::DedicatedAddress,
            ChannelIdentityBinding::agent(owner),
            NOW,
        );
        let bound = requested
            .step(
                ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
                NOW,
            )
            .expect("bind identity");
        let active = bound
            .step(ChannelIdentityStep::Fulfill, NOW)
            .expect("fulfill identity");
        vault
            .create_channel_identity(&test_id(IDENTITY_SEED), &active)
            .expect("create sending identity");
        Self {
            _dir: dir,
            vault,
            page,
            owner,
            booker,
            owner_proof,
            home_node_id,
        }
    }

    fn run_with_offered(
        &self,
        request: BookingVerbRequest,
        slot: TimeRange,
        now: u64,
    ) -> BookingVerbReceipt {
        enqueue_booking_verb(&self.vault, request, now).expect("enqueue booking verb");
        let turn = run_booking_lifecycle_once(
            &self.vault,
            |_| {
                Ok(Offered {
                    slot,
                    host: self.owner,
                })
            },
            &BookingLifecycleConsumerInput {
                local_node_id: self.home_node_id,
                lease_owner: "emergency-test".to_owned(),
                now_utc: now,
            },
        )
        .expect("run booking lifecycle");
        match turn {
            BookingLifecycleTurn::Executed(receipt) => receipt,
            other => panic!("the home node must execute the queued attempt, got {other:?}"),
        }
    }

    fn book(&self, slot: TimeRange, session_material: &[u8]) -> ConfirmReceipt {
        let session = SessionKey::derive(session_material);
        let held = self.run_with_offered(
            BookingVerbRequest::Hold(HoldSpec {
                page_ref: self.page,
                event_type: event_type(),
                slot,
                session_key: session,
                visitor_tz: "UTC".to_owned(),
                constraint: None,
                lease: HoldLeaseSpec::Ordinary,
                idempotency_key: None,
            }),
            slot,
            NOW,
        );
        let BookingVerbReceipt::Held(held) = held else {
            panic!("expected a hold receipt, got {held:?}")
        };
        let confirmed = self.run_with_offered(
            BookingVerbRequest::Confirm(ConfirmSpec {
                hold_token: held.token,
                session_key: session,
                booker_contact: self.booker,
                intake: Vec::new(),
                idempotency_key: None,
            }),
            slot,
            NOW,
        );
        let BookingVerbReceipt::Confirmed(confirmed) = confirmed else {
            panic!("expected a confirm receipt, got {confirmed:?}")
        };
        confirmed
    }

    fn instruct(
        &self,
        window: TimeRange,
        reason: &str,
        recorded_at: u64,
    ) -> EmergencyRescheduleRequest {
        let authority = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .record_emergency_instruction(&EmergencyInstructionInput {
                affected_window: CalendarRangeDto {
                    start: window.start,
                    end: window.end,
                },
                reason: reason.to_owned(),
                action_policy: EmergencyActionPolicy::Cancel,
                recorded_at,
            })
            .expect("log owner instruction");
        EmergencyRescheduleRequest {
            owner_ref: self.owner,
            affected_window: window,
            reason: reason.to_owned(),
            action_policy: EmergencyActionPolicy::Cancel,
            authority,
        }
    }

    fn plan(&self, request: &EmergencyRescheduleRequest, now: u64) -> EmergencyBatchPlan {
        let calendars = vec![(self.owner, vec![CalendarSel { system: None }])];
        plan_emergency_reschedule(&self.vault, request, &calendars, now).expect("plan emergency")
    }

    fn set_owner(&self, key: &str, value: serde_json::Value) -> Result<SetSettingOutcome, String> {
        self.vault
            .set_setting(
                SettingCaller::Owner(&self.owner_proof),
                SetSetting::vault_value(key, value),
            )
            .map_err(|error| error.to_string())
    }

    fn poll_feed(&self, body: Vec<u8>, etag: &str, now: u64) {
        let fetcher = ScriptedFeed(Mutex::new(Some(IcsFetchResponse::Complete {
            etag: Some(etag.to_owned()),
            body,
        })));
        let config = IcsFeedPollConfig {
            secret_ref: format!("ics-feed:{HOST_FEED_SYSTEM}"),
            system: HOST_FEED_SYSTEM.to_owned(),
            cadence_min_seconds: 300,
            cadence_max_seconds: 900,
        };
        run_ics_feed_poll(&self.vault, &fetcher, &config, now, 7).expect("host feed poll");
    }
}

fn assert_applied(outcome: &SetSettingOutcome, expected: &serde_json::Value) {
    match outcome {
        SetSettingOutcome::Applied {
            sequence: Some(_),
            value,
            ..
        } if value == expected => {}
        other => panic!("the owner's set applies with {expected}: got {other:?}"),
    }
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

struct BusySpec {
    uid: String,
    slot: TimeRange,
}

/// A UTC instant in March 2026 as an ICS DATE-TIME. All busy slots stay in
/// March (the 2nd plus the day offset), so no month table is needed.
fn ics_utc_general(ts: u64) -> String {
    let since_monday = ts - MONDAY;
    let days = since_monday / 86_400;
    let secs = since_monday % 86_400;
    format!(
        "202603{:02}T{:02}{:02}{:02}Z",
        2 + days,
        secs / 3_600,
        secs / 60 % 60,
        secs % 60
    )
}

fn busy_feed(specs: &[BusySpec]) -> Vec<u8> {
    let mut out = String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//test//EN\r\n");
    for spec in specs {
        out.push_str("BEGIN:VEVENT\r\n");
        out.push_str(&format!("UID:{}\r\n", spec.uid));
        out.push_str("DTSTAMP:20260302T070000Z\r\n");
        out.push_str(&format!("DTSTART:{}\r\n", ics_utc_general(spec.slot.start)));
        out.push_str(&format!("DTEND:{}\r\n", ics_utc_general(spec.slot.end)));
        out.push_str("SEQUENCE:0\r\n");
        out.push_str("SUMMARY:busy\r\n");
        out.push_str("END:VEVENT\r\n");
    }
    out.push_str("END:VCALENDAR\r\n");
    out.into_bytes()
}

/// Nine busy mornings at 10:00-11:00, days 0-8 after the search start: every
/// 10:00-11:00 window the default seven-day search could offer, plus days 7-8
/// so only day 9 stays free for the ten-day search.
fn block_first_nine_mornings() -> Vec<BusySpec> {
    (0..9)
        .map(|day| {
            let start = SEARCH_START + day * 86_400;
            BusySpec {
                uid: format!("busy-{day}@example.test"),
                slot: TimeRange {
                    start,
                    end: start + 3_600,
                },
            }
        })
        .collect()
}

#[test]
fn emergency_plan_offers_three_times_by_default_and_the_owners_count_when_set() {
    let owner = test_id(OWNER_SEED);
    let fixture = Fixture::open(base_config(owner, all_open_hours(), FOURTEEN_DAYS));
    let booked = fixture.book(booked_slot(), b"emergency-max-first");
    let window = affected_window();
    let first = fixture.instruct(window, "unavailable", NOW);
    let batch = fixture.plan(&first, NOW);
    assert!(
        batch.refusals.is_empty(),
        "default plans: {:?}",
        batch.refusals
    );
    assert_eq!(batch.plans.len(), 1, "one booking plans");
    assert_eq!(
        batch.plans[0].proposals().len(),
        3,
        "today's count is three"
    );
    assert_eq!(
        batch.plans[0].booking().calendar.event_ref,
        booked.calendar.event_ref
    );
    let applied = fixture
        .set_owner(MAX_KEY, serde_json::json!(5))
        .expect("the owner sets the count");
    assert_applied(&applied, &serde_json::json!(5));
    let second = fixture.instruct(window, "unavailable (owner count)", NOW);
    let batch = fixture.plan(&second, NOW);
    assert!(
        batch.refusals.is_empty(),
        "the new plan lands: {:?}",
        batch.refusals
    );
    assert_eq!(batch.plans.len(), 1, "one booking plans");
    assert_eq!(
        batch.plans[0].proposals().len(),
        5,
        "the owner's count rules the new plan"
    );
}

#[test]
fn emergency_plan_needs_two_times_by_default_and_the_owners_floor_when_set() {
    let owner = test_id(OWNER_SEED);
    let fixture = Fixture::open(base_config(owner, two_slot_hours(), FOURTEEN_DAYS));
    let booked = fixture.book(booked_slot(), b"emergency-min-first");
    let window = affected_window();
    let first = fixture.instruct(window, "unavailable", NOW);
    let batch = fixture.plan(&first, NOW);
    assert!(
        batch.refusals.is_empty(),
        "default plans: {:?}",
        batch.refusals
    );
    assert_eq!(batch.plans.len(), 1, "one booking plans");
    assert_eq!(
        batch.plans[0].proposals().len(),
        2,
        "today's floor leaves two"
    );
    let applied = fixture
        .set_owner(MIN_KEY, serde_json::json!(3))
        .expect("the owner sets the floor");
    assert_applied(&applied, &serde_json::json!(3));
    let second = fixture.instruct(window, "unavailable (owner floor)", NOW);
    let batch = fixture.plan(&second, NOW);
    assert!(
        batch.plans.is_empty(),
        "no plan under the floor: {:?}",
        batch.plans
    );
    assert_eq!(batch.refusals.len(), 1, "the booking is refused");
    assert_eq!(batch.refusals[0].0, booked.calendar.event_ref);
    assert!(
        batch.refusals[0].1.contains("fewer than 3"),
        "the floor names itself: {}",
        batch.refusals[0].1
    );
    let refused = fixture
        .set_owner(MIN_KEY, serde_json::json!(4))
        .expect_err("a floor above the count refuses");
    assert!(
        refused.contains("must not exceed"),
        "the hook names the pair: {refused}"
    );
    let third = fixture.instruct(window, "unavailable (floor still 3)", NOW);
    let batch = fixture.plan(&third, NOW);
    assert_eq!(batch.refusals.len(), 1, "still refused");
    assert!(
        batch.refusals[0].1.contains("fewer than 3"),
        "the value stays 3: {}",
        batch.refusals[0].1
    );
}

#[test]
fn emergency_plan_searches_seven_days_by_default_and_the_owners_span_when_set() {
    let owner = test_id(OWNER_SEED);
    let fixture = Fixture::open(base_config(
        owner,
        daily_ten_to_eleven_hours(),
        FOURTEEN_DAYS,
    ));
    let booked = fixture.book(booked_slot(), b"emergency-span-first");
    let busy = block_first_nine_mornings();
    fixture.poll_feed(busy_feed(&busy), "busy-v1", NOW + 60);
    let window = affected_window();
    let first = fixture.instruct(window, "unavailable", NOW);
    let batch = fixture.plan(&first, NOW);
    assert!(
        batch.plans.is_empty(),
        "no plan in seven days: {:?}",
        batch.plans
    );
    assert_eq!(batch.refusals.len(), 1, "the booking is refused");
    assert_eq!(batch.refusals[0].0, booked.calendar.event_ref);
    // The base words the count ("two"), the head the number: the refusal
    // itself is today's behaviour, so the base's red stays the owner's set.
    assert!(
        batch.refusals[0].1.contains("live solver proposals"),
        "seven days find nothing: {}",
        batch.refusals[0].1
    );
    let applied = fixture
        .set_owner(SPAN_KEY, serde_json::json!(TEN_DAYS))
        .expect("the owner sets the span");
    assert_applied(&applied, &serde_json::json!(TEN_DAYS));
    let second = fixture.instruct(window, "unavailable (owner span)", NOW);
    let batch = fixture.plan(&second, NOW);
    assert!(
        batch.refusals.is_empty(),
        "the wider search lands: {:?}",
        batch.refusals
    );
    assert_eq!(batch.plans.len(), 1, "one booking plans");
    assert!(
        batch.plans[0].proposals().len() >= 2,
        "days 9-10 offer at least two: {}",
        batch.plans[0].proposals().len()
    );
}
