//! BK-DEPOSITS PR 2: the refund each later cancel or move of a deposit
//! booking earns (OPUS-SECREAD-A cold read, 15 Nov; Engine rulings 18:27).
//! - N2: the owner's BK-09 emergency cancel is a host cancel, so the
//!   visitor's deposit comes back whole (RULING DEPOSIT-HOST-CANCEL-REFUND =
//!   A): a deposit still to capture is released, a captured one refunded, in
//!   the emergency's own commit.
//! - N1: a visitor's reschedule caps a later cancel's refund at what a cancel
//!   at the move would have refunded against the slot left (RULING
//!   DEPOSIT-RESCHEDULE-REFUND = A). A move with full notice keeps the full
//!   refund; a host move sets no cap.
//! - N3: a host cancellation the calendar shows at or after the booking's
//!   start leaves the deposit (RULING DEPOSIT-HOST-CANCEL-AFTER-START = A,
//!   parity with CAL-07); one first seen before the start and repaired after
//!   it still refunds. A provider tombstone from the calendar the booking was
//!   written to counts from its first arrival there, so one stopped before
//!   its refund and sent again after the start refunds (FIX
//!   [BK-DEPOSIT-TOMBSTONE-REDELIVERY-SEEN-AT]); a tombstone in another
//!   calendar before the start never dates it (RULING
//!   DEPOSIT-HOST-CANCEL-SOURCE = A).
//!
//! The fixture is the emergency fixture of `tests/booking_feed_move_held.rs`
//! (keystore, the page's facet, engine machines, this install elected the
//! lifecycle home node, the owner's seat, policy and page grant), with a
//! deposit on the page's event type. Only public paths and the test doors
//! that file uses, so the pre-fix head builds it: its red is an assert.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test booking_deposit_refund_rules`.

mod booking_host_seat_support;
mod common;

use std::sync::Mutex;

use booking_host_seat_support::{Seat, SeatChange};
use oneiron::booking::lifecycle::{
    DepositCheckoutStart, DepositProviderEvent, DepositProviderEventKind,
    DepositProviderEventOutcome, DepositProviderFailure, DepositSettleMove, DepositSettleRequest,
    DepositSettlementPort, DepositState, begin_deposit_checkout, booking_deposit_for_payment,
    record_deposit_provider_event, run_booking_deposit_settlement, settle_booking_deposit,
};
use oneiron::booking::{
    BOOKING_EVENT_TYPE_PREDICATE, BOOKING_EVENT_TYPE_SCHEMA_VERSION, BookingError,
    BookingEventTypeClaimValue, BookingLifecycleConsumerInput, BookingLifecycleTurn, BookingSolver,
    BookingVerbReceipt, BookingVerbRequest, CancelSpec, ConfirmReceipt, ConfirmSpec,
    DEFAULT_INTRO_DURATION_MIN, DepositRefundRule, DepositTerms, EmergencyActionPolicy,
    EmergencyPlan, EmergencyRescheduleRequest, EventTypeConfig, EventTypeKey, HoldLeaseSpec,
    HoldReceipt, HoldSpec, HostAvailabilityConfig, PublishBookingPageGrantRequest, RescheduleSpec,
    RoutingMode, SessionKey, SlotOracle, SolveRequest, SolveResult, VaultActiveHoldSource,
    WeeklyWallWindow, encode_event_type_claim_value, enqueue_booking_verb, execute_emergency_plan,
    mint_publish_page_invite_grant, plan_emergency_reschedule, run_booking_lifecycle_once,
};
use oneiron::calendar::CalendarError;
use oneiron::calendar::connectors::{CalendarConnectorError, RemoteWriteReceipt};
use oneiron::calendar::ingest::{
    IcsFeedFetcher, IcsFeedPollConfig, IcsFetchResponse, run_ics_feed_poll,
};
#[cfg(oneiron_test_support)]
use oneiron::calendar::outcome::{EventOutcome, read_event_outcome};
use oneiron::calendar::query::CalendarRangeDto;
use oneiron::channel_identity::{ChannelIdentityBinding, ChannelIdentityState, SelfHeldShape};
use oneiron::memory::EmergencyInstructionInput;
use oneiron::outbound::{
    OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink,
};
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::{
    CalendarSel, ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject,
    DreamerRunnerStore, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
};

/// Monday 2 March 2026, 00:00 UTC.
const MONDAY: u64 = 1_772_409_600;
const NOW: u64 = MONDAY + 8 * 3_600;

const PAGE_SEED: u8 = 0x51;
const BOOKER_SEED: u8 = 0x57;
const BUSY_SEED: u8 = 0x61;
const IDENTITY_SEED: u8 = 0x79;
const POLICY_SEED: u8 = 0x7a;

const fn at(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

/// `[seed; 16]`; every seed here is outside the production-pinned id bytes.
fn test_id(seed: u8) -> EntityId {
    common::entity(seed)
}

/// A slot of the intro call's length starting `hour` on the fixture Monday.
fn slot_at(hour: u64) -> TimeRange {
    let start = MONDAY + hour * 3_600;
    TimeRange {
        start,
        end: start + u64::from(DEFAULT_INTRO_DURATION_MIN) * 60,
    }
}

/// A visitor's own cancel this late would refund nothing.
fn terms() -> DepositTerms {
    DepositTerms {
        amount_minor: 4_000,
        currency: "usd".to_owned(),
        refund: DepositRefundRule {
            full_refund_notice_secs: 2 * 3_600,
            late_cancel_refund_percent: 0,
        },
    }
}

fn event_type() -> EventTypeKey {
    EventTypeKey("intro-call".to_owned())
}

fn fixture_config(host: EntityId) -> EventTypeConfig {
    EventTypeConfig {
        key: event_type(),
        duration_min: DEFAULT_INTRO_DURATION_MIN,
        allowed_durations_min: Vec::new(),
        slot_step_min: 30,
        pre_buffer_min: 0,
        post_buffer_min: 0,
        min_notice_secs: 0,
        booking_window_secs: 7 * 24 * 3_600,
        daily_cap: None,
        weekly_cap: None,
        deposit: Some(terms()),
        routing: RoutingMode::Either,
        hosts: vec![HostAvailabilityConfig {
            host_ref: host,
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
        // The host is the vault's embedded owner, the one owner a personal
        // vault has: the owner census refuses an owner act from any other
        // PERSON bound as human (main 34a0a330, rooted owner census).
        let host = vault.ensure_embedded_owner_actor().expect("host");
        let booker = test_id(BOOKER_SEED);
        vault
            .put_entity(&page, ENTITY_TYPE_ASSET, at(1), 1, b"booking page")
            .expect("put booking page");
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
        // only a PERSON's put stores, so the page's FACET is stored first.
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
        // The page's event type with its deposit: the confirm reads its
        // terms, and the emergency planner solves from it.
        let event_type_claim = ClaimBody::new(
            BOOKING_EVENT_TYPE_PREDICATE,
            ClaimSubject::Entity(page),
            encode_event_type_claim_value(&BookingEventTypeClaimValue {
                schema_version: BOOKING_EVENT_TYPE_SCHEMA_VERSION,
                page_ref: page,
                config: fixture_config(host),
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

    /// The calendars the emergency planner reads per host.
    fn calendars(&self) -> Vec<(EntityId, Vec<CalendarSel>)> {
        vec![(self.host, vec![CalendarSel { system: None }])]
    }

    fn state_of(&self, payment_id: &str) -> DepositState {
        booking_deposit_for_payment(&self.vault, payment_id)
            .expect("read the deposit")
            .expect("the deposit exists")
            .state
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
        let host = self.vault.ensure_embedded_owner_actor().expect("host");
        let calendars = vec![(host, vec![CalendarSel { system: None }])];
        BookingSolver {
            vault: self.vault,
            page_ref: self.page,
            calendars_by_host: &calendars,
            holds: &holds,
            now_utc: NOW,
            synthetic_config: Some(fixture_config(host)),
        }
        .solve(req)
    }
}

/// A provider that does every move it is asked.
struct AgreeingProvider;

impl DepositSettlementPort for AgreeingProvider {
    fn settle(
        &mut self,
        request: &DepositSettleRequest<'_>,
    ) -> Result<u64, DepositProviderFailure> {
        Ok(match request.movement {
            DepositSettleMove::Capture { amount_minor }
            | DepositSettleMove::Refund { amount_minor } => amount_minor,
            DepositSettleMove::Void => 0,
        })
    }
}

/// The host's own calendar, as its feed system names it.
const HOST_FEED_SYSTEM: &str = "host-calendar";

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
    let secs = ts - MONDAY;
    format!(
        "20260302T{:02}{:02}{:02}Z",
        secs / 3_600,
        secs / 60 % 60,
        secs % 60
    )
}

/// One poll of the host's feed with the booking at the slot starting
/// `start`, at `sequence`, cancelled or not.
fn poll_host_feed(
    fixture: &Fixture,
    booked: &ConfirmReceipt,
    start: u64,
    sequence: u32,
    cancelled: bool,
    etag: &str,
    now: u64,
) -> Result<(), CalendarError> {
    let mut body =
        String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//test//EN\r\n");
    body.push_str("BEGIN:VEVENT\r\n");
    body.push_str(&format!("UID:{}\r\n", booked.calendar.uid));
    body.push_str("DTSTAMP:20260302T070000Z\r\n");
    body.push_str(&format!("DTSTART:{}\r\n", ics_utc(start)));
    body.push_str(&format!(
        "DTEND:{}\r\n",
        ics_utc(start + u64::from(DEFAULT_INTRO_DURATION_MIN) * 60)
    ));
    body.push_str(&format!("SEQUENCE:{sequence}\r\n"));
    body.push_str("SUMMARY:intro-call\r\n");
    if cancelled {
        body.push_str("STATUS:CANCELLED\r\n");
    }
    body.push_str("END:VEVENT\r\nEND:VCALENDAR\r\n");
    let fetcher = ScriptedFeed(Mutex::new(Some(IcsFetchResponse::Complete {
        etag: Some(etag.to_owned()),
        body: body.into_bytes(),
    })));
    let config = IcsFeedPollConfig {
        secret_ref: format!("ics-feed:{HOST_FEED_SYSTEM}"),
        system: HOST_FEED_SYSTEM.to_owned(),
        cadence_min_seconds: 300,
        cadence_max_seconds: 900,
    };
    run_ics_feed_poll(&fixture.vault, &fetcher, &config, now, 7).map(|_| ())
}

/// The host's own calendar, as its seat system names it: the calendar each
/// cancelled booking below is written to before its first pull.
const HOST_SEAT_SYSTEM: &str = "host-seat";

/// One pull of a seat with the booking at the slot starting `start` and at
/// `sequence`, cancelled or not. The booking was written to the seat before
/// its first pull, so the resource rides the href its write returned.
fn pull_seat(
    seat: &Seat,
    fixture: &Fixture,
    wrote: &RemoteWriteReceipt,
    start: u64,
    sequence: u32,
    cancelled: bool,
    now: u64,
) -> Result<(), CalendarConnectorError> {
    let end = start + u64::from(DEFAULT_INTRO_DURATION_MIN) * 60;
    seat.pull(
        &fixture.vault,
        &[SeatChange::upsert(wrote, start, end, sequence, cancelled)],
        now,
    )
    .map(|_| ())
}

/// A calendar the visitor can write (their own calendar the owner
/// subscribes to, a shared one), as its seat system names it.
const VISITOR_SEAT_SYSTEM: &str = "visitor-seat";

/// `seat` reads the booking live at its slot starting `start`, under that
/// seat's own resource path for the UID: a calendar that already holds the
/// booking, or one it was never written to.
fn read_booking_on_seat(
    seat: &Seat,
    fixture: &Fixture,
    booked: &ConfirmReceipt,
    start: u64,
    now: u64,
) {
    let end = start + u64::from(DEFAULT_INTRO_DURATION_MIN) * 60;
    seat.pull(
        &fixture.vault,
        &[SeatChange::foreign(
            seat,
            &booked.calendar.uid,
            start,
            end,
            0,
            false,
        )],
        now,
    )
    .expect("the seat reads the booking");
}

/// The host's seat reads the booking at its slot starting `start`, and
/// Oneiron then writes the booking there: the seat's passport for the UID is
/// TwoWay, so the seat's own tombstone marks it absent and cancels the
/// booking.
fn host_seat_reading_and_written(
    fixture: &Fixture,
    booked: &ConfirmReceipt,
    start: u64,
    now: u64,
) -> Seat {
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    read_booking_on_seat(&seat, fixture, booked, start, now);
    seat.write(&fixture.vault, booked.calendar.event_ref, now + 1);
    seat
}

/// `seat`'s provider reports the booking's resource deleted: its tombstone
/// lands at `now`.
fn seat_tombstone(
    seat: &Seat,
    fixture: &Fixture,
    booked: &ConfirmReceipt,
    now: u64,
) -> Result<(), CalendarConnectorError> {
    seat.pull(
        &fixture.vault,
        &[SeatChange::tombstone(&booked.calendar.uid)],
        now,
    )
    .map(|_| ())
}

/// A sink whose every delivery lands.
struct DeliveringSink;

impl OutboundExecutionSink for DeliveringSink {
    fn execute(&mut self, _request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        OutboundExecutionOutcome::delivered_to_channel("provider:message:fixture")
    }
}

/// Checkout, a hold on its lease, the provider's authorization, confirm, for
/// the slot that starts at `hour` UTC on the fixture Monday. The deposit is
/// then due for capture.
fn paid_booking(
    fixture: &Fixture,
    session: SessionKey,
    payment_id: &str,
    hour: u64,
) -> ConfirmReceipt {
    let lease = begin_deposit_checkout(
        &fixture.vault,
        &DepositCheckoutStart {
            page_ref: fixture.page,
            event_type: event_type(),
            session_key: session,
            terms: terms(),
            payment_id: payment_id.to_owned(),
        },
        NOW,
    )
    .expect("checkout");
    let hold: HoldReceipt = match fixture
        .run(
            BookingVerbRequest::Hold(HoldSpec {
                page_ref: fixture.page,
                event_type: event_type(),
                slot: slot_at(hour),
                session_key: session,
                visitor_tz: "UTC".to_owned(),
                constraint: None,
                lease: HoldLeaseSpec::CheckoutExtension {
                    server_issued_lease: lease.lease.clone(),
                },
                idempotency_key: None,
                cap_override: None,
            }),
            NOW,
        )
        .expect("hold on the checkout lease")
    {
        BookingVerbReceipt::Held(hold) => hold,
        other => panic!("expected a hold receipt, got {other:?}"),
    };
    assert_eq!(
        record_deposit_provider_event(
            &fixture.vault,
            &DepositProviderEvent {
                event_id: format!("evt-auth-{payment_id}"),
                payment_id: payment_id.to_owned(),
                kind: DepositProviderEventKind::Authorized {
                    amount_minor: terms().amount_minor,
                    currency: terms().currency,
                },
            },
            NOW + 30,
        )
        .expect("record the provider event"),
        DepositProviderEventOutcome::Applied(DepositState::Authorized)
    );
    match fixture
        .run(
            BookingVerbRequest::Confirm(ConfirmSpec {
                hold_token: hold.token.clone(),
                session_key: session,
                booker_contact: fixture.booker,
                intake: Vec::new(),
                idempotency_key: None,
            }),
            NOW + 40,
        )
        .expect("confirm on the authorized deposit")
    {
        BookingVerbReceipt::Confirmed(confirmed) => confirmed,
        other => panic!("expected a confirm receipt, got {other:?}"),
    }
}

/// A paid booking at `hour` whose deposit the provider captured.
fn captured_booking(fixture: &Fixture, payment_id: &str, hour: u64) -> ConfirmReceipt {
    let booked = paid_booking(
        fixture,
        SessionKey::derive(payment_id.as_bytes()),
        payment_id,
        hour,
    );
    settle_booking_deposit(
        &fixture.vault,
        &booked.calendar.event_ref,
        &mut AgreeingProvider,
        NOW + 50,
    )
    .expect("capture");
    assert_eq!(
        fixture.state_of(payment_id),
        DepositState::Captured {
            amount_minor: 4_000
        }
    );
    booked
}

/// The visitor moves the booking to the slot starting at `hour`.
fn reschedule(fixture: &Fixture, booked: &ConfirmReceipt, hour: u64, now: u64) {
    match fixture
        .run(
            BookingVerbRequest::Reschedule(RescheduleSpec {
                token: booked.reschedule_token.clone(),
                new_slot: slot_at(hour),
                visitor_tz: "UTC".to_owned(),
                constraint: None,
                idempotency_key: None,
            }),
            now,
        )
        .expect("the visitor's reschedule")
    {
        BookingVerbReceipt::Rescheduled(_) => {}
        other => panic!("expected a reschedule receipt, got {other:?}"),
    }
}

/// The visitor cancels the booking.
fn cancel(fixture: &Fixture, booked: &ConfirmReceipt, now: u64) {
    match fixture
        .run(
            BookingVerbRequest::Cancel(CancelSpec {
                token: booked.cancel_token.clone(),
                idempotency_key: None,
            }),
            now,
        )
        .expect("the visitor's cancel")
    {
        BookingVerbReceipt::Cancelled(_) => {}
        other => panic!("expected a cancel receipt, got {other:?}"),
    }
}

/// The owner's delivery seat, policy and page grant, as the crate's own
/// emergency fixture installs them (`tests/booking_feed_move_held.rs`).
fn install_owner_delivery(fixture: &Fixture) {
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
        "schema_version": "1.2", "pack_id": "deposit-emergency-cancel-tests", "pack_version": "v1",
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
    // built-in pack is installed and checked (OF-519); the pack is not what
    // this test covers.
    oneiron::test_doors::builtin_pack_seed::remove_builtin_pack_seed_marker(&fixture.vault)
        .expect("remove the built-in pack seed marker");
}

#[test]
fn an_owner_emergency_cancel_gives_the_whole_deposit_back() {
    let fixture = Fixture::open();
    let captured = paid_booking(
        &fixture,
        SessionKey::derive(b"emergency-captured"),
        "pi_captured",
        9,
    );
    let due = paid_booking(&fixture, SessionKey::derive(b"emergency-due"), "pi_due", 10);
    settle_booking_deposit(
        &fixture.vault,
        &captured.calendar.event_ref,
        &mut AgreeingProvider,
        NOW + 50,
    )
    .expect("capture the 09:00 deposit");
    assert_eq!(
        fixture.state_of("pi_captured"),
        DepositState::Captured {
            amount_minor: 4_000
        }
    );
    assert_eq!(
        fixture.state_of("pi_due"),
        DepositState::CaptureDue {
            amount_minor: 4_000
        },
        "the 10:00 deposit's capture has not run yet"
    );

    // The owner cancels both bookings in an emergency, an hour before the
    // first: a visitor's own cancel this late would refund nothing.
    install_owner_delivery(&fixture);
    let window = TimeRange {
        start: slot_at(9).start,
        end: slot_at(10).end - 1,
    };
    let memory = fixture.vault.memory(fixture.host, EdgeActorClass::Human);
    let authority = memory
        .record_emergency_instruction(&EmergencyInstructionInput {
            affected_window: CalendarRangeDto {
                start: window.start,
                end: window.end,
            },
            reason: "unavailable".to_owned(),
            action_policy: EmergencyActionPolicy::Cancel,
            recorded_at: NOW + 90,
        })
        .expect("the owner logs the emergency instruction");
    let request = EmergencyRescheduleRequest {
        owner_ref: fixture.host,
        affected_window: window,
        reason: "unavailable".to_owned(),
        action_policy: EmergencyActionPolicy::Cancel,
        authority,
    };
    let batch = plan_emergency_reschedule(&fixture.vault, &request, &fixture.calendars(), NOW + 90)
        .expect("plan the emergency");
    assert!(batch.refusals.is_empty(), "{:?}", batch.refusals);
    let plans: Vec<EmergencyPlan> = batch.plans;
    assert_eq!(plans.len(), 2, "one plan per booking in the window");
    for plan in &plans {
        let event = plan.booking().calendar.event_ref;
        assert!(
            event == captured.calendar.event_ref || event == due.calendar.event_ref,
            "the plans name the two bookings"
        );
        let item = execute_emergency_plan(
            &fixture.vault,
            &request,
            plan,
            &fixture.calendars(),
            &fixture.consumer(NOW + 90),
            &mut DeliveringSink,
        )
        .expect("the owner's emergency cancel commits");
        assert!(item.calendar_delivered && item.apology_delivered);
    }

    assert_eq!(
        fixture.state_of("pi_captured"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "the owner's cancel owes the whole captured deposit back"
    );
    assert_eq!(
        fixture.state_of("pi_due"),
        DepositState::VoidDue,
        "the owner's cancel releases a deposit still to capture"
    );

    let pass = run_booking_deposit_settlement(
        &fixture.vault,
        "deposit-settle-worker",
        &mut AgreeingProvider,
        16,
        NOW + 100,
    )
    .expect("drain the settle rows");
    assert_eq!(pass.failed, 0);
    assert_eq!(
        fixture.state_of("pi_captured"),
        DepositState::Refunded {
            amount_minor: 4_000
        }
    );
    assert_eq!(
        fixture.state_of("pi_due"),
        DepositState::Voided,
        "the due capture is never taken"
    );
}

#[test]
fn a_late_visitor_reschedule_keeps_the_late_refund() {
    let fixture = Fixture::open();
    // One hour before the 09:00 booking (inside the two hours' notice), the
    // visitor moves it to 13:00, then cancels with five hours' notice of the
    // new slot: the move kept only the late refund, nothing.
    let booked = captured_booking(&fixture, "pi_late_move", 9);
    reschedule(&fixture, &booked, 13, NOW + 60);
    cancel(&fixture, &booked, NOW + 120);
    assert_eq!(
        fixture.state_of("pi_late_move"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a late move then a cancel refunds what a late cancel would"
    );
}

#[test]
fn a_visitor_reschedule_with_full_notice_keeps_the_full_refund() {
    let fixture = Fixture::open();
    // Three hours before the 11:00 booking, the visitor moves it to 13:00,
    // then cancels with full notice of the new slot.
    let booked = captured_booking(&fixture, "pi_early_move", 11);
    reschedule(&fixture, &booked, 13, NOW + 60);
    cancel(&fixture, &booked, NOW + 120);
    assert_eq!(
        fixture.state_of("pi_early_move"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "a move with full notice keeps the full refund"
    );
}

#[test]
fn a_host_move_sets_no_refund_cap() {
    let fixture = Fixture::open();
    // The host moves the 09:00 booking to 13:00 in their own calendar an
    // hour before it; the visitor then cancels with full notice of 13:00.
    let booked = captured_booking(&fixture, "pi_host_move", 9);
    poll_host_feed(
        &fixture,
        &booked,
        slot_at(9).start,
        0,
        false,
        "v1",
        NOW + 60,
    )
    .expect("the first host feed poll");
    poll_host_feed(
        &fixture,
        &booked,
        slot_at(13).start,
        1,
        false,
        "v2",
        NOW + 90,
    )
    .expect("the host's move");
    cancel(&fixture, &booked, NOW + 120);
    assert_eq!(
        fixture.state_of("pi_host_move"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "a host move caps nothing: the cancel measures against the slot the host chose"
    );
}

#[test]
fn a_host_cancel_seen_after_the_start_keeps_the_deposit() {
    let fixture = Fixture::open();
    // The 09:00 meeting happened (or the visitor did not show); at 09:01 the
    // host deletes it from their calendar.
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let booked = captured_booking(&fixture, "pi_after_start", 9);
    let wrote = seat.write(&fixture.vault, booked.calendar.event_ref, NOW + 55);
    pull_seat(
        &seat,
        &fixture,
        &wrote,
        slot_at(9).start,
        0,
        false,
        NOW + 60,
    )
    .expect("the seat's first pull");
    pull_seat(
        &seat,
        &fixture,
        &wrote,
        slot_at(9).start,
        1,
        true,
        slot_at(9).start + 60,
    )
    .expect("the host's cancellation after the start");
    assert_eq!(
        fixture.state_of("pi_after_start"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a cancellation seen after the start moves no money"
    );
}

/// The host's seat carries the booking live at SEQUENCE 5; a stale pull then
/// replays an older SEQUENCE 3 that reads cancelled. The passport keeps
/// SEQUENCE 5 (an older replay changes nothing), so the booking stays live
/// and its deposit stays captured (Muse Wonder blind review of #8230, F2,
/// 16 Nov 08:10).
#[test]
fn an_older_sequence_cancellation_replayed_after_a_live_one_keeps_the_deposit() {
    let fixture = Fixture::open();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let booked = captured_booking(&fixture, "pi_stale_replay", 9);
    let wrote = seat.write(&fixture.vault, booked.calendar.event_ref, NOW + 55);
    pull_seat(
        &seat,
        &fixture,
        &wrote,
        slot_at(9).start,
        5,
        false,
        NOW + 60,
    )
    .expect("the host seat at SEQUENCE 5, live");
    pull_seat(
        &seat,
        &fixture,
        &wrote,
        slot_at(9).start,
        3,
        true,
        NOW + 120,
    )
    .expect("a stale pull at SEQUENCE 3, cancelled");
    assert_eq!(
        fixture.state_of("pi_stale_replay"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "an older SEQUENCE replay moves no money while the passport's own version is live"
    );
}

#[cfg(oneiron_test_support)]
#[test]
fn a_host_cancel_seen_before_the_start_and_repaired_after_it_refunds() {
    let fixture = Fixture::open();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let booked = captured_booking(&fixture, "pi_repaired", 9);
    let wrote = seat.write(&fixture.vault, booked.calendar.event_ref, NOW + 55);
    pull_seat(
        &seat,
        &fixture,
        &wrote,
        slot_at(9).start,
        0,
        false,
        NOW + 60,
    )
    .expect("the seat's first pull");
    // The cancellation's passport commits at 08:02, and the pull stops
    // before its refund does.
    oneiron::test_doors::host_cancel_refund::stop_before_next_host_cancel_refund();
    assert!(
        pull_seat(
            &seat,
            &fixture,
            &wrote,
            slot_at(9).start,
            1,
            true,
            NOW + 120
        )
        .is_err(),
        "the door stops the pull"
    );
    assert_eq!(
        fixture.state_of("pi_repaired"),
        DepositState::Captured {
            amount_minor: 4_000
        }
    );
    // The next read of the same seat comes after the start.
    pull_seat(
        &seat,
        &fixture,
        &wrote,
        slot_at(9).start,
        1,
        true,
        slot_at(9).start + 60,
    )
    .expect("the repair pull");
    assert_eq!(
        fixture.state_of("pi_repaired"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "a cancellation first seen before the start keeps its full refund"
    );
}

#[test]
fn a_tombstone_seen_after_the_start_keeps_the_deposit() {
    let fixture = Fixture::open();
    let booked = captured_booking(&fixture, "pi_tombstone_late", 9);
    let seat = host_seat_reading_and_written(&fixture, &booked, slot_at(9).start, NOW + 54);
    // At 09:01 the host's provider reports the event deleted.
    seat_tombstone(&seat, &fixture, &booked, slot_at(9).start + 60)
        .expect("the tombstone after the start");
    assert_eq!(
        fixture.state_of("pi_tombstone_late"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a tombstone seen after the start moves no money"
    );
}

#[cfg(oneiron_test_support)]
#[test]
fn a_tombstone_stopped_before_its_refund_and_sent_again_after_the_start_refunds() {
    let fixture = Fixture::open();
    let booked = captured_booking(&fixture, "pi_tombstone_resent", 9);
    let seat = host_seat_reading_and_written(&fixture, &booked, slot_at(9).start, NOW + 54);
    // The tombstone's sweep marks the seat's passport absent at 08:02, and
    // the pull stops before the refund commits.
    oneiron::test_doors::host_cancel_refund::stop_before_next_host_cancel_refund();
    assert!(
        seat_tombstone(&seat, &fixture, &booked, NOW + 120).is_err(),
        "the door stops the pull"
    );
    assert_eq!(
        fixture.state_of("pi_tombstone_resent"),
        DepositState::Captured {
            amount_minor: 4_000
        }
    );
    // The provider sends the same tombstone again after the start.
    seat_tombstone(&seat, &fixture, &booked, slot_at(9).start + 60)
        .expect("the tombstone sent again");
    assert_eq!(
        fixture.state_of("pi_tombstone_resent"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "a tombstone first seen before the start keeps its full refund"
    );
}

/// Review round 1 of #9255: an omission is no cancellation evidence, so it
/// never dates the host's tombstone. The seat's complete listing leaves the
/// booking out before the start; the provider's tombstone after the start,
/// and the same tombstone sent again, keep the deposit.
#[test]
fn a_tombstone_sent_again_after_an_omission_before_the_start_keeps_the_deposit() {
    let fixture = Fixture::open();
    let booked = captured_booking(&fixture, "pi_tombstone_after_omission", 9);
    let seat = host_seat_reading_and_written(&fixture, &booked, slot_at(9).start, NOW + 54);
    // At 08:01 the seat's complete listing leaves the booking out.
    seat.pull(
        &fixture.vault,
        &[SeatChange::omitted(&booked.calendar.uid)],
        NOW + 60,
    )
    .expect("the omission before the start");
    // At 09:01 the host's provider reports the event deleted, and at 09:02 it
    // sends the same tombstone again.
    seat_tombstone(&seat, &fixture, &booked, slot_at(9).start + 60)
        .expect("the tombstone after the start");
    seat_tombstone(&seat, &fixture, &booked, slot_at(9).start + 120)
        .expect("the tombstone sent again");
    assert_eq!(
        fixture.state_of("pi_tombstone_after_omission"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "an omission before the start never dates the host's tombstone"
    );
}

/// Review round 2 of #9255: the host's tombstone of a passport its own
/// omission already flipped is still the cancellation first seen then. The
/// visitor's calendar keeps the booking live, so neither the host's omission
/// nor its tombstone before the start concludes the cancellation. The
/// visitor calendar's omission concludes it, and the host's tombstone on
/// record then refunds from its first arrival (review round 1 of #9472); the
/// same tombstone sent again after the start keeps that refund.
#[test]
fn a_tombstone_of_a_passport_its_omission_flipped_dates_the_host_cancel() {
    let fixture = Fixture::open();
    let booked = captured_booking(&fixture, "pi_tombstone_after_own_omission", 9);
    let host = host_seat_reading_and_written(&fixture, &booked, slot_at(9).start, NOW + 54);
    let visitor = Seat::install(&fixture.vault, VISITOR_SEAT_SYSTEM);
    read_booking_on_seat(&visitor, &fixture, &booked, slot_at(9).start, NOW + 56);
    // At 08:01 the host seat's complete listing leaves the booking out, and
    // at 08:02 its provider reports it deleted.
    host.pull(
        &fixture.vault,
        &[SeatChange::omitted(&booked.calendar.uid)],
        NOW + 60,
    )
    .expect("the host seat's omission");
    seat_tombstone(&host, &fixture, &booked, NOW + 120).expect("the host's tombstone");
    assert_eq!(
        fixture.state_of("pi_tombstone_after_own_omission"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "the visitor's calendar still shows the booking"
    );
    // At 08:03 the visitor's calendar leaves it out too: the booking reads
    // cancelled, and the host's tombstone of 08:02 settles the deposit.
    visitor
        .pull(
            &fixture.vault,
            &[SeatChange::omitted(&booked.calendar.uid)],
            NOW + 180,
        )
        .expect("the visitor calendar's omission");
    assert_eq!(
        fixture.state_of("pi_tombstone_after_own_omission"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "the host's tombstone on record refunds once the cancellation concludes"
    );
    // At 09:01 the host's provider sends the same tombstone again.
    seat_tombstone(&host, &fixture, &booked, slot_at(9).start + 60)
        .expect("the host's tombstone sent again");
    assert_eq!(
        fixture.state_of("pi_tombstone_after_own_omission"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "a host tombstone first seen before the start keeps its full refund"
    );
}

#[test]
fn a_tombstone_in_another_calendar_before_the_start_does_not_date_the_host_tombstone() {
    let fixture = Fixture::open();
    let booked = captured_booking(&fixture, "pi_visitor_first", 9);
    let host = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    host.write(&fixture.vault, booked.calendar.event_ref, NOW + 55);
    // The visitor's calendar shows the booking, and at 08:02 its provider
    // reports it deleted: the booking reads cancelled, the deposit stands.
    let visitor = Seat::install(&fixture.vault, VISITOR_SEAT_SYSTEM);
    read_booking_on_seat(&visitor, &fixture, &booked, slot_at(9).start, NOW + 60);
    seat_tombstone(&visitor, &fixture, &booked, NOW + 120)
        .expect("the visitor calendar's tombstone");
    assert_eq!(
        fixture.state_of("pi_visitor_first"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a tombstone from a calendar the booking was not written to moves no money"
    );
    // At 09:01 the host deletes it from the calendar it was written to.
    seat_tombstone(&host, &fixture, &booked, slot_at(9).start + 60)
        .expect("the host's tombstone after the start");
    assert_eq!(
        fixture.state_of("pi_visitor_first"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "the host's cancel is seen when its own calendar reports it, after the start"
    );
}

/// Review round 2 of #8230: a newer SEQUENCE of a cancellation whose first
/// sighting stopped before its refund is still the cancellation first seen
/// then. The host's calendar, one the booking was written to (RULING
/// DEPOSIT-HOST-CANCEL-SOURCE = A), sends it again, re-versioned, after the
/// booking's start: the refund is dated by the first sighting the passport
/// carries, and a later read of that same version keeps it.
#[cfg(oneiron_test_support)]
#[test]
fn a_host_cancel_resent_as_a_newer_version_after_the_start_keeps_its_first_sighting() {
    let fixture = Fixture::open();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let booked = captured_booking(&fixture, "pi_resent", 9);
    let wrote = seat.write(&fixture.vault, booked.calendar.event_ref, NOW + 55);
    pull_seat(
        &seat,
        &fixture,
        &wrote,
        slot_at(9).start,
        0,
        false,
        NOW + 60,
    )
    .expect("the seat's first pull");
    // The cancellation's passport commits at 08:02, and the pull stops
    // before its refund does.
    oneiron::test_doors::host_cancel_refund::stop_before_next_host_cancel_refund();
    assert!(
        pull_seat(
            &seat,
            &fixture,
            &wrote,
            slot_at(9).start,
            1,
            true,
            NOW + 120
        )
        .is_err(),
        "the door stops the pull"
    );
    // After the start the host's calendar carries the cancellation as
    // SEQUENCE 2.
    pull_seat(
        &seat,
        &fixture,
        &wrote,
        slot_at(9).start,
        2,
        true,
        slot_at(9).start + 60,
    )
    .expect("the newer version's pull");
    assert_eq!(
        fixture.state_of("pi_resent"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "a cancellation first seen before the start keeps its full refund across versions"
    );
    pull_seat(
        &seat,
        &fixture,
        &wrote,
        slot_at(9).start,
        2,
        true,
        slot_at(9).start + 120,
    )
    .expect("a later read of the same version");
    assert_eq!(
        fixture.state_of("pi_resent"),
        DepositState::RefundDue {
            amount_minor: 4_000
        }
    );
}

/// Review round 2 of #9233: a cancellation that names no DTSTART leaves the
/// booking's EVENT at its booked slot, so the host's cancel before the start
/// refunds in full.
#[test]
fn a_host_cancel_naming_no_start_refunds_against_the_booked_start() {
    let fixture = Fixture::open();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let booked = captured_booking(&fixture, "pi_undated_cancel", 9);
    let wrote = seat.write(&fixture.vault, booked.calendar.event_ref, NOW + 55);
    pull_seat(
        &seat,
        &fixture,
        &wrote,
        slot_at(9).start,
        0,
        false,
        NOW + 60,
    )
    .expect("the seat's first pull");
    // At 08:02 the host's calendar carries the cancellation as SEQUENCE 1,
    // with no DTSTART or DTEND.
    seat.pull(
        &fixture.vault,
        &[SeatChange::undated_cancel(&wrote, 1)],
        NOW + 120,
    )
    .expect("the cancellation's pull");
    assert_eq!(
        fixture.state_of("pi_undated_cancel"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "a host cancel before the start refunds whatever times it names"
    );
}

/// FIX BK-DEPOSIT-CANCELLED-ELSEWHERE-FEED-REWRITES-BOOKED-SLOT: a calendar
/// the booking was never written to cancels it, which moves no money (RULING
/// DEPOSIT-HOST-CANCEL-SOURCE = A). The host's calendar then carries the
/// booking live with no DTSTART or DTEND, and its EVENT keeps the booked
/// slot, so the host's cancel from that calendar before the start refunds in
/// full.
#[test]
fn a_host_cancel_after_another_calendar_cancelled_refunds_against_the_booked_start() {
    let fixture = Fixture::open();
    let host = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let booked = captured_booking(&fixture, "pi_cancelled_elsewhere", 9);
    let event = booked.calendar.event_ref;
    let booked_slot = slot_at(9);
    let wrote = host.write(&fixture.vault, event, NOW + 55);
    pull_seat(
        &host,
        &fixture,
        &wrote,
        booked_slot.start,
        0,
        false,
        NOW + 60,
    )
    .expect("the host seat's first pull");
    // The visitor's calendar shows the booking, and at 08:02 carries it
    // cancelled as SEQUENCE 1.
    let visitor = Seat::install(&fixture.vault, VISITOR_SEAT_SYSTEM);
    read_booking_on_seat(&visitor, &fixture, &booked, booked_slot.start, NOW + 90);
    visitor
        .pull(
            &fixture.vault,
            &[SeatChange::foreign(
                &visitor,
                &booked.calendar.uid,
                booked_slot.start,
                booked_slot.end,
                1,
                true,
            )],
            NOW + 120,
        )
        .expect("the visitor calendar's cancellation");
    assert_eq!(
        fixture.state_of("pi_cancelled_elsewhere"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a cancellation from a calendar the booking was not written to moves no money"
    );
    // At 08:03 the host's calendar carries the booking live as SEQUENCE 1,
    // with no DTSTART or DTEND.
    host.pull(
        &fixture.vault,
        &[SeatChange::undated_live(&wrote, 1)],
        NOW + 180,
    )
    .expect("the undated version's pull");
    assert_eq!(
        fixture
            .vault
            .get_occurred(&event)
            .expect("booking occurrence")
            .start,
        booked_slot.start,
        "the cancelled booking's EVENT keeps its booked start"
    );
    // At 08:04 the host cancels it in that calendar, before the 09:00 start.
    pull_seat(
        &host,
        &fixture,
        &wrote,
        booked_slot.start,
        2,
        true,
        NOW + 240,
    )
    .expect("the host's cancellation");
    assert_eq!(
        fixture.state_of("pi_cancelled_elsewhere"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "the host's cancel before the booked start refunds in full"
    );
}

/// Review round 2 of #9233: the repair of a stopped refund reads the same
/// booked start. The undated cancellation's passport commits at 08:02 and
/// the pull stops before its refund; the same version read after the start
/// refunds from that first sighting.
#[cfg(oneiron_test_support)]
#[test]
fn a_host_cancel_naming_no_start_repaired_after_the_start_refunds() {
    let fixture = Fixture::open();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let booked = captured_booking(&fixture, "pi_undated_repaired", 9);
    let wrote = seat.write(&fixture.vault, booked.calendar.event_ref, NOW + 55);
    pull_seat(
        &seat,
        &fixture,
        &wrote,
        slot_at(9).start,
        0,
        false,
        NOW + 60,
    )
    .expect("the seat's first pull");
    oneiron::test_doors::host_cancel_refund::stop_before_next_host_cancel_refund();
    assert!(
        seat.pull(
            &fixture.vault,
            &[SeatChange::undated_cancel(&wrote, 1)],
            NOW + 120,
        )
        .is_err(),
        "the door stops the pull"
    );
    assert_eq!(
        fixture.state_of("pi_undated_repaired"),
        DepositState::Captured {
            amount_minor: 4_000
        }
    );
    seat.pull(
        &fixture.vault,
        &[SeatChange::undated_cancel(&wrote, 1)],
        slot_at(9).start + 60,
    )
    .expect("the repair pull");
    assert_eq!(
        fixture.state_of("pi_undated_repaired"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "a cancellation first seen before the start keeps its full refund"
    );
}

/// Review round 1 of #9472: the repair of a stopped host cancel also records
/// the cancellation. The undated cancellation's passport commits at 08:02
/// and the pull stops before its refund, its `calendar.status` and its CAL-07
/// evidence; the same version read after the start writes all three, and
/// CAL-07 dates the cancellation by that first sighting.
#[cfg(oneiron_test_support)]
#[test]
fn a_host_cancel_repaired_after_the_start_records_its_cancellation_before_the_start() {
    let fixture = Fixture::open();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let booked = captured_booking(&fixture, "pi_repaired_status", 9);
    let wrote = seat.write(&fixture.vault, booked.calendar.event_ref, NOW + 55);
    pull_seat(
        &seat,
        &fixture,
        &wrote,
        slot_at(9).start,
        0,
        false,
        NOW + 60,
    )
    .expect("the seat's first pull");
    oneiron::test_doors::host_cancel_refund::stop_before_next_host_cancel_refund();
    assert!(
        seat.pull(
            &fixture.vault,
            &[SeatChange::undated_cancel(&wrote, 1)],
            NOW + 120,
        )
        .is_err(),
        "the door stops the pull"
    );
    seat.pull(
        &fixture.vault,
        &[SeatChange::undated_cancel(&wrote, 1)],
        slot_at(9).start + 60,
    )
    .expect("the repair pull");
    assert_eq!(
        fixture.state_of("pi_repaired_status"),
        DepositState::RefundDue {
            amount_minor: 4_000
        }
    );
    let outcome = read_event_outcome(&fixture.vault, booked.calendar.event_ref)
        .expect("read the CAL-07 outcome")
        .expect("the repair records the cancellation's CAL-07 outcome");
    assert_eq!(outcome.outcome, EventOutcome::CancelledPreStart);
    assert_eq!(
        outcome.recorded_at,
        NOW + 120,
        "CAL-07 dates the cancellation by its first sighting"
    );
}

/// Review round 1 of #9472: a calendar that holds the booking only through
/// Oneiron's write (an Outbound passport, which is no absence vote) still
/// dates its tombstone. The visitor's calendar has already left the booking
/// out; the host's tombstone at 08:02 stops before its refund, and the same
/// tombstone sent again after the start refunds from its first arrival.
#[cfg(oneiron_test_support)]
#[test]
fn a_tombstone_of_a_calendar_only_written_to_sent_again_after_the_start_refunds() {
    let fixture = Fixture::open();
    let booked = captured_booking(&fixture, "pi_outbound_tombstone", 9);
    let host = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    host.write(&fixture.vault, booked.calendar.event_ref, NOW + 55);
    let visitor = Seat::install(&fixture.vault, VISITOR_SEAT_SYSTEM);
    read_booking_on_seat(&visitor, &fixture, &booked, slot_at(9).start, NOW + 56);
    visitor
        .pull(
            &fixture.vault,
            &[SeatChange::omitted(&booked.calendar.uid)],
            NOW + 60,
        )
        .expect("the visitor calendar's omission");
    oneiron::test_doors::host_cancel_refund::stop_before_next_host_cancel_refund();
    assert!(
        seat_tombstone(&host, &fixture, &booked, NOW + 120).is_err(),
        "the door stops the pull"
    );
    assert_eq!(
        fixture.state_of("pi_outbound_tombstone"),
        DepositState::Captured {
            amount_minor: 4_000
        }
    );
    seat_tombstone(&host, &fixture, &booked, slot_at(9).start + 60)
        .expect("the tombstone sent again");
    assert_eq!(
        fixture.state_of("pi_outbound_tombstone"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "a tombstone first seen before the start keeps its full refund"
    );
}

/// Review round 1 of #9472: the host's tombstone before the start waits on
/// the visitor's calendar, which still shows the booking; when that calendar
/// leaves the booking out, the cancellation concludes and the tombstone on
/// record refunds, with no second tombstone.
#[test]
fn a_host_tombstone_on_record_refunds_when_another_calendar_concludes_the_cancel() {
    let fixture = Fixture::open();
    let booked = captured_booking(&fixture, "pi_tombstone_then_omission", 9);
    let host = host_seat_reading_and_written(&fixture, &booked, slot_at(9).start, NOW + 54);
    let visitor = Seat::install(&fixture.vault, VISITOR_SEAT_SYSTEM);
    read_booking_on_seat(&visitor, &fixture, &booked, slot_at(9).start, NOW + 56);
    seat_tombstone(&host, &fixture, &booked, NOW + 120).expect("the host's tombstone");
    assert_eq!(
        fixture.state_of("pi_tombstone_then_omission"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "the visitor's calendar still shows the booking"
    );
    visitor
        .pull(
            &fixture.vault,
            &[SeatChange::omitted(&booked.calendar.uid)],
            NOW + 180,
        )
        .expect("the visitor calendar's omission");
    assert_eq!(
        fixture.state_of("pi_tombstone_then_omission"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "the host's tombstone on record refunds once the cancellation concludes"
    );
}

/// Review round 2 of #9472: a host who shows the booking again takes back
/// their tombstone. The booking was written to the host's calendar (an
/// Outbound passport, which is no absence vote) and the visitor's calendar
/// shows it. At 08:02 the host's provider reports it deleted, and at 08:03
/// the host's calendar returns the written booking unchanged. At 09:01 the
/// visitor's calendar leaves it out: the booking reads cancelled by that
/// omission alone, which moves no money.
#[test]
fn a_host_tombstone_the_host_took_back_moves_no_money_when_another_calendar_concludes() {
    let fixture = Fixture::open();
    let booked = captured_booking(&fixture, "pi_tombstone_taken_back", 9);
    let host = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let wrote = host.write(&fixture.vault, booked.calendar.event_ref, NOW + 55);
    let visitor = Seat::install(&fixture.vault, VISITOR_SEAT_SYSTEM);
    read_booking_on_seat(&visitor, &fixture, &booked, slot_at(9).start, NOW + 56);
    seat_tombstone(&host, &fixture, &booked, NOW + 120).expect("the host's tombstone");
    host.pull_own_write(&fixture.vault, &wrote, NOW + 180)
        .expect("the host's calendar shows the booking again");
    visitor
        .pull(
            &fixture.vault,
            &[SeatChange::omitted(&booked.calendar.uid)],
            slot_at(9).start + 60,
        )
        .expect("the visitor calendar's omission");
    assert_eq!(
        fixture.state_of("pi_tombstone_taken_back"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a tombstone the host took back dates no host cancel"
    );
}

/// Review round 2 of #9472: a cancellation's CAL-07 evidence survives a stop
/// after its status. The host's cancellation at 08:02 commits its passport,
/// refund and status, and the pull stops before its CAL-07 outcome; the next
/// read of the same version records the outcome, dated 08:02.
#[cfg(oneiron_test_support)]
#[test]
fn a_host_cancel_stopped_before_its_outcome_records_it_on_the_next_read() {
    let fixture = Fixture::open();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let booked = captured_booking(&fixture, "pi_cancel_outcome_stop", 9);
    let wrote = seat.write(&fixture.vault, booked.calendar.event_ref, NOW + 55);
    pull_seat(
        &seat,
        &fixture,
        &wrote,
        slot_at(9).start,
        0,
        false,
        NOW + 60,
    )
    .expect("the seat's first pull");
    oneiron::test_doors::host_cancel_refund::stop_before_next_cancel_outcome();
    assert!(
        pull_seat(
            &seat,
            &fixture,
            &wrote,
            slot_at(9).start,
            1,
            true,
            NOW + 120
        )
        .is_err(),
        "the door stops the pull"
    );
    assert!(
        read_event_outcome(&fixture.vault, booked.calendar.event_ref)
            .expect("read the CAL-07 outcome")
            .is_none(),
        "the pull stopped before the outcome"
    );
    pull_seat(
        &seat,
        &fixture,
        &wrote,
        slot_at(9).start,
        1,
        true,
        NOW + 180,
    )
    .expect("the next read of the same version");
    assert_eq!(
        fixture.state_of("pi_cancel_outcome_stop"),
        DepositState::RefundDue {
            amount_minor: 4_000
        }
    );
    let outcome = read_event_outcome(&fixture.vault, booked.calendar.event_ref)
        .expect("read the CAL-07 outcome")
        .expect("the next read records the cancellation's CAL-07 outcome");
    assert_eq!(outcome.outcome, EventOutcome::CancelledPreStart);
    assert_eq!(
        outcome.recorded_at,
        NOW + 120,
        "CAL-07 dates the cancellation by its first sighting"
    );
}

/// Review round 2 of #9472, on the tombstone's path: the host's tombstone at
/// 08:02 cancels the booking, and the pull stops after its status and before
/// its CAL-07 outcome; the same tombstone sent again records the outcome,
/// dated 08:02.
#[cfg(oneiron_test_support)]
#[test]
fn a_host_tombstone_stopped_before_its_outcome_records_it_when_sent_again() {
    let fixture = Fixture::open();
    let booked = captured_booking(&fixture, "pi_tombstone_outcome_stop", 9);
    let host = host_seat_reading_and_written(&fixture, &booked, slot_at(9).start, NOW + 54);
    oneiron::test_doors::host_cancel_refund::stop_before_next_cancel_outcome();
    assert!(
        seat_tombstone(&host, &fixture, &booked, NOW + 120).is_err(),
        "the door stops the pull"
    );
    seat_tombstone(&host, &fixture, &booked, NOW + 180).expect("the tombstone sent again");
    assert_eq!(
        fixture.state_of("pi_tombstone_outcome_stop"),
        DepositState::RefundDue {
            amount_minor: 4_000
        }
    );
    let outcome = read_event_outcome(&fixture.vault, booked.calendar.event_ref)
        .expect("read the CAL-07 outcome")
        .expect("the tombstone sent again records the cancellation's CAL-07 outcome");
    assert_eq!(outcome.outcome, EventOutcome::CancelledPreStart);
    assert_eq!(
        outcome.recorded_at,
        NOW + 120,
        "CAL-07 dates the cancellation by the tombstone's first arrival"
    );
}

/// Review round 2 of #9472: a status written earlier in the same second is no
/// fact recorded after the host's cancellation. The booking was written to
/// the host's calendar. At 08:02:00 the visitor's calendar, the last one that
/// showed it, leaves it out, and in that same second the host's calendar
/// carries the cancellation, whose pull stops after its passport and before
/// its refund and status. The same version read at 08:03 writes both, and
/// CAL-07 dates the cancellation at 08:02.
#[cfg(oneiron_test_support)]
#[test]
fn a_host_cancel_stopped_in_the_second_another_calendar_concluded_records_its_cancellation() {
    let fixture = Fixture::open();
    let booked = captured_booking(&fixture, "pi_same_second", 9);
    let host = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let wrote = host.write(&fixture.vault, booked.calendar.event_ref, NOW + 55);
    let visitor = Seat::install(&fixture.vault, VISITOR_SEAT_SYSTEM);
    read_booking_on_seat(&visitor, &fixture, &booked, slot_at(9).start, NOW + 56);
    pull_seat(
        &host,
        &fixture,
        &wrote,
        slot_at(9).start,
        0,
        false,
        NOW + 60,
    )
    .expect("the host seat's first pull");
    visitor
        .pull(
            &fixture.vault,
            &[SeatChange::omitted(&booked.calendar.uid)],
            NOW + 120,
        )
        .expect("the visitor calendar's omission");
    oneiron::test_doors::host_cancel_refund::stop_before_next_host_cancel_refund();
    assert!(
        pull_seat(
            &host,
            &fixture,
            &wrote,
            slot_at(9).start,
            1,
            true,
            NOW + 120
        )
        .is_err(),
        "the door stops the pull"
    );
    pull_seat(
        &host,
        &fixture,
        &wrote,
        slot_at(9).start,
        1,
        true,
        NOW + 180,
    )
    .expect("the repair pull");
    assert_eq!(
        fixture.state_of("pi_same_second"),
        DepositState::RefundDue {
            amount_minor: 4_000
        }
    );
    let outcome = read_event_outcome(&fixture.vault, booked.calendar.event_ref)
        .expect("read the CAL-07 outcome")
        .expect("the repair records the host's cancellation and its CAL-07 outcome");
    assert_eq!(outcome.outcome, EventOutcome::CancelledPreStart);
    assert_eq!(
        outcome.recorded_at,
        NOW + 120,
        "CAL-07 dates the cancellation by its first sighting"
    );
}

/// Review round 2 of #9472: an omission that concludes the cancellation while
/// the host's cancellation waits on its repair does not hide it. The host's
/// cancellation at 08:02 stops after its passport and before its refund and
/// status; at 08:03 the visitor's calendar, the last one that showed the
/// booking, leaves it out, and the host's cancellation on record refunds. The
/// host's version read at 08:04 records the cancellation, and CAL-07 dates it
/// at 08:02.
#[cfg(oneiron_test_support)]
#[test]
fn a_host_cancel_repaired_after_an_omission_concluded_records_its_cancellation() {
    let fixture = Fixture::open();
    let booked = captured_booking(&fixture, "pi_omission_meanwhile", 9);
    let host = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let wrote = host.write(&fixture.vault, booked.calendar.event_ref, NOW + 55);
    let visitor = Seat::install(&fixture.vault, VISITOR_SEAT_SYSTEM);
    read_booking_on_seat(&visitor, &fixture, &booked, slot_at(9).start, NOW + 56);
    pull_seat(
        &host,
        &fixture,
        &wrote,
        slot_at(9).start,
        0,
        false,
        NOW + 60,
    )
    .expect("the host seat's first pull");
    oneiron::test_doors::host_cancel_refund::stop_before_next_host_cancel_refund();
    assert!(
        pull_seat(
            &host,
            &fixture,
            &wrote,
            slot_at(9).start,
            1,
            true,
            NOW + 120
        )
        .is_err(),
        "the door stops the pull"
    );
    visitor
        .pull(
            &fixture.vault,
            &[SeatChange::omitted(&booked.calendar.uid)],
            NOW + 180,
        )
        .expect("the visitor calendar's omission");
    assert_eq!(
        fixture.state_of("pi_omission_meanwhile"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "the host's cancellation on record refunds once the cancellation concludes"
    );
    pull_seat(
        &host,
        &fixture,
        &wrote,
        slot_at(9).start,
        1,
        true,
        NOW + 240,
    )
    .expect("the repair pull");
    let outcome = read_event_outcome(&fixture.vault, booked.calendar.event_ref)
        .expect("read the CAL-07 outcome")
        .expect("the repair records the host's cancellation and its CAL-07 outcome");
    assert_eq!(outcome.outcome, EventOutcome::CancelledPreStart);
    assert_eq!(
        outcome.recorded_at,
        NOW + 120,
        "CAL-07 dates the cancellation by its first sighting"
    );
}
