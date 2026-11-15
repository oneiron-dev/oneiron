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
//!   it still refunds.
//!
//! The fixture is the emergency fixture of `tests/booking_feed_move_held.rs`
//! (keystore, the page's facet, engine machines, this install elected the
//! lifecycle home node, the owner's seat, policy and page grant), with a
//! deposit on the page's event type. Only public paths and the test doors
//! that file uses, so the pre-fix head builds it: its red is an assert.

mod common;

use std::sync::Mutex;

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
use oneiron::calendar::ingest::{
    IcsFeedFetcher, IcsFeedPollConfig, IcsFetchResponse, run_ics_feed_poll,
};
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
const HOST_SEED: u8 = 0x52;
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
        deposit: Some(terms()),
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
    let booked = captured_booking(&fixture, "pi_after_start", 9);
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
        slot_at(9).start,
        1,
        true,
        "v2",
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

/// The host's feed carries the booking live at SEQUENCE 5; a stale copy of
/// the feed then sends an older SEQUENCE 3 that reads cancelled. The passport
/// keeps SEQUENCE 5 (an older replay changes nothing), so the booking stays
/// live and its deposit stays captured (Muse Wonder blind review of #8230,
/// F2, 16 Nov 08:10).
#[test]
fn an_older_sequence_cancellation_replayed_after_a_live_one_keeps_the_deposit() {
    let fixture = Fixture::open();
    let booked = captured_booking(&fixture, "pi_stale_replay", 9);
    poll_host_feed(
        &fixture,
        &booked,
        slot_at(9).start,
        5,
        false,
        "v5",
        NOW + 60,
    )
    .expect("the host feed at SEQUENCE 5, live");
    poll_host_feed(
        &fixture,
        &booked,
        slot_at(9).start,
        3,
        true,
        "v3-stale",
        NOW + 120,
    )
    .expect("a stale feed copy at SEQUENCE 3, cancelled");
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
    let booked = captured_booking(&fixture, "pi_repaired", 9);
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
    // The cancellation's passport commits at 08:02, and the poll stops
    // before its refund does.
    oneiron::test_doors::host_cancel_refund::stop_before_next_host_cancel_refund();
    assert!(
        poll_host_feed(
            &fixture,
            &booked,
            slot_at(9).start,
            1,
            true,
            "v2",
            NOW + 120
        )
        .is_err(),
        "the door stops the poll"
    );
    assert_eq!(
        fixture.state_of("pi_repaired"),
        DepositState::Captured {
            amount_minor: 4_000
        }
    );
    // The next read of the same feed comes after the start.
    poll_host_feed(
        &fixture,
        &booked,
        slot_at(9).start,
        1,
        true,
        "v3",
        slot_at(9).start + 60,
    )
    .expect("the repair poll");
    assert_eq!(
        fixture.state_of("pi_repaired"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "a cancellation first seen before the start keeps its full refund"
    );
}
