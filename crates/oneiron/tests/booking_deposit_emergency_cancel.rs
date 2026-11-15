//! BK-DEPOSITS PR 2, OPUS-SECREAD-A N2 (15 Nov): the owner's BK-09
//! emergency cancel is a host cancel, so the visitor's deposit comes back
//! whole (RULING DEPOSIT-HOST-CANCEL-REFUND = A, the lead 15 Nov 12:1x). A
//! deposit still to capture is released, a captured one is refunded, in the
//! emergency's own commit. Before the fix the emergency writer ran no deposit
//! step: the due capture was taken anyway and a captured deposit stayed
//! with the owner.
//!
//! The fixture is the emergency fixture of `tests/booking_feed_move_held.rs`
//! (keystore, the page's facet, engine machines, this install elected the
//! lifecycle home node, the owner's seat, policy and page grant), with a
//! deposit on the page's event type. Only public paths and the test doors
//! that file uses, so the pre-fix head builds it: its red is an assert.

mod common;

use oneiron::booking::lifecycle::{
    DepositCheckoutStart, DepositProviderEvent, DepositProviderEventKind,
    DepositProviderEventOutcome, DepositProviderFailure, DepositSettleMove, DepositSettleRequest,
    DepositSettlementPort, DepositState, begin_deposit_checkout, booking_deposit_for_payment,
    record_deposit_provider_event, run_booking_deposit_settlement, settle_booking_deposit,
};
use oneiron::booking::{
    BOOKING_EVENT_TYPE_PREDICATE, BOOKING_EVENT_TYPE_SCHEMA_VERSION, BookingError,
    BookingEventTypeClaimValue, BookingLifecycleConsumerInput, BookingLifecycleTurn, BookingSolver,
    BookingVerbReceipt, BookingVerbRequest, ConfirmReceipt, ConfirmSpec,
    DEFAULT_INTRO_DURATION_MIN, DepositRefundRule, DepositTerms, EmergencyActionPolicy,
    EmergencyPlan, EmergencyRescheduleRequest, EventTypeConfig, EventTypeKey, HoldLeaseSpec,
    HoldReceipt, HoldSpec, HostAvailabilityConfig, PublishBookingPageGrantRequest, RoutingMode,
    SessionKey, SlotOracle, SolveRequest, SolveResult, VaultActiveHoldSource, WeeklyWallWindow,
    encode_event_type_claim_value, enqueue_booking_verb, execute_emergency_plan,
    mint_publish_page_invite_grant, plan_emergency_reschedule, run_booking_lifecycle_once,
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
