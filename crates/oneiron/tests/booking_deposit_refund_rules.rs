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
//! - The owner's refund (`vault.booking.deposit.refund`, RULINGS
//!   BK-DEPOSIT-OWNER-RETURN-ACT = A and BK-DEPOSIT-OWNER-RETURN-SCOPE = A,
//!   Engine 21 Nov 02:56): a host selected at confirmation gives a held
//!   deposit back whole once the booking is cancelled or has started, in one
//!   idempotent write; an agent, a vault owner who was not a selected host
//!   and a call on a live booking before its start are refused. After a
//!   visitor's late cancel refunded part of the capture, the owner's return
//!   owes the balance, whether that refund is still owed or has settled, and
//!   the provider refunds the earlier part once (review round 2 of #9977).
//! - A refund the provider ends unpaid (Stripe's `failed` or `canceled`)
//!   stays owed: the owner's card says so, and the host's Return deposit
//!   asks for the same refund again under a new key, and for nothing more
//!   (FIX [BK-DEPOSIT-FAILED-REFUND-SURFACE]).
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

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use booking_host_seat_support::{Seat, SeatChange, seat_owner};
use oneiron::agent_inbox_lens::AgentInboxLensQuery;
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
    WeeklyWallWindow, counterparty_pick, encode_event_type_claim_value, enqueue_booking_verb,
    execute_emergency_plan, mint_publish_page_invite_grant, plan_emergency_reschedule,
    run_booking_lifecycle_once,
};
use oneiron::calendar::CalendarError;
use oneiron::calendar::claims::PREDICATE_CALENDAR_STATUS;
use oneiron::calendar::connectors::{CalendarConnectorError, RemoteWriteReceipt};
use oneiron::calendar::ingest::{
    IcsFeedFetcher, IcsFeedPollConfig, IcsFetchResponse, run_ics_feed_poll,
};
#[cfg(oneiron_test_support)]
use oneiron::calendar::outcome::{EventOutcome, read_event_outcome};
use oneiron::calendar::query::CalendarRangeDto;
use oneiron::channel_identity::{ChannelIdentityBinding, ChannelIdentityState, SelfHeldShape};
use oneiron::memory::{
    ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest, ClaimSettlementVerdict,
    EmergencyInstructionInput, MEMORY_CODE_FORBIDDEN, Memory, MemoryError,
};
use oneiron::outbound::{
    OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink,
};
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::{
    CalendarSel, ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject,
    DreamerRunnerStore, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
};
use oneiron_store::ports::manual_clock::ManualClock;

/// Monday 2 March 2026, 00:00 UTC.
const MONDAY: u64 = 1_772_409_600;
const NOW: u64 = MONDAY + 8 * 3_600;

const PAGE_SEED: u8 = 0x51;
const BOOKER_SEED: u8 = 0x57;
const BUSY_SEED: u8 = 0x61;
const IDENTITY_SEED: u8 = 0x79;
const POLICY_SEED: u8 = 0x7a;
const OTHER_HOST_SEED: u8 = 0x7b;
const AGENT_SEED: u8 = 0x7c;

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

/// [`terms`] whose late cancel refunds `late_cancel_refund_percent` of the
/// deposit.
fn late_refund_terms(late_cancel_refund_percent: u8) -> DepositTerms {
    let base = terms();
    DepositTerms {
        refund: DepositRefundRule {
            late_cancel_refund_percent,
            ..base.refund
        },
        ..base
    }
}

fn event_type() -> EventTypeKey {
    EventTypeKey("intro-call".to_owned())
}

fn fixture_config(host: EntityId, deposit: &DepositTerms) -> EventTypeConfig {
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
        deposit: Some(deposit.clone()),
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
    /// The store's clock, when the fixture sets it: each lifecycle run moves
    /// it to the run's time.
    clock: Option<Arc<ManualClock>>,
    /// The deposit terms of the page's event type.
    terms: DepositTerms,
}

impl Fixture {
    fn open() -> Self {
        Self::open_on(None, None, terms())
    }

    /// The fixture on a vault this process owns (`Vault::open_owned`, as an
    /// embedded SDK host opens one), so its embedded owner takes owner verbs,
    /// with `clock` as the store's clock. The page's host is `other_host`, a
    /// PERSON stored here, when given, else the vault's embedded owner.
    fn open_owned(clock: &Arc<ManualClock>, other_host: Option<EntityId>) -> Self {
        Self::open_on(Some(Arc::clone(clock)), other_host, terms())
    }

    /// [`Fixture::open_owned`] with the vault's embedded owner as the host,
    /// on an event type whose deposit has `terms`.
    fn open_owned_with_terms(clock: &Arc<ManualClock>, terms: DepositTerms) -> Self {
        Self::open_on(Some(Arc::clone(clock)), None, terms)
    }

    fn open_on(
        clock: Option<Arc<ManualClock>>,
        other_host: Option<EntityId>,
        terms: DepositTerms,
    ) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let vault = match &clock {
            None => Vault::open(dir.path(), VaultConfig::default()).expect("open vault"),
            Some(clock) => {
                let mut config = VaultConfig::default();
                config.store_clock = clock.bundle();
                Vault::open_owned(dir.path(), config).expect("open the owned vault")
            }
        };
        // Signing doors load this install's keys from a keystore (P6c).
        vault.install_device_keystore(std::sync::Arc::new(
            oneiron_keystore::MemoryKeystore::default(),
        ));
        let page = test_id(PAGE_SEED);
        let host = match other_host {
            Some(host) => {
                vault
                    .put_entity(&host, ENTITY_TYPE_PERSON, at(1), 1, b"host")
                    .expect("put the host");
                host
            }
            // The host is the vault's embedded owner, the one owner a
            // personal vault has: the owner census refuses an owner act from
            // any other PERSON bound as human (main 34a0a330, rooted owner
            // census).
            None => vault.ensure_embedded_owner_actor().expect("host"),
        };
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
                config: fixture_config(host, &terms),
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
            clock,
            terms,
        }
    }

    /// Sets the store's clock to `now`, when the fixture sets it.
    fn set_clock(&self, now: u64) {
        if let Some(clock) = &self.clock {
            clock.set(now);
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
        self.set_clock(now);
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
                    host: self.host,
                    terms: &self.terms,
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
    host: EntityId,
    terms: &'a DepositTerms,
}

impl SlotOracle for LifecycleSolver<'_> {
    fn solve(&self, req: &SolveRequest) -> Result<SolveResult, BookingError> {
        let holds = match self.exclude {
            Some(key) => VaultActiveHoldSource::excluding(self.vault, key),
            None => VaultActiveHoldSource::new(self.vault),
        };
        let calendars = vec![(self.host, vec![CalendarSel { system: None }])];
        BookingSolver {
            vault: self.vault,
            page_ref: self.page,
            calendars_by_host: &calendars,
            holds: &holds,
            now_utc: NOW,
            synthetic_config: Some(fixture_config(self.host, self.terms)),
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

/// The owner reviews and approves every proposed `calendar.status` import on
/// `event`, as the connector smoke approves an import's passports: a pulled
/// calendar's cancellation lands Proposed, and a booking reads only
/// surfaceable heads, so it counts once the owner approves it.
fn approve_imported_status(vault: &Vault, event: EntityId) {
    let (id, owner) = seat_owner(vault);
    let memory = vault.memory(id, EdgeActorClass::Human);
    for claim in vault
        .claims_for_subject(&event)
        .expect("claims on the EVENT")
    {
        let body = vault.get_claim(&claim).expect("read claim").expect("claim");
        if body.predicate != PREDICATE_CALENDAR_STATUS
            || body.approval != ClaimApprovalStatus::Proposed
            || body.lifecycle != ClaimLifecycleStatus::Active
        {
            continue;
        }
        let review = memory
            .claim_review_as_owner(
                &owner,
                &ClaimProposalReviewRequest {
                    claim_ref: claim.to_hex(),
                    grant_ref: None,
                },
            )
            .expect("the owner reviews the imported status");
        let settled = memory
            .claim_settle_as_owner(
                &owner,
                &ClaimSettleRequest {
                    claim_ref: claim.to_hex(),
                    review_id: review.review_id,
                    decision: ClaimSettleDecision::Approve,
                    grant_ref: None,
                },
            )
            .expect("the owner approves the imported status");
        assert_eq!(settled.verdict, ClaimSettlementVerdict::Landed);
    }
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
            terms: fixture.terms.clone(),
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
                    amount_minor: fixture.terms.amount_minor,
                    currency: fixture.terms.currency.clone(),
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
        .expect("the owner's emergency cancel commits")
        .item;
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
/// DEPOSIT-HOST-CANCEL-SOURCE = A). The pulled cancellation lands Proposed,
/// so the owner approves it and the booking reads cancelled (FIX
/// BK-CANCELLED-ELSEWHERE-PROOF-RED-ON-MAIN: unapproved, the pre-fix code
/// never met a cancelled booking here and the test passed there). The host's calendar then carries the
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
    // The owner approves that cancellation, so the booking reads cancelled.
    approve_imported_status(&fixture.vault, event);
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

// The owner's refund, `vault.booking.deposit.refund` (RULINGS
// BK-DEPOSIT-OWNER-RETURN-ACT = A and BK-DEPOSIT-OWNER-RETURN-SCOPE = A,
// Engine 21 Nov 02:56). Each call goes through the verb by its name, so the
// pre-fix head builds these tests and refuses the unknown verb.

const DEPOSIT_REFUND_VERB: &str = "vault.booking.deposit.refund";

/// `caller` calls the owner's deposit refund on `booked`.
fn refund_deposit(
    caller: &Memory<'_>,
    booked: &ConfirmReceipt,
) -> Result<serde_json::Value, MemoryError> {
    oneiron::verbs::invoke(
        caller,
        DEPOSIT_REFUND_VERB,
        serde_json::json!({ "event_ref": booked.calendar.event_ref.to_hex() }),
    )
}

/// The claims on `booked`'s EVENT, sorted: a refund writes none, so the
/// booking's status heads and revision stay as they are.
fn event_claims(fixture: &Fixture, booked: &ConfirmReceipt) -> Vec<EntityId> {
    let mut claims = fixture
        .vault
        .claims_for_subject(&booked.calendar.event_ref)
        .expect("claims on the EVENT");
    claims.sort();
    claims
}

/// A provider that does every move it is asked, and keeps each one.
#[derive(Default)]
struct RecordingProvider {
    moves: Vec<DepositSettleMove>,
}

impl DepositSettlementPort for RecordingProvider {
    fn settle(
        &mut self,
        request: &DepositSettleRequest<'_>,
    ) -> Result<u64, DepositProviderFailure> {
        self.moves.push(request.movement);
        AgreeingProvider.settle(request)
    }
}

/// The host refunds a started booking's captured deposit and releases a
/// started booking's deposit still to capture; a retry, before and after
/// settlement, queues and moves nothing, and no call writes a claim on the
/// booking.
#[test]
fn the_host_refunds_a_started_bookings_deposit_once() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned(&clock, None);
    let captured = captured_booking(&fixture, "pi_owner_refund", 9);
    let due = paid_booking(
        &fixture,
        SessionKey::derive(b"owner-refund-due"),
        "pi_owner_release",
        10,
    );
    let claims_captured = event_claims(&fixture, &captured);
    let claims_due = event_claims(&fixture, &due);
    // Both meetings have started (or the visitor did not show).
    let refunded_at = slot_at(10).start + 60;
    fixture.set_clock(refunded_at);
    let host = fixture.vault.memory(fixture.host, EdgeActorClass::Human);

    let refund = refund_deposit(&host, &captured).expect("the host refunds the captured deposit");
    assert_eq!(
        refund,
        serde_json::json!({
            "event_ref": captured.calendar.event_ref.to_hex(),
            "state": "refund_due",
            "amount_minor": 4_000,
            "currency": "usd",
            "queued": true,
        })
    );
    assert_eq!(
        fixture.state_of("pi_owner_refund"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "the whole capture is owed back"
    );
    let release = refund_deposit(&host, &due).expect("the host releases the deposit still due");
    assert_eq!(release["state"], "void_due", "{release}");
    assert_eq!(release["amount_minor"], 0, "{release}");
    assert_eq!(release["queued"], true, "{release}");
    assert_eq!(fixture.state_of("pi_owner_release"), DepositState::VoidDue);

    let retry = refund_deposit(&host, &captured).expect("the retry answers");
    assert_eq!(retry["state"], "refund_due", "{retry}");
    assert_eq!(retry["amount_minor"], 4_000, "{retry}");
    assert_eq!(retry["queued"], false, "a retry queues nothing: {retry}");
    assert_eq!(
        fixture.state_of("pi_owner_refund"),
        DepositState::RefundDue {
            amount_minor: 4_000
        }
    );
    assert_eq!(
        event_claims(&fixture, &captured),
        claims_captured,
        "the refund leaves the booking's status and revision as they are"
    );
    assert_eq!(event_claims(&fixture, &due), claims_due);

    let mut provider = RecordingProvider::default();
    let pass = run_booking_deposit_settlement(
        &fixture.vault,
        "deposit-settle-worker",
        &mut provider,
        16,
        refunded_at + 60,
    )
    .expect("drain the settle rows");
    assert_eq!(pass.failed, 0);
    assert_eq!(
        provider.moves.len(),
        2,
        "one refund and one release: {:?}",
        provider.moves
    );
    assert!(
        provider.moves.contains(&DepositSettleMove::Refund {
            amount_minor: 4_000
        }),
        "{:?}",
        provider.moves
    );
    assert!(
        provider.moves.contains(&DepositSettleMove::Void),
        "{:?}",
        provider.moves
    );
    assert_eq!(
        fixture.state_of("pi_owner_refund"),
        DepositState::Refunded {
            amount_minor: 4_000
        }
    );
    assert_eq!(fixture.state_of("pi_owner_release"), DepositState::Voided);

    fixture.set_clock(refunded_at + 120);
    let settled = refund_deposit(&host, &captured).expect("a retry after settlement answers");
    assert_eq!(settled["state"], "refunded", "{settled}");
    assert_eq!(settled["amount_minor"], 4_000, "{settled}");
    assert_eq!(settled["queued"], false, "{settled}");
    let mut after = RecordingProvider::default();
    run_booking_deposit_settlement(
        &fixture.vault,
        "deposit-settle-worker",
        &mut after,
        16,
        refunded_at + 180,
    )
    .expect("drain again");
    assert!(
        after.moves.is_empty(),
        "a retry moves no money: {:?}",
        after.moves
    );
}

/// An agent takes no refund, whatever it holds: the act is the owner's own.
/// The host's own call then refunds, so the refusal was the caller's.
#[test]
fn an_agent_cannot_refund_a_deposit() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned(&clock, None);
    let captured = captured_booking(&fixture, "pi_agent_refund", 9);
    fixture.set_clock(slot_at(9).start + 60);
    let agent = fixture
        .vault
        .memory(test_id(AGENT_SEED), EdgeActorClass::Agent);
    assert!(
        refund_deposit(&agent, &captured).is_err(),
        "an agent takes no refund"
    );
    assert_eq!(
        fixture.state_of("pi_agent_refund"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "the agent's call moves nothing"
    );
    let host = fixture.vault.memory(fixture.host, EdgeActorClass::Human);
    let refund = refund_deposit(&host, &captured).expect("the host refunds");
    assert_eq!(refund["queued"], true, "{refund}");
    assert_eq!(
        fixture.state_of("pi_agent_refund"),
        DepositState::RefundDue {
            amount_minor: 4_000
        }
    );
}

/// A booking hosted by another person: the vault's owner was not a host
/// selected at its confirmation, so the owner's call is refused, and the
/// host, who owns no vault, holds no owner proof.
#[test]
fn only_a_host_selected_at_confirmation_refunds_a_deposit() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned(&clock, Some(test_id(OTHER_HOST_SEED)));
    let captured = captured_booking(&fixture, "pi_other_host", 9);
    fixture.set_clock(slot_at(9).start + 60);
    let owner = fixture
        .vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let refusal = refund_deposit(
        &fixture.vault.memory(owner, EdgeActorClass::Human),
        &captured,
    )
    .expect_err("the vault's owner was not a selected host");
    assert_eq!(refusal.code, MEMORY_CODE_FORBIDDEN, "{refusal:?}");
    assert!(
        refusal.message.contains("host selected"),
        "the refusal names the selected hosts: {refusal:?}"
    );
    assert!(
        refund_deposit(
            &fixture.vault.memory(fixture.host, EdgeActorClass::Human),
            &captured,
        )
        .is_err(),
        "a host who owns no vault holds no owner proof"
    );
    assert_eq!(
        fixture.state_of("pi_other_host"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "no refused call moves money"
    );
}

/// Before its start, a live booking keeps its deposit: the owner's refund is
/// refused, and the owner's emergency cancel is the door. Once the visitor
/// cancels late, which refunds nothing by the visitor's terms, the booking
/// is cancelled and the host refunds it whole.
#[test]
fn a_live_booking_keeps_its_deposit_until_it_is_cancelled_or_starts() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned(&clock, None);
    let captured = captured_booking(&fixture, "pi_live", 9);
    fixture.set_clock(NOW + 60);
    let host = fixture.vault.memory(fixture.host, EdgeActorClass::Human);
    let refusal =
        refund_deposit(&host, &captured).expect_err("a live booking before its start keeps it");
    assert!(
        refusal.message.contains("has not started"),
        "the refusal names the booking's state: {refusal:?}"
    );
    assert_eq!(
        fixture.state_of("pi_live"),
        DepositState::Captured {
            amount_minor: 4_000
        }
    );
    cancel(&fixture, &captured, NOW + 120);
    assert_eq!(
        fixture.state_of("pi_live"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "the visitor's late cancel refunds nothing by its terms"
    );
    fixture.set_clock(NOW + 180);
    let refund = refund_deposit(&host, &captured).expect("the host refunds the cancelled booking");
    assert_eq!(refund["state"], "refund_due", "{refund}");
    assert_eq!(refund["queued"], true, "{refund}");
    assert_eq!(
        fixture.state_of("pi_live"),
        DepositState::RefundDue {
            amount_minor: 4_000
        }
    );
}

/// A MACRO home move carries no deposit row: the node that confirmed the
/// booking still holds its deposit after the home moved to another node, so
/// the host's refund is taken there and its settle worker returns the money
/// (review round 1 of #9977: a home-node gate left the deposit refundable on
/// neither node).
#[test]
fn the_confirming_node_refunds_a_deposit_after_the_home_moved_away() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned(&clock, None);
    let captured = captured_booking(&fixture, "pi_home_moved", 9);
    let runner = DreamerRunnerStore::new(&fixture.vault);
    let local = runner
        .local_home_node_candidate(true, true, true)
        .expect("local home node candidate");
    let cloud = oneiron::DreamerHomeNodeCandidate::cloud(fixture.node_id.wrapping_add(1), true);
    let elected = runner
        .elect_home_node(&[local, cloud], NOW + 30)
        .expect("elect the attached cloud node")
        .expect("a home node");
    assert_ne!(
        elected.node_id, fixture.node_id,
        "the home moved off the confirming node"
    );
    let refunded_at = slot_at(9).start + 60;
    fixture.set_clock(refunded_at);
    let host = fixture.vault.memory(fixture.host, EdgeActorClass::Human);

    let refund =
        refund_deposit(&host, &captured).expect("the confirming node refunds the deposit it holds");
    assert_eq!(refund["state"], "refund_due", "{refund}");
    assert_eq!(refund["queued"], true, "{refund}");
    let mut provider = RecordingProvider::default();
    let pass = run_booking_deposit_settlement(
        &fixture.vault,
        "deposit-settle-worker",
        &mut provider,
        16,
        refunded_at + 60,
    )
    .expect("drain the settle rows");
    assert_eq!(pass.failed, 0);
    assert_eq!(
        provider.moves,
        vec![DepositSettleMove::Refund {
            amount_minor: 4_000
        }]
    );
    assert_eq!(
        fixture.state_of("pi_home_moved"),
        DepositState::Refunded {
            amount_minor: 4_000
        }
    );
}

/// A provider that keeps each refund by its idempotency key, as the payment
/// provider does: a request under a key it already took answers that refund
/// again and moves no more money.
#[derive(Default)]
struct KeyedRefundProvider {
    refunds: BTreeMap<String, u64>,
    moves: Vec<DepositSettleMove>,
}

impl KeyedRefundProvider {
    /// What the payment has had refunded in all.
    fn refunded_minor(&self) -> u64 {
        self.refunds.values().sum()
    }
}

impl DepositSettlementPort for KeyedRefundProvider {
    fn settle(
        &mut self,
        request: &DepositSettleRequest<'_>,
    ) -> Result<u64, DepositProviderFailure> {
        if let DepositSettleMove::Refund { amount_minor } = request.movement {
            if let Some(refunded) = self.refunds.get(request.idempotency_key) {
                return Ok(*refunded);
            }
            self.refunds
                .insert(request.idempotency_key.to_owned(), amount_minor);
        }
        self.moves.push(request.movement);
        AgreeingProvider.settle(request)
    }
}

/// Drains the settle rows at `now` and again a minute later: a settled
/// refund whose record owes a balance queues the balance's own row.
fn drain_settle_rows<P: DepositSettlementPort>(fixture: &Fixture, provider: &mut P, now: u64) {
    for at in [now, now + 60] {
        let pass = run_booking_deposit_settlement(
            &fixture.vault,
            "deposit-settle-worker",
            provider,
            16,
            at,
        )
        .expect("drain the settle rows");
        assert_eq!(pass.failed, 0);
    }
}

/// A late cancel under a 50% rule refunds half the capture, and that refund
/// settles; the host's return then owes the other half. The provider keeps
/// refunds by idempotency key, so the balance, equal to the earlier refund,
/// is a new refund and not its replay: the payment ends refunded whole, the
/// visitor's half once (review round 2 of #9977).
#[test]
fn the_host_returns_the_balance_a_settled_late_cancel_refund_left() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned_with_terms(&clock, late_refund_terms(50));
    let booked = captured_booking(&fixture, "pi_half_late", 9);
    // One hour before the 09:00 start: half the deposit comes back.
    cancel(&fixture, &booked, NOW + 120);
    assert_eq!(
        fixture.state_of("pi_half_late"),
        DepositState::RefundDue {
            amount_minor: 2_000
        }
    );
    let mut provider = KeyedRefundProvider::default();
    drain_settle_rows(&fixture, &mut provider, NOW + 180);
    assert_eq!(
        fixture.state_of("pi_half_late"),
        DepositState::Refunded {
            amount_minor: 2_000
        }
    );
    let returned_at = NOW + 300;
    fixture.set_clock(returned_at);
    let host = fixture.vault.memory(fixture.host, EdgeActorClass::Human);

    let refund = refund_deposit(&host, &booked).expect("the host returns the balance");
    assert_eq!(
        refund,
        serde_json::json!({
            "event_ref": booked.calendar.event_ref.to_hex(),
            "state": "refund_due",
            "amount_minor": 4_000,
            "currency": "usd",
            "queued": true,
        }),
        "the half the late cancel kept is owed back"
    );
    assert_eq!(
        fixture.state_of("pi_half_late"),
        DepositState::RefundDue {
            amount_minor: 2_000
        },
        "only the balance is owed: the visitor's half is refunded already"
    );
    drain_settle_rows(&fixture, &mut provider, returned_at + 60);
    assert_eq!(
        provider.moves,
        vec![
            DepositSettleMove::Refund {
                amount_minor: 2_000
            },
            DepositSettleMove::Refund {
                amount_minor: 2_000
            },
        ],
        "the visitor's half, then the balance as a new refund"
    );
    assert_eq!(
        provider.refunded_minor(),
        4_000,
        "the payment is refunded whole"
    );
    assert_eq!(
        fixture.state_of("pi_half_late"),
        DepositState::Refunded {
            amount_minor: 4_000
        }
    );

    fixture.set_clock(returned_at + 180);
    let retry = refund_deposit(&host, &booked).expect("a retry after settlement answers");
    assert_eq!(retry["state"], "refunded", "{retry}");
    assert_eq!(retry["amount_minor"], 4_000, "{retry}");
    assert_eq!(retry["queued"], false, "{retry}");
    drain_settle_rows(&fixture, &mut provider, returned_at + 240);
    assert_eq!(
        provider.moves.len(),
        2,
        "a retry moves no money: {:?}",
        provider.moves
    );
}

/// A late cancel under a 25% rule owes a quarter of the capture back; the
/// host's return before that refund settles leaves it as it is and owes the
/// balance once it settles. A retry queues nothing, and the quarter is
/// refunded once, the balance after it (review round 2 of #9977).
#[test]
fn the_host_returns_the_balance_while_a_late_cancel_refund_is_owed() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned_with_terms(&clock, late_refund_terms(25));
    let booked = captured_booking(&fixture, "pi_quarter_late", 9);
    cancel(&fixture, &booked, NOW + 120);
    assert_eq!(
        fixture.state_of("pi_quarter_late"),
        DepositState::RefundDue {
            amount_minor: 1_000
        }
    );
    let returned_at = NOW + 180;
    fixture.set_clock(returned_at);
    let host = fixture.vault.memory(fixture.host, EdgeActorClass::Human);

    let refund = refund_deposit(&host, &booked).expect("the host returns the balance");
    assert_eq!(refund["state"], "refund_due", "{refund}");
    assert_eq!(
        refund["amount_minor"], 4_000,
        "the whole capture comes back: {refund}"
    );
    assert_eq!(refund["queued"], true, "{refund}");
    assert_eq!(
        fixture.state_of("pi_quarter_late"),
        DepositState::RefundDue {
            amount_minor: 1_000
        },
        "the quarter owed settles first, as it was asked"
    );
    let retry = refund_deposit(&host, &booked).expect("the retry answers");
    assert_eq!(retry["amount_minor"], 4_000, "{retry}");
    assert_eq!(retry["queued"], false, "a retry queues nothing: {retry}");

    let mut provider = KeyedRefundProvider::default();
    drain_settle_rows(&fixture, &mut provider, returned_at + 60);
    assert_eq!(
        provider.moves,
        vec![
            DepositSettleMove::Refund {
                amount_minor: 1_000
            },
            DepositSettleMove::Refund {
                amount_minor: 3_000
            },
        ],
        "the visitor's quarter, then the balance"
    );
    assert_eq!(
        provider.refunded_minor(),
        4_000,
        "the payment is refunded whole"
    );
    assert_eq!(
        fixture.state_of("pi_quarter_late"),
        DepositState::Refunded {
            amount_minor: 4_000
        }
    );
}

// The owner's line for a held deposit (BK-DEPOSIT-HOST-CANCEL-AFTER-START-
// OWNER-LINE PR 2; BK-DEPOSIT-OWNER-RETURN-SCOPE = A, Engine 21 Nov 02:56;
// BK-ECHO-UNMARKED-SAME-SHAPE-COPY = C, lead 21 Nov 04:3x). Once a booking
// is cancelled or has started, its card says what the deposit still holds
// and offers Return deposit to a selected host; where a calendar's cancel
// moved no money, the line is also an INBOX row of its own until the
// deposit holds nothing. Each row is read through the verbs by name, so the
// pre-fix head builds these tests: its red is an assert.

/// The prefix of a held deposit's INBOX row.
const HELD_DEPOSIT_ROW: &str = "booking-held-deposit:";

/// The held-deposit rows of `actor`'s INBOX slice at `now`.
fn held_deposit_rows(fixture: &Fixture, actor: EntityId, now: u64) -> Vec<String> {
    fixture.set_clock(now);
    fixture
        .vault
        .agent_inbox_slice(actor, 500, None)
        .expect("the actor's inbox slice")
        .into_iter()
        .map(|item| item.item_id)
        .filter(|id| id.starts_with(HELD_DEPOSIT_ROW))
        .collect()
}

/// `reader` opens the INBOX row `item_id` (`self.inbox.get`): the booking
/// card it carries, as JSON.
fn open_booking_row(reader: &Memory<'_>, item_id: &str) -> serde_json::Value {
    let opened = oneiron::verbs::invoke(
        reader,
        "self.inbox.get",
        serde_json::json!({ "item_id": item_id }),
    )
    .expect("the reader opens the row");
    opened["booking"].clone()
}

/// The visitor's calendar, which the booking was never written to, carries
/// `booked` cancelled at `now`, and the owner approves that cancellation, so
/// the booking reads cancelled with its deposit held
/// (DEPOSIT-HOST-CANCEL-SOURCE = A).
fn cancel_on_unwritten_calendar(fixture: &Fixture, booked: &ConfirmReceipt, now: u64) {
    let slot = slot_at(9);
    let visitor = Seat::install(&fixture.vault, VISITOR_SEAT_SYSTEM);
    read_booking_on_seat(&visitor, fixture, booked, slot.start, now - 30);
    visitor
        .pull(
            &fixture.vault,
            &[SeatChange::foreign(
                &visitor,
                &booked.calendar.uid,
                slot.start,
                slot.end,
                1,
                true,
            )],
            now,
        )
        .expect("the visitor calendar's cancellation");
    approve_imported_status(&fixture.vault, booked.calendar.event_ref);
}

/// A cancel from a calendar the booking was never written to moves no
/// money: the selected host's INBOX carries the held deposit as a row of its
/// own, which opens the booking card with the deposit line and Return
/// deposit. The host's return ends the row and the line.
#[test]
fn a_calendar_cancel_that_moved_no_money_lists_the_held_deposit_until_the_host_returns_it() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned(&clock, None);
    let booked = captured_booking(&fixture, "pi_held_line", 9);
    let row = format!("{HELD_DEPOSIT_ROW}{}", booked.calendar.event_ref.to_hex());
    assert!(
        held_deposit_rows(&fixture, fixture.host, NOW + 60).is_empty(),
        "a live booking before its start lists no held deposit"
    );
    cancel_on_unwritten_calendar(&fixture, &booked, NOW + 120);
    assert_eq!(
        fixture.state_of("pi_held_line"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a cancellation from a calendar the booking was not written to moves no money"
    );

    assert_eq!(
        held_deposit_rows(&fixture, fixture.host, NOW + 180),
        vec![row.clone()],
        "the selected host's INBOX lists the held deposit"
    );
    let host = fixture.vault.memory(fixture.host, EdgeActorClass::Human);
    let card = open_booking_row(&host, &row);
    assert_eq!(card["status"], "cancelled", "{card}");
    assert_eq!(
        card["deposit"],
        serde_json::json!({
            "held": "captured",
            "amount_minor": 4_000,
            "currency": "usd",
            "reason": "calendar_cancel",
            "line": "Booking at 2026-03-02 09:00 (UTC) was cancelled in a calendar. 40.00 USD is \
                     still held as its deposit. Choose Return deposit to refund it in full.",
            "return_offered": true,
        }),
        "{card}"
    );
    assert_eq!(
        held_deposit_rows(&fixture, fixture.host, NOW + 2 * 86_400),
        vec![row.clone()],
        "the row stands on later days while the deposit is held"
    );

    fixture.set_clock(NOW + 2 * 86_400 + 60);
    let refund = refund_deposit(&host, &booked).expect("the host returns the deposit");
    assert_eq!(refund["state"], "refund_due", "{refund}");
    assert!(
        held_deposit_rows(&fixture, fixture.host, NOW + 2 * 86_400 + 120).is_empty(),
        "a return owed ends the row"
    );
    assert!(
        oneiron::verbs::invoke(
            &host,
            "self.inbox.get",
            serde_json::json!({ "item_id": row }),
        )
        .is_err(),
        "the row's handle no longer opens once the return is owed"
    );
}

/// The host deletes the booking from the calendar it was written to after
/// the meeting started: the cancel moves no money
/// (DEPOSIT-HOST-CANCEL-AFTER-START = A), so the held deposit is listed.
#[test]
fn a_calendar_cancel_after_the_start_lists_the_held_deposit() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned(&clock, None);
    let booked = captured_booking(&fixture, "pi_after_start_line", 9);
    let slot = slot_at(9);
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let wrote = seat.write(&fixture.vault, booked.calendar.event_ref, NOW + 55);
    pull_seat(&seat, &fixture, &wrote, slot.start, 0, false, NOW + 60)
        .expect("the seat's first pull");
    fixture.set_clock(slot.start + 60);
    pull_seat(
        &seat,
        &fixture,
        &wrote,
        slot.start,
        1,
        true,
        slot.start + 60,
    )
    .expect("the host's cancellation after the start");
    approve_imported_status(&fixture.vault, booked.calendar.event_ref);
    assert_eq!(
        fixture.state_of("pi_after_start_line"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a cancellation seen after the start moves no money"
    );
    let row = format!("{HELD_DEPOSIT_ROW}{}", booked.calendar.event_ref.to_hex());
    assert_eq!(
        held_deposit_rows(&fixture, fixture.host, slot.start + 120),
        vec![row.clone()]
    );
    let card = open_booking_row(
        &fixture.vault.memory(fixture.host, EdgeActorClass::Human),
        &row,
    );
    assert_eq!(card["deposit"]["reason"], "calendar_cancel", "{card}");
    assert_eq!(card["deposit"]["held"], "captured", "{card}");
    assert_eq!(card["deposit"]["return_offered"], true, "{card}");
}

/// BK-ECHO-UNMARKED-SAME-SHAPE-COPY = C: the owner's cancelled write lands
/// but its answer is lost, and the provider drops the write's marker from
/// the copy it stores. The replay reads that copy as the owner's own write
/// (A: a host's cancel at that SEQUENCE reads the same), so the deposit
/// stays held, and the owner's line names a cancel Oneiron cannot
/// attribute, with Return deposit.
#[test]
fn a_cancel_read_as_the_owners_write_without_its_marker_lists_the_held_deposit_as_unattributed() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned(&clock, None);
    let booked = captured_booking(&fixture, "pi_unattributed_line", 9);
    let event = booked.calendar.event_ref;
    let slot = slot_at(9);
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let live = seat.write(&fixture.vault, event, NOW + 55);
    pull_seat(&seat, &fixture, &live, slot.start, 0, false, NOW + 60)
        .expect("the seat's first pull");
    cancel_on_unwritten_calendar(&fixture, &booked, NOW + 120);

    let stored = seat.write_with_lost_answer(&fixture.vault, event, NOW + 150);
    let copy = seat.stripped_rewrite_of_own_write(&live, stored, NOW + 160);
    seat.replay_refused_over(&fixture.vault, event, &copy, NOW + 170);
    seat.pull(&fixture.vault, std::slice::from_ref(&copy), NOW + 180)
        .expect("seat pull");
    assert_eq!(
        fixture.state_of("pi_unattributed_line"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "the copy with its marker dropped reads as the owner's own write and moves no money"
    );

    let row = format!("{HELD_DEPOSIT_ROW}{}", event.to_hex());
    assert_eq!(
        held_deposit_rows(&fixture, fixture.host, NOW + 240),
        vec![row.clone()]
    );
    let card = open_booking_row(
        &fixture.vault.memory(fixture.host, EdgeActorClass::Human),
        &row,
    );
    assert_eq!(
        card["deposit"],
        serde_json::json!({
            "held": "captured",
            "amount_minor": 4_000,
            "currency": "usd",
            "reason": "unattributed_cancel",
            "line": "Booking at 2026-03-02 09:00 (UTC): a cancel we can't attribute: refund by \
                     hand? 40.00 USD is still held as its deposit. Choose Return deposit to \
                     refund it in full.",
            "return_offered": true,
        }),
        "{card}"
    );
}

/// A booking that simply started (the visitor did not show) keeps its
/// captured deposit: the line is on the booking card only, from the start,
/// and no row of its own is listed.
#[test]
fn a_started_booking_shows_its_held_deposit_on_its_card_only() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned(&clock, None);
    let booked = captured_booking(&fixture, "pi_started_line", 9);
    let card_row = format!("booking:{}", booked.calendar.event_ref.to_hex());
    let host = fixture.vault.memory(fixture.host, EdgeActorClass::Human);
    fixture.set_clock(NOW + 60);
    let before = open_booking_row(&host, &card_row);
    assert!(
        before.get("deposit").is_none(),
        "a live booking before its start shows no deposit line: {before}"
    );
    let started = slot_at(9).start + 60;
    assert!(held_deposit_rows(&fixture, fixture.host, started).is_empty());
    let card = open_booking_row(&host, &card_row);
    assert_eq!(
        card["deposit"],
        serde_json::json!({
            "held": "captured",
            "amount_minor": 4_000,
            "currency": "usd",
            "reason": "started",
            "line": "Booking at 2026-03-02 09:00 (UTC) has started. 40.00 USD is still held as \
                     its deposit. Choose Return deposit to refund it in full.",
            "return_offered": true,
        }),
        "{card}"
    );
}

/// The vault's owner was not the host selected at confirmation: no held
/// row is listed for them, and the card they open says the deposit is held
/// without offering them Return deposit, which would refuse them.
#[test]
fn an_owner_who_was_not_a_selected_host_is_not_offered_the_return() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned(&clock, Some(test_id(OTHER_HOST_SEED)));
    let booked = captured_booking(&fixture, "pi_not_selected_line", 9);
    cancel_on_unwritten_calendar(&fixture, &booked, NOW + 120);
    let owner = fixture
        .vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    assert!(
        held_deposit_rows(&fixture, owner, NOW + 180).is_empty(),
        "only a selected host's INBOX lists the held deposit"
    );
    let card = open_booking_row(
        &fixture.vault.memory(owner, EdgeActorClass::Human),
        &format!("booking:{}", booked.calendar.event_ref.to_hex()),
    );
    assert_eq!(card["deposit"]["reason"], "calendar_cancel", "{card}");
    assert_eq!(card["deposit"]["return_offered"], false, "{card}");
    assert_eq!(
        card["deposit"]["line"],
        "Booking at 2026-03-02 09:00 (UTC) was cancelled in a calendar. 40.00 USD is still held \
         as its deposit. A host selected when it was confirmed can return it.",
        "{card}"
    );
}

// Review round 1 of #10028.

/// Whether `rows` carries the INBOX row `row`.
fn lists_held_row(rows: &[oneiron::agent_inbox_lens::AgentInboxLensItem], row: &str) -> bool {
    rows.iter().any(|item| item.item_id == row)
}

/// Review round 1 of #10028 (P1 held_deposit.rs:110): the one calendar
/// that carries the booking, written to it, leaves it out of a complete
/// listing before the start. The omission reads the booking cancelled but
/// is no cancel and moves no money, so the deposit line stays on the
/// booking card and no row of its own is listed.
#[test]
fn a_plain_omission_shows_the_held_deposit_on_its_card_only() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned(&clock, None);
    let booked = captured_booking(&fixture, "pi_omission_line", 9);
    let seat = host_seat_reading_and_written(&fixture, &booked, slot_at(9).start, NOW + 54);
    seat.pull(
        &fixture.vault,
        &[SeatChange::omitted(&booked.calendar.uid)],
        NOW + 60,
    )
    .expect("the omission before the start");
    approve_imported_status(&fixture.vault, booked.calendar.event_ref);
    assert_eq!(
        fixture.state_of("pi_omission_line"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "an omission moves no money"
    );

    assert!(
        held_deposit_rows(&fixture, fixture.host, NOW + 120).is_empty(),
        "a plain omission lists no held deposit"
    );
    let card = open_booking_row(
        &fixture.vault.memory(fixture.host, EdgeActorClass::Human),
        &format!("booking:{}", booked.calendar.event_ref.to_hex()),
    );
    assert_eq!(card["status"], "cancelled", "{card}");
    assert_eq!(
        card["deposit"],
        serde_json::json!({
            "held": "captured",
            "amount_minor": 4_000,
            "currency": "usd",
            "reason": "calendar_omission",
            "line": "Booking at 2026-03-02 09:00 (UTC) is missing from every calendar that \
                     listed it, so it reads as cancelled. 40.00 USD is still held as its \
                     deposit. Choose Return deposit to refund it in full.",
            "return_offered": true,
        }),
        "{card}"
    );
}

/// Review round 1 of #10028 (P1 owner_card.rs:165): the held-deposit row
/// is listed only on the own INBOX slice of a selected host. The
/// cross-identity lens, and another reader's view of the host's slice, list
/// it for no one.
#[test]
fn the_held_deposit_row_lists_only_on_a_selected_hosts_own_slice() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned(&clock, None);
    let booked = captured_booking(&fixture, "pi_own_slice_line", 9);
    cancel_on_unwritten_calendar(&fixture, &booked, NOW + 120);
    let row = format!("{HELD_DEPOSIT_ROW}{}", booked.calendar.event_ref.to_hex());
    assert_eq!(
        held_deposit_rows(&fixture, fixture.host, NOW + 180),
        vec![row.clone()],
        "the selected host's own slice lists the held deposit"
    );

    let lens = fixture
        .vault
        .agent_inbox_lens(AgentInboxLensQuery {
            identity_ref: None,
            limit: 500,
            before: None,
        })
        .expect("the cross-identity lens");
    assert!(
        !lists_held_row(&lens, &row),
        "the cross-identity lens lists no held deposit"
    );
    let viewed = fixture
        .vault
        .agent_identity_inbox_slice(fixture.host, None, 500, None, false)
        .expect("another reader's view of the host's slice");
    assert!(
        !lists_held_row(&viewed, &row),
        "another reader's view of the host's slice lists no held deposit"
    );
}

/// Review round 1 of #10028 (P1 owner_card.rs:212): the host marks the
/// held row of a cancel from an unwritten calendar done; the replay of the
/// owner's cancelled write then reads a copy with its marker dropped, which
/// makes the cancel one Oneiron cannot attribute. The row comes back new,
/// under the same handle.
#[test]
fn a_held_deposit_row_marked_done_comes_back_when_its_cancel_turns_unattributed() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned(&clock, None);
    let booked = captured_booking(&fixture, "pi_done_then_unattributed", 9);
    let event = booked.calendar.event_ref;
    let slot = slot_at(9);
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let live = seat.write(&fixture.vault, event, NOW + 55);
    pull_seat(&seat, &fixture, &live, slot.start, 0, false, NOW + 60)
        .expect("the seat's first pull");
    cancel_on_unwritten_calendar(&fixture, &booked, NOW + 120);
    let row = format!("{HELD_DEPOSIT_ROW}{}", event.to_hex());
    let board = |now: u64| -> Vec<(String, oneiron::agent_inbox_lens::AgentInboxReadState)> {
        fixture.set_clock(now);
        fixture
            .vault
            .agent_inbox_board_slice(fixture.host, 500, now)
            .expect("the host's board")
            .rows
            .into_iter()
            .map(|(item, state)| (item.item_id, state))
            .filter(|(id, _)| id.starts_with(HELD_DEPOSIT_ROW))
            .collect()
    };
    assert_eq!(
        board(NOW + 130),
        vec![(
            row.clone(),
            oneiron::agent_inbox_lens::AgentInboxReadState::New
        )]
    );
    let host = fixture.vault.memory(fixture.host, EdgeActorClass::Human);
    oneiron::verbs::invoke(
        &host,
        "self.inbox.done",
        serde_json::json!({ "item_id": row }),
    )
    .expect("the host marks the held row done");
    assert!(board(NOW + 140).is_empty(), "a row marked done leaves");

    let stored = seat.write_with_lost_answer(&fixture.vault, event, NOW + 150);
    let copy = seat.stripped_rewrite_of_own_write(&live, stored, NOW + 160);
    seat.replay_refused_over(&fixture.vault, event, &copy, NOW + 170);
    seat.pull(&fixture.vault, std::slice::from_ref(&copy), NOW + 180)
        .expect("seat pull");
    assert_eq!(
        board(NOW + 240),
        vec![(
            row.clone(),
            oneiron::agent_inbox_lens::AgentInboxReadState::New
        )],
        "the unattributed cancel brings the row back"
    );
    let card = open_booking_row(&host, &row);
    assert_eq!(card["deposit"]["reason"], "unattributed_cancel", "{card}");
}

/// Review round 1 of #10028 (P1 held_deposit.rs:176): a late visitor cancel
/// under a 25% rule owes a quarter of the capture back. Until that refund
/// settles, the card says it is owed, not made; once it settles, the card
/// says it was made. Both keep the balance and Return deposit.
#[test]
fn a_partial_refund_still_owed_is_not_shown_as_made() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned_with_terms(&clock, late_refund_terms(25));
    let booked = captured_booking(&fixture, "pi_owed_line", 9);
    cancel(&fixture, &booked, NOW + 120);
    assert_eq!(
        fixture.state_of("pi_owed_line"),
        DepositState::RefundDue {
            amount_minor: 1_000
        }
    );
    let card_row = format!("booking:{}", booked.calendar.event_ref.to_hex());
    let host = fixture.vault.memory(fixture.host, EdgeActorClass::Human);
    fixture.set_clock(NOW + 180);
    let owed = open_booking_row(&host, &card_row);
    assert_eq!(
        owed["deposit"],
        serde_json::json!({
            "held": "balance_after_owed_refund",
            "amount_minor": 3_000,
            "currency": "usd",
            "reason": "cancelled",
            "line": "Booking at 2026-03-02 09:00 (UTC) was cancelled. A partial refund of its \
                     deposit is owed and not yet made; 30.00 USD more is still held. Choose \
                     Return deposit to refund the balance once that refund is made.",
            "return_offered": true,
        }),
        "{owed}"
    );

    let mut provider = KeyedRefundProvider::default();
    drain_settle_rows(&fixture, &mut provider, NOW + 240);
    assert_eq!(
        fixture.state_of("pi_owed_line"),
        DepositState::Refunded {
            amount_minor: 1_000
        }
    );
    fixture.set_clock(NOW + 360);
    let made = open_booking_row(&host, &card_row);
    assert_eq!(
        made["deposit"],
        serde_json::json!({
            "held": "balance_after_refund",
            "amount_minor": 3_000,
            "currency": "usd",
            "reason": "cancelled",
            "line": "Booking at 2026-03-02 09:00 (UTC) was cancelled. 30.00 USD of its deposit \
                     is still held after a partial refund. Choose Return deposit to refund the \
                     balance.",
            "return_offered": true,
        }),
        "{made}"
    );
}

// Review round 2 of #10028.

/// Review round 2 of #10028 (P1 held_deposit.rs:134): the host deletes the
/// booking after the start from the calendar it was written to, while the
/// visitor's calendar still shows it; the visitor's calendar then leaves it
/// out, and that omission concludes the cancel. The host's delete, first
/// seen after the start, moved no money (DEPOSIT-HOST-CANCEL-AFTER-START =
/// A), so the held deposit is listed as a calendar's cancel.
#[test]
fn a_host_delete_after_the_start_that_an_omission_concludes_lists_the_held_deposit() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned(&clock, None);
    let booked = captured_booking(&fixture, "pi_late_delete_then_omission", 9);
    let start = slot_at(9).start;
    let host_seat = host_seat_reading_and_written(&fixture, &booked, start, NOW + 54);
    let visitor = Seat::install(&fixture.vault, VISITOR_SEAT_SYSTEM);
    read_booking_on_seat(&visitor, &fixture, &booked, start, NOW + 56);
    fixture.set_clock(start + 60);
    seat_tombstone(&host_seat, &fixture, &booked, start + 60)
        .expect("the host's delete after the start");
    fixture.set_clock(start + 120);
    visitor
        .pull(
            &fixture.vault,
            &[SeatChange::omitted(&booked.calendar.uid)],
            start + 120,
        )
        .expect("the visitor calendar's omission");
    approve_imported_status(&fixture.vault, booked.calendar.event_ref);
    assert_eq!(
        fixture.state_of("pi_late_delete_then_omission"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a host delete first seen after the start moves no money"
    );

    let row = format!("{HELD_DEPOSIT_ROW}{}", booked.calendar.event_ref.to_hex());
    assert_eq!(
        held_deposit_rows(&fixture, fixture.host, start + 180),
        vec![row.clone()],
        "the host's delete lists the held deposit, though an omission concluded the cancel"
    );
    let card = open_booking_row(
        &fixture.vault.memory(fixture.host, EdgeActorClass::Human),
        &row,
    );
    assert_eq!(card["status"], "cancelled", "{card}");
    assert_eq!(card["deposit"]["reason"], "calendar_cancel", "{card}");
    assert_eq!(card["deposit"]["return_offered"], true, "{card}");
}

/// Review round 2 of #10028 (P1 owner_card.rs:222): before the start, a
/// calendar the booking was never written to cancels it in one second, and
/// the host marks the held row done in that second; the replay of the
/// owner's cancelled write then reads a copy with its marker dropped, in the
/// same second. The row's time does not move, but the cancel Oneiron cannot
/// attribute is a new version of the row: it comes back new, under the same
/// handle.
#[test]
fn a_held_deposit_row_marked_done_comes_back_when_its_cancel_turns_unattributed_in_one_second() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned(&clock, None);
    let booked = captured_booking(&fixture, "pi_done_then_unattributed_same_second", 9);
    let event = booked.calendar.event_ref;
    let slot = slot_at(9);
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let live = seat.write(&fixture.vault, event, NOW + 55);
    pull_seat(&seat, &fixture, &live, slot.start, 0, false, NOW + 60)
        .expect("the seat's first pull");
    let second = NOW + 120;
    fixture.set_clock(second);
    cancel_on_unwritten_calendar(&fixture, &booked, second);
    let row = format!("{HELD_DEPOSIT_ROW}{}", event.to_hex());
    let board = || -> Vec<(String, oneiron::agent_inbox_lens::AgentInboxReadState)> {
        fixture
            .vault
            .agent_inbox_board_slice(fixture.host, 500, second)
            .expect("the host's board")
            .rows
            .into_iter()
            .map(|(item, state)| (item.item_id, state))
            .filter(|(id, _)| id.starts_with(HELD_DEPOSIT_ROW))
            .collect()
    };
    assert_eq!(
        board(),
        vec![(
            row.clone(),
            oneiron::agent_inbox_lens::AgentInboxReadState::New
        )]
    );
    let host = fixture.vault.memory(fixture.host, EdgeActorClass::Human);
    oneiron::verbs::invoke(
        &host,
        "self.inbox.done",
        serde_json::json!({ "item_id": row }),
    )
    .expect("the host marks the held row done");
    assert!(board().is_empty(), "a row marked done leaves");

    let stored = seat.write_with_lost_answer(&fixture.vault, event, second);
    let copy = seat.stripped_rewrite_of_own_write(&live, stored, second);
    seat.replay_refused_over(&fixture.vault, event, &copy, second);
    seat.pull(&fixture.vault, std::slice::from_ref(&copy), second)
        .expect("seat pull");
    assert_eq!(
        fixture.state_of("pi_done_then_unattributed_same_second"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "the copy with its marker dropped moves no money"
    );
    assert_eq!(
        board(),
        vec![(
            row.clone(),
            oneiron::agent_inbox_lens::AgentInboxReadState::New
        )],
        "the unattributed cancel in the same second brings the row back"
    );
    let card = open_booking_row(&host, &row);
    assert_eq!(card["deposit"]["reason"], "unattributed_cancel", "{card}");
}

/// Review round 2 of #10028 (P1 read_state.rs:197): a booking's row is
/// listed on the day it was confirmed only. On a later day the booking has
/// started, and its held deposit, which a start lists on no row of its own,
/// is on its card alone: the booking handle the host kept still opens that
/// card, with Return deposit.
#[test]
fn a_kept_booking_handle_opens_its_card_on_a_later_day() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned(&clock, None);
    let booked = captured_booking(&fixture, "pi_kept_handle", 9);
    let card_row = format!("booking:{}", booked.calendar.event_ref.to_hex());
    let host = fixture.vault.memory(fixture.host, EdgeActorClass::Human);
    let next_day = NOW + 86_400;
    assert!(
        held_deposit_rows(&fixture, fixture.host, next_day).is_empty(),
        "a started booking lists no held deposit row"
    );
    let listed = fixture
        .vault
        .agent_inbox_slice(fixture.host, 500, None)
        .expect("the host's inbox slice");
    assert!(
        !listed.iter().any(|item| item.item_id == card_row),
        "the booking's row has left the same-day listing"
    );
    let opened = oneiron::verbs::invoke(
        &host,
        "self.inbox.get",
        serde_json::json!({ "item_id": card_row }),
    );
    assert!(
        opened.is_ok(),
        "the kept booking handle opens on a later day: {opened:?}"
    );
    let card = opened.expect("the kept booking handle opens")["booking"].clone();
    assert_eq!(card["deposit"]["reason"], "started", "{card}");
    assert_eq!(card["deposit"]["held"], "captured", "{card}");
    assert_eq!(card["deposit"]["return_offered"], true, "{card}");
}

// The emergency repick's note (BK-DEPOSIT-HOST-CANCEL-AFTER-START-OWNER-LINE
// PR 3; RULING DEPOSIT-PICK-AFTER-EMERGENCY-CANCEL = A, Engine 15 Nov 19:08).
// A booking the visitor takes again from the owner's emergency proposals
// carries no deposit, because the emergency cancel gave it back whole; the
// owner's card of that booking says so. The line names no owner: in a shared
// vault every live owner reads the card, and the emergency cancel may be
// another owner's (review round 1 of #10073). Nor does it say which act
// refunded or released the deposit, or when: the settle may find it refunded
// by hand in the Stripe dashboard before the emergency cancel (review round 2
// of #10073). Each card is read through the verbs by name, so the pre-fix
// head builds these tests: its red is an assert.

/// The owner cancels `booked`, which starts at `hour`, in a BK-09 emergency
/// at `now`, before its start, with its proposals delivered; then the
/// visitor picks the emergency's first proposal at `picked_at`. Returns the
/// picked slot, at which the booking stands confirmed again.
fn emergency_cancel_then_repick(
    fixture: &Fixture,
    booked: &ConfirmReceipt,
    hour: u64,
    now: u64,
    picked_at: u64,
) -> TimeRange {
    install_owner_delivery(fixture);
    let window = TimeRange {
        start: slot_at(hour).start,
        end: slot_at(hour).end - 1,
    };
    fixture.set_clock(now);
    let authority = fixture
        .vault
        .memory(fixture.host, EdgeActorClass::Human)
        .record_emergency_instruction(&EmergencyInstructionInput {
            affected_window: CalendarRangeDto {
                start: window.start,
                end: window.end,
            },
            reason: "unavailable".to_owned(),
            action_policy: EmergencyActionPolicy::Cancel,
            recorded_at: now,
        })
        .expect("the owner logs the emergency instruction");
    let request = EmergencyRescheduleRequest {
        owner_ref: fixture.host,
        affected_window: window,
        reason: "unavailable".to_owned(),
        action_policy: EmergencyActionPolicy::Cancel,
        authority,
    };
    let batch = plan_emergency_reschedule(&fixture.vault, &request, &fixture.calendars(), now)
        .expect("plan the emergency");
    assert!(batch.refusals.is_empty(), "{:?}", batch.refusals);
    let [plan] = batch.plans.as_slice() else {
        panic!("one plan for the one booking: {:?}", batch.plans.len());
    };
    assert_eq!(plan.booking().calendar.event_ref, booked.calendar.event_ref);
    let proposal = plan
        .proposals()
        .first()
        .expect("the emergency proposes a slot");
    let picked = TimeRange {
        start: proposal.start_utc,
        end: proposal.end_utc,
    };
    let item = execute_emergency_plan(
        &fixture.vault,
        &request,
        plan,
        &fixture.calendars(),
        &fixture.consumer(now),
        &mut DeliveringSink,
    )
    .expect("the owner's emergency cancel commits")
    .item;
    assert!(item.calendar_delivered && item.apology_delivered);
    let card = open_booking_row(
        &fixture.vault.memory(fixture.host, EdgeActorClass::Human),
        &format!("booking:{}", booked.calendar.event_ref.to_hex()),
    );
    assert_eq!(card["status"], "cancelled", "{card}");
    assert!(
        card.get("emergency_return").is_none(),
        "the cancelled booking carries no repick note: {card}"
    );
    fixture.set_clock(picked_at);
    let action = item.actions.first().expect("the first proposal's action");
    counterparty_pick(
        &fixture.vault,
        action,
        &fixture.calendars(),
        &fixture.consumer(picked_at),
        &mut DeliveringSink,
    )
    .expect("the visitor picks the first proposal");
    picked
}

/// `Booking at <date> <time> (UTC)`, the label the owner's lines give the
/// booking that starts at `start`.
fn booking_label_utc(start: u64) -> String {
    let wall = oneiron::calendar::utc_to_wall(start, "UTC").expect("a UTC wall time");
    format!(
        "Booking at {:04}-{:02}-{:02} {:02}:{:02} (UTC)",
        wall.y, wall.mo, wall.d, wall.h, wall.mi
    )
}

/// A captured deposit: the owner's emergency cancel owes it back whole, the
/// visitor picks one of its proposals, and the booking stands confirmed
/// again with no deposit. Its card says the refund of the deposit from
/// before the emergency cancel is pending, then, once the provider refunded
/// it, that no deposit is held and that deposit is refunded. It offers no
/// Return deposit.
#[test]
fn a_booking_picked_again_after_an_emergency_cancel_says_its_deposit_was_refunded() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned(&clock, None);
    let booked = captured_booking(&fixture, "pi_repick_refund", 9);
    let picked = emergency_cancel_then_repick(&fixture, &booked, 9, NOW + 90, NOW + 120);
    assert_eq!(
        fixture.state_of("pi_repick_refund"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "the emergency cancel owes the whole deposit back; the pick takes none"
    );
    let host = fixture.vault.memory(fixture.host, EdgeActorClass::Human);
    let card_row = format!("booking:{}", booked.calendar.event_ref.to_hex());
    let label = booking_label_utc(picked.start);
    fixture.set_clock(NOW + 150);
    let card = open_booking_row(&host, &card_row);
    assert_eq!(card["status"], "confirmed", "{card}");
    assert_eq!(card["start_utc"], picked.start, "{card}");
    assert!(card.get("deposit").is_none(), "nothing is held: {card}");
    assert_eq!(
        card["emergency_return"],
        serde_json::json!({
            "returned": "refund_pending",
            "line": format!(
                "{label}: no new deposit held; the refund of the deposit from before the \
                 emergency cancel is pending."
            ),
        }),
        "{card}"
    );

    settle_booking_deposit(
        &fixture.vault,
        &booked.calendar.event_ref,
        &mut AgreeingProvider,
        NOW + 180,
    )
    .expect("the refund settles");
    assert_eq!(
        fixture.state_of("pi_repick_refund"),
        DepositState::Refunded {
            amount_minor: 4_000
        }
    );
    fixture.set_clock(NOW + 210);
    let card = open_booking_row(&host, &card_row);
    assert!(card.get("deposit").is_none(), "nothing is held: {card}");
    assert_eq!(
        card["emergency_return"],
        serde_json::json!({
            "returned": "refunded",
            "line": format!(
                "{label}: no deposit held; the deposit from before the emergency cancel is \
                 refunded."
            ),
        }),
        "{card}"
    );
}

/// A deposit still to capture: the owner's emergency cancel releases it,
/// and the card of the booking the visitor picks again says the release of
/// the deposit from before the emergency cancel is pending, then that no
/// deposit is held and that deposit is released.
#[test]
fn a_booking_picked_again_after_an_emergency_cancel_says_its_deposit_was_released() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned(&clock, None);
    let booked = paid_booking(
        &fixture,
        SessionKey::derive(b"repick-release"),
        "pi_repick_release",
        9,
    );
    assert_eq!(
        fixture.state_of("pi_repick_release"),
        DepositState::CaptureDue {
            amount_minor: 4_000
        }
    );
    let picked = emergency_cancel_then_repick(&fixture, &booked, 9, NOW + 90, NOW + 120);
    assert_eq!(fixture.state_of("pi_repick_release"), DepositState::VoidDue);
    let host = fixture.vault.memory(fixture.host, EdgeActorClass::Human);
    let card_row = format!("booking:{}", booked.calendar.event_ref.to_hex());
    let label = booking_label_utc(picked.start);
    fixture.set_clock(NOW + 150);
    let card = open_booking_row(&host, &card_row);
    assert_eq!(card["status"], "confirmed", "{card}");
    assert_eq!(
        card["emergency_return"],
        serde_json::json!({
            "returned": "release_pending",
            "line": format!(
                "{label}: no new deposit held; the release of the deposit from before the \
                 emergency cancel is pending."
            ),
        }),
        "{card}"
    );

    settle_booking_deposit(
        &fixture.vault,
        &booked.calendar.event_ref,
        &mut AgreeingProvider,
        NOW + 180,
    )
    .expect("the release settles");
    assert_eq!(fixture.state_of("pi_repick_release"), DepositState::Voided);
    fixture.set_clock(NOW + 210);
    let card = open_booking_row(&host, &card_row);
    assert!(card.get("deposit").is_none(), "nothing is held: {card}");
    assert_eq!(
        card["emergency_return"],
        serde_json::json!({
            "returned": "released",
            "line": format!(
                "{label}: no deposit held; the deposit from before the emergency cancel is \
                 released."
            ),
        }),
        "{card}"
    );
}

// FIX [BK-DEPOSIT-FAILED-REFUND-SURFACE]: a refund the provider ends with
// nothing paid back (Stripe's `failed` or `canceled`, a closed card, say).

/// A provider that keeps each refund by its idempotency key, as
/// [`KeyedRefundProvider`] does, and, while `end_new_refunds` is set, ends a
/// refund asked under a key it has not seen with nothing paid back, as
/// Stripe ends a refund failed: every later ask under that key answers the
/// same. `part_refunded_by_hand` says, on each ended answer, that refunds
/// made by hand cover a part of what is owed.
#[derive(Default)]
struct EndingRefundProvider {
    end_new_refunds: bool,
    part_refunded_by_hand: bool,
    /// The keys whose refund ended unpaid, in order.
    ended: Vec<String>,
    /// The key of every refund asked, in order.
    asked: Vec<String>,
    keyed: KeyedRefundProvider,
}

impl DepositSettlementPort for EndingRefundProvider {
    fn settle(
        &mut self,
        request: &DepositSettleRequest<'_>,
    ) -> Result<u64, DepositProviderFailure> {
        if matches!(request.movement, DepositSettleMove::Refund { .. }) {
            let key = request.idempotency_key.to_owned();
            self.asked.push(key.clone());
            let new = !self.ended.contains(&key) && !self.keyed.refunds.contains_key(&key);
            if new && self.end_new_refunds {
                self.ended.push(key.clone());
            }
            if self.ended.contains(&key) {
                return Err(DepositProviderFailure::RefundEndedUnpaid {
                    reason: format!("the refund under {key} failed"),
                    part_refunded_by_hand: self.part_refunded_by_hand,
                });
            }
        }
        self.keyed.settle(request)
    }
}

/// The board of the host's INBOX at `now`: its held-deposit rows and their
/// read states.
fn held_deposit_board(
    fixture: &Fixture,
    now: u64,
) -> Vec<(String, oneiron::agent_inbox_lens::AgentInboxReadState)> {
    fixture.set_clock(now);
    fixture
        .vault
        .agent_inbox_board_slice(fixture.host, 500, now)
        .expect("the host's board")
        .rows
        .into_iter()
        .map(|(item, state)| (item.item_id, state))
        .filter(|(id, _)| id.starts_with(HELD_DEPOSIT_ROW))
        .collect()
}

/// A late visitor cancel under a 50% rule owes half the capture back, and
/// the provider ends that refund unpaid: it stays owed, the hourly ask
/// makes no second refund under its key, and the host's booking card says
/// the refund did not go through, as a held-deposit INBOX row of its own
/// though a visitor cancelled (BK-DEPOSIT-FAILED-REFUND-INBOX = A). The
/// host's Return deposit asks for the same half again under a new key, and
/// a second press changes nothing; the half the terms keep stays kept, on
/// the booking card only.
#[test]
fn the_host_asks_again_for_a_refund_the_provider_ended_unpaid() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned_with_terms(&clock, late_refund_terms(50));
    let booked = captured_booking(&fixture, "pi_ended_late", 9);
    cancel(&fixture, &booked, NOW + 120);
    let owed = DepositState::RefundDue {
        amount_minor: 2_000,
    };
    assert_eq!(fixture.state_of("pi_ended_late"), owed);
    let mut provider = EndingRefundProvider {
        end_new_refunds: true,
        ..EndingRefundProvider::default()
    };
    drain_settle_rows(&fixture, &mut provider, NOW + 180);
    assert_eq!(
        provider.ended.len(),
        1,
        "guard: the provider ended the refund"
    );
    let first_key = provider.ended[0].clone();
    assert!(!first_key.contains("-retry-"), "{first_key}");
    assert_eq!(
        fixture.state_of("pi_ended_late"),
        owed,
        "a refund ended unpaid stays owed"
    );

    let card_row = format!("booking:{}", booked.calendar.event_ref.to_hex());
    let host = fixture.vault.memory(fixture.host, EdgeActorClass::Human);
    fixture.set_clock(NOW + 240);
    let card = open_booking_row(&host, &card_row);
    assert_eq!(
        card["deposit"],
        serde_json::json!({
            "held": "refund_ended_unpaid",
            "amount_minor": 2_000,
            "currency": "usd",
            "reason": "cancelled",
            "line": "Booking at 2026-03-02 09:00 (UTC) was cancelled. The refund of 20.00 USD to \
                     the visitor did not go through at Stripe. Choose Return deposit to ask \
                     Stripe again, or refund it by hand in the Stripe dashboard.",
            "return_offered": true,
        }),
        "{card}"
    );
    let row = format!("{HELD_DEPOSIT_ROW}{}", booked.calendar.event_ref.to_hex());
    assert_eq!(
        held_deposit_rows(&fixture, fixture.host, NOW + 240),
        vec![row.clone()],
        "the stuck refund lists on the INBOX, whatever cancelled the booking"
    );
    assert_eq!(
        open_booking_row(&host, &row)["deposit"],
        card["deposit"],
        "the row opens the same card"
    );

    // The hourly ask finds the ended refund under its key again and makes
    // no second one.
    drain_settle_rows(&fixture, &mut provider, NOW + 3_800);
    assert_eq!(provider.asked, vec![first_key.clone(), first_key.clone()]);
    assert_eq!(fixture.state_of("pi_ended_late"), owed);

    provider.end_new_refunds = false;
    fixture.set_clock(NOW + 3_900);
    let retry = refund_deposit(&host, &booked).expect("the host asks again");
    assert_eq!(
        retry,
        serde_json::json!({
            "event_ref": booked.calendar.event_ref.to_hex(),
            "state": "refund_due",
            "amount_minor": 2_000,
            "currency": "usd",
            "queued": true,
        }),
        "the same half is asked again, and nothing more"
    );
    assert_eq!(fixture.state_of("pi_ended_late"), owed);
    let card = open_booking_row(&host, &card_row);
    assert!(
        card.get("deposit").is_none(),
        "the line goes while the refund is asked again: {card}"
    );
    assert!(
        held_deposit_rows(&fixture, fixture.host, NOW + 3_900).is_empty(),
        "so does the row"
    );
    let again = refund_deposit(&host, &booked).expect("a second press answers");
    assert_eq!(
        again["queued"], false,
        "a second press changes nothing: {again}"
    );

    drain_settle_rows(&fixture, &mut provider, NOW + 3_960);
    let second_key = provider.asked.last().expect("a refund asked again").clone();
    assert_ne!(
        second_key, first_key,
        "the refund asked again has a key of its own"
    );
    assert!(second_key.contains("-retry-1-"), "{second_key}");
    assert_eq!(
        fixture.state_of("pi_ended_late"),
        DepositState::Refunded {
            amount_minor: 2_000
        }
    );
    assert_eq!(
        provider.keyed.refunded_minor(),
        2_000,
        "the visitor's half is refunded once, and the half the terms keep is not"
    );
    fixture.set_clock(NOW + 4_100);
    let card = open_booking_row(&host, &card_row);
    assert_eq!(card["deposit"]["held"], "balance_after_refund", "{card}");
    assert_eq!(
        card["deposit"]["line"],
        "Booking at 2026-03-02 09:00 (UTC) was cancelled. 20.00 USD of its deposit is still held \
         after a partial refund. Choose Return deposit to refund the balance.",
        "{card}"
    );
    assert!(
        held_deposit_rows(&fixture, fixture.host, NOW + 4_100).is_empty(),
        "the half a visitor's late cancel keeps is on the booking card only"
    );
}

/// A calendar the booking was never written to cancels it, so its held
/// deposit is listed; the host marks the row done and returns the deposit.
/// The provider ends that refund unpaid: the row comes back, new, with the
/// stuck-refund line. The host marks it done and asks again; the provider
/// ends that refund unpaid too, and the row comes back once more. The third
/// ask, under the next key, is refunded, and the row goes.
#[test]
fn a_refund_ended_unpaid_again_after_the_hosts_ask_comes_back_to_the_inbox() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned(&clock, None);
    let booked = captured_booking(&fixture, "pi_ended_twice", 9);
    cancel_on_unwritten_calendar(&fixture, &booked, NOW + 120);
    let row = format!("{HELD_DEPOSIT_ROW}{}", booked.calendar.event_ref.to_hex());
    let new = oneiron::agent_inbox_lens::AgentInboxReadState::New;
    assert_eq!(
        held_deposit_board(&fixture, NOW + 130),
        vec![(row.clone(), new)]
    );
    let host = fixture.vault.memory(fixture.host, EdgeActorClass::Human);
    let done = || {
        oneiron::verbs::invoke(
            &host,
            "self.inbox.done",
            serde_json::json!({ "item_id": row }),
        )
        .expect("the host marks the held row done");
    };
    done();
    assert!(held_deposit_board(&fixture, NOW + 135).is_empty());
    fixture.set_clock(NOW + 140);
    let returned = refund_deposit(&host, &booked).expect("the host returns the deposit");
    assert_eq!(returned["queued"], true, "{returned}");

    let mut provider = EndingRefundProvider {
        end_new_refunds: true,
        ..EndingRefundProvider::default()
    };
    drain_settle_rows(&fixture, &mut provider, NOW + 180);
    assert_eq!(
        provider.ended.len(),
        1,
        "guard: the provider ended the refund"
    );
    assert_eq!(
        held_deposit_board(&fixture, NOW + 300),
        vec![(row.clone(), new)],
        "the stuck refund brings the row back"
    );
    let card = open_booking_row(&host, &row);
    assert_eq!(
        card["deposit"],
        serde_json::json!({
            "held": "refund_ended_unpaid",
            "amount_minor": 4_000,
            "currency": "usd",
            "reason": "calendar_cancel",
            "line": "Booking at 2026-03-02 09:00 (UTC) was cancelled in a calendar. The refund of \
                     40.00 USD to the visitor did not go through at Stripe. Choose Return \
                     deposit to ask Stripe again, or refund it by hand in the Stripe dashboard.",
            "return_offered": true,
        }),
        "{card}"
    );

    done();
    assert!(held_deposit_board(&fixture, NOW + 310).is_empty());
    fixture.set_clock(NOW + 320);
    let retry = refund_deposit(&host, &booked).expect("the host asks again");
    assert_eq!(retry["queued"], true, "{retry}");
    drain_settle_rows(&fixture, &mut provider, NOW + 360);
    assert_eq!(
        provider.ended.len(),
        2,
        "guard: the provider ended the second ask"
    );
    assert!(
        provider.ended[1].contains("-retry-1-"),
        "{:?}",
        provider.ended
    );
    assert_eq!(
        held_deposit_board(&fixture, NOW + 480),
        vec![(row.clone(), new)],
        "the second stuck refund brings the row back again"
    );

    provider.end_new_refunds = false;
    fixture.set_clock(NOW + 500);
    let retry = refund_deposit(&host, &booked).expect("the host asks a third time");
    assert_eq!(retry["queued"], true, "{retry}");
    drain_settle_rows(&fixture, &mut provider, NOW + 540);
    let last_key = provider.asked.last().expect("a refund asked").clone();
    assert!(last_key.contains("-retry-2-"), "{last_key}");
    assert_eq!(
        fixture.state_of("pi_ended_twice"),
        DepositState::Refunded {
            amount_minor: 4_000
        }
    );
    assert_eq!(
        provider.keyed.refunded_minor(),
        4_000,
        "refunded once, whole"
    );
    assert!(
        held_deposit_board(&fixture, NOW + 700).is_empty(),
        "the refund made ends the row"
    );
}

/// A refund the provider ended unpaid that a hand refund then covers (the
/// provider answers the owed amount under the ended key, as Stripe's
/// answer reads a covering dashboard refund): the deposit is refunded, the
/// line goes, and no refund is asked under a new key.
#[test]
fn a_hand_refund_after_a_refund_ended_unpaid_ends_the_line() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned_with_terms(&clock, late_refund_terms(50));
    let booked = captured_booking(&fixture, "pi_ended_by_hand", 9);
    cancel(&fixture, &booked, NOW + 120);
    let mut provider = EndingRefundProvider {
        end_new_refunds: true,
        ..EndingRefundProvider::default()
    };
    drain_settle_rows(&fixture, &mut provider, NOW + 180);
    let card_row = format!("booking:{}", booked.calendar.event_ref.to_hex());
    let host = fixture.vault.memory(fixture.host, EdgeActorClass::Human);
    fixture.set_clock(NOW + 240);
    let card = open_booking_row(&host, &card_row);
    assert_eq!(card["deposit"]["held"], "refund_ended_unpaid", "{card}");

    // The owner refunds the half by hand; the next hourly ask finds it.
    let ended = std::mem::take(&mut provider.ended);
    for key in ended {
        provider.keyed.refunds.insert(key, 2_000);
    }
    provider.end_new_refunds = false;
    drain_settle_rows(&fixture, &mut provider, NOW + 3_800);
    assert_eq!(
        fixture.state_of("pi_ended_by_hand"),
        DepositState::Refunded {
            amount_minor: 2_000
        }
    );
    fixture.set_clock(NOW + 3_900);
    let card = open_booking_row(&host, &card_row);
    assert_eq!(card["deposit"]["held"], "balance_after_refund", "{card}");
    assert_eq!(
        provider.asked.len(),
        2,
        "no refund was asked under a new key: {:?}",
        provider.asked
    );
}

/// Review round 1 of #10149: the owner's emergency cancel owes the captured
/// deposit back whole, the visitor picks a later slot from its proposals,
/// and the provider ends that refund unpaid. Before the slot picked again
/// starts, the card of that booking says so, with Return deposit, and so
/// does a held-deposit INBOX row dated by the failure; the emergency line
/// says the refund did not go through. Return deposit asks for it again,
/// and once it is refunded the card says so.
#[test]
fn a_refund_ended_unpaid_after_an_emergency_cancel_shows_on_the_booking_picked_again() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned(&clock, None);
    let booked = captured_booking(&fixture, "pi_repick_ended", 9);
    let picked = emergency_cancel_then_repick(&fixture, &booked, 9, NOW + 90, NOW + 120);
    assert_eq!(
        fixture.state_of("pi_repick_ended"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "guard: the emergency cancel owes the whole deposit back"
    );
    let mut provider = EndingRefundProvider {
        end_new_refunds: true,
        ..EndingRefundProvider::default()
    };
    drain_settle_rows(&fixture, &mut provider, NOW + 180);
    assert_eq!(
        provider.ended.len(),
        1,
        "guard: the provider ended the refund"
    );

    let host = fixture.vault.memory(fixture.host, EdgeActorClass::Human);
    let card_row = format!("booking:{}", booked.calendar.event_ref.to_hex());
    let label = booking_label_utc(picked.start);
    assert!(
        picked.start > NOW + 240,
        "guard: the slot picked again has not started"
    );
    fixture.set_clock(NOW + 240);
    let card = open_booking_row(&host, &card_row);
    assert_eq!(card["status"], "confirmed", "{card}");
    assert_eq!(
        card["deposit"],
        serde_json::json!({
            "held": "refund_ended_unpaid",
            "amount_minor": 4_000,
            "currency": "usd",
            "reason": "picked_again_after_emergency_cancel",
            "line": format!(
                "{label} was picked again after an emergency cancel. The refund of 40.00 USD to \
                 the visitor did not go through at Stripe. Choose Return deposit to ask Stripe \
                 again, or refund it by hand in the Stripe dashboard."
            ),
            "return_offered": true,
        }),
        "{card}"
    );
    assert_eq!(
        card["emergency_return"],
        serde_json::json!({
            "returned": "refund_ended_unpaid",
            "line": format!(
                "{label}: no new deposit held; the refund of the deposit from before the \
                 emergency cancel did not go through at Stripe."
            ),
        }),
        "{card}"
    );
    let row = format!("{HELD_DEPOSIT_ROW}{}", booked.calendar.event_ref.to_hex());
    let listed: Vec<(String, u64)> = fixture
        .vault
        .agent_inbox_slice(fixture.host, 500, None)
        .expect("the host's inbox slice")
        .into_iter()
        .filter(|item| item.item_id.starts_with(HELD_DEPOSIT_ROW))
        .map(|item| (item.item_id, item.occurred_at))
        .collect();
    assert_eq!(
        listed,
        vec![(row, NOW + 180)],
        "the stuck refund lists on the INBOX, dated by the failure"
    );

    provider.end_new_refunds = false;
    fixture.set_clock(NOW + 300);
    let retry = refund_deposit(&host, &booked).expect("the host asks again");
    assert_eq!(retry["queued"], true, "{retry}");
    drain_settle_rows(&fixture, &mut provider, NOW + 360);
    let last_key = provider.asked.last().expect("a refund asked").clone();
    assert!(last_key.contains("-retry-1-"), "{last_key}");
    assert_eq!(
        fixture.state_of("pi_repick_ended"),
        DepositState::Refunded {
            amount_minor: 4_000
        }
    );
    fixture.set_clock(NOW + 400);
    let card = open_booking_row(&host, &card_row);
    assert!(card.get("deposit").is_none(), "nothing is held: {card}");
    assert_eq!(card["emergency_return"]["returned"], "refunded", "{card}");
}

/// Review round 1 of #10149: the provider ends the host's refund unpaid,
/// the host marks the held row done and asks again, and the provider ends
/// that ask unpaid too, in the same second. The row comes back, new.
#[test]
fn a_refund_ended_unpaid_again_in_the_same_second_comes_back_to_the_inbox() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned(&clock, None);
    let booked = captured_booking(&fixture, "pi_ended_same_second", 9);
    cancel_on_unwritten_calendar(&fixture, &booked, NOW + 120);
    let row = format!("{HELD_DEPOSIT_ROW}{}", booked.calendar.event_ref.to_hex());
    let host = fixture.vault.memory(fixture.host, EdgeActorClass::Human);
    fixture.set_clock(NOW + 140);
    let returned = refund_deposit(&host, &booked).expect("the host returns the deposit");
    assert_eq!(returned["queued"], true, "{returned}");

    let mut provider = EndingRefundProvider {
        end_new_refunds: true,
        ..EndingRefundProvider::default()
    };
    let at = NOW + 180;
    drain_settle_rows(&fixture, &mut provider, at);
    assert_eq!(
        provider.ended.len(),
        1,
        "guard: the provider ended the refund"
    );
    let new = oneiron::agent_inbox_lens::AgentInboxReadState::New;
    assert_eq!(held_deposit_board(&fixture, at), vec![(row.clone(), new)]);
    oneiron::verbs::invoke(
        &host,
        "self.inbox.done",
        serde_json::json!({ "item_id": row }),
    )
    .expect("the host marks the held row done");
    assert!(held_deposit_board(&fixture, at).is_empty());

    fixture.set_clock(at);
    let retry = refund_deposit(&host, &booked).expect("the host asks again");
    assert_eq!(retry["queued"], true, "{retry}");
    drain_settle_rows(&fixture, &mut provider, at);
    assert_eq!(
        provider.ended.len(),
        2,
        "guard: the provider ended the second ask, in the same second"
    );
    assert_eq!(
        held_deposit_board(&fixture, at),
        vec![(row, new)],
        "the second stuck refund brings the row back"
    );
}

/// Review round 1 of #10149: the provider ends the refund unpaid and says
/// refunds made by hand in its dashboard cover a part of what is owed. The
/// host's card says only a hand refund pays the rest, as a held-deposit
/// INBOX row of its own, and Return deposit asks the provider nothing: the
/// hourly ask stays under the first key.
#[test]
fn a_refund_ended_unpaid_beside_a_part_refunded_by_hand_is_asked_no_more() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned_with_terms(&clock, late_refund_terms(50));
    let booked = captured_booking(&fixture, "pi_ended_part_by_hand", 9);
    cancel(&fixture, &booked, NOW + 120);
    let mut provider = EndingRefundProvider {
        end_new_refunds: true,
        part_refunded_by_hand: true,
        ..EndingRefundProvider::default()
    };
    drain_settle_rows(&fixture, &mut provider, NOW + 180);
    assert_eq!(
        provider.ended.len(),
        1,
        "guard: the provider ended the refund"
    );
    let first_key = provider.ended[0].clone();

    let card_row = format!("booking:{}", booked.calendar.event_ref.to_hex());
    let host = fixture.vault.memory(fixture.host, EdgeActorClass::Human);
    fixture.set_clock(NOW + 240);
    let card = open_booking_row(&host, &card_row);
    assert_eq!(
        card["deposit"],
        serde_json::json!({
            "held": "refund_ended_unpaid_part_refunded_by_hand",
            "amount_minor": 2_000,
            "currency": "usd",
            "reason": "cancelled",
            "line": "Booking at 2026-03-02 09:00 (UTC) was cancelled. The refund of 20.00 USD to \
                     the visitor did not go through at Stripe, and refunds made by hand in the \
                     Stripe dashboard cover only part of it. Refund the rest by hand in the \
                     Stripe dashboard.",
            "return_offered": false,
        }),
        "Return deposit moves nothing here, so the card offers none (review round 2 of \
         #10149): {card}"
    );
    let row = format!("{HELD_DEPOSIT_ROW}{}", booked.calendar.event_ref.to_hex());
    assert_eq!(
        held_deposit_rows(&fixture, fixture.host, NOW + 240),
        vec![row.clone()],
        "the stuck refund lists on the INBOX"
    );
    assert_eq!(
        open_booking_row(&host, &row)["deposit"],
        card["deposit"],
        "the row opens the same card, though it offers no Return deposit"
    );

    fixture.set_clock(NOW + 300);
    let again = refund_deposit(&host, &booked).expect("the host's press answers");
    assert_eq!(
        again["queued"], false,
        "Return deposit asks nothing: {again}"
    );
    drain_settle_rows(&fixture, &mut provider, NOW + 3_800);
    assert_eq!(
        provider.asked,
        vec![first_key.clone(), first_key],
        "only the hourly ask under the first key"
    );
    assert_eq!(
        fixture.state_of("pi_ended_part_by_hand"),
        DepositState::RefundDue {
            amount_minor: 2_000
        }
    );
}

/// Review round 2 of #10149: the owner's emergency cancel owes the captured
/// deposit back whole, the visitor picks a later slot from its proposals,
/// and the provider ends that refund unpaid. The host asks again, and before
/// that refund settles presses Return deposit a second time on the booking
/// picked again, which stands live and has not started: the press changes
/// nothing and answers so, as on a cancelled booking, and the refund is made
/// once.
#[test]
fn a_second_press_on_a_picked_again_booking_while_its_refund_is_asked_again_changes_nothing() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned(&clock, None);
    let booked = captured_booking(&fixture, "pi_repick_pressed_twice", 9);
    let picked = emergency_cancel_then_repick(&fixture, &booked, 9, NOW + 90, NOW + 120);
    let mut provider = EndingRefundProvider {
        end_new_refunds: true,
        ..EndingRefundProvider::default()
    };
    drain_settle_rows(&fixture, &mut provider, NOW + 180);
    assert_eq!(
        provider.ended.len(),
        1,
        "guard: the provider ended the refund"
    );
    assert!(
        picked.start > NOW + 400,
        "guard: the slot picked again has not started"
    );

    let host = fixture.vault.memory(fixture.host, EdgeActorClass::Human);
    fixture.set_clock(NOW + 300);
    let retry = refund_deposit(&host, &booked).expect("the host asks again");
    assert_eq!(retry["queued"], true, "{retry}");
    let again = refund_deposit(&host, &booked).expect("a second press answers");
    assert_eq!(
        again,
        serde_json::json!({
            "event_ref": booked.calendar.event_ref.to_hex(),
            "state": "refund_due",
            "amount_minor": 4_000,
            "currency": "usd",
            "queued": false,
        }),
        "a second press while the refund is asked again changes nothing"
    );

    provider.end_new_refunds = false;
    drain_settle_rows(&fixture, &mut provider, NOW + 360);
    assert_eq!(
        provider.asked.len(),
        2,
        "the refund is asked again once: {:?}",
        provider.asked
    );
    assert_eq!(
        fixture.state_of("pi_repick_pressed_twice"),
        DepositState::Refunded {
            amount_minor: 4_000
        }
    );
    assert_eq!(provider.keyed.refunded_minor(), 4_000, "refunded once");
}

/// Review round 2 of #10149: the host's return is refunded under one settle
/// row, the provider ends it unpaid, the host asks again under a row of its
/// own, and the provider ends that ask unpaid too. On the hourly ask only
/// the row of the host's last ask asks the provider; the row queued before
/// it ends on its next run, and does not ask the same refund beside it hour
/// after hour.
#[test]
fn the_hosts_ask_again_ends_the_settle_row_queued_before_it() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned(&clock, None);
    let booked = captured_booking(&fixture, "pi_ended_rows", 9);
    cancel_on_unwritten_calendar(&fixture, &booked, NOW + 120);
    let host = fixture.vault.memory(fixture.host, EdgeActorClass::Human);
    fixture.set_clock(NOW + 140);
    let returned = refund_deposit(&host, &booked).expect("the host returns the deposit");
    assert_eq!(returned["queued"], true, "{returned}");
    let mut provider = EndingRefundProvider {
        end_new_refunds: true,
        ..EndingRefundProvider::default()
    };
    drain_settle_rows(&fixture, &mut provider, NOW + 180);
    fixture.set_clock(NOW + 320);
    let retry = refund_deposit(&host, &booked).expect("the host asks again");
    assert_eq!(retry["queued"], true, "{retry}");
    drain_settle_rows(&fixture, &mut provider, NOW + 360);
    assert_eq!(
        provider.ended.len(),
        2,
        "guard: the provider ended both asks: {:?}",
        provider.ended
    );
    let retry_key = provider.ended[1].clone();
    assert!(retry_key.contains("-retry-1-"), "{retry_key}");

    // Both rows are due again an hour after their last ask.
    let asked_before = provider.asked.len();
    let pass = run_booking_deposit_settlement(
        &fixture.vault,
        "deposit-settle-worker",
        &mut provider,
        16,
        NOW + 4_000,
    )
    .expect("the hourly pass");
    assert_eq!(
        provider.asked[asked_before..].to_vec(),
        vec![retry_key.clone()],
        "only the row of the host's last ask asks the provider"
    );
    assert_eq!(
        (pass.settled_nothing, pass.still_owed),
        (1, 1),
        "the row queued before the host's ask ends: {pass:?}"
    );
    let asked_before = provider.asked.len();
    drain_settle_rows(&fixture, &mut provider, NOW + 8_000);
    assert_eq!(
        provider.asked[asked_before..].to_vec(),
        vec![retry_key],
        "one row asks hourly from then on"
    );
    assert_eq!(
        fixture.state_of("pi_ended_rows"),
        DepositState::RefundDue {
            amount_minor: 4_000
        }
    );
}

/// Review round 2 of #10149: the provider ends the host's refund unpaid, the
/// host asks again, and refunds made by hand in the provider's dashboard
/// before that ask ran cover a part of what is owed, so the provider makes
/// no new refund and answers that the refund ended unpaid beside them. The
/// card keeps the stuck refund, says only a hand refund pays the rest and
/// offers no Return deposit; its INBOX row comes back and opens; a press asks
/// nothing.
#[test]
fn a_short_hand_refund_before_the_hosts_ask_runs_keeps_the_stuck_refund_on_the_card() {
    let clock = ManualClock::new(NOW);
    let fixture = Fixture::open_owned(&clock, None);
    let booked = captured_booking(&fixture, "pi_short_before_retry", 9);
    cancel_on_unwritten_calendar(&fixture, &booked, NOW + 120);
    let host = fixture.vault.memory(fixture.host, EdgeActorClass::Human);
    fixture.set_clock(NOW + 140);
    let returned = refund_deposit(&host, &booked).expect("the host returns the deposit");
    assert_eq!(returned["queued"], true, "{returned}");
    let mut provider = EndingRefundProvider {
        end_new_refunds: true,
        ..EndingRefundProvider::default()
    };
    drain_settle_rows(&fixture, &mut provider, NOW + 180);
    fixture.set_clock(NOW + 320);
    let retry = refund_deposit(&host, &booked).expect("the host asks again");
    assert_eq!(retry["queued"], true, "{retry}");

    // A hand refund of a part of the 40.00 lands before the ask runs.
    provider.part_refunded_by_hand = true;
    drain_settle_rows(&fixture, &mut provider, NOW + 360);
    assert_eq!(
        provider.ended.len(),
        2,
        "guard: the ask again ended beside the hand refund: {:?}",
        provider.ended
    );
    let row = format!("{HELD_DEPOSIT_ROW}{}", booked.calendar.event_ref.to_hex());
    let new = oneiron::agent_inbox_lens::AgentInboxReadState::New;
    assert_eq!(
        held_deposit_board(&fixture, NOW + 400),
        vec![(row.clone(), new)],
        "the stuck refund keeps its INBOX row"
    );
    let card = open_booking_row(&host, &row);
    assert_eq!(
        card["deposit"],
        serde_json::json!({
            "held": "refund_ended_unpaid_part_refunded_by_hand",
            "amount_minor": 4_000,
            "currency": "usd",
            "reason": "calendar_cancel",
            "line": "Booking at 2026-03-02 09:00 (UTC) was cancelled in a calendar. The refund of \
                     40.00 USD to the visitor did not go through at Stripe, and refunds made by \
                     hand in the Stripe dashboard cover only part of it. Refund the rest by hand \
                     in the Stripe dashboard.",
            "return_offered": false,
        }),
        "{card}"
    );
    fixture.set_clock(NOW + 420);
    let again = refund_deposit(&host, &booked).expect("the host's press answers");
    assert_eq!(
        again["queued"], false,
        "Return deposit asks nothing: {again}"
    );
    assert_eq!(
        fixture.state_of("pi_short_before_retry"),
        DepositState::RefundDue {
            amount_minor: 4_000
        }
    );
}
