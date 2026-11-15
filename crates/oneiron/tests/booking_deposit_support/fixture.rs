//! The deposit tests' booking fixture: a trimmed copy of the `it` booking
//! fixture (`tests/it/booking_lifecycle.rs`), as in
//! `tests/booking_calendar_cancel_reschedule.rs`, because the `it` target does
//! not compile on main today. Beside it, the page's `booking.event_type`
//! claim is stored, so the confirm writer reads the deposit terms the owner
//! configured. Only paths that exist before the deposit doors, so a red pin
//! of this file builds.

#![allow(dead_code)]

use oneiron::booking::{
    BOOKING_EVENT_TYPE_PREDICATE, BOOKING_EVENT_TYPE_SCHEMA_VERSION, BookingError,
    BookingEventTypeClaimValue, BookingLifecycleConsumerInput, BookingLifecycleTurn, BookingSolver,
    BookingVerbReceipt, BookingVerbRequest, CancelSpec, ConfirmReceipt, ConfirmSpec,
    DEFAULT_INTRO_DURATION_MIN, DepositTerms, EventTypeConfig, EventTypeKey, HoldLeaseSpec,
    HoldReceipt, HoldSpec, HostAvailabilityConfig, OpaqueLifecycleToken, RankedSlot, RoutingMode,
    SessionKey, SlotOracle, SolveRequest, SolveResult, VaultActiveHoldSource, WeeklyWallWindow,
    encode_event_type_claim_value, enqueue_booking_verb, run_booking_lifecycle_once,
};
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::{
    CalendarSel, ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject,
    DreamerHomeNodeCandidate, DreamerRunnerStore, EntityId, TimeRange, Vault, VaultConfig,
};

/// Monday 2 Mar 2026 00:00 UTC.
pub const MONDAY: u64 = 1_772_409_600;
/// 08:00 UTC: the host's working hours open at 09:00.
pub const NOW: u64 = MONDAY + 8 * 3_600;

const PAGE_SEED: u8 = 0x51;
const HOST_SEED: u8 = 0x52;
const CONFIG_SEED: u8 = 0x53;
const BOOKER_SEED: u8 = 0x57;
const BUSY_SEED: u8 = 0x61;
const HOME_NODE_ID: u64 = 9;

const fn at(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

/// `[seed; 16]`, as the shared integration helper builds it.
pub fn test_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("fixture id")
}

pub fn event_type() -> EventTypeKey {
    EventTypeKey("intro-call".to_owned())
}

pub fn fixture_config(deposit: Option<DepositTerms>) -> EventTypeConfig {
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
        deposit,
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

pub struct Fixture {
    _dir: tempfile::TempDir,
    pub vault: Vault,
    pub page: EntityId,
    pub booker: EntityId,
    pub config: EventTypeConfig,
}

impl Fixture {
    /// A vault with a booking page whose `intro-call` event type asks
    /// `deposit`, a host, a booker contact, and an elected home node.
    pub fn open(deposit: Option<DepositTerms>) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
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
        let config = fixture_config(deposit);
        let value = encode_event_type_claim_value(&BookingEventTypeClaimValue {
            schema_version: BOOKING_EVENT_TYPE_SCHEMA_VERSION,
            page_ref: page,
            config: config.clone(),
        })
        .expect("encode the configuration");
        let mut body = ClaimBody::new(
            BOOKING_EVENT_TYPE_PREDICATE,
            ClaimSubject::Entity(page),
            value,
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )
        .expect("configuration claim body");
        // The page is not a PERSON, so its configuration takes the vault's
        // default facet, as the server's booking fixture does.
        body.scope_facet = vault.default_facet().expect("default facet");
        vault
            .put_claim(&test_id(CONFIG_SEED), &body, at(1), 1)
            .expect("store the configuration claim");
        Self {
            _dir: dir,
            vault,
            page,
            booker,
            config,
        }
    }

    /// Lets a calendar feed import into this vault: the feed's import actor
    /// writes as an enrolled engine machine, as in `tests/booking_feed_move.rs`.
    pub fn enable_host_feed(&self) {
        let issuer =
            oneiron::authority::HostSlipIssuer::from_secret(b"oneiron integration test host")
                .expect("host issuer");
        self.vault
            .ensure_host_root_slip(&issuer)
            .expect("host root");
        self.vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
    }

    pub fn run(
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
                    config: self.config.clone(),
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

    /// The fixture Monday's 30-minute slots, 09:00 to 13:30 UTC.
    pub fn offered_slots(&self) -> Vec<RankedSlot> {
        LifecycleSolver {
            page: self.page,
            exclude: None,
            vault: &self.vault,
            config: self.config.clone(),
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

    pub fn hold(
        &self,
        session_key: SessionKey,
        slot: TimeRange,
        lease: HoldLeaseSpec,
        now: u64,
    ) -> Result<HoldReceipt, BookingError> {
        self.hold_type(session_key, event_type(), slot, lease, now)
    }

    pub fn hold_type(
        &self,
        session_key: SessionKey,
        event_type: EventTypeKey,
        slot: TimeRange,
        lease: HoldLeaseSpec,
        now: u64,
    ) -> Result<HoldReceipt, BookingError> {
        match self.run(
            BookingVerbRequest::Hold(HoldSpec {
                page_ref: self.page,
                event_type,
                slot,
                session_key,
                visitor_tz: "UTC".to_owned(),
                constraint: None,
                lease,
                idempotency_key: None,
            }),
            now,
        )? {
            BookingVerbReceipt::Held(hold) => Ok(hold),
            other => panic!("expected a hold receipt, got {other:?}"),
        }
    }

    pub fn confirm(
        &self,
        hold: &HoldReceipt,
        session_key: SessionKey,
        now: u64,
    ) -> Result<ConfirmReceipt, BookingError> {
        match self.run(
            BookingVerbRequest::Confirm(ConfirmSpec {
                hold_token: hold.token.clone(),
                session_key,
                booker_contact: self.booker,
                intake: Vec::new(),
                idempotency_key: None,
            }),
            now,
        )? {
            BookingVerbReceipt::Confirmed(confirmed) => Ok(confirmed),
            other => panic!("expected a confirm receipt, got {other:?}"),
        }
    }

    pub fn cancel(&self, token: &OpaqueLifecycleToken, now: u64) -> Result<(), BookingError> {
        match self.run(
            BookingVerbRequest::Cancel(CancelSpec {
                token: token.clone(),
                idempotency_key: None,
            }),
            now,
        )? {
            BookingVerbReceipt::Cancelled(_) => Ok(()),
            other => panic!("expected a cancel receipt, got {other:?}"),
        }
    }
}

struct LifecycleSolver<'a> {
    page: EntityId,
    exclude: Option<SessionKey>,
    vault: &'a Vault,
    config: EventTypeConfig,
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
            synthetic_config: Some(self.config.clone()),
        }
        .solve(req)
    }
}

pub fn slot_of(ranked: &RankedSlot) -> TimeRange {
    TimeRange {
        start: ranked.start_utc,
        end: ranked.end_utc,
    }
}
