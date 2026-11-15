//! The owner's same-day booking card (ARCH-0062:155 "every booking surfaces
//! to the owner as an inbox card same-day"; RULING INB-05-OWNER-CARD = A).
//!
//! Each booking committed or cancelled since the start of its owner's day is
//! one row of the owners' INBOX, an update the lens projects from the
//! booking's own lifecycle rows. Opening the row names the visitor, the event
//! type, the slot and the page, and offers the owner's cancel and reschedule
//! doors while the booking stands.
//!
//! The host works in Asia/Tokyo, so the owner's day turns at 15:00 UTC while
//! the UTC day goes on. A standalone file with a trimmed copy of the booking
//! fixture (`tests/booking_calendar_cancel_reschedule.rs`), because the `it`
//! target does not compile on main today. Rows are picked by their item-id
//! prefix and the opened card is read as JSON, so the file builds where the
//! engine makes no booking row. The imported-source permit is test-support
//! only.
#![cfg(feature = "test-support")]

use std::sync::Arc;

use oneiron::agent_inbox_lens::{
    AgentInboxItemKind, AgentInboxLensItem, AgentInboxLensQuery, InboxItemRequest,
};
use oneiron::booking::{
    BookingError, BookingLifecycleConsumerInput, BookingLifecycleTurn, BookingSolver,
    BookingVerbReceipt, BookingVerbRequest, CancelSpec, ConfirmReceipt, ConfirmSpec,
    DEFAULT_INTRO_DURATION_MIN, EventTypeConfig, EventTypeKey, HoldLeaseSpec, HoldReceipt,
    HoldSpec, HostAvailabilityConfig, RankedSlot, RoutingMode, SessionKey, SlotOracle,
    SolveRequest, SolveResult, VaultActiveHoldSource, WeeklyWallWindow, enqueue_booking_verb,
    run_booking_lifecycle_once,
};
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::{
    CalendarSel, DreamerHomeNodeCandidate, DreamerRunnerStore, EdgeActorClass, EntityId, TimeRange,
    Vault, VaultConfig,
};
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::json;

const MONDAY: u64 = 1_772_409_600;
/// Monday 08:00 UTC, 17:00 in the host's Tokyo.
const NOW: u64 = MONDAY + 8 * 3_600;
/// Monday 23:59 in Tokyo: the owner's day of the booking is still on.
const LAST_MINUTE_OF_THE_HOSTS_DAY: u64 = MONDAY + 15 * 3_600 - 60;
/// Tuesday 00:30 in Tokyo, still Monday 15:30 in UTC.
const NEXT_HOSTS_DAY: u64 = MONDAY + 15 * 3_600 + 30 * 60;
const HOST_TZ: &str = "Asia/Tokyo";
/// The item id prefix of a booking card's INBOX row, spelled here so the
/// file builds where the engine names no such row.
const BOOKING_ITEM_PREFIX: &str = "booking:";

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
    clock: Arc<ManualClock>,
    owner: EntityId,
    page: EntityId,
    booker: EntityId,
    actor: EntityId,
}

impl Fixture {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let clock = ManualClock::new(NOW);
        let mut config = VaultConfig::default();
        config.store_clock = clock.bundle();
        let vault = Vault::open(dir.path(), config).expect("open vault");
        let owner = vault
            .ensure_embedded_owner_actor()
            .expect("the vault's owner");
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
            clock,
            owner,
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

    /// A visitor holds `slot` and confirms it at [`NOW`]. The vault's own
    /// clock only moves forward, so a booking made after a later read
    /// leaves it where it is.
    fn book(&self, session: &[u8], slot: TimeRange) -> ConfirmReceipt {
        let session_key = SessionKey::derive(session);
        let hold: HoldReceipt = match self
            .run(
                BookingVerbRequest::Hold(HoldSpec {
                    page_ref: self.page,
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
        match self
            .run(
                BookingVerbRequest::Confirm(ConfirmSpec {
                    hold_token: hold.token.clone(),
                    session_key,
                    booker_contact: self.booker,
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

    /// The visitor cancels `booked` at `now`.
    fn cancel(&self, booked: &ConfirmReceipt, now: u64) {
        self.clock.set(now);
        self.run(
            BookingVerbRequest::Cancel(CancelSpec {
                token: booked.cancel_token.clone(),
                idempotency_key: None,
            }),
            now,
        )
        .expect("the visitor cancels");
    }

    /// The owners' INBOX rows that carry a booking card, read at `now`.
    fn booking_rows_at(&self, now: u64) -> Vec<AgentInboxLensItem> {
        self.clock.set(now);
        booking_rows_of(
            self.vault
                .agent_inbox_lens(AgentInboxLensQuery {
                    identity_ref: None,
                    limit: 500,
                    before: None,
                })
                .expect("the owners' inbox lens"),
        )
    }

    /// The owner opens `item_id`; the opened row's JSON.
    fn open_as_owner(&self, item_id: &str) -> serde_json::Value {
        let view = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .inbox_item_get(&InboxItemRequest {
                item_id: item_id.to_owned(),
            })
            .expect("the owner opens the booking row");
        serde_json::to_value(&view).expect("the opened row serializes")
    }
}

fn booking_rows_of(items: Vec<AgentInboxLensItem>) -> Vec<AgentInboxLensItem> {
    items
        .into_iter()
        .filter(|item| item.item_id.starts_with(BOOKING_ITEM_PREFIX))
        .collect()
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

/// Monday 18:00-23:00 in Tokyo: 09:00-14:00 UTC.
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
            host_tz: HOST_TZ.to_owned(),
            working_hours: vec![WeeklyWallWindow {
                weekday: 0,
                start_minute: 18 * 60,
                end_minute: 23 * 60,
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

fn item_id_of(booked: &ConfirmReceipt) -> String {
    format!(
        "{BOOKING_ITEM_PREFIX}{}",
        booked.calendar.event_ref.to_hex()
    )
}

#[test]
fn a_booking_committed_today_is_one_update_row_for_the_owners() {
    let fixture = Fixture::open();
    let slots = fixture.offered_slots();
    let booked = fixture.book(b"committed-today", slot_of(&slots[0]));

    let rows = fixture.booking_rows_at(NOW + 5);
    assert_eq!(rows.len(), 1, "one row for the one booking: {rows:?}");
    let row = &rows[0];
    assert_eq!(row.item_id, item_id_of(&booked));
    assert_eq!(row.kind, AgentInboxItemKind::CoordinationUpdate);
    assert_eq!(row.occurred_at, NOW, "the row stands at the commit");
    assert_eq!(
        row.payload_ref.as_deref(),
        Some(booked.calendar.event_ref.to_hex().as_str())
    );
    assert_eq!(row.thread_ref, None);
    assert_eq!(row.identity_ref, None);
    assert_eq!(row.actor_ref, fixture.owner);
    assert_eq!(
        row.participants
            .iter()
            .map(|participant| participant.actor_ref)
            .collect::<Vec<_>>(),
        vec![fixture.owner],
        "the owners are the row's participants"
    );

    // Every booking gets one.
    let second = fixture.book(b"committed-today-too", slot_of(&slots[4]));
    let rows = fixture.booking_rows_at(NOW + 6);
    let mut ids: Vec<_> = rows.iter().map(|row| row.item_id.clone()).collect();
    ids.sort();
    let mut expected = vec![item_id_of(&booked), item_id_of(&second)];
    expected.sort();
    assert_eq!(ids, expected);
}

#[test]
fn a_booking_cancelled_today_keeps_one_row_at_the_cancel() {
    let fixture = Fixture::open();
    let slots = fixture.offered_slots();
    let booked = fixture.book(b"cancelled-today", slot_of(&slots[0]));
    fixture.cancel(&booked, NOW + 60);

    let rows = fixture.booking_rows_at(NOW + 65);
    assert_eq!(rows.len(), 1, "one row, not one per transition: {rows:?}");
    assert_eq!(rows[0].item_id, item_id_of(&booked));
    assert_eq!(
        rows[0].occurred_at,
        NOW + 60,
        "the row stands at the cancel"
    );
}

#[test]
fn the_opened_card_names_the_visitor_type_slot_and_page_and_offers_the_owners_doors() {
    let fixture = Fixture::open();
    let slot = slot_of(&fixture.offered_slots()[0]);
    let booked = fixture.book(b"opened-card", slot);
    fixture.clock.set(NOW + 5);

    let view = fixture.open_as_owner(&item_id_of(&booked));
    let window = json!({ "start": slot.start, "end": slot.end - 1 });
    assert_eq!(
        view["booking"],
        json!({
            "event_ref": booked.calendar.event_ref.to_hex(),
            "visitor": "visitor@example.test",
            "event_type": "intro-call",
            "start_utc": slot.start,
            "end_utc": slot.end,
            "source_page": fixture.page.to_hex(),
            "status": "confirmed",
            "recorded_at": NOW,
            "offers": [
                { "action_policy": "cancel", "affected_window": window },
                { "action_policy": "request_update", "affected_window": window },
            ],
        }),
        "opened row: {view}"
    );
}

#[test]
fn a_cancelled_bookings_card_offers_no_door() {
    let fixture = Fixture::open();
    let booked = fixture.book(b"cancelled-card", slot_of(&fixture.offered_slots()[0]));
    fixture.cancel(&booked, NOW + 60);
    fixture.clock.set(NOW + 65);

    let view = fixture.open_as_owner(&item_id_of(&booked));
    assert_eq!(view["booking"]["status"], json!("cancelled"), "{view}");
    assert_eq!(view["booking"]["recorded_at"], json!(NOW + 60), "{view}");
    assert_eq!(view["booking"]["offers"], json!([]), "{view}");
}

#[test]
fn the_row_stands_until_the_hosts_day_ends_not_the_utc_day() {
    let fixture = Fixture::open();
    let booked = fixture.book(b"hosts-day", slot_of(&fixture.offered_slots()[0]));

    let rows = fixture.booking_rows_at(LAST_MINUTE_OF_THE_HOSTS_DAY);
    assert_eq!(
        rows.iter()
            .map(|row| row.item_id.clone())
            .collect::<Vec<_>>(),
        vec![item_id_of(&booked)],
        "23:59 in Tokyo: the booking's day is still on"
    );
    assert!(
        fixture.booking_rows_at(NEXT_HOSTS_DAY).is_empty(),
        "00:30 in Tokyo (15:30 UTC, the same UTC day): a booking from the day before makes no row"
    );
}

#[test]
fn the_booking_agents_own_slice_holds_no_booking_row() {
    let fixture = Fixture::open();
    fixture.book(b"agent-slice", slot_of(&fixture.offered_slots()[0]));
    fixture.clock.set(NOW + 5);

    let rows = booking_rows_of(
        fixture
            .vault
            .agent_inbox_slice(fixture.actor, 500, None)
            .expect("the booking actor's inbox slice"),
    );
    assert!(rows.is_empty(), "the card is the owners': {rows:?}");
}
