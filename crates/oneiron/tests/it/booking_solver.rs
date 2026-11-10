//! ONE-1823 [BK-00] availability-solver oracle.
//!
//! Pins the laws the solver exists to hold, at the public boundary:
//!
//! 1. **Eight stages, one order.** Working hours → busy union → buffers →
//!    notice/horizon → event-type knobs → live holds → routing → ranked UTC
//!    emit. Each stage has a witness candidate only it removes, so a skipped or
//!    neutralized stage is visible in the answer.
//! 2. **CAL owns the calendar.** The solver consumes ONE-1791's normalized,
//!    busy-only union and re-filters nothing: free and cancelled occurrences
//!    were already excluded upstream, and no booking code re-derives them.
//! 3. **The core is UTC.** Every IANA conversion goes through ONE-1783's
//!    border. A malformed visitor zone fails typed; it never falls back to UTC.
//! 4. **The mask is the ceiling.** What crosses a public boundary is a
//!    `SlotMask` — an event type, a half-open window, ranked UTC slots, and one
//!    flex flag. No event, attendee, busy interval, or calendar identity has a
//!    field to travel in.

use crate::common::entity as test_id;
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_EVENT, ENTITY_TYPE_PERSON};
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
    booking::ActiveHoldSource, booking::BookingError, booking::BookingSolver,
    booking::ConstraintObject, booking::DEFAULT_INTRO_DURATION_MIN, booking::DisclosureRung,
    booking::EventDetailsRow, booking::EventRow, booking::EventTypeConfig, booking::EventTypeKey,
    booking::HostAvailabilityConfig, booking::NoActiveHolds, booking::RoutingMode,
    booking::RungProjection, booking::SlotOracle, booking::SolveRequest, booking::SolveResult,
    booking::SurfaceClass, booking::WeeklyWallWindow, booking::project_at_rung, booking::slot_mask,
};
use rmpv::Value;

/// `2026-03-02T00:00:00Z`, a Monday well clear of any northern DST transition.
const MONDAY: u64 = 1_772_409_600;
/// Request time: 08:00Z that Monday.
const NOW: u64 = MONDAY + 8 * 3_600;

const PAGE_SEED: u8 = 0x51;
const HOST_A_SEED: u8 = 0x52;
const ACTOR_SEED: u8 = 0x56;
const BUSY_SEED: u8 = 0x61;
const FREE_SEED: u8 = 0x62;
const CANCELLED_SEED: u8 = 0x63;

const SECRET_NAME: &str = "Board review with the CFO";
const SECRET_DESCRIPTION: &str = "term sheet, do not disclose";
const SECRET_ATTENDEE: &str = "cfo@acme.example";

/// Fixture claim ids are keyed `(0xB1, seed, index)` so none can alias a
/// generic `entity(seed)` id.
fn claim_id(seed: u8, index: u8) -> EntityId {
    let mut bytes = [0xB1_u8; 16];
    bytes[1] = seed;
    bytes[2] = index;
    EntityId::from_bytes(bytes).expect("fixture claim id")
}

fn at(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

/// Hour-offset half-open helper: `hour(9)` is 09:00Z that Monday.
const fn hour(hours: u64) -> u64 {
    MONDAY + hours * 3_600
}

/// The whole Monday as an inclusive engine range — what a caller asks for.
const fn monday() -> TimeRange {
    TimeRange {
        start: MONDAY,
        end: MONDAY + 86_399,
    }
}

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

fn booking_actor(vault: &Vault) -> EntityId {
    let actor = test_id(ACTOR_SEED);
    vault
        .put_entity(&actor, ENTITY_TYPE_PERSON, at(1), 1, b"booking actor")
        .expect("put actor");
    oneiron::calendar::transcript::permit_imported_calendar_source_for_test(vault, actor)
        .expect("authorize this CAL ingest actor's Imported source");
    actor
}

fn booking_page(vault: &Vault) -> EntityId {
    let page = test_id(PAGE_SEED);
    vault
        .put_entity(&page, ENTITY_TYPE_ASSET, at(1), 1, b"booking page")
        .expect("put booking page");
    page
}

fn event_body(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(
        &mut out,
        &Value::Map(vec![
            (Value::from("name"), Value::from(name)),
            (Value::from("desc"), Value::from(SECRET_DESCRIPTION)),
        ]),
    )
    .expect("encode event body");
    out
}

/// One calendar EVENT and its `calendar.*` family, written through the ordinary
/// claim-candidate door with Auto so preflight can match the actor's Imported permit.
fn store_event(
    vault: &Vault,
    actor: EntityId,
    seed: u8,
    occurred: TimeRange,
    transparency: &str,
    status: Option<&str>,
) {
    let id = test_id(seed);
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_EVENT,
            occurred,
            1,
            &event_body(SECRET_NAME),
        )
        .expect("put event");

    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Human),
        ClaimSource::Imported,
        WriteProvenance::new(Value::from("one-1823-oracle")).expect("provenance"),
        ClaimApprovalStatus::Auto,
    );
    let mut family = vec![
        ("calendar.origin", Value::from("imported")),
        (
            "calendar.time_kind",
            Value::Map(vec![
                (Value::from("kind"), Value::from("absolute")),
                (Value::from("busy_transparency"), Value::from(transparency)),
            ]),
        ),
        (
            "calendar.attendee",
            Value::Map(vec![
                (Value::from("who"), Value::from(SECRET_ATTENDEE)),
                (Value::from("role"), Value::from("REQ-PARTICIPANT")),
                (Value::from("partstat"), Value::from("ACCEPTED")),
            ]),
        ),
    ];
    if let Some(status) = status {
        family.push((
            "calendar.status",
            Value::Map(vec![
                (Value::from("status"), Value::from(status)),
                (Value::from("basis"), Value::from("imported_cancel")),
                (Value::from("recorded_at"), Value::from(1_u64)),
            ]),
        ));
    }
    for (index, (predicate, value)) in family.into_iter().enumerate() {
        vault
            .batch()
            .claim_candidate(
                &claim_id(seed, u8::try_from(index).expect("family fits a byte")),
                ClaimCandidate::new(predicate, ClaimSubject::Entity(id), value, 1.0),
                &envelope,
                at(1),
                1,
            )
            .commit()
            .expect("claim candidate commits");
    }
}

fn window(weekday: u8, start_hour: u16, end_hour: u16) -> WeeklyWallWindow {
    WeeklyWallWindow {
        weekday,
        start_minute: start_hour * 60,
        end_minute: end_hour * 60,
    }
}

fn host(seed: u8, working: Vec<WeeklyWallWindow>) -> HostAvailabilityConfig {
    HostAvailabilityConfig {
        host_ref: test_id(seed),
        calendar_refs: vec![test_id(BUSY_SEED)],
        host_tz: "UTC".to_owned(),
        working_hours: working,
        preferred_hours: Vec::new(),
    }
}

/// The oracle configuration. Each knob is tuned so exactly one stage removes
/// each witness candidate.
fn oracle_config() -> EventTypeConfig {
    EventTypeConfig {
        key: EventTypeKey("intro-call".to_owned()),
        duration_min: DEFAULT_INTRO_DURATION_MIN,
        slot_step_min: 30,
        pre_buffer_min: 0,
        // Grows the 11:00 busy block by a quarter hour on each side.
        post_buffer_min: 15,
        // 08:00 + 1.5h — the first bookable instant is 09:30.
        min_notice_secs: 5_400,
        // 08:00 + 5h — the last bookable instant is 13:00.
        booking_window_secs: 5 * 3_600,
        daily_cap: None,
        weekly_cap: None,
        routing: RoutingMode::Either,
        hosts: vec![host(HOST_A_SEED, vec![window(0, 9, 14)])],
        flex_windows: Vec::new(),
    }
}

fn request(constraint: Option<ConstraintObject>) -> SolveRequest {
    SolveRequest {
        event_type: EventTypeKey("intro-call".to_owned()),
        window: monday(),
        constraint,
        visitor_tz: "UTC".to_owned(),
    }
}

fn solve_with(
    vault: &Vault,
    page_ref: EntityId,
    config: EventTypeConfig,
    holds: &dyn ActiveHoldSource,
    req: &SolveRequest,
) -> SolveResult {
    let calendars: Vec<(EntityId, Vec<oneiron::CalendarSel>)> = config
        .hosts
        .iter()
        .map(|host| (host.host_ref, vec![oneiron::CalendarSel { system: None }]))
        .collect();
    BookingSolver {
        vault,
        page_ref,
        calendars_by_host: &calendars,
        holds,
        now_utc: NOW,
        synthetic_config: Some(config),
    }
    .solve(req)
    .expect("solve")
}

fn slot_hours(result: &SolveResult) -> Vec<u64> {
    result
        .slots
        .iter()
        .map(|slot| (slot.start_utc - MONDAY) / 60)
        .collect()
}

const HOLD_WITNESS: u64 = 10 * 60;
const BUSY_WITNESS: u64 = 11 * 60;
const CONSTRAINT_WITNESS: u64 = 12 * 60;

/// The busy-hour fixture the oracle removes candidates around.
fn seed_busy_hour(vault: &Vault, actor: EntityId) {
    store_event(
        vault,
        actor,
        BUSY_SEED,
        TimeRange {
            start: hour(11),
            end: hour(11) + 1_799,
        },
        "busy",
        None,
    );
}

#[test]
fn busy_union_is_consumed_without_status_refilter() {
    let (_dir, vault) = temp_vault();
    let actor = booking_actor(&vault);
    vault
        .install_imported_source_permit_for_test(actor)
        .expect("permit this fixture actor's Imported calendar claims");
    let page = booking_page(&vault);

    // Busy, transparent, and cancelled occurrences all sit in the same hour.
    seed_busy_hour(&vault, actor);
    store_event(
        &vault,
        actor,
        FREE_SEED,
        TimeRange {
            start: hour(10),
            end: hour(10) + 1_799,
        },
        "free",
        None,
    );
    store_event(
        &vault,
        actor,
        CANCELLED_SEED,
        TimeRange {
            start: hour(12),
            end: hour(12) + 1_799,
        },
        "busy",
        Some("cancelled"),
    );

    // CAL applied the Busy-only law upstream: only the busy occurrence is in
    // the union the solver is handed.
    let union = oneiron::calendar::freebusy(&vault, &[], monday()).expect("freebusy");
    assert_eq!(
        union
            .iter()
            .map(|interval| (interval.start_utc, interval.end_utc))
            .collect::<Vec<_>>(),
        [(hour(11), hour(11) + 1_800)],
        "free and cancelled occurrences were excluded by CAL, not here"
    );

    // And the solver reproduces exactly that: the 10:00 and 12:00 candidates
    // survive because nothing in booking re-derives occupancy.
    let mut config = oracle_config();
    config.post_buffer_min = 0;
    config.min_notice_secs = 0;
    let hours = slot_hours(&solve_with(
        &vault,
        page,
        config,
        &NoActiveHolds,
        &request(None),
    ));
    assert!(
        hours.contains(&HOLD_WITNESS),
        "a `free` block occupies nothing"
    );
    assert!(
        hours.contains(&CONSTRAINT_WITNESS),
        "a cancelled EVENT bills no availability"
    );
    assert!(!hours.contains(&BUSY_WITNESS), "the busy hour is occupied");
}

#[test]
fn slot_mask_contains_no_calendar_or_event_detail() {
    let (_dir, vault) = temp_vault();
    let actor = booking_actor(&vault);
    vault
        .install_imported_source_permit_for_test(actor)
        .expect("permit this fixture actor's Imported calendar claims");
    let page = booking_page(&vault);
    seed_busy_hour(&vault, actor);

    let req = request(None);
    let solved = solve_with(&vault, page, oracle_config(), &NoActiveHolds, &req);
    let mask = slot_mask(&req, solved);

    assert_eq!(mask.window_start_utc, monday().start);
    assert_eq!(
        mask.window_end_utc,
        monday().end + 1,
        "the inclusive request window becomes a half-open mask window"
    );
    assert!(
        mask.slots
            .iter()
            .all(|slot| slot.start_utc >= mask.window_start_utc
                && slot.end_utc <= mask.window_end_utc)
    );

    let projection = project_at_rung(
        &[EventRow {
            event_ref: test_id(BUSY_SEED),
            start_utc: hour(11),
            end_utc: hour(11) + 1_800,
            title: Some(SECRET_NAME.to_owned()),
            details: EventDetailsRow {
                description: Some(SECRET_DESCRIPTION.to_owned()),
                location: Some("Boardroom".to_owned()),
                attendee_refs: vec![test_id(HOST_A_SEED)],
            },
        }],
        DisclosureRung::Slots,
        SurfaceClass::Public,
        Some(&mask),
    )
    .expect("slots projection");
    assert!(matches!(&projection, RungProjection::Slots(_)));
    let value = serde_json::to_value(&projection).expect("serialize");
    let busy_id = test_id(BUSY_SEED).to_hex();
    let host_id = test_id(HOST_A_SEED).to_hex();
    let secrets = [
        SECRET_NAME,
        SECRET_DESCRIPTION,
        SECRET_ATTENDEE,
        "Boardroom",
        busy_id.as_str(),
        host_id.as_str(),
    ];
    let mut pending = vec![&value];
    while let Some(value) = pending.pop() {
        if let Some(fields) = value.as_object() {
            for (key, value) in fields {
                assert!(
                    !matches!(
                        key.as_str(),
                        "event_ref"
                            | "attendee_refs"
                            | "description"
                            | "location"
                            | "title"
                            | "details"
                            | "calendar_ref"
                            | "calendar_refs"
                    ),
                    "the slots rung leaked field {key}"
                );
                for secret in secrets {
                    assert!(!key.contains(secret), "the slots rung leaked {secret}");
                }
                pending.push(value);
            }
        } else if let Some(values) = value.as_array() {
            pending.extend(values);
        } else if let Some(text) = value.as_str() {
            for secret in secrets {
                assert!(!text.contains(secret), "the slots rung leaked {secret}");
            }
        }
    }
    // Exactly the five mask fields cross the boundary, in any order.
    let value = serde_json::to_value(&mask).expect("serialize mask");
    let fields = value.as_object().expect("object");
    let expected = [
        "event_type",
        "window_start_utc",
        "window_end_utc",
        "slots",
        "flex_used",
    ];
    assert_eq!(fields.len(), expected.len());
    for key in expected {
        assert!(fields.contains_key(key), "mask is missing {key}");
    }
}

#[test]
fn public_rung_cannot_exceed_slots() {
    let (_dir, vault) = temp_vault();
    let page = booking_page(&vault);
    let req = request(None);
    let mask = slot_mask(
        &req,
        solve_with(&vault, page, oracle_config(), &NoActiveHolds, &req),
    );
    let events = [EventRow {
        event_ref: test_id(BUSY_SEED),
        start_utc: hour(11),
        end_utc: hour(11) + 1_800,
        title: Some(SECRET_NAME.to_owned()),
        details: EventDetailsRow {
            description: None,
            location: None,
            attendee_refs: Vec::new(),
        },
    }];

    // However generous the grant, a public surface is clamped INSIDE the
    // chokepoint — no caller has to remember to do it.
    for granted in [
        DisclosureRung::Full,
        DisclosureRung::Titles,
        DisclosureRung::Busy,
        DisclosureRung::Slots,
    ] {
        let projection = project_at_rung(&events, granted, SurfaceClass::Public, Some(&mask))
            .expect("public projection");
        assert_eq!(projection.rung(), DisclosureRung::Slots, "{granted:?}");
        assert!(matches!(projection, RungProjection::Slots(_)));
    }
    assert_eq!(SurfaceClass::Public.ceiling(), DisclosureRung::Slots);

    // A missing mask is an error, never a silently empty one that would read as
    // "no availability".
    assert!(matches!(
        project_at_rung(&events, DisclosureRung::Full, SurfaceClass::Public, None),
        Err(BookingError::Surface(_))
    ));
}
