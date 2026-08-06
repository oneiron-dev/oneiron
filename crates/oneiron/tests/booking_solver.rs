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

mod common;

use common::entity as test_id;
use oneiron::booking::config::BOOKING_EVENT_TYPE_PREDICATE;
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_EVENT, ENTITY_TYPE_PERSON};
use oneiron::{
    ActiveHoldSource, BOOKING_EVENT_TYPE_META_PREFIX, BOOKING_EVENT_TYPE_SCHEMA_VERSION,
    BookingError, BookingEventTypeClaimValue, BookingSolver, ClaimApprovalStatus, ClaimCandidate,
    ClaimSource, ClaimSubject, ConstraintObject, DEFAULT_INTRO_DURATION_MIN, DisclosureRung,
    EdgeActorClass, EntityId, EventDetailsRow, EventRow, EventTypeConfig, EventTypeKey,
    HostAvailabilityConfig, NoActiveHolds, RoutingMode, RungProjection, SlotOracle, SolveRequest,
    SolveResult, SurfaceClass, TimeRange, Vault, VaultConfig, WeeklyWallWindow, WriteActor,
    WriteEnvelope, WriteProvenance, encode_event_type_claim_value, event_type_index_key,
    is_booking_claim_predicate, project_at_rung, slot_mask,
};
use rmpv::Value;

/// `2026-03-02T00:00:00Z`, a Monday well clear of any northern DST transition.
const MONDAY: u64 = 1_772_409_600;
/// Request time: 08:00Z that Monday.
const NOW: u64 = MONDAY + 8 * 3_600;

const PAGE_SEED: u8 = 0x51;
const HOST_A_SEED: u8 = 0x52;
const HOST_B_SEED: u8 = 0x55;
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

/// An unseeded vault: keeps the claim write door open without a policy fixture,
/// so the configuration oracles measure BK-00's lookup rather than the missing
/// `booking.` rule in the default policy manifest — the hole
/// [`booking_claims_are_gate_pending_under_the_default_policy_manifest`] pins,
/// whose fix lives in `gate.rs`, a lane-wide BK non-claim.
fn unseeded_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_unseeded_for_test(dir.path(), config).expect("open vault");
    (dir, vault)
}

fn booking_actor(vault: &Vault) -> EntityId {
    let actor = test_id(ACTOR_SEED);
    vault
        .put_entity(&actor, ENTITY_TYPE_PERSON, at(1), 1, b"booking actor")
        .expect("put actor");
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
/// claim-candidate door at `approval`, exactly as CAL's ingest would.
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
        ClaimApprovalStatus::Approved,
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

/// One `booking.event_type` configuration claim, written through the same
/// ordinary claim-candidate door a page editor would use.
fn store_event_type_claim(
    vault: &Vault,
    actor: EntityId,
    page: EntityId,
    index: u8,
    config: EventTypeConfig,
) {
    let value = BookingEventTypeClaimValue {
        schema_version: BOOKING_EVENT_TYPE_SCHEMA_VERSION,
        page_ref: page,
        config,
    };
    vault
        .batch()
        .claim_candidate(
            &claim_id(PAGE_SEED, index),
            ClaimCandidate::new(
                BOOKING_EVENT_TYPE_PREDICATE,
                ClaimSubject::Entity(page),
                encode_event_type_claim_value(&value).expect("encode configuration"),
                1.0,
            ),
            &WriteEnvelope::new(
                WriteActor::new(actor, EdgeActorClass::Human),
                ClaimSource::UserStated,
                WriteProvenance::new(Value::from("one-1823-oracle")).expect("provenance"),
                ClaimApprovalStatus::Approved,
            ),
            at(1),
            1,
        )
        .commit()
        .expect("the booking claim family passes the write door");
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
/// each witness candidate; see [`eight_step_pipeline_order_oracle`].
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

/// Excludes 12:00 local and nothing else.
fn oracle_constraint() -> ConstraintObject {
    ConstraintObject {
        schema_version: 1,
        weekdays: Vec::new(),
        local_time_windows: vec![
            oneiron::booking::constraint::LocalMinuteWindow {
                start_minute: 9 * 60,
                end_minute: 12 * 60,
            },
            oneiron::booking::constraint::LocalMinuteWindow {
                start_minute: 12 * 60 + 30,
                end_minute: 1_440,
            },
        ],
        utc_window: None,
        allow_flex_pool: true,
    }
    .canonicalize()
    .expect("canonical constraint")
}

fn request(constraint: Option<ConstraintObject>) -> SolveRequest {
    SolveRequest {
        event_type: EventTypeKey("intro-call".to_owned()),
        window: monday(),
        constraint,
        visitor_tz: "UTC".to_owned(),
    }
}

/// A hold source with a fixed set of ranges — the shape ONE-1813 replaces with
/// session-keyed vault-meta rows.
struct FixtureHolds(Vec<TimeRange>);

impl ActiveHoldSource for FixtureHolds {
    fn active_holds(
        &self,
        _page_ref: EntityId,
        _window: TimeRange,
        _now_utc: u64,
        _exclude_session_key: Option<&[u8; 32]>,
    ) -> Result<Vec<TimeRange>, BookingError> {
        Ok(self.0.clone())
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

/// Round-trips one seam type through the five derives it is pinned to carry.
fn seam<T: serde::Serialize + serde::de::DeserializeOwned + Clone + std::fmt::Debug + PartialEq>(
    value: &T,
) {
    let json = serde_json::to_string(value).expect("serialize");
    let restored: T = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(&restored, value, "{value:?}");
}

/// Coerces an implementor to the seam's trait object, which only compiles while
/// `SlotOracle` is one trait with one home.
fn oracle_object(oracle: &dyn SlotOracle) -> &dyn SlotOracle {
    oracle
}

fn slot_hours(result: &SolveResult) -> Vec<u64> {
    result
        .slots
        .iter()
        .map(|slot| (slot.start_utc - MONDAY) / 60)
        .collect()
}

/// Minute-of-day labels for the oracle's ten candidates.
const NOTICE_WITNESS: u64 = 9 * 60;
const SURVIVOR_MORNING: u64 = 9 * 60 + 30;
const HOLD_WITNESS: u64 = 10 * 60;
const BUFFER_WITNESS_EARLY: u64 = 10 * 60 + 30;
const BUSY_WITNESS: u64 = 11 * 60;
const BUFFER_WITNESS_LATE: u64 = 11 * 60 + 30;
const CONSTRAINT_WITNESS: u64 = 12 * 60;
const SURVIVOR_AFTERNOON: u64 = 12 * 60 + 30;
const HORIZON_WITNESS: u64 = 13 * 60;
const HORIZON_WITNESS_LATE: u64 = 13 * 60 + 30;

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
fn eight_step_pipeline_order_oracle() {
    let (_dir, vault) = temp_vault();
    let actor = booking_actor(&vault);
    let page = booking_page(&vault);
    seed_busy_hour(&vault, actor);

    let holds = FixtureHolds(vec![TimeRange {
        start: hour(10),
        end: hour(10) + 900,
    }]);
    let req = request(Some(oracle_constraint()));
    let baseline = solve_with(&vault, page, oracle_config(), &holds, &req);

    // Ten candidates enter; eight stages each take their own, and two survive.
    assert_eq!(
        slot_hours(&baseline),
        [SURVIVOR_MORNING, SURVIVOR_AFTERNOON],
        "each stage removed exactly its witness"
    );

    // Stage 1 — working hours. Narrowing them narrows the answer.
    let mut narrow = oracle_config();
    narrow.hosts[0].working_hours = vec![window(0, 9, 10)];
    assert_eq!(
        slot_hours(&solve_with(&vault, page, narrow, &holds, &req)),
        [SURVIVOR_MORNING]
    );

    // Stages 2 and 3 — the busy union and its buffers. On a vault with no busy
    // EVENT all three of their witnesses return.
    let (_empty_dir, empty_vault) = temp_vault();
    let empty_page = booking_page(&empty_vault);
    let no_busy = solve_with(&empty_vault, empty_page, oracle_config(), &holds, &req);
    assert!(
        slot_hours(&no_busy).contains(&BUSY_WITNESS)
            && slot_hours(&no_busy).contains(&BUFFER_WITNESS_EARLY)
            && slot_hours(&no_busy).contains(&BUFFER_WITNESS_LATE),
        "{:?}",
        slot_hours(&no_busy)
    );

    // Stage 3 alone — dropping the buffer returns only the buffered witnesses,
    // and never the busy hour itself.
    let mut unbuffered = oracle_config();
    unbuffered.post_buffer_min = 0;
    let unbuffered = slot_hours(&solve_with(&vault, page, unbuffered, &holds, &req));
    assert!(
        unbuffered.contains(&BUFFER_WITNESS_EARLY) && unbuffered.contains(&BUFFER_WITNESS_LATE)
    );
    assert!(
        !unbuffered.contains(&BUSY_WITNESS),
        "the busy hour is occupied whatever the buffer is"
    );

    // Stage 4 — notice and horizon, each measured from request time.
    let mut prompt = oracle_config();
    prompt.min_notice_secs = 0;
    assert!(slot_hours(&solve_with(&vault, page, prompt, &holds, &req)).contains(&NOTICE_WITNESS));
    let mut distant = oracle_config();
    distant.booking_window_secs = 86_400;
    let distant = slot_hours(&solve_with(&vault, page, distant, &holds, &req));
    assert!(distant.contains(&HORIZON_WITNESS) && distant.contains(&HORIZON_WITNESS_LATE));

    // Stage 5 — every emitted slot is one duration long and sits on the shared
    // step grid, anchored at the epoch rather than at a mask's own start.
    let config = oracle_config();
    let step = u64::from(config.slot_step_min) * 60;
    let duration = u64::from(config.duration_min) * 60;
    for slot in &baseline.slots {
        assert_eq!(slot.end_utc - slot.start_utc, duration);
        assert_eq!(slot.start_utc % step, 0);
    }

    // Stage 6 — live holds.
    assert!(
        slot_hours(&solve_with(
            &vault,
            page,
            oracle_config(),
            &NoActiveHolds,
            &req
        ))
        .contains(&HOLD_WITNESS)
    );

    // Stage 8 — the visitor's normalized constraint, and only it.
    assert!(
        slot_hours(&solve_with(
            &vault,
            page,
            oracle_config(),
            &holds,
            &request(None)
        ))
        .contains(&CONSTRAINT_WITNESS)
    );

    // Stage 7 — routing. A second host working only the afternoon unions to the
    // same answer and intersects to the afternoon alone.
    let mut two_hosts = oracle_config();
    two_hosts
        .hosts
        .push(host(HOST_B_SEED, vec![window(0, 12, 14)]));
    let mut both = two_hosts.clone();
    both.routing = RoutingMode::Both;
    assert_eq!(
        slot_hours(&solve_with(&vault, page, two_hosts, &holds, &req)),
        [SURVIVOR_MORNING, SURVIVOR_AFTERNOON]
    );
    assert_eq!(
        slot_hours(&solve_with(&vault, page, both, &holds, &req)),
        [SURVIVOR_AFTERNOON],
        "Both keeps only the time every host is free"
    );
}

#[test]
fn busy_union_is_consumed_without_status_refilter() {
    let (_dir, vault) = temp_vault();
    let actor = booking_actor(&vault);
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
    let union = oneiron::freebusy(&vault, &[], monday()).expect("freebusy");
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
fn flex_pool_surfaces_only_after_primary_mask_is_empty() {
    let (_dir, vault) = temp_vault();
    let page = booking_page(&vault);

    let mut config = oracle_config();
    config.flex_windows = vec![window(0, 18, 20)];
    config.booking_window_secs = 86_400;

    // Ordinary availability exists, so the pool stays shut and the evening
    // windows never surface.
    let ordinary = solve_with(&vault, page, config.clone(), &NoActiveHolds, &request(None));
    assert!(!ordinary.flex_used);
    assert!(!ordinary.slots.is_empty());
    assert!(
        slot_hours(&ordinary).iter().all(|minute| *minute < 18 * 60),
        "the flex pool is not ordinary availability"
    );

    // With the ordinary windows gone the pool answers, and says so.
    let mut flex_only = config;
    flex_only.hosts[0].working_hours.clear();
    let fallback = solve_with(
        &vault,
        page,
        flex_only.clone(),
        &NoActiveHolds,
        &request(None),
    );
    assert!(fallback.flex_used);
    assert!(
        slot_hours(&fallback)
            .iter()
            .all(|minute| *minute >= 18 * 60),
        "{:?}",
        slot_hours(&fallback)
    );

    // A constraint that refuses the pool keeps it shut even with nothing else
    // to offer, and an empty fallback is not a flex answer.
    let mut refuses = oracle_constraint();
    refuses.allow_flex_pool = false;
    refuses.local_time_windows.clear();
    let refused = solve_with(
        &vault,
        page,
        flex_only,
        &NoActiveHolds,
        &request(Some(refuses)),
    );
    assert!(refused.slots.is_empty() && !refused.flex_used);
}

#[test]
fn visitor_zone_is_validated_at_calendar_border() {
    let (_dir, vault) = temp_vault();
    let page = booking_page(&vault);
    let calendars = vec![(
        test_id(HOST_A_SEED),
        vec![oneiron::CalendarSel { system: None }],
    )];
    let solver = |visitor_tz: &str| {
        BookingSolver {
            vault: &vault,
            page_ref: page,
            calendars_by_host: &calendars,
            holds: &NoActiveHolds,
            now_utc: NOW,
            synthetic_config: Some(oracle_config()),
        }
        .solve(&SolveRequest {
            event_type: EventTypeKey("intro-call".to_owned()),
            window: monday(),
            constraint: None,
            visitor_tz: visitor_tz.to_owned(),
        })
    };

    // A malformed or case-mangled zone is a typed rejection, never a silent
    // fall back to UTC that would answer with somebody else's clock.
    for bogus in ["Mars/Olympus_Mons", "europe/london", "", "Not A Zone"] {
        assert!(
            matches!(solver(bogus), Err(BookingError::InvalidConstraint(_))),
            "{bogus} must fail typed"
        );
    }
    // A real zone solves, and what comes back is UTC — no wall time, no offset,
    // and no zone label rides the result.
    let solved = solver("Pacific/Auckland").expect("a real zone solves");
    assert!(!solved.slots.is_empty());
    let json = serde_json::to_string(&solved).expect("serialize");
    for leak in ["Auckland", "tz", "wall", "offset", "+12", "+13"] {
        assert!(!json.contains(leak), "SolveResult leaked {leak}: {json}");
    }

    // A host zone with a spring-forward gap keeps its typed behaviour at the
    // border: the skipped hour has no instants, so it offers nothing, while the
    // hour beside it converts normally.
    let sunday = TimeRange {
        start: MONDAY + 27 * 86_400,
        end: MONDAY + 28 * 86_400 - 1,
    };
    let gap_config = |start_hour: u16, end_hour: u16| {
        let mut config = oracle_config();
        config.hosts[0].host_tz = "Europe/London".to_owned();
        config.hosts[0].working_hours = vec![window(6, start_hour, end_hour)];
        config.min_notice_secs = 0;
        config.booking_window_secs = 40 * 86_400;
        config
    };
    let gap_request = SolveRequest {
        event_type: EventTypeKey("intro-call".to_owned()),
        window: sunday,
        constraint: None,
        visitor_tz: "UTC".to_owned(),
    };
    assert!(
        solve_with(&vault, page, gap_config(1, 2), &NoActiveHolds, &gap_request)
            .slots
            .is_empty(),
        "an hour the zone skips is never shifted into the adjacent one"
    );
    assert!(
        !solve_with(&vault, page, gap_config(3, 5), &NoActiveHolds, &gap_request)
            .slots
            .is_empty(),
        "the rejection is the gap, not the whole day"
    );
}

#[test]
fn synthetic_config_bypasses_page_lookup() {
    let (_dir, vault) = temp_vault();
    let page = booking_page(&vault);

    // No `booking.event_type` claim exists anywhere, so the claim path fails
    // typed — which is what makes the synthetic arm's success meaningful.
    let calendars = vec![(
        test_id(HOST_A_SEED),
        vec![oneiron::CalendarSel { system: None }],
    )];
    let from_claim = BookingSolver {
        vault: &vault,
        page_ref: page,
        calendars_by_host: &calendars,
        holds: &NoActiveHolds,
        now_utc: NOW,
        synthetic_config: None,
    }
    .solve(&request(None));
    assert!(matches!(from_claim, Err(BookingError::InvalidConfig(_))));

    // The same page, solved verbatim from a supplied preset, with holds and
    // counts still scoped by that subject.
    let holds = FixtureHolds(vec![TimeRange {
        start: hour(10),
        end: hour(10) + 900,
    }]);
    let preset = solve_with(&vault, page, oracle_config(), &holds, &request(None));
    assert!(!slot_hours(&preset).contains(&HOLD_WITNESS));
    assert!(slot_hours(&preset).contains(&SURVIVOR_MORNING));

    // The preset's key must be the one asked for; a mismatch is typed, not a
    // silently substituted event type.
    let mut wrong = oracle_config();
    wrong.key = EventTypeKey("deep-dive".to_owned());
    let mismatch = BookingSolver {
        vault: &vault,
        page_ref: page,
        calendars_by_host: &calendars,
        holds: &NoActiveHolds,
        now_utc: NOW,
        synthetic_config: Some(wrong),
    }
    .solve(&request(None));
    assert!(matches!(mismatch, Err(BookingError::InvalidConfig(_))));
}

/// KNOWN HOLE, inherited and not owned by BK-00.
///
/// `gate::default_policy_manifest()` carries a `calendar.` rule but no
/// `booking.` one, so every booking-family claim falls to the manifest's
/// `critical` default and is gate-pending on write. The fix is one rule in
/// `crates/oneiron/src/gate.rs`, a lane-wide BK non-claim — exactly the shape
/// `tests/calendar_surface_oracle.rs` pinned for `calendar.` before CAL closed
/// it. Pinned here so the hole is measured rather than discovered later.
#[test]
fn booking_claims_are_gate_pending_under_the_default_policy_manifest() {
    let (_dir, vault) = temp_vault();
    let actor = booking_actor(&vault);
    let page = booking_page(&vault);
    let value = BookingEventTypeClaimValue {
        schema_version: BOOKING_EVENT_TYPE_SCHEMA_VERSION,
        page_ref: page,
        config: oracle_config(),
    };
    let rejection = vault
        .batch()
        .claim_candidate(
            &claim_id(PAGE_SEED, 9),
            ClaimCandidate::new(
                BOOKING_EVENT_TYPE_PREDICATE,
                ClaimSubject::Entity(page),
                encode_event_type_claim_value(&value).expect("encode configuration"),
                1.0,
            ),
            &WriteEnvelope::new(
                WriteActor::new(actor, EdgeActorClass::Human),
                ClaimSource::UserStated,
                WriteProvenance::new(Value::from("one-1823-oracle")).expect("provenance"),
                ClaimApprovalStatus::Approved,
            ),
            at(1),
            1,
        )
        .commit()
        .expect_err("the booking family has no policy rule yet");
    assert!(
        format!("{rejection:?}").contains("criticality_floor"),
        "the hole is the missing `booking.` rule, not the claim body: {rejection:?}"
    );
}

#[test]
fn booking_event_type_index_uses_canonical_prefix() {
    let (_dir, vault) = unseeded_vault();
    let page = booking_page(&vault);

    let key = EventTypeKey("intro-call".to_owned());
    let index_key = event_type_index_key(page, &key);
    assert!(index_key.starts_with(BOOKING_EVENT_TYPE_META_PREFIX));
    assert_eq!(BOOKING_EVENT_TYPE_META_PREFIX, b"booking.event_type.v1:");
    // Both axes of `(page_ref, key)` are in the shortcut.
    assert_ne!(index_key, event_type_index_key(test_id(0x54), &key));
    assert_ne!(
        index_key,
        event_type_index_key(page, &EventTypeKey("deep-dive".to_owned()))
    );

    // Synced truth is the claim: with no node-local shortcut written at all,
    // the configuration still resolves, exactly as it must on a replica whose
    // claim arrived by replication and left no local index row behind.
    let actor = booking_actor(&vault);
    assert!(is_booking_claim_predicate(BOOKING_EVENT_TYPE_PREDICATE));
    store_event_type_claim(&vault, actor, page, 0, oracle_config());

    let calendars = vec![(
        test_id(HOST_A_SEED),
        vec![oneiron::CalendarSel { system: None }],
    )];
    let solve_from_claim = |vault: &Vault, page: EntityId| {
        BookingSolver {
            vault,
            page_ref: page,
            calendars_by_host: &calendars,
            holds: &NoActiveHolds,
            now_utc: NOW,
            synthetic_config: None,
        }
        .solve(&request(None))
    };
    let solved = solve_from_claim(&vault, page).expect("the page claim configures the solve");
    assert!(slot_hours(&solved).contains(&SURVIVOR_MORNING));

    // One live configuration per `(page_ref, key)`: after an update supersedes
    // the first claim, the solve reflects the NEW hours and never the retired
    // ones — a superseded claim is stored history, not configuration.
    let mut narrowed = oracle_config();
    narrowed.hosts[0].working_hours = vec![window(0, 12, 14)];
    store_event_type_claim(&vault, actor, page, 1, narrowed);
    vault
        .supersede_claim(&claim_id(PAGE_SEED, 1), &claim_id(PAGE_SEED, 0), 2)
        .expect("the update supersedes the previous configuration");
    assert_eq!(
        slot_hours(&solve_from_claim(&vault, page).expect("the live claim configures the solve")),
        [CONSTRAINT_WITNESS, SURVIVOR_AFTERNOON],
        "only the live claim's afternoon hours are offered; the retired claim's \
         morning hours are gone"
    );

    // A claim for another event type is not this one's configuration.
    let (_other_dir, other_vault) = unseeded_vault();
    let other_actor = booking_actor(&other_vault);
    let other_page = booking_page(&other_vault);
    let mut other_key = oracle_config();
    other_key.key = EventTypeKey("deep-dive".to_owned());
    store_event_type_claim(&other_vault, other_actor, other_page, 2, other_key);
    assert!(matches!(
        solve_from_claim(&other_vault, other_page),
        Err(BookingError::InvalidConfig(_))
    ));
}

#[test]
fn slot_mask_contains_no_calendar_or_event_detail() {
    let (_dir, vault) = temp_vault();
    let actor = booking_actor(&vault);
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
    let json = serde_json::to_string(&projection).expect("serialize");
    for leak in [
        SECRET_NAME,
        SECRET_DESCRIPTION,
        SECRET_ATTENDEE,
        "Boardroom",
        "event_ref",
        "attendee_refs",
        "description",
        "location",
        "title",
        &test_id(BUSY_SEED).to_hex(),
        &test_id(HOST_A_SEED).to_hex(),
    ] {
        assert!(!json.contains(leak), "the slots rung leaked {leak}: {json}");
    }
    // Exactly the five mask fields cross the boundary.
    let value = serde_json::to_value(&mask).expect("serialize mask");
    assert_eq!(
        value
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "event_type",
            "window_start_utc",
            "window_end_utc",
            "slots",
            "flex_used"
        ]
    );
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

#[test]
fn booking_seam_has_one_definition_home() {
    // Each seam type resolves to the SAME type through the module re-export and
    // through its definition home, so there is exactly one definition.
    let key: oneiron::booking::constraint::EventTypeKey = EventTypeKey("intro-call".to_owned());
    let request: oneiron::booking::constraint::SolveRequest = request(None);
    let result: oneiron::booking::constraint::SolveResult = SolveResult {
        slots: Vec::new(),
        flex_used: false,
    };
    let mask: oneiron::booking::constraint::SlotMask = slot_mask(&request, result.clone());
    let error: oneiron::booking::constraint::BookingError =
        BookingError::SlotOracle("probe".to_owned());
    let constraint: oneiron::booking::constraint::ConstraintObject = oracle_constraint();

    // The five seam derives, checked by bound rather than by eye.
    seam(&key);
    seam(&request);
    seam(&result);
    seam(&mask);
    seam(&error);
    seam(&constraint);
    seam(&oneiron::RankedSlot {
        start_utc: hour(9),
        end_utc: hour(9) + 1_800,
        rank: 0.5,
    });

    // `SlotOracle` is the seam's trait, and `BookingSolver` is an implementor —
    // this ticket supplies the implementation, never a second contract.
    let (_dir, vault) = temp_vault();
    let page = booking_page(&vault);
    let calendars = vec![(
        test_id(HOST_A_SEED),
        vec![oneiron::CalendarSel { system: None }],
    )];
    let solver = BookingSolver {
        vault: &vault,
        page_ref: page,
        calendars_by_host: &calendars,
        holds: &NoActiveHolds,
        now_utc: NOW,
        synthetic_config: Some(oracle_config()),
    };
    assert!(
        !oracle_object(&solver)
            .solve(&request)
            .expect("the solver is the oracle")
            .slots
            .is_empty()
    );
}

#[test]
fn booking_source_carries_no_third_party_time_type() {
    // The two files this ticket owns. Sibling booking files are not asserted
    // here: an oracle over source it does not own goes stale the moment a
    // sibling lands.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/booking");
    for name in ["config.rs", "solver.rs"] {
        let source = std::fs::read_to_string(root.join(name)).expect("read booking source");
        for forbidden in [
            "chrono",
            "chrono_tz",
            "jiff",
            "icalendar",
            "rrule",
            "NaiveDate",
            "DateTime",
            "SlotMaskArtifact",
            "crate::TimeRange",
        ] {
            assert!(
                !source.contains(forbidden),
                "{name} names {forbidden}; the TZ/ICS border is CAL's and the one \
                 TimeRange import path is `crate::temporal::TimeRange`"
            );
        }
        assert!(
            source.contains("crate::temporal::TimeRange") || name == "config.rs",
            "{name} must import TimeRange from its one home"
        );
    }
}
