//! Meeting caps on the public booking page (BK-MEETING-CAPS; ARCH-0062 §7
//! "meeting caps surfaces"; Engine rulings 15 Nov 01:10: an explicit full
//! marker, per event type). A visitor-local day whose times the event type's
//! daily or weekly cap removed is answered as full, with its date and the cap
//! only: no booking's title, booker, interval or count. A day with no working
//! hours is never full, and an event type without caps has no full days.
//!
//! Every case drives the real router (`build_app`) over a vault with one
//! published page, as an anonymous visitor: the bodies are the public wire,
//! written as JSON.
//!
//! Fleet command: `cargo test --locked -p oneiron-server --all-features
//! --test booking_cap_full_days`.
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use oneiron::booking::{
    BOOKING_EVENT_TYPE_PREDICATE, BOOKING_EVENT_TYPE_SCHEMA_VERSION, BOOKING_PUBLIC_PAGE_PREDICATE,
    BOOKING_PUBLIC_PAGE_SCHEMA_VERSION, BookingEventTypeClaimValue, BookingLandingContent,
    BookingPagePublication, ConstraintFieldConfig, EventTypeCard, EventTypeConfig, EventTypeKey,
    HostAvailabilityConfig, PublicBookingAvailability, PublicBookingPageToken, RoutingMode,
    ThemeTokens, WeeklyWallWindow, booking_config_hash, encode_event_type_claim_value,
};
use oneiron::memory::ClaimInput;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, DreamerHomeNodeCandidate,
    DreamerRunnerStore, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
};
use oneiron_server::config::SyncServerConfig;
use oneiron_server::{build_app, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const EVENT_TYPE: &str = "intro";
const EVENT_TITLE: &str = "Intro call";
const DAY: u64 = 86_400;
/// The home node this server is: its lease vault id, elected always-on.
const HOME_NODE: u64 = 9;

/// Runs one case on an engine-sized stack, as the served doors need.
fn on_engine_stack<F, Fut>(case: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()>,
{
    let thread = std::thread::Builder::new()
        .stack_size(oneiron_server::ENGINE_THREAD_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .thread_stack_size(oneiron_server::ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .expect("build engine-stack runtime")
                .block_on(case());
        })
        .expect("spawn engine-stack thread");
    if let Err(panic) = thread.join() {
        std::panic::resume_unwind(panic);
    }
}

/// The gap brief's proof: with a daily cap of one, the booked day answers
/// full with no offered time and no booking detail, the days after it stay
/// open, and the page model carries the same marker in its mask and its
/// first view.
#[test]
fn public_booking_capped_day_surfaces_full_without_leaking_events() {
    on_engine_stack(|| async {
        let page = PublishedPage::new(every_day(Some(1), None));
        let slot = page.first_offered_slot().await;
        page.book(slot, "sess-owen", "owen@example.com").await;
        let booked_day = slot.0 / DAY;

        let answer = page.availability(booked_day, 3).await;
        let result = &answer["result"];
        assert_eq!(
            keys_of(result),
            ["flex_used", "full_days", "slots"],
            "availability answers slots, the flex flag and the full days only: {answer}"
        );
        assert_eq!(
            result["full_days"],
            json!([{"date": civil_date(booked_day), "cap": "daily"}]),
            "the capped day is answered full by its date and cap: {answer}"
        );
        let starts = slot_starts(result);
        assert!(
            starts.iter().all(|start| start / DAY != booked_day),
            "a full day offers no time: {answer}"
        );
        for open_day in [booked_day + 1, booked_day + 2] {
            assert!(
                starts.iter().any(|start| start / DAY == open_day),
                "the day after the cap stays open: {answer}"
            );
        }
        let text = answer.to_string();
        for detail in ["owen@example.com", EVENT_TITLE, &slot.0.to_string()] {
            assert!(
                !text.contains(detail),
                "the full marker leaks no booking detail ({detail}): {answer}"
            );
        }

        // The page model renders the same marker, in the SLOTS mask and in
        // the first view, and the first view equals the mask's.
        let model = page.model().await;
        let mask_days = &model["slots"]["rows"]["full_days"];
        assert_eq!(
            &model["preview"]["full_days"], mask_days,
            "the first view shows the mask's full days: {model}"
        );
        let days = mask_days
            .as_array()
            .unwrap_or_else(|| panic!("the page mask carries full days: {model}"));
        assert!(
            days.iter()
                .all(|day| *day == json!({"date": civil_date(booked_day), "cap": "daily"})),
            "only the capped day is full on the page: {model}"
        );
        // The page's window opens a day ahead, so the booked slot is in it;
        // its day is in the page's window past the booked slot unless that
        // slot was the day's last.
        if slot.1 % DAY != 0 {
            assert_eq!(days.len(), 1, "the page shows the capped day full: {model}");
        }
    });
}

/// Weekly cap one, open Monday to Thursday: a Monday booking fills that
/// week, so each open day of it is full by the weekly cap and offers nothing,
/// while Friday to Sunday (no hours) are never full.
#[test]
fn a_weekly_cap_marks_each_open_day_of_its_week_full_and_never_a_closed_day() {
    on_engine_stack(|| async {
        let page = PublishedPage::new(monday_to_thursday(None, Some(1)));
        let monday = next_monday();
        let first = page.availability(monday, 1).await;
        let slot = slot_starts(&first["result"])
            .first()
            .map(|start| (*start, start + 30 * 60))
            .unwrap_or_else(|| panic!("Monday offers a slot: {first}"));
        page.book(slot, "sess-owen", "owen@example.com").await;

        let answer = page.availability(monday, 7).await;
        let result = &answer["result"];
        assert_eq!(
            result["full_days"],
            json!(
                (0..4)
                    .map(|offset| json!({"date": civil_date(monday + offset), "cap": "weekly"}))
                    .collect::<Vec<_>>()
            ),
            "each open day of the filled week is full by the weekly cap: {answer}"
        );
        assert_eq!(
            result["slots"],
            json!([]),
            "a filled week offers nothing: {answer}"
        );
    });
}

/// An event type with no cap answers no full day, even on a booked day.
#[test]
fn an_event_type_without_caps_answers_no_full_day() {
    on_engine_stack(|| async {
        let page = PublishedPage::new(every_day(None, None));
        let slot = page.first_offered_slot().await;
        page.book(slot, "sess-owen", "owen@example.com").await;
        let booked_day = slot.0 / DAY;

        let answer = page.availability(booked_day, 2).await;
        assert_eq!(
            answer["result"]["full_days"],
            json!([]),
            "no cap, no full day: {answer}"
        );
        assert!(
            slot_starts(&answer["result"])
                .iter()
                .any(|start| start / DAY == booked_day + 1),
            "the page still offers times: {answer}"
        );
    });
}

// -------------------------------------------------------------------------
// Fixture
// -------------------------------------------------------------------------

fn id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("fixture id")
}

fn page_id() -> EntityId {
    id(0x71)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs()
}

/// The first Monday (UTC day number) at least two days ahead, so its whole
/// week lies inside the booking window and past the notice.
fn next_monday() -> u64 {
    let mut day = now_secs() / DAY + 2;
    // 1970-01-01 was a Thursday: day 4 is the first Monday.
    while day % 7 != 4 {
        day += 1;
    }
    day
}

/// A UTC day number as its `YYYY-MM-DD` date (Hinnant's civil_from_days).
fn civil_date(day: u64) -> String {
    let shifted = i64::try_from(day).expect("day") + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let month_day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{month_day:02}")
}

/// The sorted keys of a JSON object.
fn keys_of(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value
        .as_object()
        .unwrap_or_else(|| panic!("an object: {value}"))
        .keys()
        .cloned()
        .collect();
    keys.sort();
    keys
}

/// The UTC starts of an availability result's slots.
fn slot_starts(result: &Value) -> Vec<u64> {
    result["slots"]
        .as_array()
        .unwrap_or_else(|| panic!("slots: {result}"))
        .iter()
        .map(|slot| slot["start_utc"].as_u64().expect("slot start"))
        .collect()
}

/// One event type, bookable all day on `weekdays` (0 = Monday), for two
/// weeks, with no notice.
fn event_type_config(
    weekdays: std::ops::Range<u8>,
    daily_cap: Option<u16>,
    weekly_cap: Option<u16>,
) -> EventTypeConfig {
    EventTypeConfig {
        key: EventTypeKey(EVENT_TYPE.to_owned()),
        duration_min: 30,
        slot_step_min: 30,
        pre_buffer_min: 0,
        post_buffer_min: 0,
        min_notice_secs: 0,
        booking_window_secs: 14 * DAY,
        daily_cap,
        weekly_cap,
        routing: RoutingMode::Either,
        hosts: vec![HostAvailabilityConfig {
            host_ref: id(0x73),
            calendar_refs: vec![id(0x74)],
            host_tz: "UTC".to_owned(),
            working_hours: weekdays
                .map(|weekday| WeeklyWallWindow {
                    weekday,
                    start_minute: 0,
                    end_minute: 1_440,
                })
                .collect(),
            preferred_hours: Vec::new(),
        }],
        flex_windows: Vec::new(),
    }
}

fn every_day(daily_cap: Option<u16>, weekly_cap: Option<u16>) -> EventTypeConfig {
    event_type_config(0..7, daily_cap, weekly_cap)
}

fn monday_to_thursday(daily_cap: Option<u16>, weekly_cap: Option<u16>) -> EventTypeConfig {
    event_type_config(0..4, daily_cap, weekly_cap)
}

/// A server over a device vault holding one configured and published page.
struct PublishedPage {
    _dir: tempfile::TempDir,
    server: Arc<SyncServer>,
    token: String,
}

impl PublishedPage {
    fn new(config: EventTypeConfig) -> Self {
        let dir = tempfile::tempdir().expect("temp vault");
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("vault"));
        let at = TimeRange { start: 1, end: 1 };
        let page = page_id();
        vault
            .put_entity(
                &page,
                oneiron::registry::ENTITY_TYPE_ASSET,
                at,
                1,
                b"booking page",
            )
            .expect("page");
        let value = encode_event_type_claim_value(&BookingEventTypeClaimValue {
            schema_version: BOOKING_EVENT_TYPE_SCHEMA_VERSION,
            page_ref: page,
            config: config.clone(),
        })
        .expect("event type value");
        let mut body = ClaimBody::new(
            BOOKING_EVENT_TYPE_PREDICATE,
            ClaimSubject::Entity(page),
            value,
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )
        .expect("event type claim");
        // A claim about the ASSET page is born under the vault's default
        // facet: the constructor's derived facet names no stored FACET.
        body.scope_facet = vault.default_facet().expect("default facet");
        vault
            .put_claim(&id(0x72), &body, at, 1)
            .expect("event type claim");
        // The vault has no authority root yet, so the one actor whose owner
        // write it admits is its own live embedded owner.
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        publish(&vault, owner, page, &config);
        DreamerRunnerStore::new(&vault)
            .elect_home_node(&[DreamerHomeNodeCandidate::always_on_local(HOME_NODE)], 1)
            .expect("home node");
        let server = SyncServer::new(
            vault,
            SyncServerConfig {
                lease_vault_id: HOME_NODE,
                ..Default::default()
            },
        )
        .expect("server");
        Self {
            _dir: dir,
            server: Arc::new(server),
            token: PublicBookingPageToken::for_page(page).0,
        }
    }

    async fn route(&self, method: &str, path: &str, body: Option<&Value>) -> (StatusCode, Value) {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .extension(ConnectInfo(
                "127.0.0.1:43123".parse::<SocketAddr>().expect("peer"),
            ))
            .body(match body {
                Some(body) => Body::from(body.to_string()),
                None => Body::empty(),
            })
            .expect("request");
        let response = build_app(Arc::clone(&self.server))
            .oneshot(request)
            .await
            .expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }

    /// Posts one verb and answers its body, which must be a 200.
    async fn ok(&self, verb: &str, body: Value) -> Value {
        let path = format!("/public/booking/{}/verbs/{verb}", self.token);
        let (status, answer) = self.route("POST", &path, Some(&body)).await;
        assert_eq!(status, StatusCode::OK, "{verb} answers 200: {answer}");
        answer
    }

    /// The public availability answer over `days` whole UTC days from `first_day`.
    async fn availability(&self, first_day: u64, days: u64) -> Value {
        let path = format!("/public/booking/{}/availability", self.token);
        let body = json!({
            "event_type": EVENT_TYPE,
            "window": {"start": first_day * DAY, "end": (first_day + days) * DAY - 1},
            "visitor_tz": "UTC", "constraint": null, "session_ref": "sess-visitor",
        });
        let (status, answer) = self.route("POST", &path, Some(&body)).await;
        assert_eq!(status, StatusCode::OK, "availability answers 200: {answer}");
        assert_eq!(answer["op"], "availability", "{answer}");
        answer
    }

    /// The rendered page's model, as JSON.
    async fn model(&self) -> Value {
        let path = format!("/public/booking/{}", self.token);
        let (status, page) = self.route("GET", &path, None).await;
        assert_eq!(status, StatusCode::OK, "the page renders: {page}");
        page["model"].clone()
    }

    /// The first slot the published page offers.
    async fn first_offered_slot(&self) -> (u64, u64) {
        let model = self.model().await;
        let slot = &model["slots"]["rows"]["slots"][0];
        match (slot["start_utc"].as_u64(), slot["end_utc"].as_u64()) {
            (Some(start), Some(end)) => (start, end),
            _ => panic!("the page offers a slot: {model}"),
        }
    }

    /// Holds and confirms `slot` for `session`.
    async fn book(&self, slot: (u64, u64), session: &str, email: &str) {
        let held = self
            .ok(
                "booking.hold",
                json!({"op": "book", "input": {"stage": "hold", "input": {
                    "event_type": EVENT_TYPE,
                    "selected_slot": {"start_utc": slot.0, "end_utc": slot.1},
                    "visitor_tz": "UTC", "constraint": null, "session_ref": session,
                    "checkout_lease_token": null, "idempotency_key": format!("hold-{session}"),
                }}}),
            )
            .await;
        assert_eq!(held["result"]["stage"], "held", "{held}");
        let hold_token = held["result"]["result"]["hold_token"]
            .as_str()
            .unwrap_or_else(|| panic!("hold token: {held}"))
            .to_owned();
        let confirmed = self
            .ok(
                "booking.confirm",
                json!({"op": "book", "input": {"stage": "confirm", "input": {
                    "hold_token": hold_token, "booker_email": email, "intake": [],
                    "session_ref": session, "idempotency_key": format!("confirm-{session}"),
                }}}),
            )
            .await;
        assert_eq!(confirmed["result"]["stage"], "confirmed", "{confirmed}");
    }
}

/// Publishes `page` as the owner's own write, before any server runs.
fn publish(vault: &Vault, owner: EntityId, page: EntityId, config: &EventTypeConfig) {
    let publication = BookingPagePublication {
        schema_version: BOOKING_PUBLIC_PAGE_SCHEMA_VERSION,
        published: true,
        event_config_hashes: [(
            EVENT_TYPE.to_owned(),
            booking_config_hash(config).expect("config hash"),
        )]
        .into(),
        owner_display: "Page owner".to_owned(),
        event_types: vec![EventTypeCard {
            key: EventTypeKey(EVENT_TYPE.to_owned()),
            title: EVENT_TITLE.to_owned(),
            duration_min: 30,
            description: "A first call".to_owned(),
        }],
        constraint_field: ConstraintFieldConfig {
            enabled: false,
            placeholder: String::new(),
        },
        theme: ThemeTokens(json!({})),
        landing: BookingLandingContent::default(),
        initial_availability: PublicBookingAvailability {
            event_type: EventTypeKey(EVENT_TYPE.to_owned()),
            start_after_secs: DAY,
            window_secs: DAY,
            visitor_tz: "UTC".to_owned(),
        },
        constraint_front: None,
        sponsor: None,
    };
    let input = ClaimInput {
        id: None,
        predicate: BOOKING_PUBLIC_PAGE_PREDICATE.to_owned(),
        subject_ref: page.to_hex(),
        value: serde_json::to_value(publication).expect("publication"),
        confidence: 1.0,
        source: "user_stated".to_owned(),
        world_ref: None,
        relationship_ref: None,
        scope: None,
        valid_from: Some(1),
        valid_to: Some(now_secs() + 15 * DAY),
        occurred_at: None,
        learned_at: None,
        salience: None,
        confidence_details: None,
    };
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let receipt = memory
        .claim_upsert(&input)
        .expect("owner publication write");
    if receipt.approval == "proposed" {
        memory
            .confirm_booking_publication(&receipt.claim_short_id, now_secs())
            .expect("owner confirms the publication");
    }
}
