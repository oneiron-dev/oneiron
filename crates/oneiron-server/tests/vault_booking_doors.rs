//! The `vault.booking.*` verb rows and the public page route, one canon promise
//! per test (oneiron-arch-0062-booking-loop-v1).
//!
//! Every booking row is a host door: in process it answers the host-only
//! refusal, so these tests drive the server's real router (`build_app`) at
//! `POST /v1/core/facade/vault.booking.*` with the self-hosted root credential,
//! which acts as the vault's embedded owner, and the anonymous public route
//! `GET /public/booking/{page_token}`. Each test owns its vault, publishes its
//! page as that owner through the memory claim door, and runs on the engine's
//! stack, as the facade dispatch needs.
//!
//! - `no_booking_door_discloses_more_than_slots`: "no public surface ever
//!   climbs above SLOTS".
//! - `an_action_token_from_another_page_fails_like_a_forged_one`
//!   (promise-gate-27).
//! - `a_confirm_retry_answers_the_pair_the_first_confirm_issued`
//!   (promise-other-40): only the tokens' digests are stored, so a retry
//!   derives the recorded pair again; no door reads a stored row itself.
//! - `a_stale_event_configuration_answers_the_unknown_page_404`
//!   (promise-gate-28).
//! - `a_reschedule_moves_the_one_booking_its_tokens_name`: the door shadow of
//!   a revision keeping its booking. The UID and sequence a revision reuses
//!   reach no door: the confirm answer carries only the two tokens.
//! - `a_malformed_or_unsigned_booking_act_is_refused`: each of the six rows.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer};
use oneiron::booking::config::{
    BOOKING_EVENT_TYPE_PREDICATE, BOOKING_EVENT_TYPE_SCHEMA_VERSION, BookingEventTypeClaimValue,
    EventTypeConfig, HostAvailabilityConfig, RoutingMode, WeeklyWallWindow,
    encode_event_type_claim_value,
};
use oneiron::booking::{
    BOOKING_LIFECYCLE_ATTEMPT_KIND, BOOKING_PUBLIC_PAGE_PREDICATE,
    BOOKING_PUBLIC_PAGE_SCHEMA_VERSION, BookingLandingContent, BookingPagePublication,
    ConstraintFieldConfig, EventTypeCard, EventTypeKey, PublicBookingAvailability,
    PublicBookingPageToken, ThemeTokens, booking_config_hash,
};
use oneiron::memory::ClaimInput;
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::{
    AttemptQueue, ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject,
    DreamerHomeNodeCandidate, DreamerRunnerStore, EdgeActorClass, EntityId, TimeRange, Vault,
    VaultConfig,
};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET: &str = "vault-booking-doors-secret";
const EVENT_TYPE: &str = "intro";
const HOME_NODE_ID: u64 = 7;
const HOST: u8 = 0xB1;
const CALENDAR: u8 = 0xB2;
const PAGE_A: u8 = 0xB0;
const PAGE_A_CONFIG: u8 = 0xB3;
const PAGE_B: u8 = 0xC0;
const PAGE_B_CONFIG: u8 = 0xC1;
/// Slot step and length of the one event type, in seconds.
const SLOT_SECS: u64 = 30 * 60;
/// The keys and strings a slot answer may never carry.
const BUSY_STRINGS: [&str; 7] = [
    "title",
    "description",
    "attendees",
    "busy",
    "summary",
    "calendar",
    "event_ref",
];

fn seeded_id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).unwrap()
}

fn at(value: u64) -> TimeRange {
    TimeRange {
        start: value,
        end: value,
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn test_vault_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.max_readers = 32;
    config
}

/// One host, every hour of every day, no notice floor and a 30-day horizon,
/// so every window below is bookable whenever the suite runs.
fn event_config() -> EventTypeConfig {
    EventTypeConfig {
        key: EventTypeKey(EVENT_TYPE.to_owned()),
        duration_min: 30,
        slot_step_min: 30,
        pre_buffer_min: 0,
        post_buffer_min: 0,
        min_notice_secs: 0,
        booking_window_secs: 30 * 86_400,
        daily_cap: None,
        weekly_cap: None,
        routing: RoutingMode::Either,
        hosts: vec![HostAvailabilityConfig {
            host_ref: seeded_id(HOST),
            calendar_refs: vec![seeded_id(CALENDAR)],
            host_tz: "UTC".to_owned(),
            working_hours: (0..7)
                .map(|weekday| WeeklyWallWindow {
                    weekday,
                    start_minute: 0,
                    end_minute: 1440,
                })
                .collect(),
            preferred_hours: Vec::new(),
        }],
        flex_windows: Vec::new(),
    }
}

/// The page and its live `booking.event_type` claim, under the vault's
/// default facet (a CLAIM birth needs a stored FACET).
fn configure_page(vault: &Vault, page: EntityId, claim_byte: u8) {
    vault
        .put_entity(&page, ENTITY_TYPE_ASSET, at(1), 1, b"booking page")
        .unwrap();
    let value = BookingEventTypeClaimValue {
        schema_version: BOOKING_EVENT_TYPE_SCHEMA_VERSION,
        page_ref: page,
        config: event_config(),
    };
    let mut body = ClaimBody::new(
        BOOKING_EVENT_TYPE_PREDICATE,
        ClaimSubject::Entity(page),
        encode_event_type_claim_value(&value).unwrap(),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("event type claim");
    body.scope_facet = vault.default_facet().unwrap();
    vault
        .put_claim(&seeded_id(claim_byte), &body, at(1), 1)
        .unwrap();
}

fn publication(owner_display: &str) -> BookingPagePublication {
    BookingPagePublication {
        schema_version: BOOKING_PUBLIC_PAGE_SCHEMA_VERSION,
        published: true,
        event_config_hashes: [(
            EVENT_TYPE.to_owned(),
            booking_config_hash(&event_config()).unwrap(),
        )]
        .into(),
        owner_display: owner_display.to_owned(),
        event_types: vec![EventTypeCard {
            key: EventTypeKey(EVENT_TYPE.to_owned()),
            title: "Door event".to_owned(),
            duration_min: 30,
            description: "Door description".to_owned(),
        }],
        constraint_field: ConstraintFieldConfig {
            enabled: true,
            placeholder: "Door constraint".to_owned(),
        },
        theme: ThemeTokens(json!({})),
        landing: BookingLandingContent::default(),
        initial_availability: PublicBookingAvailability {
            event_type: EventTypeKey(EVENT_TYPE.to_owned()),
            start_after_secs: 86_400,
            window_secs: 86_400,
            visitor_tz: "UTC".to_owned(),
        },
        constraint_front: None,
        sponsor: None,
    }
}

/// One rooted vault with one or two live published pages, the server's
/// router, and the self-hosted root credential.
struct Door {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    slip: CapabilitySlip,
    token_a: String,
    page_a: EntityId,
    token_b: String,
    /// Start of every availability window: a slot boundary an hour ahead.
    window_start: u64,
    /// Lengthens each window by a second, so no call reads another's cached
    /// slot list (the cache keys a query by its window).
    calls: AtomicU64,
}

impl Door {
    fn open(second_page: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), test_vault_config()).unwrap();
        vault
            .put_entity(&seeded_id(HOST), ENTITY_TYPE_PERSON, at(1), 1, b"host")
            .unwrap();
        vault
            .put_entity(
                &seeded_id(CALENDAR),
                ENTITY_TYPE_ASSET,
                at(1),
                1,
                b"calendar",
            )
            .unwrap();
        // Only the always-on-local class names this device as the writer.
        DreamerRunnerStore::new(&vault)
            .elect_home_node(
                &[DreamerHomeNodeCandidate::always_on_local(HOME_NODE_ID)],
                1,
            )
            .unwrap();
        configure_page(&vault, seeded_id(PAGE_A), PAGE_A_CONFIG);
        if second_page {
            configure_page(&vault, seeded_id(PAGE_B), PAGE_B_CONFIG);
        }
        let vault = Arc::new(vault);
        let server = Arc::new(
            SyncServer::new(
                Arc::clone(&vault),
                SyncServerConfig {
                    auth_secret: Some(SECRET.to_owned()),
                    ..Default::default()
                },
            )
            .unwrap(),
        );
        // The self-hosted root binds the embedded owner at genesis; its
        // credential acts as that owner.
        let issuer = HostSlipIssuer::from_secret(SECRET.as_bytes()).unwrap();
        let slip = vault.ensure_host_root_slip(&issuer).unwrap();
        let door = Self {
            _dir: dir,
            app: build_app(server),
            vault,
            issuer,
            slip,
            token_a: PublicBookingPageToken::for_page(seeded_id(PAGE_A)).0,
            page_a: seeded_id(PAGE_A),
            token_b: PublicBookingPageToken::for_page(seeded_id(PAGE_B)).0,
            window_start: (now_secs() / SLOT_SECS + 2) * SLOT_SECS,
            calls: AtomicU64::new(0),
        };
        door.publish(seeded_id(PAGE_A), "Door host");
        if second_page {
            door.publish(seeded_id(PAGE_B), "Door host");
        }
        door
    }

    /// The owner's own publication write, confirmed when it is staged.
    fn publish(&self, page: EntityId, owner_display: &str) {
        let owner = self.vault.ensure_embedded_owner_actor().unwrap();
        let memory = self.vault.memory(owner, EdgeActorClass::Human);
        let receipt = memory
            .claim_upsert(&ClaimInput {
                id: None,
                predicate: BOOKING_PUBLIC_PAGE_PREDICATE.to_owned(),
                subject_ref: page.to_hex(),
                value: serde_json::to_value(publication(owner_display)).unwrap(),
                confidence: 1.0,
                source: "user_stated".to_owned(),
                world_ref: None,
                relationship_ref: None,
                scope: None,
                valid_from: Some(1),
                valid_to: Some(now_secs() + 86_400),
                occurred_at: None,
                learned_at: None,
                salience: None,
                confidence_details: None,
            })
            .expect("the owner's publication write");
        if receipt.approval == "proposed" {
            memory
                .confirm_booking_publication(&receipt.claim_short_id, now_secs())
                .expect("the owner confirms the staged revision");
        }
    }

    /// A fresh holder proof for one request.
    fn binding(&self) -> String {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature: String = self
            .issuer
            .binding_proof(&self.slip, challenge.as_bytes())
            .unwrap()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1_048_576).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// `POST /v1/core/facade/<verb>` with `body` as sent, signed by the owner
    /// credential when `signed`.
    async fn post_raw(&self, verb: &str, body: String, signed: bool) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("/v1/core/facade/{verb}"))
            .header("content-type", "application/json");
        if signed {
            request = request
                .header(
                    "authorization",
                    format!("Bearer {}", self.slip.to_token().unwrap()),
                )
                .header("x-oneiron-binding", self.binding());
        }
        self.send(request.body(Body::from(body)).unwrap()).await
    }

    async fn post(&self, verb: &str, body: &Value) -> (StatusCode, Value) {
        self.post_raw(verb, body.to_string(), true).await
    }

    /// The anonymous public page, from a peer (public admission keys a caller
    /// by its connection and fails closed without one).
    async fn get_page(&self, token: &str) -> (StatusCode, Value) {
        let request = Request::builder()
            .method("GET")
            .uri(format!("/public/booking/{token}"))
            .header("content-type", "application/json")
            .extension(ConnectInfo(
                "127.0.0.1:43123".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::from("null"))
            .unwrap();
        self.send(request).await
    }

    /// Booking lifecycle verbs the queue has ever carried (completed rows stay).
    fn attempts(&self) -> usize {
        AttemptQueue::new(&self.vault)
            .list()
            .unwrap()
            .into_iter()
            .filter(|record| record.kind == BOOKING_LIFECYCLE_ATTEMPT_KIND)
            .count()
    }

    async fn availability(&self, token: &str, session: &str) -> (StatusCode, Value) {
        let call = self.calls.fetch_add(1, Ordering::Relaxed);
        self.post(
            "vault.booking.availability",
            &json!({
                "op": "availability",
                "page_token": token,
                "input": {
                    "event_type": EVENT_TYPE,
                    "window": {
                        "start": self.window_start,
                        "end": self.window_start + 12 * SLOT_SECS + 1 + call,
                    },
                    "visitor_tz": "UTC",
                    "constraint": null,
                    "session_ref": session,
                },
            }),
        )
        .await
    }

    /// The slots an availability answer offers, as (start, end) pairs.
    async fn slots(&self, token: &str, session: &str) -> Vec<(u64, u64)> {
        let (status, body) = self.availability(token, session).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["result"]["slots"]
            .as_array()
            .unwrap()
            .iter()
            .map(|slot| {
                (
                    slot["start_utc"].as_u64().unwrap(),
                    slot["end_utc"].as_u64().unwrap(),
                )
            })
            .collect()
    }

    async fn hold(&self, token: &str, slot: (u64, u64), session: &str, key: &str) -> String {
        let (status, body) = self
            .post(
                "vault.booking.book",
                &json!({
                    "op": "book",
                    "page_token": token,
                    "input": {
                        "stage": "hold",
                        "input": {
                            "event_type": EVENT_TYPE,
                            "selected_slot": { "start_utc": slot.0, "end_utc": slot.1 },
                            "visitor_tz": "UTC",
                            "constraint": null,
                            "session_ref": session,
                            "checkout_lease_token": null,
                            "idempotency_key": key,
                        },
                    },
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["result"]["stage"], "held", "{body}");
        body["result"]["result"]["hold_token"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    async fn confirm(
        &self,
        token: &str,
        hold_token: &str,
        session: &str,
        key: &str,
    ) -> (StatusCode, Value) {
        self.post(
            "vault.booking.book",
            &json!({
                "op": "book",
                "page_token": token,
                "input": {
                    "stage": "confirm",
                    "input": {
                        "hold_token": hold_token,
                        "booker_email": "visitor@example.com",
                        "intake": [],
                        "session_ref": session,
                        "idempotency_key": key,
                    },
                },
            }),
        )
        .await
    }

    /// Hold then confirm `slot` on `token`'s page: (reschedule, cancel) tokens.
    async fn book(&self, token: &str, slot: (u64, u64), session: &str) -> (String, String) {
        let hold_token = self
            .hold(token, slot, session, &format!("{session}-hold"))
            .await;
        let (status, body) = self
            .confirm(token, &hold_token, session, &format!("{session}-confirm"))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["result"]["stage"], "confirmed", "{body}");
        let tokens = &body["result"]["result"];
        (
            tokens["reschedule_token"].as_str().unwrap().to_owned(),
            tokens["cancel_token"].as_str().unwrap().to_owned(),
        )
    }

    async fn reschedule(
        &self,
        token: &str,
        reschedule_token: &str,
        slot: (u64, u64),
        key: &str,
    ) -> (StatusCode, Value) {
        self.post(
            "vault.booking.reschedule",
            &json!({
                "op": "reschedule",
                "page_token": token,
                "input": {
                    "reschedule_token": reschedule_token,
                    "selected_slot": { "start_utc": slot.0, "end_utc": slot.1 },
                    "visitor_tz": "UTC",
                    "idempotency_key": key,
                },
            }),
        )
        .await
    }

    async fn cancel(&self, token: &str, cancel_token: &str, key: &str) -> (StatusCode, Value) {
        self.post(
            "vault.booking.cancel",
            &json!({
                "op": "cancel",
                "page_token": token,
                "input": { "cancel_token": cancel_token, "idempotency_key": key },
            }),
        )
        .await
    }
}

/// Every key and string reachable from `value`.
fn all_strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(text) => out.push(text.clone()),
        Value::Array(items) => {
            for item in items {
                all_strings(item, out);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                out.push(key.clone());
                all_strings(item, out);
            }
        }
        _ => {}
    }
}

fn assert_no_busy_strings(value: &Value, what: &str) {
    let mut strings = Vec::new();
    all_strings(value, &mut strings);
    for forbidden in BUSY_STRINGS {
        assert!(
            !strings.iter().any(|text| text == forbidden),
            "{what} discloses `{forbidden}`: {value}"
        );
    }
}

fn assert_slot_rows(slots: &Value, what: &str) {
    let slots = slots.as_array().unwrap();
    assert!(!slots.is_empty(), "{what} offers no slot");
    for slot in slots {
        let mut keys: Vec<&str> = slot
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["end_utc", "rank", "start_utc"], "{what}: {slot}");
        assert!(slot["start_utc"].as_u64().unwrap() < slot["end_utc"].as_u64().unwrap());
    }
}

/// A refusal's (status, code, message): what a caller can tell apart. The
/// request id and the call receipt differ on every call.
fn refusal(status: StatusCode, body: &Value) -> (StatusCode, Value, Value) {
    (
        status,
        body["error"]["code"].clone(),
        body["error"]["message"].clone(),
    )
}

/// "No public surface ever climbs above SLOTS": the availability row answers
/// ranked slots and the flex flag only, and the public page projects its slots
/// at the SLOTS rung.
#[test]
fn no_booking_door_discloses_more_than_slots() {
    run_on_engine_stack("booking-slots-only", || async {
        let door = Door::open(false);

        let (status, body) = door.availability(&door.token_a, "sess-slots").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["op"], "availability", "{body}");
        let mut keys: Vec<&str> = body["result"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["flex_used", "slots"], "{body}");
        assert_slot_rows(&body["result"]["slots"], "vault.booking.availability");
        assert_no_busy_strings(&body, "vault.booking.availability");

        let (status, page) = door.get_page(&door.token_a).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        let projection = &page["model"]["slots"];
        assert_eq!(projection["rung"], "slots", "{page}");
        assert_slot_rows(&projection["rows"]["slots"], "the public page");
        assert_no_busy_strings(projection, "the public page's slot projection");
    });
}

/// promise-gate-27: a hold, reschedule or cancel token used on another booking
/// page fails with the same error as a forged token, and the refused move or
/// cancel reaches no queue.
#[test]
fn an_action_token_from_another_page_fails_like_a_forged_one() {
    run_on_engine_stack("booking-cross-page-token", || async {
        let door = Door::open(true);
        let (page_a, page_b) = (door.token_a.clone(), door.token_b.clone());
        assert!(
            !door.slots(&page_b, "sess-cross-b").await.is_empty(),
            "page B is live and bookable"
        );

        let slots = door.slots(&page_a, "sess-cross-a").await;
        let (reschedule_token, cancel_token) =
            door.book(&page_a, slots[0], "sess-cross-book").await;
        let target = *slots.last().unwrap();

        let enqueued = door.attempts();
        let (status, cross) = door
            .reschedule(&page_b, &reschedule_token, target, "cross-rs")
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{cross}");
        let (forged_status, forged) = door
            .reschedule(&page_b, &"b".repeat(64), target, "forged-rs")
            .await;
        assert_eq!(
            refusal(status, &cross),
            refusal(forged_status, &forged),
            "a page-A reschedule token on page B answers as a forged one"
        );

        let (status, cross) = door.cancel(&page_b, &cancel_token, "cross-cx").await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{cross}");
        let (forged_status, forged) = door.cancel(&page_b, &"b".repeat(64), "forged-cx").await;
        assert_eq!(
            refusal(status, &cross),
            refusal(forged_status, &forged),
            "a page-A cancel token on page B answers as a forged one"
        );
        assert_eq!(
            door.attempts(),
            enqueued,
            "a cross-page token enqueues nothing"
        );
        let text = cross.to_string();
        assert!(
            !text.contains(&cancel_token),
            "the refusal echoes no credential: {text}"
        );
        assert!(
            !text.contains(&door.page_a.to_hex()),
            "the refusal names no page: {text}"
        );

        let slots = door.slots(&page_a, "sess-cross-hold").await;
        let hold_token = door
            .hold(&page_a, slots[0], "sess-cross-hold", "cross-hold")
            .await;
        let (status, cross) = door
            .confirm(&page_b, &hold_token, "sess-cross-hold", "cross-confirm")
            .await;
        assert_ne!(
            status,
            StatusCode::OK,
            "a page-A hold confirms nothing on page B: {cross}"
        );
        let (forged_status, forged) = door
            .confirm(
                &page_b,
                &"a".repeat(64),
                "sess-cross-hold",
                "forged-confirm",
            )
            .await;
        assert_eq!(
            refusal(status, &cross),
            refusal(forged_status, &forged),
            "a page-A hold token on page B answers as a forged one"
        );

        // Both credentials still act on their own page.
        let (status, moved) = door
            .reschedule(&page_a, &reschedule_token, target, "same-rs")
            .await;
        assert_eq!(status, StatusCode::OK, "{moved}");
        let (status, cancelled) = door.cancel(&page_a, &cancel_token, "same-cx").await;
        assert_eq!(status, StatusCode::OK, "{cancelled}");
    });
}

/// promise-other-40: the booking keeps only digests of its tokens, so a
/// confirm retry, under a fresh idempotency key, derives and answers the very
/// pair the first confirm issued; nothing new is minted.
#[test]
fn a_confirm_retry_answers_the_pair_the_first_confirm_issued() {
    run_on_engine_stack("booking-confirm-retry", || async {
        let door = Door::open(false);
        let slots = door.slots(&door.token_a, "sess-retry").await;
        let hold_token = door
            .hold(&door.token_a, slots[0], "sess-retry-book", "retry-hold")
            .await;

        let (status, first) = door
            .confirm(&door.token_a, &hold_token, "sess-retry-book", "retry-c1")
            .await;
        assert_eq!(status, StatusCode::OK, "{first}");
        let first = &first["result"]["result"];
        let reschedule_token = first["reschedule_token"].as_str().unwrap();
        let cancel_token = first["cancel_token"].as_str().unwrap();
        for token in [reschedule_token, cancel_token] {
            assert_eq!(token.len(), 64, "{token}");
            assert_ne!(token, hold_token);
        }
        assert_ne!(reschedule_token, cancel_token);

        let (status, second) = door
            .confirm(&door.token_a, &hold_token, "sess-retry-book", "retry-c2")
            .await;
        assert_eq!(status, StatusCode::OK, "{second}");
        assert_eq!(second["result"]["stage"], "confirmed", "{second}");
        assert_eq!(
            second["result"]["result"]["reschedule_token"],
            reschedule_token
        );
        assert_eq!(second["result"]["result"]["cancel_token"], cancel_token);
    });
}

/// promise-gate-28: a published page stays reachable through an ordinary
/// publication write; once its event configuration is stale it answers the
/// unknown-page 404 at both doors, exactly as an unknown token does.
#[test]
fn a_stale_event_configuration_answers_the_unknown_page_404() {
    run_on_engine_stack("booking-stale-config", || async {
        let door = Door::open(false);
        let (status, body) = door.availability(&door.token_a, "sess-stale").await;
        assert_eq!(status, StatusCode::OK, "{body}");

        door.publish(door.page_a, "Edited host");
        let (status, body) = door.availability(&door.token_a, "sess-stale-edit").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "an ordinary edit keeps the page live: {body}"
        );

        let config = seeded_id(PAGE_A_CONFIG);
        let mut body = door.vault.get_claim(&config).unwrap().unwrap();
        body.stale = true;
        door.vault.put_claim(&config, &body, at(1), 1).unwrap();

        let unknown = format!("bkp_{}", "c".repeat(32));
        let (status, stale) = door.availability(&door.token_a, "sess-stale-gone").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{stale}");
        assert_eq!(stale["error"]["code"], "NOT_FOUND", "{stale}");
        let (unknown_status, unknown_body) =
            door.availability(&unknown, "sess-stale-unknown").await;
        assert_eq!(
            refusal(status, &stale),
            refusal(unknown_status, &unknown_body),
            "a stale page answers as an unknown one at the verb row"
        );

        let (status, page) = door.get_page(&door.token_a).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{page}");
        let (unknown_status, unknown_page) = door.get_page(&unknown).await;
        assert_eq!(
            (status, &page),
            (unknown_status, &unknown_page),
            "a stale page answers as an unknown one at the public route"
        );
        for body in [&stale, &page] {
            let text = body.to_string();
            assert!(
                !text.contains(&door.token_a),
                "the 404 echoes no token: {text}"
            );
            assert!(
                !text.contains(&door.page_a.to_hex()),
                "the 404 names no page: {text}"
            );
        }
    });
}

/// A revision keeps its booking: a reschedule answers with the token it was
/// given and moves the one booking (its old slot is offered again, its new
/// one is taken); the original cancel token cancels that same booking, a
/// second cancel lands on the same receipt, and the booking's reschedule
/// token then finds it cancelled.
#[test]
fn a_reschedule_moves_the_one_booking_its_tokens_name() {
    run_on_engine_stack("booking-reschedule-identity", || async {
        let door = Door::open(false);
        let route = door.token_a.clone();
        let slots = door.slots(&route, "sess-move").await;
        let (old, target) = (slots[0], *slots.last().unwrap());
        let (reschedule_token, cancel_token) = door.book(&route, old, "sess-move-book").await;
        let booked = door.slots(&route, "sess-move-booked").await;
        assert!(!booked.contains(&old), "the booked slot is taken");

        let (status, moved) = door
            .reschedule(&route, &reschedule_token, target, "move-rs")
            .await;
        assert_eq!(status, StatusCode::OK, "{moved}");
        assert_eq!(moved["op"], "reschedule", "{moved}");
        assert_eq!(
            moved["result"]["reschedule_token"],
            reschedule_token.as_str()
        );
        let after = door.slots(&route, "sess-move-after").await;
        assert!(
            after.contains(&old),
            "the old slot is offered again: {after:?}"
        );
        assert!(!after.contains(&target), "the new slot is taken: {after:?}");

        let (status, cancelled) = door.cancel(&route, &cancel_token, "move-cx").await;
        assert_eq!(status, StatusCode::OK, "{cancelled}");
        assert_eq!(cancelled["result"]["cancel_token"], cancel_token.as_str());
        let (status, again) = door.cancel(&route, &cancel_token, "move-cx-again").await;
        assert_eq!(status, StatusCode::OK, "one logical cancel: {again}");
        assert_eq!(again["result"]["cancel_token"], cancel_token.as_str());
        assert!(
            door.slots(&route, "sess-move-cancelled")
                .await
                .contains(&target),
            "the cancelled booking frees its slot"
        );

        let (status, refused) = door
            .reschedule(&route, &reschedule_token, old, "move-rs-cancelled")
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
        assert!(
            refused["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("cancelled")),
            "the reschedule token names the cancelled booking: {refused}"
        );
    });
}

/// Each `vault.booking.*` row refuses a body of the wrong shape (400) and a
/// caller with no credential (401); the page-token row refuses an unknown
/// field and a page_ref that is not an id, and answers the page's token.
#[test]
fn a_malformed_or_unsigned_booking_act_is_refused() {
    run_on_engine_stack("booking-refusals", || async {
        let door = Door::open(false);
        let start = door.window_start;
        let rows = [
            (
                "vault.booking.availability",
                json!({
                    "op": "availability", "page_token": door.token_a,
                    "input": { "event_type": EVENT_TYPE,
                        "window": { "start": start, "end": start + 4 * SLOT_SECS },
                        "visitor_tz": "UTC", "constraint": null, "session_ref": "sess-refused" },
                }),
            ),
            (
                "vault.booking.book",
                json!({
                    "op": "book", "page_token": door.token_a,
                    "input": { "stage": "confirm", "input": { "hold_token": "a".repeat(64),
                        "booker_email": "refused@example.com", "intake": [],
                        "session_ref": "sess-refused", "idempotency_key": "refused-c" } },
                }),
            ),
            (
                "vault.booking.reschedule",
                json!({
                    "op": "reschedule", "page_token": door.token_a,
                    "input": { "reschedule_token": "b".repeat(64),
                        "selected_slot": { "start_utc": start, "end_utc": start + SLOT_SECS },
                        "visitor_tz": "UTC", "idempotency_key": "refused-r" },
                }),
            ),
            (
                "vault.booking.cancel",
                json!({
                    "op": "cancel", "page_token": door.token_a,
                    "input": { "cancel_token": "b".repeat(64), "idempotency_key": "refused-x" },
                }),
            ),
            (
                "vault.booking.page_token",
                json!({ "page_ref": door.page_a.to_hex() }),
            ),
            (
                "vault.booking.constraint_turn",
                json!({
                    "page_token": door.token_a,
                    "turn": { "event_type": EVENT_TYPE,
                        "window": { "start": start, "end": start + 4 * SLOT_SECS },
                        "visitor_tz": "UTC", "free_text": "mornings", "session_ref": "sess-refused" },
                }),
            ),
        ];
        let enqueued = door.attempts();
        for (verb, body) in &rows {
            let (status, refused) = door.post(verb, &json!({})).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{verb} with an empty object: {refused}"
            );
            assert_eq!(refused["error"]["code"], "BAD_REQUEST", "{verb}: {refused}");
            let (status, refused) = door.post_raw(verb, body.to_string(), false).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{verb} with no credential: {refused}"
            );
        }
        assert_eq!(door.attempts(), enqueued, "a refused act enqueues nothing");

        let (status, refused) = door
            .post_raw("vault.booking.availability", "{not json".to_owned(), true)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
        assert_eq!(
            refused["error"]["message"], "invalid JSON request body",
            "{refused}"
        );

        let (status, refused) = door
            .post(
                "vault.booking.page_token",
                &json!({ "page_ref": door.page_a.to_hex(), "page": "extra" }),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an unknown field: {refused}"
        );
        let (status, refused) = door
            .post(
                "vault.booking.page_token",
                &json!({ "page_ref": "not-hex" }),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
        assert_eq!(
            refused["error"]["message"], "invalid booking page_ref",
            "{refused}"
        );

        let (status, answer) = door
            .post(
                "vault.booking.page_token",
                &json!({ "page_ref": door.page_a.to_hex() }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(answer["page_token"], door.token_a.as_str(), "{answer}");
    });
}
