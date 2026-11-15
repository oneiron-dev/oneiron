//! The waitlist on the public booking verb route (census L3-13 PR 2;
//! ARCH-0062 §7 "waitlist on full slots"; RULINGs L3-13 OFFER = A, WINDOW =
//! B). A visitor whose window offers no slot joins its line with
//! `booking.waitlist`; a cancel then holds the freed slot for the first
//! waiter, so nobody else can hold it, and the waiter claims it with the
//! entry token alone, from a new session. A waiter who left is never offered.
//! The operation table every transport advertises names the waitlist last.
//!
//! Every case drives the real router (`build_app`) over a vault with one
//! published page, as an anonymous visitor: the bodies are the public wire,
//! written as JSON.
//!
//! Fleet command: `cargo test --locked -p oneiron-server --all-features
//! --test booking_waitlist_routes`.
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use oneiron::booking::agent_api::{
    BOOKING_AGENT_INSTRUCTIONS_VERSION, BookingAgentEndpoint, BookingAgentInstructionsBlock,
    BookingAgentOperation,
};
use oneiron::booking::{
    BOOKING_EVENT_TYPE_PREDICATE, BOOKING_EVENT_TYPE_SCHEMA_VERSION, BOOKING_PUBLIC_PAGE_PREDICATE,
    BOOKING_PUBLIC_PAGE_SCHEMA_VERSION, BookingEventTypeClaimValue, BookingLandingContent,
    BookingPageModel, BookingPagePublication, ConstraintFieldConfig, EventTypeCard,
    EventTypeConfig, EventTypeKey, HostAvailabilityConfig, PublicBookingAvailability,
    PublicBookingPageToken, RoutingMode, RungProjection, ThemeTokens, WeeklyWallWindow,
    booking_config_hash, encode_event_type_claim_value,
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

#[test]
fn a_waiter_on_a_booked_window_is_offered_its_cancelled_slot_and_claims_it() {
    on_engine_stack(|| async {
        let page = PublishedPage::new();
        let slot = page.first_offered_slot().await;
        let (_, cancel_token) = page.book(slot, "sess-owen", "owen@example.com").await;

        let joined = page.ok("booking.waitlist", join(slot, "sess-yuki")).await;
        assert_eq!(joined["op"], "waitlist");
        assert_eq!(
            joined["result"]["stage"], "joined",
            "a booked window takes a waiter: {joined}"
        );
        assert_eq!(joined["result"]["result"]["position"], 1);
        let entry_token = token_at(&joined, "entry_token");

        page.ok("booking.cancel", cancel(&cancel_token)).await;

        // The freed slot is held for the waiter: another visitor's hold on
        // it gets the ordinary taken answer.
        let stranger = page.ok("booking.hold", hold(slot, "sess-stranger")).await;
        assert_eq!(
            stranger["result"]["stage"], "slot_taken",
            "the offered slot is held for the waiter: {stranger}"
        );

        // The waiter claims with the entry token alone (no session).
        let claimed = page
            .ok("booking.waitlist", claim(&entry_token, "yuki@example.com"))
            .await;
        assert_eq!(
            claimed["result"]["stage"], "claimed",
            "the waiter books the offered slot: {claimed}"
        );
        let reschedule = token_at(&claimed, "reschedule_token");
        let cancel_again = token_at(&claimed, "cancel_token");
        assert_ne!(reschedule, cancel_again);
        assert_ne!(cancel_again, cancel_token, "the claim is a new booking");
    });
}

#[test]
fn a_waiter_who_left_is_never_offered_the_freed_slot() {
    on_engine_stack(|| async {
        let page = PublishedPage::new();
        let slot = page.first_offered_slot().await;
        let (_, cancel_token) = page.book(slot, "sess-owen", "owen@example.com").await;

        let joined = page.ok("booking.waitlist", join(slot, "sess-yuki")).await;
        let entry_token = token_at(&joined, "entry_token");
        let left = page.ok("booking.waitlist", leave(&entry_token)).await;
        assert_eq!(left["op"], "waitlist");
        assert_eq!(left["result"]["stage"], "left", "{left}");

        page.ok("booking.cancel", cancel(&cancel_token)).await;

        // Nobody waits, so the freed slot is everyone's again.
        let stranger = page.ok("booking.hold", hold(slot, "sess-stranger")).await;
        assert_eq!(
            stranger["result"]["stage"], "held",
            "a left waiter holds nothing: {stranger}"
        );
        let (status, refused) = page
            .post("booking.waitlist", claim(&entry_token, "yuki@example.com"))
            .await;
        assert_ne!(
            status,
            StatusCode::OK,
            "a left entry claims nothing: {refused}"
        );
    });
}

#[test]
fn a_waitlist_stage_posted_under_another_verb_is_not_found() {
    on_engine_stack(|| async {
        let page = PublishedPage::new();
        let slot = page.first_offered_slot().await;
        let (unknown, _) = page.post("booking.peek", join(slot, "sess-yuki")).await;
        assert_eq!(unknown, StatusCode::NOT_FOUND);
        let (status, body) = page.post("booking.hold", join(slot, "sess-yuki")).await;
        assert_eq!(
            status, unknown,
            "a waitlist stage under the hold verb answers as an unknown verb: {body}"
        );
    });
}

#[test]
fn every_transport_advertises_the_waitlist_after_cancel() {
    let names: Vec<&str> = BookingAgentOperation::CANONICAL
        .iter()
        .map(|operation| operation.as_str())
        .collect();
    assert_eq!(
        names,
        ["availability", "book", "reschedule", "cancel", "waitlist"],
        "the canonical operation order"
    );
    // Discovery, the OpenAPI operation index and the MCP book tool all read
    // this list.
    assert_eq!(oneiron_server::mcp::MCP_BOOK_OPERATIONS, names.as_slice());
    let page_token = PublicBookingPageToken::for_page(page_id()).0;
    let block = BookingAgentInstructionsBlock {
        version: BOOKING_AGENT_INSTRUCTIONS_VERSION,
        page_token: page_token.clone(),
        event_types: vec![EventTypeKey(EVENT_TYPE.to_owned())],
        operations: BookingAgentOperation::CANONICAL
            .iter()
            .map(|operation| BookingAgentEndpoint {
                operation: *operation,
                method: "POST".to_owned(),
                path: format!("/api/booking/{page_token}/{}", operation.as_str()),
            })
            .collect(),
        constraint_schema_version: oneiron::booking::constraint::CONSTRAINT_SCHEMA_VERSION,
    };
    assert_eq!(block.validate(), Ok(()));
    let parsed: BookingAgentOperation =
        serde_json::from_value(json!("waitlist")).expect("the waitlist operation is on the wire");
    assert_eq!(parsed.as_str(), "waitlist");
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

/// One event type, bookable all day, every day, for a week, with no notice.
fn event_type_config() -> EventTypeConfig {
    EventTypeConfig {
        key: EventTypeKey(EVENT_TYPE.to_owned()),
        duration_min: 30,
        slot_step_min: 30,
        pre_buffer_min: 0,
        post_buffer_min: 0,
        min_notice_secs: 0,
        booking_window_secs: 7 * 86_400,
        daily_cap: None,
        weekly_cap: None,
        routing: RoutingMode::Either,
        hosts: vec![HostAvailabilityConfig {
            host_ref: id(0x73),
            calendar_refs: vec![id(0x74)],
            host_tz: "UTC".to_owned(),
            working_hours: (0..7)
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

/// A server over a device vault holding one configured and published page.
struct PublishedPage {
    _dir: tempfile::TempDir,
    server: Arc<SyncServer>,
    token: String,
}

impl PublishedPage {
    fn new() -> Self {
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
        let config = event_type_config();
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
        let owner = id(0x77);
        vault
            .put_entity(
                &owner,
                oneiron::registry::ENTITY_TYPE_PERSON,
                at,
                1,
                b"page owner",
            )
            .expect("owner");
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

    async fn post(&self, verb: &str, body: Value) -> (StatusCode, Value) {
        let path = format!("/public/booking/{}/verbs/{verb}", self.token);
        self.route("POST", &path, Some(&body)).await
    }

    /// Posts one verb and answers its body, which must be a 200.
    async fn ok(&self, verb: &str, body: Value) -> Value {
        let (status, answer) = self.post(verb, body).await;
        assert_eq!(status, StatusCode::OK, "{verb} answers 200: {answer}");
        answer
    }

    /// The first slot the published page offers.
    async fn first_offered_slot(&self) -> (u64, u64) {
        let path = format!("/public/booking/{}", self.token);
        let (status, page) = self.route("GET", &path, None).await;
        assert_eq!(status, StatusCode::OK, "the page renders: {page}");
        let model: BookingPageModel =
            serde_json::from_value(page["model"].clone()).expect("page model");
        let RungProjection::Slots(mask) = model.slots else {
            panic!("the public page offers slots only")
        };
        let slot = mask.slots.first().expect("the page offers a slot");
        (slot.start_utc, slot.end_utc)
    }

    /// Holds and confirms `slot` for `session`; answers its reschedule and
    /// cancel tokens.
    async fn book(&self, slot: (u64, u64), session: &str, email: &str) -> (String, String) {
        let held = self.ok("booking.hold", hold(slot, session)).await;
        assert_eq!(held["result"]["stage"], "held", "{held}");
        let hold_token = token_at(&held, "hold_token");
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
        (
            token_at(&confirmed, "reschedule_token"),
            token_at(&confirmed, "cancel_token"),
        )
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
            title: "Intro call".to_owned(),
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
            start_after_secs: 86_400,
            window_secs: 86_400,
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
        valid_to: Some(now_secs() + 86_400),
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

fn hold(slot: (u64, u64), session: &str) -> Value {
    json!({"op": "book", "input": {"stage": "hold", "input": {
        "event_type": EVENT_TYPE,
        "selected_slot": {"start_utc": slot.0, "end_utc": slot.1},
        "visitor_tz": "UTC", "constraint": null, "session_ref": session,
        "checkout_lease_token": null, "idempotency_key": format!("hold-{session}"),
    }}})
}

fn join(slot: (u64, u64), session: &str) -> Value {
    json!({"op": "waitlist", "input": {"stage": "join", "input": {
        "event_type": EVENT_TYPE,
        "window": {"start": slot.0, "end": slot.1},
        "visitor_tz": "UTC", "session_ref": session,
        "booker_email": "yuki@example.com",
        "idempotency_key": format!("join-{session}"),
    }}})
}

fn leave(entry_token: &str) -> Value {
    json!({"op": "waitlist", "input": {"stage": "leave", "input": {
        "entry_token": entry_token, "idempotency_key": "leave-yuki",
    }}})
}

fn claim(entry_token: &str, email: &str) -> Value {
    json!({"op": "waitlist", "input": {"stage": "claim", "input": {
        "entry_token": entry_token, "booker_email": email, "intake": [],
        "idempotency_key": "claim-yuki",
    }}})
}

fn cancel(cancel_token: &str) -> Value {
    json!({"op": "cancel", "input": {
        "cancel_token": cancel_token, "idempotency_key": "cancel-owen",
    }})
}

/// The 64-hex token `field` of a staged answer (`result.result.<field>`) or
/// of a flat one (`result.<field>`).
fn token_at(answer: &Value, field: &str) -> String {
    let token = answer["result"]["result"][field]
        .as_str()
        .or_else(|| answer["result"][field].as_str())
        .unwrap_or_else(|| panic!("{field} in {answer}"));
    assert!(
        token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{field} is an opaque lifecycle token: {token}"
    );
    token.to_owned()
}
