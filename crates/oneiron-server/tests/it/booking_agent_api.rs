//! ONE-1819 [BK-08] HTTP-side gates for the agent-readable booking surface.
//!
//! Every row here drives the real router built by `oneiron_server::build_app`
//! over a real vault: no fakes, no network, no fixtures that could pass while
//! the shipped path is broken.
//!
//! Two gates are asserted against the source instead of the wire, and
//! deliberately so. "No `EntityId` in any public booking DTO" and "every
//! booking handler threads `State<Arc<SyncServer>>`" are properties of the
//! DECLARATIONS, not of any one response — a wire test could only sample
//! them, while a declaration test covers the whole surface at once.

// Integration-test helpers (non-`#[test]` fns) are not covered by
// allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oneiron::booking::agent_api::{
    BOOKING_AGENT_INSTRUCTIONS_MIME, BOOKING_AGENT_INSTRUCTIONS_VERSION,
    BookingAgentInstructionsBlock, BookingAgentOperation,
};
use oneiron::booking::config::{
    BOOKING_EVENT_TYPE_PREDICATE, BOOKING_EVENT_TYPE_SCHEMA_VERSION, BookingEventTypeClaimValue,
    EventTypeConfig, HostAvailabilityConfig, RoutingMode, WeeklyWallWindow,
    encode_event_type_claim_value,
};
use oneiron::booking::constraint::CONSTRAINT_SCHEMA_VERSION;
use oneiron::booking::{BOOKING_LIFECYCLE_ATTEMPT_KIND, EventTypeKey};
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::{
    AttemptQueue, ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject,
    DreamerHomeNodeCandidate, DreamerRunnerStore, EntityId, TimeRange, Vault, VaultConfig,
};
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SECRET: &str = "booking-agent-api-secret";
const EVENT_TYPE: &str = "intro-call";
/// An event-type key built entirely from the characters that could break out
/// of a `<script>` block. It is configuration, so it reaches the instructions
/// block verbatim — which is exactly what makes it a script-safety probe.
const HOSTILE_EVENT_TYPE: &str = "</script><b>&\u{2028}\u{2029}pwn";
const HOME_NODE_ID: u64 = 7;

/// Mirrors `crate::api::booking`'s page-token derivation. The server side is
/// private, so this recomputation IS the pin: if the derivation changed, every
/// row below would 404 instead of silently agreeing with a stale copy.
const PAGE_TOKEN_DOMAIN: &[u8] = b"oneiron.booking.agent_api.page_token.v1\0";

// -------------------------------------------------------------------------
// Fixture
// -------------------------------------------------------------------------

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

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0F)]));
    }
    out
}

fn page_token(page_ref: EntityId) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PAGE_TOKEN_DOMAIN);
    hasher.update(page_ref.as_bytes());
    let digest = *hasher.finalize().as_bytes();
    format!("bkp_{}", hex_lower(&digest[..16]))
}

fn test_vault_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.max_readers = 32;
    config
}

fn event_type_config(key: &str, host: EntityId, calendar: EntityId) -> EventTypeConfig {
    EventTypeConfig {
        key: EventTypeKey(key.to_owned()),
        duration_min: 30,
        slot_step_min: 30,
        pre_buffer_min: 0,
        post_buffer_min: 0,
        // The fixture's clock is the only thing that moves: no notice floor
        // and a wide horizon keep every row's window inside the bookable
        // extent regardless of when the suite runs.
        min_notice_secs: 0,
        booking_window_secs: 30 * 86_400,
        daily_cap: None,
        weekly_cap: None,
        routing: RoutingMode::Either,
        hosts: vec![HostAvailabilityConfig {
            host_ref: host,
            calendar_refs: vec![calendar],
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

fn install_event_type(vault: &Vault, page: EntityId, claim_byte: u8, key: &str) {
    let value = BookingEventTypeClaimValue {
        schema_version: BOOKING_EVENT_TYPE_SCHEMA_VERSION,
        page_ref: page,
        config: event_type_config(key, seeded_id(0xB1), seeded_id(0xB2)),
    };
    let body = ClaimBody::new(
        BOOKING_EVENT_TYPE_PREDICATE,
        ClaimSubject::Entity(page),
        encode_event_type_claim_value(&value).unwrap(),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("fixture");
    vault
        .put_claim(&seeded_id(claim_byte), &body, at(1), 1)
        .unwrap();
}

/// A vault carrying one published booking page and an elected local writer.
fn seeded_vault(extra_event_type: Option<&str>) -> (tempfile::TempDir, Arc<Vault>, EntityId) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), test_vault_config()).unwrap();
    let page = seeded_id(0xB0);
    vault
        .put_entity(&page, ENTITY_TYPE_ASSET, at(1), 1, b"booking page")
        .unwrap();
    vault
        .put_entity(&seeded_id(0xB1), ENTITY_TYPE_PERSON, at(1), 1, b"host")
        .unwrap();
    vault
        .put_entity(&seeded_id(0xB2), ENTITY_TYPE_ASSET, at(1), 1, b"calendar")
        .unwrap();
    // Only the always-on-local class names THIS device; without it the
    // lifecycle refuses to write here at all.
    DreamerRunnerStore::new(&vault)
        .elect_home_node(
            &[DreamerHomeNodeCandidate::always_on_local(HOME_NODE_ID)],
            1,
        )
        .unwrap();
    install_event_type(&vault, page, 0xB3, EVENT_TYPE);
    if let Some(key) = extra_event_type {
        install_event_type(&vault, page, 0xB4, key);
    }
    (dir, Arc::new(vault), page)
}

/// A SECOND published booking page in the same vault.
///
/// Configured exactly like the first — same event type, same host, same
/// calendar — so a cross-page refusal can only be explained by which page a
/// credential belongs to, never by this page being unbookable, differently
/// configured, or unable to answer its own token.
fn install_second_page(vault: &Vault) -> EntityId {
    let page = seeded_id(0xC0);
    vault
        .put_entity(&page, ENTITY_TYPE_ASSET, at(1), 1, b"second booking page")
        .unwrap();
    install_event_type(vault, page, 0xC1, EVENT_TYPE);
    page
}

/// How many booking lifecycle verbs the queue has ever carried.
///
/// The queue is where a verb becomes a mutation, and completed rows stay, so
/// "the same count before and after" is direct evidence that a refused request
/// enqueued nothing and reached no writer.
fn booking_attempts(vault: &Vault) -> usize {
    AttemptQueue::new(vault)
        .list()
        .unwrap()
        .into_iter()
        .filter(|record| record.kind == BOOKING_LIFECYCLE_ATTEMPT_KIND)
        .count()
}

async fn spawn(vault: Arc<Vault>) -> (SocketAddr, Arc<SyncServer>, tokio::task::JoinHandle<()>) {
    let config = SyncServerConfig {
        auth_secret: Some(SECRET.to_owned()),
        ..Default::default()
    };
    let server = Arc::new(SyncServer::new(vault, config).unwrap());
    let app = build_app(server.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, server, handle)
}

async fn read_response(mut stream: tokio::net::TcpStream, request: String) -> String {
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut response))
        .await
        .expect("timed out waiting for HTTP response")
        .expect("failed reading HTTP response");
    String::from_utf8(response).unwrap()
}

fn root_headers(server: &SyncServer) -> String {
    let issuer = oneiron::authority::HostSlipIssuer::from_secret(SECRET.as_bytes()).unwrap();
    let slip = server.vault().ensure_host_root_slip(&issuer).unwrap();
    let timestamp = server.vault().now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature: String = issuer
        .binding_proof(&slip, challenge.as_bytes())
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let binding = json!({"timestamp":timestamp,"nonce":nonce,"signature":signature});
    format!(
        "Authorization: Bearer {}\r\nx-oneiron-binding: {binding}\r\n",
        slip.to_token().unwrap()
    )
}

async fn http_get(
    addr: SocketAddr,
    server: &SyncServer,
    path: &str,
    accept: Option<&str>,
) -> String {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let accept = accept
        .map(|value| format!("Accept: {value}\r\n"))
        .unwrap_or_default();
    let auth = root_headers(server);
    read_response(
        stream,
        format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n{auth}{accept}\r\n"),
    )
    .await
}

async fn http_post(addr: SocketAddr, server: &SyncServer, path: &str, body: &Value) -> String {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let body = body.to_string();
    let auth = root_headers(server);
    read_response(
        stream,
        format!(
            "POST {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{auth}\r\n{body}",
            body.len()
        ),
    )
    .await
}

fn status_of(response: &str) -> u16 {
    response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no HTTP status in {:?}", response.lines().next()))
}

fn body_of(response: &str) -> &str {
    response.split_once("\r\n\r\n").unwrap().1
}

fn json_of(response: &str) -> Value {
    serde_json::from_str(body_of(response)).unwrap_or_else(|error| {
        panic!(
            "response body should be JSON ({error}): {}",
            body_of(response)
        )
    })
}

fn availability_body(window_hours: u64, constraint: Value) -> Value {
    let now = now_secs();
    json!({
        "event_type": EVENT_TYPE,
        "window": { "start": now, "end": now + window_hours * 3_600 },
        "visitor_tz": "UTC",
        "constraint": constraint,
        "session_ref": "sess-booking-agent",
    })
}

/// Every JSON string reachable from `value`, so a disclosure or identifier
/// assertion can cover a whole payload rather than one sampled field.
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

fn object_keys(value: &Value) -> BTreeSet<String> {
    value
        .as_object()
        .unwrap_or_else(|| panic!("expected an object, got {value}"))
        .keys()
        .cloned()
        .collect()
}

fn keys(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

// -------------------------------------------------------------------------
// Instructions document + embedded fragment
// -------------------------------------------------------------------------

#[tokio::test]
async fn booking_agent_instructions_v1_is_canonical() {
    let (_dir, vault, page) = seeded_vault(None);
    let (addr, server, handle) = spawn(vault).await;
    let token = page_token(page);

    let response = http_get(
        addr,
        &server,
        &format!("/api/booking/{token}/agent-instructions"),
        None,
    )
    .await;
    assert_eq!(status_of(&response), 200);
    assert!(
        response.contains(BOOKING_AGENT_INSTRUCTIONS_MIME),
        "the document is served under its own media type"
    );

    let body = body_of(&response);
    let block: BookingAgentInstructionsBlock = serde_json::from_str(body).unwrap();
    assert_eq!(block.version, BOOKING_AGENT_INSTRUCTIONS_VERSION);
    assert_eq!(block.version, 1);
    assert_eq!(block.constraint_schema_version, CONSTRAINT_SCHEMA_VERSION);
    assert_eq!(block.page_token, token);
    assert_eq!(block.event_types, vec![EventTypeKey(EVENT_TYPE.to_owned())]);

    let operations: Vec<BookingAgentOperation> = block
        .operations
        .iter()
        .map(|endpoint| endpoint.operation)
        .collect();
    assert_eq!(
        operations,
        vec![
            BookingAgentOperation::Availability,
            BookingAgentOperation::Book,
            BookingAgentOperation::Reschedule,
            BookingAgentOperation::Cancel,
        ],
        "operations are canonicalized in exactly this order"
    );
    for endpoint in &block.operations {
        assert_eq!(endpoint.method, "POST");
        assert!(
            endpoint.path.starts_with('/') && !endpoint.path.starts_with("//"),
            "path must be relative and same-origin: {}",
            endpoint.path
        );
        assert!(
            !endpoint.path.contains("://"),
            "path must name no scheme or authority: {}",
            endpoint.path
        );
        assert!(
            endpoint.path.contains(&token),
            "path addresses the page by its opaque token: {}",
            endpoint.path
        );
    }

    // Strict round-trip: the exact bytes come back, and an unknown field is
    // rejected rather than ignored.
    assert_eq!(serde_json::to_string(&block).unwrap(), body);
    let mut widened: Value = serde_json::from_str(body).unwrap();
    widened
        .as_object_mut()
        .unwrap()
        .insert("smuggled".to_owned(), json!("value"));
    assert!(
        serde_json::from_value::<BookingAgentInstructionsBlock>(widened).is_err(),
        "the block rejects unknown fields"
    );

    handle.abort();
}

#[tokio::test]
async fn booking_agent_instructions_fragment_is_script_safe() {
    let (_dir, vault, page) = seeded_vault(Some(HOSTILE_EVENT_TYPE));
    let (addr, server, handle) = spawn(vault).await;
    let token = page_token(page);
    let path = format!("/api/booking/{token}/agent-instructions");

    let fragment_response = http_get(addr, &server, &path, Some("text/html")).await;
    assert_eq!(status_of(&fragment_response), 200);
    let fragment = body_of(&fragment_response);

    let opening = format!("<script type=\"{BOOKING_AGENT_INSTRUCTIONS_MIME}\">");
    let inner = fragment
        .strip_prefix(&opening)
        .and_then(|rest| rest.strip_suffix("</script>"))
        .expect("fragment is exactly one versioned script block");

    // The hostile configuration really did reach the block — otherwise this
    // row would prove escaping of a string nobody sent.
    assert!(
        inner.contains("\\u003c/script\\u003e"),
        "the hostile event-type key is present and escaped: {inner}"
    );
    for forbidden in ["</script", "<", ">", "&", "\u{2028}", "\u{2029}"] {
        assert!(
            !inner.contains(forbidden),
            "the block body must not contain {forbidden:?}"
        );
    }

    // Decoding the escaped body yields exactly the endpoint document.
    let decoded: Value = serde_json::from_str(inner).unwrap();
    let document_response = http_get(addr, &server, &path, None).await;
    let document = body_of(&document_response);
    assert_eq!(serde_json::to_string(&decoded).unwrap(), document);

    // Nothing private rides along.
    let mut strings = Vec::new();
    all_strings(&decoded, &mut strings);
    for text in &strings {
        assert!(
            !text.contains('@'),
            "the block carries no email address: {text}"
        );
        assert!(
            !text.eq_ignore_ascii_case(SECRET),
            "the block carries no credential"
        );
        assert_ne!(
            *text,
            page.to_hex(),
            "the block carries no internal identifier"
        );
    }

    handle.abort();
}

// -------------------------------------------------------------------------
// Executor behaviour
// -------------------------------------------------------------------------

#[tokio::test]
async fn booking_availability_discloses_slots_only() {
    let (_dir, vault, page) = seeded_vault(None);
    let (addr, server, handle) = spawn(vault).await;
    let token = page_token(page);

    let response = http_post(
        addr,
        &server,
        &format!("/api/booking/{token}/availability"),
        &availability_body(6, Value::Null),
    )
    .await;
    assert_eq!(status_of(&response), 200, "{}", body_of(&response));
    let body = json_of(&response);

    assert_eq!(object_keys(&body), keys(&["op", "result"]));
    assert_eq!(body["op"], "availability");
    assert_eq!(object_keys(&body["result"]), keys(&["slots", "flex_used"]));
    assert!(body["result"]["flex_used"].is_boolean());

    let slots = body["result"]["slots"].as_array().unwrap();
    assert!(
        !slots.is_empty(),
        "the fixture page must offer slots: {body}"
    );
    for slot in slots {
        assert_eq!(object_keys(slot), keys(&["start_utc", "end_utc", "rank"]));
        assert!(slot["start_utc"].as_u64().unwrap() < slot["end_utc"].as_u64().unwrap());
    }

    // Nothing calendar-shaped is representable in this response.
    let mut strings = Vec::new();
    all_strings(&body, &mut strings);
    for forbidden in [
        "title",
        "description",
        "attendees",
        "busy",
        "summary",
        "calendar",
        "event_ref",
    ] {
        assert!(
            !strings.iter().any(|text| text == forbidden),
            "availability must not disclose {forbidden}"
        );
    }

    handle.abort();
}

#[tokio::test]
async fn booking_hold_then_confirm_is_real_lifecycle_flow() {
    let (_dir, vault, page) = seeded_vault(None);
    let (addr, server, handle) = spawn(vault).await;
    let token = page_token(page);

    let availability = http_post(
        addr,
        &server,
        &format!("/api/booking/{token}/availability"),
        &availability_body(6, Value::Null),
    )
    .await;
    let slots = json_of(&availability)["result"]["slots"].clone();
    let slot = slots.as_array().unwrap().first().cloned().unwrap();

    let hold_body = json!({
        "stage": "hold",
        "input": {
            "event_type": EVENT_TYPE,
            "selected_slot": { "start_utc": slot["start_utc"], "end_utc": slot["end_utc"] },
            "visitor_tz": "UTC",
            "constraint": null,
            "session_ref": "sess-hold-confirm",
            "checkout_lease_token": null,
            "idempotency_key": "hold-1",
        },
    });
    let response = http_post(
        addr,
        &server,
        &format!("/api/booking/{token}/book"),
        &hold_body,
    )
    .await;
    assert_eq!(status_of(&response), 200, "{}", body_of(&response));
    let held = json_of(&response);
    assert_eq!(held["op"], "book");
    assert_eq!(held["result"]["stage"], "held");
    let hold_token = held["result"]["result"]["hold_token"].as_str().unwrap();
    assert_eq!(hold_token.len(), 64, "the lifecycle minted an opaque token");
    assert!(hold_token.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(
        held["result"]["result"]["expires_at"].as_u64().unwrap() > now_secs(),
        "the hold carries a server-capped expiry"
    );
    assert_eq!(
        object_keys(&held["result"]["result"]),
        keys(&["hold_token", "selected_slot", "expires_at"]),
    );

    // There is no caller TTL to supply: the field does not exist, and an
    // attempt to introduce one is rejected rather than ignored.
    let mut with_ttl = hold_body.clone();
    with_ttl["input"]
        .as_object_mut()
        .unwrap()
        .insert("ttl_secs".to_owned(), json!(86_400));
    let response = http_post(
        addr,
        &server,
        &format!("/api/booking/{token}/book"),
        &with_ttl,
    )
    .await;
    assert_eq!(
        status_of(&response),
        400,
        "a caller-supplied TTL must be refused: {}",
        body_of(&response)
    );

    // An unverified checkout lease cannot buy an extension.
    let mut forged_lease = hold_body.clone();
    forged_lease["input"]
        .as_object_mut()
        .unwrap()
        .insert("checkout_lease_token".to_owned(), json!("f".repeat(64)));
    forged_lease["input"]
        .as_object_mut()
        .unwrap()
        .insert("idempotency_key".to_owned(), json!("hold-forged"));
    let response = http_post(
        addr,
        &server,
        &format!("/api/booking/{token}/book"),
        &forged_lease,
    )
    .await;
    assert_ne!(
        status_of(&response),
        200,
        "a lease this server never issued must not extend a hold: {}",
        body_of(&response)
    );

    let confirm_body = json!({
        "stage": "confirm",
        "input": {
            "hold_token": hold_token,
            "booker_email": "visitor@example.com",
            "intake": [{ "field_key": "reason", "value": "an introduction call" }],
            "session_ref": "sess-hold-confirm",
            "idempotency_key": "confirm-1",
        },
    });
    let response = http_post(
        addr,
        &server,
        &format!("/api/booking/{token}/book"),
        &confirm_body,
    )
    .await;
    assert_eq!(status_of(&response), 200, "{}", body_of(&response));
    let confirmed = json_of(&response);
    assert_eq!(confirmed["result"]["stage"], "confirmed");
    assert_eq!(
        object_keys(&confirmed["result"]["result"]),
        keys(&["reschedule_token", "cancel_token"]),
    );
    let reschedule_token = confirmed["result"]["result"]["reschedule_token"]
        .as_str()
        .unwrap();
    let cancel_token = confirmed["result"]["result"]["cancel_token"]
        .as_str()
        .unwrap();
    assert_ne!(
        reschedule_token, cancel_token,
        "confirm returns two distinct action-scoped credentials"
    );
    assert_ne!(reschedule_token, hold_token);
    assert_ne!(cancel_token, hold_token);

    handle.abort();
}

#[tokio::test]
async fn booking_mutations_revalidate() {
    let (_dir, vault, page) = seeded_vault(None);
    let (addr, server, handle) = spawn(vault).await;
    let token = page_token(page);

    // A hallucinated slot — one the oracle never offered, far outside the
    // page's bookable horizon — cannot become a hold. Only the home-node
    // writer decides, and it decides against this.
    let far_future = now_secs() + 3_650 * 86_400;
    let hallucinated = json!({
        "stage": "hold",
        "input": {
            "event_type": EVENT_TYPE,
            "selected_slot": { "start_utc": far_future, "end_utc": far_future + 1_800 },
            "visitor_tz": "UTC",
            "constraint": null,
            "session_ref": "sess-revalidate",
            "checkout_lease_token": null,
            "idempotency_key": "hallucinated-1",
        },
    });
    let response = http_post(
        addr,
        &server,
        &format!("/api/booking/{token}/book"),
        &hallucinated,
    )
    .await;
    let body = body_of(&response).to_owned();
    if status_of(&response) == 200 {
        let held = json_of(&response);
        assert_eq!(
            held["result"]["stage"], "slot_taken",
            "an unofferable slot must never mint a hold: {body}"
        );
    }

    // A confirm against a well-formed but never-minted hold token fails at
    // the writer, not at the transport.
    let orphan = json!({
        "stage": "confirm",
        "input": {
            "hold_token": "a".repeat(64),
            "booker_email": "ghost@example.com",
            "intake": [],
            "session_ref": "sess-revalidate",
            "idempotency_key": "orphan-1",
        },
    });
    let response = http_post(
        addr,
        &server,
        &format!("/api/booking/{token}/book"),
        &orphan,
    )
    .await;
    assert_ne!(
        status_of(&response),
        200,
        "an unknown hold token cannot mint a booking: {}",
        body_of(&response)
    );

    handle.abort();
}

#[tokio::test]
async fn booking_reschedule_cancel_require_action_scoped_tokens() {
    let (_dir, vault, page) = seeded_vault(None);
    let (addr, server, handle) = spawn(vault).await;
    let token = page_token(page);
    let now = now_secs();

    // An internal identifier is not a credential: it does not even have the
    // shape of one.
    let with_entity_id = json!({
        "reschedule_token": page.to_hex(),
        "selected_slot": { "start_utc": now + 3_600, "end_utc": now + 5_400 },
        "visitor_tz": "UTC",
        "idempotency_key": "rs-entity",
    });
    let response = http_post(
        addr,
        &server,
        &format!("/api/booking/{token}/reschedule"),
        &with_entity_id,
    )
    .await;
    assert_eq!(
        status_of(&response),
        400,
        "an entity id must be refused as a reschedule token: {}",
        body_of(&response)
    );

    let with_entity_id = json!({
        "cancel_token": page.to_hex(),
        "idempotency_key": "cx-entity",
    });
    let response = http_post(
        addr,
        &server,
        &format!("/api/booking/{token}/cancel"),
        &with_entity_id,
    )
    .await;
    assert_eq!(status_of(&response), 400);

    // Malformed credentials are refused before any storage lookup.
    let malformed_tokens = vec![
        String::new(),
        "not-a-token".to_owned(),
        "a".repeat(63),
        "A".repeat(64),
    ];
    for malformed in &malformed_tokens {
        let response = http_post(
            addr,
            &server,
            &format!("/api/booking/{token}/cancel"),
            &json!({ "cancel_token": malformed, "idempotency_key": "cx-bad" }),
        )
        .await;
        assert_eq!(
            status_of(&response),
            400,
            "malformed cancel token {malformed:?} must be refused"
        );
    }

    // A well-formed credential that names no booking is refused too.
    let response = http_post(
        addr,
        &server,
        &format!("/api/booking/{token}/cancel"),
        &json!({ "cancel_token": "b".repeat(64), "idempotency_key": "cx-unknown" }),
    )
    .await;
    assert_ne!(status_of(&response), 200);

    // A token minted for the WRONG action is insufficient: a hold token is
    // not a cancel token.
    let availability = http_post(
        addr,
        &server,
        &format!("/api/booking/{token}/availability"),
        &availability_body(6, Value::Null),
    )
    .await;
    let slot = json_of(&availability)["result"]["slots"]
        .as_array()
        .unwrap()
        .first()
        .cloned()
        .unwrap();
    let hold = http_post(
        addr,
        &server,
        &format!("/api/booking/{token}/book"),
        &json!({
            "stage": "hold",
            "input": {
                "event_type": EVENT_TYPE,
                "selected_slot": { "start_utc": slot["start_utc"], "end_utc": slot["end_utc"] },
                "visitor_tz": "UTC",
                "constraint": null,
                "session_ref": "sess-wrong-action",
                "checkout_lease_token": null,
                "idempotency_key": "hold-wrong-action",
            },
        }),
    )
    .await;
    assert_eq!(status_of(&hold), 200, "{}", body_of(&hold));
    let hold_token = json_of(&hold)["result"]["result"]["hold_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let response = http_post(
        addr,
        &server,
        &format!("/api/booking/{token}/cancel"),
        &json!({ "cancel_token": hold_token, "idempotency_key": "cx-wrong-action" }),
    )
    .await;
    assert_ne!(
        status_of(&response),
        200,
        "a hold token must not cancel a booking: {}",
        body_of(&response)
    );

    handle.abort();
}

// -------------------------------------------------------------------------
// Cross-page action tokens
// -------------------------------------------------------------------------

/// Books a real slot on `route` through hold and confirm, and returns the two
/// action-scoped credentials the lifecycle minted for that booking.
async fn confirmed_booking(
    addr: SocketAddr,
    server: &SyncServer,
    route: &str,
    session: &str,
) -> (String, String) {
    let availability = http_post(
        addr,
        server,
        &format!("/api/booking/{route}/availability"),
        &availability_body(6, Value::Null),
    )
    .await;
    let slot = json_of(&availability)["result"]["slots"]
        .as_array()
        .unwrap()
        .first()
        .cloned()
        .unwrap();
    let hold = http_post(
        addr,
        server,
        &format!("/api/booking/{route}/book"),
        &json!({
            "stage": "hold",
            "input": {
                "event_type": EVENT_TYPE,
                "selected_slot": { "start_utc": slot["start_utc"], "end_utc": slot["end_utc"] },
                "visitor_tz": "UTC",
                "constraint": null,
                "session_ref": session,
                "checkout_lease_token": null,
                "idempotency_key": format!("{session}-hold"),
            },
        }),
    )
    .await;
    assert_eq!(status_of(&hold), 200, "{}", body_of(&hold));
    let hold_token = json_of(&hold)["result"]["result"]["hold_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let confirm = http_post(
        addr,
        server,
        &format!("/api/booking/{route}/book"),
        &json!({
            "stage": "confirm",
            "input": {
                "hold_token": hold_token,
                "booker_email": "cross-page@example.com",
                "intake": [],
                "session_ref": session,
                "idempotency_key": format!("{session}-confirm"),
            },
        }),
    )
    .await;
    assert_eq!(status_of(&confirm), 200, "{}", body_of(&confirm));
    let confirmed = json_of(&confirm)["result"]["result"].clone();
    let reschedule_token = confirmed["reschedule_token"].as_str().unwrap().to_owned();
    let cancel_token = confirmed["cancel_token"].as_str().unwrap().to_owned();
    (reschedule_token, cancel_token)
}

/// A credential minted on one page cannot act through another page's route.
///
/// The URL page and the action token are independent inputs, so this is the
/// one row that keeps them from disagreeing: the token names the booking the
/// writer would move, the URL names the page whose admission budget, windows,
/// and caps the request spends. A page-A token accepted on page B's route
/// would mutate page A while page B paid for it.
#[tokio::test]
async fn booking_action_tokens_do_not_cross_pages() {
    let (_dir, vault, page_a) = seeded_vault(None);
    let page_b = install_second_page(&vault);
    let (addr, server, handle) = spawn(Arc::clone(&vault)).await;
    let route_a = page_token(page_a);
    let route_b = page_token(page_b);

    // Page B is genuinely bookable on its own: it answers its own token and
    // offers its own slots, so no refusal below is a broken-fixture artifact.
    let avail_b = http_post(
        addr,
        &server,
        &format!("/api/booking/{route_b}/availability"),
        &availability_body(6, Value::Null),
    )
    .await;
    assert_eq!(status_of(&avail_b), 200, "{}", body_of(&avail_b));
    let avail_b = json_of(&avail_b);
    let slots_b = avail_b["result"]["slots"].as_array().unwrap();
    assert!(!slots_b.is_empty(), "page B offers slots of its own");

    // A real booking on page A, holding the real credentials confirm minted.
    let (reschedule_token, cancel_token) =
        confirmed_booking(addr, &server, &route_a, "sess-cross-page").await;

    // A slot page A still offers, read AFTER the booking exists so the move
    // below can only fail for the reason under test.
    let availability = http_post(
        addr,
        &server,
        &format!("/api/booking/{route_a}/availability"),
        &availability_body(6, Value::Null),
    )
    .await;
    let target = json_of(&availability)["result"]["slots"]
        .as_array()
        .unwrap()
        .last()
        .cloned()
        .unwrap();
    let move_to = json!({ "start_utc": target["start_utc"], "end_utc": target["end_utc"] });

    // ── page B's route, page A's credential ─────────────────────────────
    let enqueued = booking_attempts(&vault);
    let cross_reschedule = http_post(
        addr,
        &server,
        &format!("/api/booking/{route_b}/reschedule"),
        &json!({
            "reschedule_token": reschedule_token,
            "selected_slot": move_to,
            "visitor_tz": "UTC",
            "idempotency_key": "rs-cross-page",
        }),
    )
    .await;
    assert_eq!(
        status_of(&cross_reschedule),
        400,
        "a page-A reschedule token must not act through page B: {}",
        body_of(&cross_reschedule)
    );
    let cross_cancel = http_post(
        addr,
        &server,
        &format!("/api/booking/{route_b}/cancel"),
        &json!({ "cancel_token": cancel_token, "idempotency_key": "cx-cross-page" }),
    )
    .await;
    assert_eq!(
        status_of(&cross_cancel),
        400,
        "a page-A cancel token must not act through page B: {}",
        body_of(&cross_cancel)
    );
    // Refused before page B's admission call and before the queue: no verb was
    // enqueued, so no writer ran, no window was charged, and nothing moved.
    assert_eq!(
        booking_attempts(&vault),
        enqueued,
        "a cross-page credential enqueues no lifecycle verb"
    );

    // The refusal is exactly the one an unknown credential receives, so it is
    // no oracle for "this token is real, just not here" — and it names no page.
    let unknown = http_post(
        addr,
        &server,
        &format!("/api/booking/{route_b}/cancel"),
        &json!({ "cancel_token": "b".repeat(64), "idempotency_key": "cx-unknown-page" }),
    )
    .await;
    assert_eq!(status_of(&unknown), status_of(&cross_cancel));
    assert_eq!(
        json_of(&unknown),
        json_of(&cross_cancel),
        "a wrong-page credential answers exactly like an unknown one"
    );
    let mut strings = Vec::new();
    all_strings(&json_of(&cross_cancel), &mut strings);
    for text in &strings {
        assert_ne!(*text, page_a.to_hex(), "the refusal names no page");
        assert_ne!(*text, page_b.to_hex(), "the refusal names no page");
        assert!(
            !text.contains(&cancel_token),
            "the refusal echoes no credential"
        );
    }

    // ── same page, unchanged ────────────────────────────────────────────
    // The booking was never touched: both credentials still work on their own
    // page, still reach the writer, and still answer in the shipped shape.
    let moved = http_post(
        addr,
        &server,
        &format!("/api/booking/{route_a}/reschedule"),
        &json!({
            "reschedule_token": reschedule_token,
            "selected_slot": move_to,
            "visitor_tz": "UTC",
            "idempotency_key": "rs-same-page",
        }),
    )
    .await;
    assert_eq!(status_of(&moved), 200, "{}", body_of(&moved));
    let moved = json_of(&moved);
    assert_eq!(object_keys(&moved), keys(&["op", "result"]));
    assert_eq!(moved["op"], "reschedule");
    assert_eq!(moved["result"]["reschedule_token"], reschedule_token);

    let cancelled = http_post(
        addr,
        &server,
        &format!("/api/booking/{route_a}/cancel"),
        &json!({ "cancel_token": cancel_token, "idempotency_key": "cx-same-page" }),
    )
    .await;
    assert_eq!(status_of(&cancelled), 200, "{}", body_of(&cancelled));
    let cancelled = json_of(&cancelled);
    assert_eq!(cancelled["op"], "cancel");
    assert_eq!(cancelled["result"]["cancel_token"], cancel_token);
    assert_eq!(
        booking_attempts(&vault),
        enqueued + 2,
        "the two same-page verbs did reach the queue"
    );

    handle.abort();
}
