//! ONE-1819 [BK-08] agent-readable booking API — HTTP round trips.
//!
//! These arms exercise the real server: `build_app` mounts the booking
//! sub-router, every handler threads `State<Arc<SyncServer>>`, and every
//! refusal comes back as the shared `ApiError` envelope. What they pin is the
//! public contract that does not depend on a seeded booking page:
//!
//! * the five routes exist and are PUBLIC (no bearer credential is demanded);
//! * a request is refused before any vault work when its page token is shaped
//!   like an internal entity id — the "no `EntityId` at the public door"
//!   invariant, checked on the instructions path and on every operation path;
//! * a well-formed but unresolvable page token answers `404`, not `500`;
//! * the instructions endpoint serves canonical JSON.
//!
//! Positive availability answers need a page carrying a live
//! `booking.event_type` claim AND a short-id row; seeding that is ONE-1823's
//! configuration fixture, so it is deliberately not duplicated here.

// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use oneiron::VaultConfig;
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A canonical 32-hex entity id. The public booking door must never accept one.
const ENTITY_ID_SHAPED: &str = "7e0000000000000000000000000000aa";

/// A syntactically valid presentation id that resolves to nothing.
const UNRESOLVABLE_PAGE_TOKEN: &str = "bp404:ab";

fn test_vault_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.max_readers = 32;
    config
}

async fn spawn_server() -> (
    tempfile::TempDir,
    SocketAddr,
    tokio::task::JoinHandle<()>,
) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), test_vault_config()).unwrap());
    let config = SyncServerConfig {
        auth_secret: Some("booking-agent-secret".to_owned()),
        ..Default::default()
    };
    let server = Arc::new(SyncServer::new(vault, config).unwrap());
    let app = build_app(server);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (dir, addr, handle)
}

async fn http_get(addr: SocketAddr, path: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    read_response(stream).await
}

async fn http_post(addr: SocketAddr, path: &str, body: &Value) -> String {
    let body = body.to_string();
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    read_response(stream).await
}

async fn read_response(mut stream: tokio::net::TcpStream) -> String {
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .expect("timed out waiting for HTTP response")
        .expect("failed reading HTTP response");
    String::from_utf8(response).unwrap()
}

fn http_status(response: &str) -> u16 {
    response
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no HTTP status in {:?}", response.lines().next()))
}

fn http_body(response: &str) -> &str {
    response
        .split_once("\r\n\r\n")
        .map(|(_headers, body)| body)
        .expect("HTTP response should contain header/body delimiter")
}

fn http_json(response: &str) -> Value {
    serde_json::from_str(http_body(response)).expect("response body should be JSON")
}

fn availability_body() -> Value {
    json!({
        "event_type": "intro",
        "window": { "start": 1_800_000_000_u64, "end": 1_800_600_000_u64 },
        "visitor_tz": "Europe/Warsaw",
        "constraint": null,
        "session_ref": "visitor-session-1",
    })
}

/// One well-formed body per operation route. The bodies must decode, or the
/// `Json` extractor would refuse before the handler runs and these arms would
/// prove nothing about the executor.
fn operation_bodies() -> Vec<(&'static str, Value)> {
    vec![
        ("availability", availability_body()),
        (
            "book",
            json!({
                "stage": "hold",
                "input": {
                    "event_type": "intro",
                    "selected_slot": { "start_utc": 1_800_000_000_u64, "end_utc": 1_800_001_800_u64 },
                    "visitor_tz": "Europe/Warsaw",
                    "constraint": null,
                    "session_ref": "visitor-session-1",
                    "checkout_lease_token": null,
                    "idempotency_key": "idem-hold-1",
                },
            }),
        ),
        (
            "reschedule",
            json!({
                "reschedule_token": "rs-token-1",
                "selected_slot": { "start_utc": 1_800_003_600_u64, "end_utc": 1_800_005_400_u64 },
                "visitor_tz": "Europe/Warsaw",
                "idempotency_key": "idem-reschedule-1",
            }),
        ),
        (
            "cancel",
            json!({
                "cancel_token": "cx-token-1",
                "idempotency_key": "idem-cancel-1",
            }),
        ),
    ]
}

/// Every booking route is mounted, PUBLIC, and answers the shared `ApiError`
/// envelope. A missing credential must not turn into `401`: a visiting agent
/// holds none, and ONE-1817's caps are what bound this surface.
#[tokio::test]
async fn booking_routes_are_public_and_return_api_errors() {
    let (_dir, addr, handle) = spawn_server().await;

    let response = http_get(
        addr,
        &format!("/api/booking/{UNRESOLVABLE_PAGE_TOKEN}/agent-instructions"),
    )
    .await;
    assert_eq!(
        http_status(&response),
        404,
        "unresolvable page token must be 404, got: {response}"
    );
    let body = http_json(&response);
    assert_eq!(body["details"]["code"], "NOT_FOUND", "{body}");
    assert_eq!(body["code"], "NOT_FOUND", "{body}");

    for (operation, body) in operation_bodies() {
        let path = format!("/api/booking/{UNRESOLVABLE_PAGE_TOKEN}/{operation}");
        let response = http_post(addr, &path, &body).await;
        let status = http_status(&response);
        assert_ne!(
            status, 401,
            "{path} must not demand a credential: {response}"
        );
        assert_eq!(
            status, 404,
            "{path} names no live booking page and must answer 404: {response}"
        );
        assert_eq!(http_json(&response)["code"], "NOT_FOUND", "{response}");
    }

    handle.abort();
}

/// The "no `EntityId` at the public door" invariant, on every route.
///
/// A canonical 32-hex id is refused as a REQUEST DEFECT (`400`), never resolved
/// and never answered `404`: `404` would mean the server tried to look it up.
#[tokio::test]
async fn booking_public_door_refuses_entity_id_shaped_page_tokens() {
    let (_dir, addr, handle) = spawn_server().await;

    let response = http_get(
        addr,
        &format!("/api/booking/{ENTITY_ID_SHAPED}/agent-instructions"),
    )
    .await;
    assert_eq!(
        http_status(&response),
        400,
        "an entity id must be a request defect: {response}"
    );
    let body = http_json(&response);
    assert_eq!(body["code"], "BAD_REQUEST", "{body}");
    assert_eq!(body["details"]["field"], "page_token", "{body}");

    for (operation, body) in operation_bodies() {
        let path = format!("/api/booking/{ENTITY_ID_SHAPED}/{operation}");
        let response = http_post(addr, &path, &body).await;
        assert_eq!(
            http_status(&response),
            400,
            "{path} must refuse an entity id outright: {response}"
        );
        let refusal = http_json(&response);
        assert_eq!(refusal["code"], "BAD_REQUEST", "{refusal}");
        assert_eq!(refusal["details"]["field"], "page_token", "{refusal}");
    }

    handle.abort();
}

/// A blank or non-presentation-id token is a request defect, and the refusal
/// never leaks an internal identifier or a storage detail.
#[tokio::test]
async fn booking_instructions_refuse_malformed_page_tokens() {
    let (_dir, addr, handle) = spawn_server().await;

    for token in ["not-a-short-ref", "1:zz", "%20"] {
        let response = http_get(addr, &format!("/api/booking/{token}/agent-instructions")).await;
        assert_eq!(
            http_status(&response),
            400,
            "token {token:?} must be a request defect: {response}"
        );
        let body = http_body(&response);
        assert!(
            !body.contains("lmdb") && !body.contains("heed"),
            "refusal must not leak storage detail: {body}"
        );
    }

    handle.abort();
}

/// The availability route decodes ONE-1819's strict DTO: an unknown field is
/// rejected rather than ignored, so a caller cannot smuggle a TTL, an entity
/// id, or another operation's payload past the shared executor.
#[tokio::test]
async fn booking_availability_rejects_unknown_fields() {
    let (_dir, addr, handle) = spawn_server().await;

    let mut body = availability_body();
    body["page_ref"] = json!(ENTITY_ID_SHAPED);
    let response = http_post(
        addr,
        &format!("/api/booking/{UNRESOLVABLE_PAGE_TOKEN}/availability"),
        &body,
    )
    .await;
    assert!(
        (400..500).contains(&http_status(&response)),
        "an unknown field must be refused: {response}"
    );

    handle.abort();
}

/// Discovery, the MCP catalog, and the booking contract agree on one version
/// and one closed four-operation vocabulary.
#[tokio::test]
async fn booking_discovery_advertises_the_versioned_contract() {
    let (_dir, addr, handle) = spawn_server().await;

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "GET /api/core/discover HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nAuthorization: Bearer booking-agent-secret\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let response = read_response(stream).await;
    assert_eq!(http_status(&response), 200, "{response}");

    let body = http_json(&response);
    let capabilities = body["feature_flags"]["capabilities"]
        .as_array()
        .expect("capabilities array")
        .iter()
        .map(|token| token.as_str().expect("capability is a string").to_owned())
        .collect::<Vec<_>>();

    for expected in [
        "booking.agent_instructions",
        "booking.agent_instructions.v1",
        "booking.availability",
        "booking.book",
        "booking.reschedule",
        "booking.cancel",
        "mcp.tool.oneiron.book",
        "mcp.tool.oneiron.book.availability",
        "mcp.tool.oneiron.book.book",
        "mcp.tool.oneiron.book.reschedule",
        "mcp.tool.oneiron.book.cancel",
    ] {
        assert!(
            capabilities.iter().any(|token| token == expected),
            "discovery must advertise {expected}: {capabilities:?}"
        );
    }

    // CAL-09's tool is untouched by this batch.
    assert!(
        capabilities
            .iter()
            .any(|token| token == "mcp.tool.oneiron.calendar"),
        "the calendar tool must stay advertised: {capabilities:?}"
    );

    handle.abort();
}

/// OpenAPI publishes the same versioned contract, and the public booking routes
/// carry NO `CoreBearer` requirement — documenting a gate that does not exist
/// would be worse than documenting none.
#[tokio::test]
async fn booking_openapi_publishes_the_contract_without_a_bearer_gate() {
    let (_dir, addr, handle) = spawn_server().await;

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "GET /api/openapi.json HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nAuthorization: Bearer booking-agent-secret\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let response = read_response(stream).await;
    assert_eq!(http_status(&response), 200, "{response}");

    let spec = http_json(&response);
    let contract = &spec["x-oneiron-booking-agent"];
    assert_eq!(contract["instructions_version"], json!(1), "{contract}");
    assert_eq!(
        contract["instructions_media_type"],
        json!("application/vnd.oneiron.booking-agent+json"),
        "{contract}"
    );
    assert_eq!(contract["mcp_tool"], json!("oneiron.book"), "{contract}");
    assert_eq!(
        contract["operations"],
        json!(["availability", "book", "reschedule", "cancel"]),
        "{contract}"
    );

    for (path, method) in [
        ("/api/booking/{page_token}/agent-instructions", "get"),
        ("/api/booking/{page_token}/availability", "post"),
        ("/api/booking/{page_token}/book", "post"),
        ("/api/booking/{page_token}/reschedule", "post"),
        ("/api/booking/{page_token}/cancel", "post"),
    ] {
        let operation = &spec["paths"][path][method];
        assert!(
            operation.is_object(),
            "{path} {method} must be published in OpenAPI"
        );
        assert!(
            operation.get("security").is_none(),
            "{path} {method} is public and must document no security scheme"
        );
    }

    handle.abort();
}
