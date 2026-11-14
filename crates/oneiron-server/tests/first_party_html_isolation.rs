//! First-party HTML on the API's origin is isolated from every other document
//! there (ARCH-0050 #artifact-origin-open): the booking instructions fragment,
//! the signing ceremony, the certificate's QR page and the owner's field
//! editor each carry a content security policy and one isolation set, and the
//! pages run only the scripts they pin by hash.
//!
//! Every row drives the real router built by `oneiron_server::build_app` over
//! a real vault.

// Integration-test helpers (non-`#[test]` fns) are not covered by
// allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode, header};
use base64::Engine;
use oneiron::booking::EventTypeKey;
use oneiron::booking::config::{
    BOOKING_EVENT_TYPE_PREDICATE, BOOKING_EVENT_TYPE_SCHEMA_VERSION, BookingEventTypeClaimValue,
    EventTypeConfig, HostAvailabilityConfig, RoutingMode, WeeklyWallWindow,
    encode_event_type_claim_value,
};
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, DreamerHomeNodeCandidate,
    DreamerRunnerStore, EntityId, TimeRange, Vault, VaultConfig,
};
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

const SECRET: &str = "first-party-html-secret";
const HOME_NODE_ID: u64 = 7;
/// Mirrors `crate::api::booking`'s page-token derivation, as
/// `tests/it/booking_agent_api.rs` does: a changed derivation 404s here.
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

fn page_token(page_ref: EntityId) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PAGE_TOKEN_DOMAIN);
    hasher.update(page_ref.as_bytes());
    let digest = *hasher.finalize().as_bytes();
    let hex: String = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("bkp_{hex}")
}

fn test_vault_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.max_readers = 32;
    config
}

/// A vault carrying one published booking page and an elected local writer,
/// as `tests/it/booking_agent_api.rs` seeds it.
fn seeded_booking_vault() -> (tempfile::TempDir, Arc<Vault>, EntityId) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), test_vault_config()).unwrap();
    let page = seeded_id(0xB0);
    let host = seeded_id(0xB1);
    let calendar = seeded_id(0xB2);
    vault
        .put_entity(&page, ENTITY_TYPE_ASSET, at(1), 1, b"booking page")
        .unwrap();
    vault
        .put_entity(&host, ENTITY_TYPE_PERSON, at(1), 1, b"host")
        .unwrap();
    vault
        .put_entity(&calendar, ENTITY_TYPE_ASSET, at(1), 1, b"calendar")
        .unwrap();
    DreamerRunnerStore::new(&vault)
        .elect_home_node(
            &[DreamerHomeNodeCandidate::always_on_local(HOME_NODE_ID)],
            1,
        )
        .unwrap();
    let value = BookingEventTypeClaimValue {
        schema_version: BOOKING_EVENT_TYPE_SCHEMA_VERSION,
        page_ref: page,
        config: EventTypeConfig {
            key: EventTypeKey("intro-call".to_owned()),
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
        },
    };
    let mut body = ClaimBody::new(
        BOOKING_EVENT_TYPE_PREDICATE,
        ClaimSubject::Entity(page),
        encode_event_type_claim_value(&value).unwrap(),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    // FIX 7757: a CLAIM is born under a stored FACET; stamp the vault default.
    body.scope_facet = vault.default_facet().unwrap();
    vault.put_claim(&seeded_id(0xB3), &body, at(1), 1).unwrap();
    (dir, Arc::new(vault), page)
}

/// A server over `vault`. `hosted` puts it behind the hosted device-lease
/// gate, as `tests/it_esign_public.rs` serves the signing pages; the booking
/// rows run unleased, as `tests/it/booking_agent_api.rs` serves them.
fn server_over(vault: Arc<Vault>, hosted: bool) -> Arc<SyncServer> {
    Arc::new(
        SyncServer::new(
            vault,
            SyncServerConfig {
                lease_vault_id: u64::from(hosted),
                auth_secret: Some(SECRET.to_owned()),
                ..Default::default()
            },
        )
        .unwrap(),
    )
}

/// The host root slip's bearer and binding proof: an owner-grade caller.
fn owner_headers(server: &SyncServer) -> (String, String) {
    let issuer = oneiron::authority::HostSlipIssuer::from_secret(SECRET.as_bytes()).unwrap();
    let slip = server.vault().ensure_host_root_slip(&issuer).unwrap();
    let timestamp = server.vault().now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature: String = issuer
        .binding_proof(&slip, challenge.as_bytes())
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let binding = json!({"timestamp":timestamp,"nonce":nonce,"signature":signature});
    (
        format!("Bearer {}", slip.to_token().unwrap()),
        binding.to_string(),
    )
}

/// One GET through the router; the reply's status, headers and body text.
async fn get(server: &Arc<SyncServer>, path: &str, owner: bool) -> (StatusCode, HeaderMap, String) {
    let mut request = Request::builder().uri(path);
    if owner {
        let (bearer, binding) = owner_headers(server);
        request = request
            .header(header::AUTHORIZATION, bearer)
            .header("x-oneiron-binding", binding);
    }
    let response = build_app(Arc::clone(server))
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, headers, String::from_utf8(body.to_vec()).unwrap())
}

/// The booking routes key admission by the caller's connection, so the
/// fragment is read over a real listener, as unmanaged serve answers it.
async fn get_over_tcp(server: &Arc<SyncServer>, path: &str, accept: &str) -> String {
    let app = build_app(Arc::clone(server));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serving = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    let (bearer, binding) = owner_headers(server);
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nAuthorization: {bearer}\r\nx-oneiron-binding: {binding}\r\nAccept: {accept}\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    serving.abort();
    String::from_utf8(response).unwrap()
}

/// The raw reply's header `name` (lower case), if it carries one.
fn raw_header<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    let (head, _) = response.split_once("\r\n\r\n")?;
    head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then_some(value.trim())
    })
}

/// The policy's `name` directive, without its name.
fn directive<'a>(csp: &'a str, name: &str) -> Option<&'a str> {
    csp.split(';').map(str::trim).find_map(|entry| {
        entry
            .strip_prefix(name)
            .filter(|rest| rest.is_empty() || rest.starts_with(' '))
            .map(str::trim)
    })
}

/// Asserts the isolation set every first-party page carries, and that its
/// policy runs exactly the page's one inline script.
fn assert_isolated_page(path: &str, headers: &HeaderMap, body: &str) {
    for (name, value) in [
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
        ("x-frame-options", "DENY"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("cache-control", "no-store"),
    ] {
        assert_eq!(
            headers.get(name).and_then(|value| value.to_str().ok()),
            Some(value),
            "{path} carries {name}: {value}"
        );
    }
    let csp = headers
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| panic!("{path} carries a content security policy"));
    assert_eq!(
        directive(csp, "frame-ancestors"),
        Some("'none'"),
        "{path}: {csp}"
    );
    assert_eq!(directive(csp, "base-uri"), Some("'none'"), "{path}: {csp}");
    assert!(directive(csp, "form-action").is_some(), "{path}: {csp}");
    assert!(!body.contains("<script src"), "{path} loads no script file");
    let script = body
        .split_once("<script>")
        .and_then(|(_, rest)| rest.rsplit_once("</script>"))
        .map(|(script, _)| script)
        .unwrap_or_else(|| panic!("{path} has one inline script"));
    let digest = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(script));
    assert_eq!(
        directive(csp, "script-src"),
        Some(format!("'sha256-{digest}'").as_str()),
        "{path} runs only its own pinned script, never another script on the origin: {csp}"
    );
}

// -------------------------------------------------------------------------
// Rows
// -------------------------------------------------------------------------

#[tokio::test]
async fn booking_fragment_serves_content_security_policy() {
    let (_dir, vault, page) = seeded_booking_vault();
    let server = server_over(vault, false);
    let path = format!("/api/booking/{}/agent-instructions", page_token(page));
    let response = get_over_tcp(&server, &path, "text/html").await;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "the fragment is served: {response}"
    );
    let csp = raw_header(&response, "content-security-policy")
        .unwrap_or_else(|| panic!("the fragment carries a content security policy: {response}"));
    // A data block: opened as a document it is an opaque origin that runs,
    // loads, frames and submits nothing.
    assert_eq!(directive(csp, "sandbox"), Some(""), "{csp}");
    assert_eq!(directive(csp, "default-src"), Some("'none'"), "{csp}");
    assert_eq!(directive(csp, "frame-ancestors"), Some("'none'"), "{csp}");
    assert_eq!(directive(csp, "form-action"), Some("'none'"), "{csp}");
    for (name, value) in [
        ("x-content-type-options", "nosniff"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
        ("x-frame-options", "DENY"),
    ] {
        assert_eq!(
            raw_header(&response, name),
            Some(value),
            "the fragment carries {name}"
        );
    }
    assert!(
        raw_header(&response, "content-type").is_some_and(|value| value.starts_with("text/html")),
        "the fragment stays HTML: {response}"
    );
}

#[tokio::test]
async fn signing_pages_are_isolated_from_other_documents() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let server = server_over(vault, true);
    for path in ["/sign", "/esign/verify"] {
        let (status, headers, body) = get(&server, path, false).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_isolated_page(path, &headers, &body);
    }
}

#[tokio::test]
async fn signing_editor_runs_only_its_pinned_scripts() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let server = server_over(vault, true);
    let (status, headers, body) = get(&server, "/sign/editor", true).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an owner-grade caller loads the editor"
    );
    assert_isolated_page("/sign/editor", &headers, &body);
    let csp = headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
    assert_eq!(directive(csp, "form-action"), Some("'none'"), "{csp}");
    assert!(
        body.contains("id=editor-capability"),
        "the editor still carries its minted token for its script"
    );
}
