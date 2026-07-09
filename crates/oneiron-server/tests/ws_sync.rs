//! WebSocket integration tests for the sync server (ONE-1129).
//!
//! Covers the M4 server-durability + auth acceptance criteria:
//! - `/ws` upgrade auth (Phase-1 shared secret, fail-closed when configured)
//! - update relay between two live clients + sync_state durability literals
//! - restart durability: a relayed update AND a relayed tombstone survive a
//!   server restart (the cross-device delete-propagation case)
//! - persist-failure eviction: when the durable append of an imported update
//!   fails, the mutated RAM doc is evicted so a later VV_REQUEST cannot serve
//!   state a restart would lose
//! - oversized updates are rejected before any state mutates
//! - the client (`SyncConnection`) sends `SyncClientConfig.auth_token` on the
//!   upgrade request
//!
//! Restart is simulated by dropping the `SyncServer` (all in-RAM Loro Docs)
//! and constructing a new one over the same vault: the durability property
//! under test is exactly "state must round-trip through sync_state".
//! Full-suite re-scope stays ONE-474.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use loro::{ExportMode, LoroDoc};
use oneiron::habit::TaskRole;
use oneiron::registry::{ENTITY_TYPE_TASK, ENTITY_TYPE_TURN};
use oneiron::sync::bridge::Materializer;
use oneiron::sync::transport::{
    self, TAG_EPHEMERAL, TAG_SYNC_UPDATE, TAG_WINDOW_SYNC, window_sub_tags,
};
use oneiron::sync::{
    ConnectionConfig, EphemeralStore, EphemeralWireState, LoroValue, SyncClient, SyncClientConfig,
    SyncConnection, SyncEvent, SyncStatus, WindowManager,
};
use oneiron::{EdgeKind, EntityId, TimeRange, VaultConfig};
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::error::{ApiError, ApiErrorDetails, ErrorCode};
use oneiron_server::server::SyncServer;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

fn open_vault(dir: &std::path::Path) -> Arc<oneiron::Vault> {
    Arc::new(oneiron::Vault::open(dir, oneiron::VaultConfig::device()).unwrap())
}

fn open_search_vault(dir: &std::path::Path) -> Arc<oneiron::Vault> {
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.embedding_model = Some("ws-search-test-model".to_owned());
    Arc::new(oneiron::Vault::open(dir, config).unwrap())
}

fn seeded_entity(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).unwrap()
}

fn test_range(timestamp: u64) -> TimeRange {
    TimeRange {
        start: timestamp,
        end: timestamp,
    }
}

fn seed_text_search_matches(vault: &oneiron::Vault) {
    let ids = [
        seeded_entity(0x31),
        seeded_entity(0x32),
        seeded_entity(0x33),
    ];
    let mut batch = vault.batch();
    for (index, id) in ids.iter().enumerate() {
        let learned_at = (index + 1) as u64;
        batch = batch
            .put(
                id,
                ENTITY_TYPE_TURN,
                test_range(learned_at),
                learned_at,
                b"text-search-match",
            )
            .text(id, &[("body", "metaneedle shared term")]);
    }
    batch.commit().unwrap();
}

fn seed_vector_search_matches(vault: &oneiron::Vault) {
    let fixtures = [
        (seeded_entity(0x41), [1.0_f32, 0.0, 0.0, 0.0]),
        (seeded_entity(0x42), [0.9_f32, 0.1, 0.0, 0.0]),
        (seeded_entity(0x43), [0.8_f32, 0.2, 0.0, 0.0]),
    ];

    for (index, (id, vector)) in fixtures.iter().enumerate() {
        let learned_at = (index + 1) as u64;
        vault
            .put_entity(
                id,
                ENTITY_TYPE_TURN,
                test_range(learned_at),
                learned_at,
                b"vector-search-match",
            )
            .unwrap();
        vault.put_vector(id, vector).unwrap();
    }
}
/// Client-side window manager over a fresh vault (the client API is
/// manager-owned post-ONE-1125).
fn open_manager(vault: Arc<oneiron::Vault>) -> Arc<WindowManager> {
    Arc::new(WindowManager::new(
        vault,
        Arc::new(Materializer::new()),
        "ws-sync-test",
    ))
}

fn config_with_secret(secret: Option<&str>) -> SyncServerConfig {
    SyncServerConfig {
        auth_secret: secret.map(str::to_string),
        ..Default::default()
    }
}

fn config_with_secret_and_dev(
    secret: Option<&str>,
    allow_unauthenticated: bool,
) -> SyncServerConfig {
    SyncServerConfig {
        auth_secret: secret.map(str::to_string),
        allow_unauthenticated,
        ..Default::default()
    }
}

async fn spawn_server(
    vault: Arc<oneiron::Vault>,
    config: SyncServerConfig,
) -> (SocketAddr, Arc<SyncServer>, tokio::task::JoinHandle<()>) {
    let server = Arc::new(SyncServer::new(vault, config).unwrap());
    let app = build_app(server.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, server, handle)
}

async fn connect(
    addr: SocketAddr,
    secret: Option<&str>,
) -> Result<WsStream, tokio_tungstenite::tungstenite::Error> {
    let url = format!("ws://{addr}/ws");
    let mut request = url.into_client_request().unwrap();
    if let Some(secret) = secret {
        request
            .headers_mut()
            .insert("x-oneiron-secret", secret.parse().unwrap());
    }
    let mut ws = tokio_tungstenite::connect_async(request)
        .await
        .map(|(ws, _resp)| ws)?;
    // Phase 0 (ONE-1127): the FIRST frame must be the protocol-version
    // hello, or the server closes with 4006 before any sync payload flows.
    // These integration tests exercise the legacy unscoped full-window lane;
    // selector sync is gated behind the v3 hello.
    ws.send(Message::Binary(
        transport::encode_legacy_full_window_protocol_hello().into(),
    ))
    .await?;
    Ok(ws)
}

async fn next_binary(ws: &mut WsStream) -> Vec<u8> {
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("timed out waiting for a WebSocket message")
            .expect("WebSocket stream ended unexpectedly")
            .expect("WebSocket error");
        match msg {
            Message::Binary(data) => return data.to_vec(),
            Message::Ping(_) | Message::Pong(_) => continue,
            other => panic!("unexpected WebSocket message: {other:?}"),
        }
    }
}

async fn expect_no_binary(ws: &mut WsStream, duration: Duration) {
    let result = tokio::time::timeout(duration, async {
        loop {
            let msg = ws
                .next()
                .await
                .expect("WebSocket stream ended unexpectedly")
                .expect("WebSocket error");
            match msg {
                Message::Binary(data) => return data.to_vec(),
                Message::Ping(_) | Message::Pong(_) => continue,
                other => panic!("unexpected WebSocket message: {other:?}"),
            }
        }
    })
    .await;
    assert!(
        result.is_err(),
        "unexpected binary frame: {:?}",
        result.ok()
    );
}

async fn assert_ws_closes(ws: &mut WsStream, reason: &str) {
    let closed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match ws.next().await {
                None | Some(Ok(Message::Close(_))) | Some(Err(_)) => break,
                Some(Ok(_)) => continue,
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "{reason}");
}

async fn http_get(addr: SocketAddr, path: &str, secret: Option<&str>) -> String {
    String::from_utf8(http_get_bytes(addr, path, secret).await).unwrap()
}

async fn http_get_bytes(addr: SocketAddr, path: &str, secret: Option<&str>) -> Vec<u8> {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let secret_header = secret
        .map(|secret| format!("x-oneiron-secret: {secret}\r\n"))
        .unwrap_or_default();
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n{secret_header}\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .expect("timed out waiting for HTTP response")
        .expect("failed reading HTTP response");
    response
}

async fn http_post(
    addr: SocketAddr,
    path: &str,
    body: &str,
    secret: Option<&str>,
    idempotency_key: Option<&str>,
) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let secret_header = secret
        .map(|secret| format!("x-oneiron-secret: {secret}\r\n"))
        .unwrap_or_default();
    let idempotency_header = idempotency_key
        .map(|key| format!("Idempotency-Key: {key}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{secret_header}{idempotency_header}\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .expect("timed out waiting for HTTP response")
        .expect("failed reading HTTP response");
    String::from_utf8(response).unwrap()
}

fn assert_http_status(response: &str, status: u16) {
    let expected = format!("HTTP/1.1 {status} ");
    assert!(
        response.starts_with(&expected),
        "expected HTTP status {status}, got response head: {:?}",
        response.lines().next()
    );
}

fn assert_http_status_bytes(response: &[u8], status: u16) {
    let expected = format!("HTTP/1.1 {status} ");
    assert!(
        response.starts_with(expected.as_bytes()),
        "expected HTTP status {status}, got response head: {:?}",
        response
            .split(|byte| *byte == b'\n')
            .next()
            .map(String::from_utf8_lossy)
    );
}

fn http_body(response: &[u8]) -> &[u8] {
    let Some(offset) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        panic!("HTTP response missing header/body separator");
    };
    &response[offset + 4..]
}

fn http_json(response: &[u8]) -> Value {
    serde_json::from_slice(http_body(response)).unwrap()
}

fn json_key_set(value: &Value) -> std::collections::BTreeSet<&str> {
    value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect()
}

fn msgpack_json(value: &Value) -> Vec<u8> {
    rmp_serde::to_vec_named(value).unwrap()
}

fn http_json_body(response: &str) -> &str {
    response
        .split_once("\r\n\r\n")
        .map(|(_headers, body)| body)
        .expect("HTTP response should contain header/body delimiter")
}

fn http_json_value(response: &str) -> serde_json::Value {
    serde_json::from_str(http_json_body(response)).expect("HTTP body must be valid JSON")
}

fn api_error_body(response: &str) -> ApiError {
    serde_json::from_str(http_json_body(response)).expect("response body should be ApiError JSON")
}

async fn send_window_vv_request(ws: &mut WsStream, key: &str) {
    let doc = LoroDoc::new();
    let msg =
        transport::encode_window_sync(key, window_sub_tags::VV_REQUEST, &doc.oplog_vv().encode());
    ws.send(Message::Binary(msg.into())).await.unwrap();
}

async fn drain_vv_request_responses(ws: &mut WsStream, expected_key: &str) {
    for _ in 0..2 {
        let frame = next_binary(ws).await;
        assert_eq!(frame[0], TAG_WINDOW_SYNC);
        let (window_key, _sub_tag, _payload) = transport::decode_window_sync(&frame[1..]).unwrap();
        assert_eq!(window_key, expected_key);
    }
}

/// Polls sync_state until `key` exists (persistence is synchronous in the
/// handler, but the client send is fire-and-forget, so the test must wait
/// for the server task to process the frame).
async fn wait_for_sync_state_key(vault: &oneiron::Vault, key: &str) {
    for _ in 0..250 {
        if vault.sync_state_get(key).unwrap().is_some() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for sync_state key {key}");
}

fn assert_unauthorized(err: &tokio_tungstenite::tungstenite::Error) {
    let tokio_tungstenite::tungstenite::Error::Http(response) = err else {
        panic!("expected HTTP 401 rejection, got {err:?}");
    };
    assert_eq!(
        response.status(),
        401,
        "expected HTTP 401 Unauthorized, got {}",
        response.status()
    );
}

fn deep_map_bytes(doc: &LoroDoc, map: &str, key: &str) -> Option<Vec<u8>> {
    let deep = doc.get_deep_value();
    let root = deep.as_map()?;
    let inner = root.get(map)?.as_map()?;
    let value = inner.get(key)?.as_binary()?;
    Some(value.to_vec())
}

fn encode_ephemeral_set(key: &str, value: impl Into<LoroValue>) -> Vec<u8> {
    let store = EphemeralStore::new(30_000);
    store.set(key, value);
    transport::encode_ephemeral(&store.encode(key))
        .into_result()
        .unwrap()
}

fn encode_ephemeral_delete(key: &str) -> Vec<u8> {
    let store = EphemeralStore::new(30_000);
    store.delete(key);
    transport::encode_ephemeral(&store.encode(key))
        .into_result()
        .unwrap()
}

fn encode_ephemeral_wire_state(key: &str, value: impl Into<LoroValue>, timestamp: i64) -> Vec<u8> {
    let payload = transport::encode_ephemeral_states(&[EphemeralWireState {
        key: key.to_owned(),
        value: Some(value.into()),
        timestamp,
    }])
    .unwrap();
    transport::encode_ephemeral(&payload).into_result().unwrap()
}

fn epoch_millis() -> i64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    millis.min(i64::MAX as u128) as i64
}

fn apply_ephemeral_frame(store: &EphemeralStore, frame: &[u8]) {
    assert_eq!(frame[0], TAG_EPHEMERAL);
    store.apply(&frame[1..]).unwrap();
}

// ─── /ws auth ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ws_upgrade_rejects_unauthenticated_when_secret_configured() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, _server, handle) = spawn_server(
        open_vault(dir.path()),
        config_with_secret(Some("test-secret-aaaa")),
    )
    .await;

    // Missing header → 401 before upgrade (fail-closed).
    let err = connect(addr, None).await.unwrap_err();
    assert_unauthorized(&err);

    // Wrong secret of the SAME length → 401 (exercises the constant-time
    // comparison branch, not just the length check).
    let err = connect(addr, Some("test-secret-bbbb")).await.unwrap_err();
    assert_unauthorized(&err);

    // Correct secret → upgrade succeeds and the Phase-1 root snapshot
    // (TAG_SYNC_UPDATE) arrives.
    let mut ws = connect(addr, Some("test-secret-aaaa")).await.unwrap();
    let first = next_binary(&mut ws).await;
    assert_eq!(first[0], TAG_SYNC_UPDATE);

    handle.abort();
}

#[tokio::test]
async fn ws_upgrade_rejects_empty_configured_secret_even_with_empty_header() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, _server, handle) =
        spawn_server(open_vault(dir.path()), config_with_secret(Some(""))).await;

    let err = connect(addr, None).await.unwrap_err();
    assert_unauthorized(&err);

    let err = connect(addr, Some("")).await.unwrap_err();
    assert_unauthorized(&err);

    handle.abort();
}

#[tokio::test]
async fn ws_upgrade_rejects_unauthenticated_when_no_secret_and_not_dev() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, _server, handle) =
        spawn_server(open_vault(dir.path()), config_with_secret(None)).await;

    let err = connect(addr, None).await.unwrap_err();
    assert_unauthorized(&err);

    handle.abort();
}

#[tokio::test]
async fn ws_upgrade_allows_unauthenticated_only_in_dev_mode() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, _server, handle) = spawn_server(
        open_vault(dir.path()),
        config_with_secret_and_dev(None, true),
    )
    .await;

    let mut ws = connect(addr, None).await.unwrap();
    let first = next_binary(&mut ws).await;
    assert_eq!(first[0], TAG_SYNC_UPDATE);

    handle.abort();
}

#[tokio::test]
async fn http_guarded_route_rejects_when_no_secret_and_not_dev() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, _server, handle) =
        spawn_server(open_vault(dir.path()), config_with_secret(None)).await;

    let response = http_get(addr, "/api/search/text?query=hello", None).await;
    assert_http_status(&response, 401);
    let error = api_error_body(&response);
    assert_eq!(error.code(), ErrorCode::Unauthorized);
    assert!(matches!(error.details(), ApiErrorDetails::Unauthorized));
    assert!(!error.suggestions().is_empty());

    handle.abort();
}

#[tokio::test]
async fn http_bad_entity_id_returns_structured_api_error_body() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, _server, handle) = spawn_server(
        open_vault(dir.path()),
        config_with_secret_and_dev(None, true),
    )
    .await;

    let response = http_get(addr, "/api/entity/not-hex", None).await;
    assert_http_status(&response, 400);
    let error = api_error_body(&response);
    assert_eq!(error.code(), ErrorCode::BadRequest);
    assert_eq!(
        error.message(),
        "entity id must be a 32-character hex entity id"
    );
    assert!(
        matches!(error.details(), ApiErrorDetails::BadRequest { field } if field.as_deref() == Some("id"))
    );
    assert!(!error.suggestions().is_empty());

    let response = http_get(addr, "/api/edges/not-hex", None).await;
    assert_http_status(&response, 400);
    let error = api_error_body(&response);
    assert_eq!(error.code(), ErrorCode::BadRequest);
    assert_eq!(
        error.message(),
        "entity id must be a 32-character hex entity id"
    );
    assert!(
        matches!(error.details(), ApiErrorDetails::BadRequest { field } if field.as_deref() == Some("id"))
    );
    assert!(!error.suggestions().is_empty());

    handle.abort();
}

#[tokio::test]
async fn http_entity_summary_projects_exact_keys_and_hides_heavy_fields() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault(dir.path());
    let id = EntityId::now();
    let body = msgpack_json(&serde_json::json!({
        "title": "Ship projection",
        "role": TaskRole::Task.role_byte(),
        "status": "open",
        "priority": 2,
        "body": "long heavy body",
        "metadata": {"large": true}
    }));
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_TASK,
            TimeRange { start: 10, end: 10 },
            42,
            &body,
        )
        .unwrap();
    let (addr, _server, handle) = spawn_server(vault, config_with_secret_and_dev(None, true)).await;

    let response = http_get_bytes(
        addr,
        &format!("/api/entity/{}?view=summary", id.to_hex()),
        None,
    )
    .await;
    assert_http_status_bytes(&response, 200);
    let json = http_json(&response);
    assert_eq!(
        json_key_set(&json),
        std::collections::BTreeSet::from(["id", "kind", "label", "updatedAt"])
    );
    assert_eq!(json["id"], id.to_hex());
    assert_eq!(json["kind"], "TASK");
    assert_eq!(json["label"], "Ship projection");
    assert_eq!(json["updatedAt"], 42);
    assert!(json.get("body").is_none());
    assert!(json.get("metadata").is_none());

    handle.abort();
}

#[tokio::test]
async fn http_entity_default_returns_standard_raw_body() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault(dir.path());
    let id = EntityId::now();
    let body = msgpack_json(&serde_json::json!({
        "title": "Raw default",
        "role": TaskRole::Task.role_byte(),
        "status": "open"
    }));
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_TASK,
            TimeRange { start: 20, end: 20 },
            50,
            &body,
        )
        .unwrap();
    let (addr, _server, handle) = spawn_server(vault, config_with_secret_and_dev(None, true)).await;

    let response = http_get_bytes(addr, &format!("/api/entity/{}", id.to_hex()), None).await;
    assert_http_status_bytes(&response, 200);
    assert_eq!(http_body(&response), body.as_slice());

    handle.abort();
}

#[tokio::test]
async fn http_vector_search_defaults_to_summary_and_full_supersets_standard() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_search_vault(dir.path());
    let id = EntityId::now();
    let body = msgpack_json(&serde_json::json!({
        "title": "Vector hit",
        "role": TaskRole::Task.role_byte(),
        "status": "open",
        "priority": 1,
        "dueDate": 1_777_100_000_u64,
        "body": "heavy vector payload",
        "custom": {"nested": true}
    }));
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_TASK,
            TimeRange { start: 30, end: 30 },
            60,
            &body,
        )
        .unwrap();
    vault.put_vector(&id, &[1.0_f32, 0.0, 0.0, 0.0]).unwrap();
    let (addr, _server, handle) = spawn_server(vault, config_with_secret_and_dev(None, true)).await;

    let summary_response =
        http_get_bytes(addr, "/api/search/vector?query=1,0,0,0&limit=1", None).await;
    assert_http_status_bytes(&summary_response, 200);
    let summary = http_json(&summary_response);
    let summary_hit = summary["items"].as_array().unwrap().first().unwrap();
    assert_eq!(
        json_key_set(summary_hit),
        std::collections::BTreeSet::from(["id", "kind", "label", "updatedAt"])
    );
    assert!(summary_hit.get("score").is_none());

    let standard_response = http_get_bytes(
        addr,
        "/api/search/vector?query=1,0,0,0&limit=1&view=standard",
        None,
    )
    .await;
    assert_http_status_bytes(&standard_response, 200);
    let standard = http_json(&standard_response);
    let standard_hit = standard["items"].as_array().unwrap().first().unwrap();
    assert_eq!(
        json_key_set(standard_hit),
        std::collections::BTreeSet::from(["id", "score"])
    );

    let full_response = http_get_bytes(
        addr,
        "/api/search/vector?query=1,0,0,0&limit=1&view=full",
        None,
    )
    .await;
    assert_http_status_bytes(&full_response, 200);
    let full = http_json(&full_response);
    let full_hit = full["items"].as_array().unwrap().first().unwrap();
    let full_keys = json_key_set(full_hit);
    for key in json_key_set(summary_hit)
        .into_iter()
        .chain(json_key_set(standard_hit))
    {
        assert!(full_keys.contains(key), "full missing key {key}");
    }
    assert_eq!(full_hit["title"], "Vector hit");
    assert_eq!(full_hit["status"], "open");
    assert_eq!(full_hit["body"], "heavy vector payload");
    assert_eq!(full_hit["custom"], serde_json::json!({"nested": true}));

    handle.abort();
}

#[tokio::test]
async fn http_edges_default_summary_and_standard_preserves_current_fields() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault(dir.path());
    let source = EntityId::now();
    let target = EntityId::now();
    let body =
        msgpack_json(&serde_json::json!({"title": "node", "role": TaskRole::Task.role_byte()}));
    for id in [source, target] {
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_TASK,
                TimeRange { start: 40, end: 40 },
                70,
                &body,
            )
            .unwrap();
    }
    vault
        .put_edge(&source, EdgeKind::BelongsTo, &target, 0.5)
        .unwrap();
    let (addr, _server, handle) = spawn_server(vault, config_with_secret_and_dev(None, true)).await;

    let summary_response =
        http_get_bytes(addr, &format!("/api/edges/{}", source.to_hex()), None).await;
    assert_http_status_bytes(&summary_response, 200);
    let summary = http_json(&summary_response);
    let summary_edge = summary.as_array().unwrap().first().unwrap();
    assert_eq!(
        json_key_set(summary_edge),
        std::collections::BTreeSet::from(["kind", "target"])
    );

    let standard_response = http_get_bytes(
        addr,
        &format!("/api/edges/{}?view=standard", source.to_hex()),
        None,
    )
    .await;
    assert_http_status_bytes(&standard_response, 200);
    let standard = http_json(&standard_response);
    let standard_edge = standard.as_array().unwrap().first().unwrap();
    assert_eq!(
        json_key_set(standard_edge),
        std::collections::BTreeSet::from(["created_at", "kind", "target", "weight"])
    );

    handle.abort();
}

#[tokio::test]
async fn http_text_search_invalid_view_returns_error_code() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, _server, handle) = spawn_server(
        open_vault(dir.path()),
        config_with_secret_and_dev(None, true),
    )
    .await;

    let response = http_get(addr, "/api/search/text?query=hello&view=tiny", None).await;
    assert_http_status(&response, 400);
    let error = api_error_body(&response);
    assert_eq!(error.code(), ErrorCode::BadRequest);
    assert_eq!(
        error.message(),
        "view must be one of summary, standard, full"
    );
    assert!(
        matches!(error.details(), ApiErrorDetails::BadRequest { field } if field.as_deref() == Some("view"))
    );

    handle.abort();
}

#[tokio::test]
async fn http_search_text_response_defaults_to_estimate_meta() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, _server, handle) = spawn_server(
        open_vault(dir.path()),
        config_with_secret_and_dev(None, true),
    )
    .await;

    let response = http_get(addr, "/api/search/text?query=no-such-term", None).await;
    assert_http_status(&response, 200);
    let body = http_json_value(&response);

    assert_eq!(body["items"], serde_json::json!([]));
    assert!(body.get("nextCursor").is_none());
    assert_eq!(
        body["meta"],
        serde_json::json!({
            "total": 0,
            "countMode": "estimate"
        })
    );

    handle.abort();
}

#[tokio::test]
async fn http_search_text_estimate_counts_before_page_truncation() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_search_vault(dir.path());
    seed_text_search_matches(&vault);
    let (addr, _server, handle) = spawn_server(vault, config_with_secret_and_dev(None, true)).await;

    let response = http_get(addr, "/api/search/text?query=metaneedle&limit=2", None).await;
    assert_http_status(&response, 200);
    let body = http_json_value(&response);

    assert_eq!(body["items"].as_array().unwrap().len(), 2);
    assert_eq!(
        body["meta"],
        serde_json::json!({
            "total": 3,
            "countMode": "estimate"
        })
    );

    handle.abort();
}

#[tokio::test]
async fn http_search_text_count_mode_none_returns_zero_none_meta() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, _server, handle) = spawn_server(
        open_vault(dir.path()),
        config_with_secret_and_dev(None, true),
    )
    .await;

    let response = http_get(
        addr,
        "/api/search/text?query=no-such-term&countMode=none",
        None,
    )
    .await;
    assert_http_status(&response, 200);
    let body = http_json_value(&response);

    assert_eq!(body["items"], serde_json::json!([]));
    assert_eq!(
        body["meta"],
        serde_json::json!({
            "total": 0,
            "countMode": "none"
        })
    );

    handle.abort();
}

#[tokio::test]
async fn http_search_vector_response_defaults_to_estimate_meta() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, _server, handle) = spawn_server(
        open_vault(dir.path()),
        config_with_secret_and_dev(None, true),
    )
    .await;
    let vector = vec!["0.0"; 1024].join(",");
    let path = format!("/api/search/vector?query={vector}&limit=2");

    let response = http_get(addr, &path, None).await;
    assert_http_status(&response, 200);
    let body = http_json_value(&response);

    assert_eq!(body["items"], serde_json::json!([]));
    assert_eq!(
        body["meta"],
        serde_json::json!({
            "total": 0,
            "countMode": "estimate"
        })
    );

    handle.abort();
}

#[tokio::test]
async fn http_search_vector_estimate_counts_before_page_truncation() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_search_vault(dir.path());
    seed_vector_search_matches(&vault);
    let (addr, _server, handle) = spawn_server(vault, config_with_secret_and_dev(None, true)).await;

    let response = http_get(
        addr,
        "/api/search/vector?query=1.0,0.0,0.0,0.0&limit=2",
        None,
    )
    .await;
    assert_http_status(&response, 200);
    let body = http_json_value(&response);

    assert_eq!(body["items"].as_array().unwrap().len(), 2);
    assert_eq!(
        body["meta"],
        serde_json::json!({
            "total": 3,
            "countMode": "estimate"
        })
    );

    handle.abort();
}

#[tokio::test]
async fn lease_revoke_route_uses_idempotency_key_replay_cache() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, _server, handle) = spawn_server(
        open_vault(dir.path()),
        config_with_secret(Some("route-secret")),
    )
    .await;

    let body = r#"{"client_id":"0000000000000001"}"#;
    let first = http_post(
        addr,
        "/api/lease/revoke",
        body,
        Some("route-secret"),
        Some("lease-revoke-key"),
    )
    .await;
    assert_http_status(&first, 200);

    let replay = http_post(
        addr,
        "/api/lease/revoke",
        body,
        Some("route-secret"),
        Some("lease-revoke-key"),
    )
    .await;
    assert_http_status(&replay, 200);
    assert_eq!(
        http_json_body(&first).as_bytes(),
        http_json_body(&replay).as_bytes()
    );

    let conflict = http_post(
        addr,
        "/api/lease/revoke",
        r#"{"client_id":"0000000000000002"}"#,
        Some("route-secret"),
        Some("lease-revoke-key"),
    )
    .await;
    assert_http_status(&conflict, 409);
    let error = api_error_body(&conflict);
    assert_eq!(error.code(), ErrorCode::IdempotencyReplayConflict);
    assert!(matches!(
        error.details(),
        ApiErrorDetails::IdempotencyReplayConflict { idempotency_key }
            if idempotency_key.as_deref() == Some("lease-revoke-key")
    ));
    assert!(!error.suggestions().is_empty());

    handle.abort();
}

// ─── Update relay + durability ────────────────────────────────────────────────

#[tokio::test]
async fn ephemeral_presence_relays_between_two_clients() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, _server, handle) = spawn_server(
        open_vault(dir.path()),
        config_with_secret(Some("presence-secret")),
    )
    .await;

    let mut client_a = connect(addr, Some("presence-secret")).await.unwrap();
    let mut client_b = connect(addr, Some("presence-secret")).await.unwrap();
    let _ = next_binary(&mut client_a).await; // root snapshot
    let _ = next_binary(&mut client_b).await; // root snapshot

    client_a
        .send(Message::Binary(
            encode_ephemeral_set("presence:device-a", "online").into(),
        ))
        .await
        .unwrap();

    let relayed = next_binary(&mut client_b).await;
    let receiver = EphemeralStore::new(30_000);
    apply_ephemeral_frame(&receiver, &relayed);
    assert_eq!(receiver.get("presence:device-a"), Some("online".into()));

    handle.abort();
}

#[tokio::test]
async fn ephemeral_late_join_receives_hub_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, _server, handle) = spawn_server(
        open_vault(dir.path()),
        config_with_secret(Some("late-secret")),
    )
    .await;

    let mut client_a = connect(addr, Some("late-secret")).await.unwrap();
    let _ = next_binary(&mut client_a).await; // root snapshot
    client_a
        .send(Message::Binary(
            encode_ephemeral_set("presence:device-a", "online").into(),
        ))
        .await
        .unwrap();

    let mut client_b = connect(addr, Some("late-secret")).await.unwrap();
    let root = next_binary(&mut client_b).await;
    assert_eq!(root[0], TAG_SYNC_UPDATE);
    let snapshot = next_binary(&mut client_b).await;
    let receiver = EphemeralStore::new(30_000);
    apply_ephemeral_frame(&receiver, &snapshot);
    assert_eq!(receiver.get("presence:device-a"), Some("online".into()));

    handle.abort();
}

#[tokio::test]
async fn ephemeral_late_join_snapshot_prunes_expired_keys() {
    let dir = tempfile::tempdir().unwrap();
    let config = SyncServerConfig {
        auth_secret: Some("ttl-secret".to_string()),
        ephemeral_timeout_ms: 5,
        ..Default::default()
    };
    let (addr, _server, handle) = spawn_server(open_vault(dir.path()), config).await;

    let mut client_a = connect(addr, Some("ttl-secret")).await.unwrap();
    let _ = next_binary(&mut client_a).await; // root snapshot
    client_a
        .send(Message::Binary(
            encode_ephemeral_set("presence:device-a", "online").into(),
        ))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(25)).await;

    let mut client_b = connect(addr, Some("ttl-secret")).await.unwrap();
    let root = next_binary(&mut client_b).await;
    assert_eq!(root[0], TAG_SYNC_UPDATE);
    expect_no_binary(&mut client_b, Duration::from_millis(150)).await;

    handle.abort();
}

#[tokio::test]
async fn ephemeral_late_join_snapshot_includes_delete_tombstone() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, _server, handle) = spawn_server(
        open_vault(dir.path()),
        config_with_secret(Some("tombstone-secret")),
    )
    .await;

    let mut client_a = connect(addr, Some("tombstone-secret")).await.unwrap();
    let mut client_b = connect(addr, Some("tombstone-secret")).await.unwrap();
    let _ = next_binary(&mut client_a).await; // root snapshot
    let _ = next_binary(&mut client_b).await; // root snapshot

    let key = "presence:device-a";
    client_a
        .send(Message::Binary(encode_ephemeral_set(key, "online").into()))
        .await
        .unwrap();

    let stale_receiver = EphemeralStore::new(30_000);
    let relayed_set = next_binary(&mut client_b).await;
    apply_ephemeral_frame(&stale_receiver, &relayed_set);
    assert_eq!(stale_receiver.get(key), Some("online".into()));

    tokio::time::sleep(Duration::from_millis(2)).await;
    client_a
        .send(Message::Binary(encode_ephemeral_delete(key).into()))
        .await
        .unwrap();

    let mut client_c = connect(addr, Some("tombstone-secret")).await.unwrap();
    let root = next_binary(&mut client_c).await;
    assert_eq!(root[0], TAG_SYNC_UPDATE);
    let tombstone_snapshot = next_binary(&mut client_c).await;
    apply_ephemeral_frame(&stale_receiver, &tombstone_snapshot);
    assert!(
        stale_receiver.get(key).is_none(),
        "late-join snapshot must carry tombstones, not only live values"
    );

    handle.abort();
}

#[tokio::test]
async fn ephemeral_relay_uses_hub_canonical_state_for_stale_payload() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, _server, handle) = spawn_server(
        open_vault(dir.path()),
        config_with_secret(Some("canonical-secret")),
    )
    .await;

    let mut client_a = connect(addr, Some("canonical-secret")).await.unwrap();
    let _ = next_binary(&mut client_a).await; // root snapshot

    let key = "presence:device-a";
    let now = epoch_millis();
    client_a
        .send(Message::Binary(
            encode_ephemeral_wire_state(key, "newer", now).into(),
        ))
        .await
        .unwrap();

    let mut client_b = connect(addr, Some("canonical-secret")).await.unwrap();
    let _ = next_binary(&mut client_b).await; // root snapshot
    let _ = next_binary(&mut client_b).await; // late-join snapshot

    client_a
        .send(Message::Binary(
            encode_ephemeral_wire_state(key, "stale", now - 1).into(),
        ))
        .await
        .unwrap();

    let relayed = next_binary(&mut client_b).await;
    assert_eq!(relayed[0], TAG_EPHEMERAL);
    let states = transport::decode_ephemeral_states(&relayed[1..]).unwrap();
    assert_eq!(states.len(), 1);
    assert_eq!(states[0].key, key);
    assert_eq!(states[0].value, Some("newer".into()));
    assert_eq!(
        states[0].timestamp, now,
        "server must relay the hub's accepted LWW timestamp"
    );

    handle.abort();
}

#[tokio::test]
async fn ephemeral_rejects_far_future_timestamp_before_apply() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, _server, handle) = spawn_server(
        open_vault(dir.path()),
        config_with_secret(Some("future-secret")),
    )
    .await;

    let mut ws = connect(addr, Some("future-secret")).await.unwrap();
    let _ = next_binary(&mut ws).await; // root snapshot

    ws.send(Message::Binary(
        encode_ephemeral_wire_state(
            "presence:future-device",
            "online",
            epoch_millis() + 10 * 60_000,
        )
        .into(),
    ))
    .await
    .unwrap();

    assert_ws_closes(
        &mut ws,
        "server must close on implausibly future-dated ephemeral state",
    )
    .await;

    let mut late = connect(addr, Some("future-secret")).await.unwrap();
    let root = next_binary(&mut late).await;
    assert_eq!(root[0], TAG_SYNC_UPDATE);
    expect_no_binary(&mut late, Duration::from_millis(150)).await;

    handle.abort();
}

#[tokio::test]
async fn oversized_ephemeral_payload_is_rejected_before_apply() {
    let dir = tempfile::tempdir().unwrap();
    let config = SyncServerConfig {
        auth_secret: Some("eph-size-secret".to_string()),
        max_ephemeral_payload_bytes: 4,
        ..Default::default()
    };
    let (addr, _server, handle) = spawn_server(open_vault(dir.path()), config).await;

    let mut ws = connect(addr, Some("eph-size-secret")).await.unwrap();
    let _ = next_binary(&mut ws).await; // root snapshot
    let mut oversized = vec![TAG_EPHEMERAL];
    oversized.extend_from_slice(&[0u8; 5]);
    ws.send(Message::Binary(oversized.into())).await.unwrap();

    assert_ws_closes(
        &mut ws,
        "server must close before applying oversized ephemeral payload",
    )
    .await;

    let mut late = connect(addr, Some("eph-size-secret")).await.unwrap();
    let root = next_binary(&mut late).await;
    assert_eq!(root[0], TAG_SYNC_UPDATE);
    expect_no_binary(&mut late, Duration::from_millis(150)).await;

    handle.abort();
}

#[tokio::test]
async fn ephemeral_snapshot_cap_rejects_growth_before_hub_apply() {
    let key_a = "presence:device-a";
    let key_b = "presence:device-b";
    let frame_a = encode_ephemeral_set(key_a, "online-online-online");
    let frame_b = encode_ephemeral_set(key_b, "online-online-online");
    let candidate = EphemeralStore::new(30_000);
    candidate.apply(&frame_a[1..]).unwrap();
    let first_snapshot_len = candidate.encode_all().len();
    candidate.apply(&frame_b[1..]).unwrap();
    let two_key_snapshot_len = candidate.encode_all().len();
    assert!(two_key_snapshot_len > first_snapshot_len);

    let dir = tempfile::tempdir().unwrap();
    let config = SyncServerConfig {
        auth_secret: Some("eph-hub-cap-secret".to_string()),
        max_ephemeral_payload_bytes: frame_a.len().max(frame_b.len()),
        max_ephemeral_snapshot_bytes: two_key_snapshot_len - 1,
        ..Default::default()
    };
    assert!(config.max_ephemeral_snapshot_bytes >= first_snapshot_len);
    let (addr, _server, handle) = spawn_server(open_vault(dir.path()), config).await;

    let mut client_a = connect(addr, Some("eph-hub-cap-secret")).await.unwrap();
    let mut client_b = connect(addr, Some("eph-hub-cap-secret")).await.unwrap();
    let _ = next_binary(&mut client_a).await; // root snapshot
    let _ = next_binary(&mut client_b).await; // root snapshot

    client_a
        .send(Message::Binary(frame_a.into()))
        .await
        .unwrap();
    let relayed = next_binary(&mut client_b).await;
    let receiver = EphemeralStore::new(30_000);
    apply_ephemeral_frame(&receiver, &relayed);
    assert_eq!(receiver.get(key_a), Some("online-online-online".into()));

    client_a
        .send(Message::Binary(frame_b.into()))
        .await
        .unwrap();
    assert_ws_closes(
        &mut client_a,
        "server must reject ephemeral updates that would exceed hub snapshot cap",
    )
    .await;

    let mut late = connect(addr, Some("eph-hub-cap-secret")).await.unwrap();
    let root = next_binary(&mut late).await;
    assert_eq!(root[0], TAG_SYNC_UPDATE);
    let snapshot = next_binary(&mut late).await;
    let receiver = EphemeralStore::new(30_000);
    apply_ephemeral_frame(&receiver, &snapshot);
    assert_eq!(receiver.get(key_a), Some("online-online-online".into()));
    assert!(receiver.get(key_b).is_none());

    handle.abort();
}

#[tokio::test]
async fn ephemeral_frames_coexist_with_window_sync_updates() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, _server, handle) = spawn_server(
        open_vault(dir.path()),
        config_with_secret(Some("coexist-secret")),
    )
    .await;

    let mut client_a = connect(addr, Some("coexist-secret")).await.unwrap();
    let mut client_b = connect(addr, Some("coexist-secret")).await.unwrap();
    let _ = next_binary(&mut client_a).await; // root snapshot
    let _ = next_binary(&mut client_b).await; // root snapshot

    client_a
        .send(Message::Binary(
            encode_ephemeral_set("presence:device-a", "online").into(),
        ))
        .await
        .unwrap();
    let relayed = next_binary(&mut client_b).await;
    let receiver = EphemeralStore::new(30_000);
    apply_ephemeral_frame(&receiver, &relayed);
    assert_eq!(receiver.get("presence:device-a"), Some("online".into()));

    let author = LoroDoc::new();
    author
        .get_map("entities")
        .insert("e-coexist", b"window-payload".as_slice())
        .unwrap();
    author.commit();
    let update = author.export(ExportMode::all_updates()).unwrap();
    let window_update = transport::encode_window_sync("2026-02", window_sub_tags::UPDATE, &update);
    client_a
        .send(Message::Binary(window_update.into()))
        .await
        .unwrap();

    let relayed = next_binary(&mut client_b).await;
    assert_eq!(relayed[0], TAG_WINDOW_SYNC);
    let (key, sub_tag, payload) = transport::decode_window_sync(&relayed[1..]).unwrap();
    assert_eq!(key, "2026-02");
    assert_eq!(sub_tag, window_sub_tags::UPDATE);
    assert_eq!(payload, update.as_slice());

    handle.abort();
}

#[tokio::test]
async fn imported_update_relays_to_second_client_and_persists_contract_keys() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault(dir.path());
    let (addr, server, handle) =
        spawn_server(vault.clone(), config_with_secret(Some("relay-secret"))).await;

    let mut client_a = connect(addr, Some("relay-secret")).await.unwrap();
    let mut client_b = connect(addr, Some("relay-secret")).await.unwrap();
    // Drain the Phase-1 root snapshot on both connections; once B has its
    // snapshot, B's broadcast subscription is live.
    let _ = next_binary(&mut client_a).await;
    let _ = next_binary(&mut client_b).await;

    // Author an update in a local Loro doc.
    let author = LoroDoc::new();
    author
        .get_map("entities")
        .insert("e-relay", b"relay-payload".as_slice())
        .unwrap();
    author.commit();
    let update = author.export(ExportMode::all_updates()).unwrap();

    let msg = transport::encode_window_sync("2026-02", window_sub_tags::UPDATE, &update);
    client_a.send(Message::Binary(msg.into())).await.unwrap();

    // B receives the relayed WindowSync UPDATE with the exact payload.
    let relayed = next_binary(&mut client_b).await;
    assert_eq!(relayed[0], TAG_WINDOW_SYNC);
    let (key, sub_tag, payload) = transport::decode_window_sync(&relayed[1..]).unwrap();
    assert_eq!(key, "2026-02");
    assert_eq!(sub_tag, window_sub_tags::UPDATE);
    assert_eq!(payload, update.as_slice());

    // Durability: the imported update was persisted under the ARCH-0023b
    // sync_state key layout BEFORE it was broadcast — so by the time B holds
    // the relay, the bytes are on disk.
    let vault = server.vault();
    assert!(
        vault.sync_state_get("d:w:2026-02").unwrap().is_some(),
        "window snapshot d:w:2026-02 must exist"
    );
    assert_eq!(
        vault
            .sync_state_get("u:w:2026-02:00000001")
            .unwrap()
            .unwrap(),
        update,
        "imported update bytes must be appended at u:w:2026-02:00000001"
    );
    assert_eq!(
        vault.sync_state_get("m:u_seq:w:2026-02").unwrap().unwrap(),
        1u32.to_le_bytes(),
        "m:u_seq:w:2026-02 must be a u32 LE counter at 1"
    );
    assert_eq!(
        vault.sync_state_get("svf:w:2026-02").unwrap().unwrap(),
        vec![0u8],
        "svf:w:2026-02 must be marked stale (0) after an appended update"
    );
    assert!(
        vault.sync_state_get("d:root").unwrap().is_some(),
        "root snapshot d:root must exist"
    );

    handle.abort();
}

#[tokio::test]
async fn relayed_update_and_tombstone_survive_server_restart() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault(dir.path());

    // ── Session 1: client A relays an entity update, then a tombstone.
    let (addr, server1, handle1) =
        spawn_server(vault.clone(), config_with_secret(Some("restart-secret"))).await;
    let mut client_a = connect(addr, Some("restart-secret")).await.unwrap();
    let _ = next_binary(&mut client_a).await; // root snapshot

    let author = LoroDoc::new();
    author
        .get_map("entities")
        .insert("e-durable", b"survives".as_slice())
        .unwrap();
    author.commit();
    let entity_update = author.export(ExportMode::all_updates()).unwrap();
    let msg = transport::encode_window_sync("2026-02", window_sub_tags::UPDATE, &entity_update);
    client_a.send(Message::Binary(msg.into())).await.unwrap();

    // The delete-propagation case: a TOMBSTONE relayed through the server
    // must survive a restart, or durable cross-device delete propagation is
    // impossible.
    let vv_before_tombstone = author.oplog_vv();
    author
        .get_map("tombstones")
        .insert("e-deleted", b"1".as_slice())
        .unwrap();
    author.commit();
    let tombstone_update = author
        .export(ExportMode::updates(&vv_before_tombstone))
        .unwrap();
    let msg = transport::encode_window_sync("2026-02", window_sub_tags::UPDATE, &tombstone_update);
    client_a.send(Message::Binary(msg.into())).await.unwrap();

    // Wait until both updates are durable, then "restart": kill the server
    // task and drop ALL in-RAM CRDT state.
    wait_for_sync_state_key(&vault, "u:w:2026-02:00000002").await;
    let _ = client_a.close(None).await;
    handle1.abort();
    drop(server1);

    // ── Session 2: a fresh SyncServer over the same vault.
    let (addr2, _server2, handle2) =
        spawn_server(vault.clone(), config_with_secret(Some("restart-secret"))).await;
    let mut client_b = connect(addr2, Some("restart-secret")).await.unwrap();

    // The reloaded root doc still announces the window — decoded through the
    // REAL client path (SyncClient::server_windows, client.rs read path).
    let root_msg = next_binary(&mut client_b).await;
    assert_eq!(root_msg[0], TAG_SYNC_UPDATE);
    let client_dir = tempfile::tempdir().unwrap();
    let client_vault = open_vault(client_dir.path());
    let (mut sync_client, _events) =
        SyncClient::new(open_manager(client_vault), SyncClientConfig::default()).unwrap();
    sync_client.handle_server_message(&root_msg).unwrap();
    assert_eq!(
        sync_client.server_windows(),
        vec!["2026-02".to_string()],
        "restarted server must still announce the persisted window in meta.windows"
    );

    // Pull the window state. The server currently ignores the VV_REQUEST
    // payload and replies with all updates; send an empty Loro VV.
    let empty_vv = LoroDoc::new().oplog_vv().encode();
    let vv_req = transport::encode_window_sync("2026-02", window_sub_tags::VV_REQUEST, &empty_vv);
    client_b.send(Message::Binary(vv_req.into())).await.unwrap();

    let reply = next_binary(&mut client_b).await;
    assert_eq!(reply[0], TAG_WINDOW_SYNC);
    let (key, sub_tag, payload) = transport::decode_window_sync(&reply[1..]).unwrap();
    assert_eq!(key, "2026-02");
    assert_eq!(sub_tag, window_sub_tags::UPDATE);

    let receiver = LoroDoc::new();
    receiver.import(payload).unwrap();
    assert_eq!(
        deep_map_bytes(&receiver, "entities", "e-durable").unwrap(),
        b"survives",
        "a relayed entity update must survive the server restart"
    );
    assert_eq!(
        deep_map_bytes(&receiver, "tombstones", "e-deleted").unwrap(),
        b"1",
        "a relayed TOMBSTONE must survive the server restart (delete propagation)"
    );

    handle2.abort();
}

#[tokio::test]
async fn persist_failure_evicts_window_so_vv_request_omits_unpersisted_update() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault(dir.path());
    let (addr, _server, handle) =
        spawn_server(vault.clone(), config_with_secret(Some("evict-secret"))).await;

    let mut client_a = connect(addr, Some("evict-secret")).await.unwrap();
    let _ = next_binary(&mut client_a).await; // root snapshot

    // First update persists fine (window created, appended at seq 1).
    let author = LoroDoc::new();
    author
        .get_map("entities")
        .insert("e-ok", b"persisted".as_slice())
        .unwrap();
    author.commit();
    let ok_update = author.export(ExportMode::all_updates()).unwrap();
    let msg = transport::encode_window_sync("2026-02", window_sub_tags::UPDATE, &ok_update);
    client_a.send(Message::Binary(msg.into())).await.unwrap();
    wait_for_sync_state_key(&vault, "u:w:2026-02:00000001").await;

    // Corrupt the monotonic seq row: the NEXT persist_imported_update trips
    // CorruptedIndex (fail-closed, server_state policy) AFTER the handler
    // has already imported the update into the cached RAM doc.
    vault
        .sync_state_put("m:u_seq:w:2026-02", &[1, 2, 3])
        .unwrap();

    // The failing update is a TOMBSTONE — the exact fleet-wide-loss shape:
    // if the unpersisted import stayed servable, the origin would VV-confirm
    // and clear its local queue, and a server restart would then drop the
    // delete everywhere.
    let vv_before = author.oplog_vv();
    author
        .get_map("tombstones")
        .insert("e-victim", b"1".as_slice())
        .unwrap();
    author.commit();
    let tombstone_update = author.export(ExportMode::updates(&vv_before)).unwrap();
    let msg = transport::encode_window_sync("2026-02", window_sub_tags::UPDATE, &tombstone_update);
    client_a.send(Message::Binary(msg.into())).await.unwrap();

    // (a) The connection closes (Persistence error → fail-closed break).
    // Eviction happens before the error propagates, so once the close is
    // observed the window cache no longer holds the poisoned doc.
    let closed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match client_a.next().await {
                None | Some(Ok(Message::Close(_))) | Some(Err(_)) => break,
                Some(Ok(_)) => continue,
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "server must close on persist failure");

    // (b) A second client's VV_REQUEST against the SAME live server (no
    // restart) must NOT contain the failed update: the mutated RAM doc was
    // evicted and the window reloaded from durable d:w:/u:w: state.
    let mut client_b = connect(addr, Some("evict-secret")).await.unwrap();
    let _ = next_binary(&mut client_b).await; // root snapshot

    let empty_vv = LoroDoc::new().oplog_vv().encode();
    let vv_req = transport::encode_window_sync("2026-02", window_sub_tags::VV_REQUEST, &empty_vv);
    client_b.send(Message::Binary(vv_req.into())).await.unwrap();

    let reply = next_binary(&mut client_b).await;
    assert_eq!(reply[0], TAG_WINDOW_SYNC);
    let (key, sub_tag, payload) = transport::decode_window_sync(&reply[1..]).unwrap();
    assert_eq!(key, "2026-02");
    assert_eq!(sub_tag, window_sub_tags::UPDATE);

    let receiver = LoroDoc::new();
    receiver.import(payload).unwrap();
    assert_eq!(
        deep_map_bytes(&receiver, "entities", "e-ok").unwrap(),
        b"persisted",
        "the durably persisted update must still be served after eviction"
    );
    assert!(
        deep_map_bytes(&receiver, "tombstones", "e-victim").is_none(),
        "an update whose durable append failed must NOT be servable from RAM \
         (evict-on-persist-failure: RAM must never serve state a restart loses)"
    );

    handle.abort();
}

#[tokio::test]
async fn oversized_update_is_rejected_before_any_state_mutates() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault(dir.path());
    let config = SyncServerConfig {
        auth_secret: Some("payload-secret".to_string()),
        max_update_payload: 64,
        ..Default::default()
    };
    let (addr, server, handle) = spawn_server(vault, config).await;

    let mut ws = connect(addr, Some("payload-secret")).await.unwrap();
    let _ = next_binary(&mut ws).await; // root snapshot

    let oversized = vec![0u8; 65];
    let msg = transport::encode_window_sync("2026-02", window_sub_tags::UPDATE, &oversized);
    ws.send(Message::Binary(msg.into())).await.unwrap();

    // The server closes the connection (FrameTooLarge → break).
    assert_ws_closes(&mut ws, "server must close on oversized update").await;

    // Fail-closed and side-effect free: nothing was created or persisted —
    // the size check runs before the window doc is fetched or created.
    let vault = server.vault();
    assert!(vault.sync_state_get("d:w:2026-02").unwrap().is_none());
    assert!(
        vault
            .sync_state_get("u:w:2026-02:00000001")
            .unwrap()
            .is_none()
    );
    assert!(vault.sync_state_get("m:u_seq:w:2026-02").unwrap().is_none());

    handle.abort();
}

#[tokio::test]
async fn window_creation_cap_closes_on_fabricated_distinct_keys_only() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault(dir.path());
    let config = SyncServerConfig {
        auth_secret: Some("cap-secret".to_string()),
        max_windows_per_connection: 2,
        ..Default::default()
    };
    let (addr, _server, handle) = spawn_server(vault, config).await;

    let mut ws = connect(addr, Some("cap-secret")).await.unwrap();
    let _ = next_binary(&mut ws).await; // root snapshot

    send_window_vv_request(&mut ws, "2026-01").await;
    drain_vv_request_responses(&mut ws, "2026-01").await;
    send_window_vv_request(&mut ws, "2026-02").await;
    drain_vv_request_responses(&mut ws, "2026-02").await;

    // Re-touching a previously counted window stays under the cap, preserving
    // legitimate historical-window tombstone sync that revisits old windows.
    send_window_vv_request(&mut ws, "2026-01").await;
    drain_vv_request_responses(&mut ws, "2026-01").await;

    send_window_vv_request(&mut ws, "2026-03").await;
    assert_ws_closes(
        &mut ws,
        "server must close when a connection exceeds the distinct-window cap",
    )
    .await;

    handle.abort();
}

#[tokio::test]
async fn inbound_message_rate_limit_closes_over_limit_connection() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault(dir.path());
    let config = SyncServerConfig {
        auth_secret: Some("rate-secret".to_string()),
        max_messages_per_sec: 1,
        ..Default::default()
    };
    let (addr, _server, handle) = spawn_server(vault, config).await;

    let mut ws = connect(addr, Some("rate-secret")).await.unwrap();
    let _ = next_binary(&mut ws).await; // root snapshot

    ws.send(Message::Binary(vec![TAG_SYNC_UPDATE].into()))
        .await
        .unwrap();
    ws.send(Message::Binary(vec![TAG_SYNC_UPDATE].into()))
        .await
        .unwrap();

    assert_ws_closes(
        &mut ws,
        "server must close when one connection exceeds max_messages_per_sec",
    )
    .await;

    handle.abort();
}

#[tokio::test]
async fn inbound_ping_pong_frames_count_toward_rate_limit() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault(dir.path());
    let config = SyncServerConfig {
        auth_secret: Some("control-rate-secret".to_string()),
        max_messages_per_sec: 1,
        ..Default::default()
    };
    let (addr, _server, handle) = spawn_server(vault, config).await;

    let mut ws = connect(addr, Some("control-rate-secret")).await.unwrap();
    let _ = next_binary(&mut ws).await; // root snapshot

    ws.send(Message::Ping(Vec::new().into())).await.unwrap();
    ws.send(Message::Pong(Vec::new().into())).await.unwrap();

    assert_ws_closes(
        &mut ws,
        "server must count Ping/Pong frames toward max_messages_per_sec",
    )
    .await;

    handle.abort();
}

// ─── Client-side auth (SyncConnection sends auth_token) ──────────────────────

async fn run_sync_connection_once(server_url: String, auth_token: &str) -> Vec<SyncEvent> {
    let client_dir = tempfile::tempdir().unwrap();
    let client_vault = open_vault(client_dir.path());
    let config = ConnectionConfig {
        client_config: SyncClientConfig {
            server_url,
            auth_token: auth_token.to_string(),
            ..Default::default()
        },
        auto_reconnect: false,
    };
    let connection = SyncConnection::new(open_manager(client_vault), config).unwrap();

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    let run_handle = tokio::spawn(async move { connection.run(shutdown_rx).await });
    // Give the connection time to handshake + finish initial sync, then
    // request a clean shutdown (ignored if the run loop already exited).
    tokio::time::sleep(Duration::from_secs(2)).await;
    let _ = shutdown_tx.send(());

    let mut event_rx = tokio::time::timeout(Duration::from_secs(30), run_handle)
        .await
        .expect("SyncConnection::run did not exit")
        .expect("SyncConnection::run task panicked")
        .expect("SyncConnection::run returned an error");

    let mut events = Vec::new();
    while let Ok(event) = event_rx.try_recv() {
        events.push(event);
    }
    events
}

#[tokio::test]
async fn sync_connection_sends_auth_token_on_upgrade() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, _server, handle) = spawn_server(
        open_vault(dir.path()),
        config_with_secret(Some("conn-secret")),
    )
    .await;

    // Correct auth_token → handshake passes and the client reaches Synced.
    let events = run_sync_connection_once(format!("ws://{addr}/ws"), "conn-secret").await;
    assert!(
        events
            .iter()
            .any(|e| matches!(e, SyncEvent::StatusChanged(SyncStatus::Synced))),
        "client with the correct auth_token must reach Synced; events: {events:?}"
    );

    // Wrong token → the server rejects the upgrade (fail-closed); the client
    // never syncs.
    let events = run_sync_connection_once(format!("ws://{addr}/ws"), "wrong-secret").await;
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, SyncEvent::StatusChanged(SyncStatus::Synced))),
        "client with a wrong auth_token must NOT reach Synced; events: {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, SyncEvent::Error(msg) if msg.contains("Connection failed"))),
        "client must surface the rejected connection; events: {events:?}"
    );

    handle.abort();
}
