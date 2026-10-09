use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::extract::Extension;
use axum::middleware;
use axum::routing::{MethodRouter, post};
use axum::{Json, Router};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::config::SyncServerConfig;

async fn counted_handler(
    Extension(counter): Extension<Arc<AtomicUsize>>,
) -> Json<serde_json::Value> {
    let count = counter.fetch_add(1, Ordering::SeqCst) + 1;
    Json(json!({ "count": count }))
}

/// Fails the first call and succeeds afterwards, standing in for any route
/// whose verdict depends on state the caller can go fix between attempts.
async fn rejecting_once_handler(Extension(counter): Extension<Arc<AtomicUsize>>) -> Response {
    let count = counter.fetch_add(1, Ordering::SeqCst) + 1;
    let status = if count == 1 {
        StatusCode::UNPROCESSABLE_ENTITY
    } else {
        StatusCode::OK
    };
    (status, Json(json!({ "count": count }))).into_response()
}

async fn spawn_counted_app_with_config(
    store: IdempotencyStore,
    counter: Arc<AtomicUsize>,
    config: SyncServerConfig,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    spawn_app_with_config(store, counter, config, post(counted_handler)).await
}

async fn spawn_app_with_config(
    store: IdempotencyStore,
    counter: Arc<AtomicUsize>,
    config: SyncServerConfig,
    route: MethodRouter,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let server = Arc::new(SyncServer::new(store.vault.clone(), config).unwrap());
    let state = IdempotencyLayerState { server, store };
    let app = Router::new()
        .route("/mutate", route.clone())
        // Same handler on a core-auth path: that prefix is what switches the
        // middleware from the owner-grade fallback to CoreAuth partitioning.
        .route("/v1/core/mutate", route)
        .layer(Extension(counter))
        .route_layer(middleware::from_fn_with_state(
            state,
            idempotency_middleware,
        ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, handle)
}

async fn http_post(addr: SocketAddr, body: &str, key: &str, credential: Option<&str>) -> Vec<u8> {
    http_post_to(addr, "/mutate", body, key, credential).await
}

async fn http_post_to(
    addr: SocketAddr,
    path: &str,
    body: &str,
    key: &str,
    credential: Option<&str>,
) -> Vec<u8> {
    let auth_header = credential
        .map(|credential| format!("Authorization: Bearer {credential}\r\n"))
        .unwrap_or_default();
    http_post_with_headers(addr, path, body, key, &auth_header).await
}
async fn http_post_bound(
    server: &SyncServer,
    addr: SocketAddr,
    path: &str,
    body: &str,
    key: &str,
    slip: &oneiron::authority::CapabilitySlip,
    holder: &ed25519_dalek::SigningKey,
) -> Vec<u8> {
    let request = crate::test_credentials::bind_slip_request(
        server,
        slip,
        holder,
        axum::http::Request::new(Body::empty()),
    );
    let headers = request.headers();
    let auth_header = format!(
        "Authorization: {}\r\nX-Oneiron-Binding: {}\r\n",
        headers[axum::http::header::AUTHORIZATION].to_str().unwrap(),
        headers["x-oneiron-binding"].to_str().unwrap()
    );
    http_post_with_headers(addr, path, body, key, &auth_header).await
}
async fn http_post_with_headers(
    addr: SocketAddr,
    path: &str,
    body: &str,
    key: &str,
    auth_header: &str,
) -> Vec<u8> {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\nIdempotency-Key: {key}\r\n{auth_header}\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}

fn status(response: &[u8]) -> u16 {
    let text = String::from_utf8_lossy(response);
    let status = text
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap();
    status.parse().unwrap()
}

fn body(response: &[u8]) -> &[u8] {
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    &response[split..]
}

struct StoreFixture {
    _dir: tempfile::TempDir,
    store: IdempotencyStore,
}

fn test_store(clock: Arc<dyn IdempotencyClock>) -> StoreFixture {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    StoreFixture {
        _dir: dir,
        store: IdempotencyStore::with_clock(vault, clock),
    }
}

/// A failed response is never cached, so the same key and body retried after
/// the caller fixes the underlying state reaches the handler and gets the
/// fresh verdict — not the day-old rejection replayed back at it.
#[tokio::test]
async fn failed_response_is_not_replayed_after_the_condition_clears() {
    let store = test_store(Arc::new(SystemClock));
    let counter = Arc::new(AtomicUsize::new(0));
    let (addr, handle) = spawn_app_with_config(
        store.store.clone(),
        counter.clone(),
        SyncServerConfig {
            allow_unauthenticated: true,
            ..Default::default()
        },
        post(rejecting_once_handler),
    )
    .await;

    let rejected = http_post(addr, r#"{"value":1}"#, "retry-key", None).await;
    assert_eq!(status(&rejected), 422);

    let retried = http_post(addr, r#"{"value":1}"#, "retry-key", None).await;
    assert_eq!(status(&retried), 200);
    assert_eq!(counter.load(Ordering::SeqCst), 2);

    // The success that did land is cached, so the effect still runs once.
    let replayed = http_post(addr, r#"{"value":1}"#, "retry-key", None).await;
    assert_eq!(status(&replayed), 200);
    assert_eq!(body(&replayed), body(&retried));
    assert_eq!(counter.load(Ordering::SeqCst), 2);

    handle.abort();
}

/// On core-auth routes the partition follows the authenticated grant, so two
/// differently-scoped tokens never share a cache entry. This is the only
/// partition that was ever a boundary: the old non-core one was derived from
/// a client-chosen header.
#[tokio::test]
async fn same_key_and_body_are_isolated_by_principal() {
    let store = test_store(Arc::new(SystemClock));
    let counter = Arc::new(AtomicUsize::new(0));
    let (addr, handle) = spawn_counted_app_with_config(
        store.store.clone(),
        counter.clone(),
        SyncServerConfig {
            auth_secret: Some("secret".to_owned()),
            ..Default::default()
        },
    )
    .await;

    let server = SyncServer::new(
        store.store.vault.clone(),
        SyncServerConfig {
            auth_secret: Some("secret".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let (read, read_key) = crate::test_credentials::credential(&server, "scope=core:read");
    let (write, write_key) = crate::test_credentials::credential(&server, "scope=core:write");
    let first = http_post_bound(
        &server,
        addr,
        "/v1/core/mutate",
        r#"{"value":1}"#,
        "shared-key",
        &read,
        &read_key,
    )
    .await;
    let second = http_post_bound(
        &server,
        addr,
        "/v1/core/mutate",
        r#"{"value":1}"#,
        "shared-key",
        &write,
        &write_key,
    )
    .await;

    assert_eq!(status(&first), 200);
    assert_eq!(status(&second), 200);
    assert_eq!(counter.load(Ordering::SeqCst), 2);
    assert_ne!(body(&first), body(&second));

    // Same mint and same read verb, but a narrower record capability must not
    // replay the broader result under the same idempotency key and request body.
    let mut narrow = read.clone();
    let mut scope = oneiron::federation::Scope::top();
    scope.sensitivity =
        oneiron::federation::SensitivityCeiling::AtMost(oneiron::federation::Sensitivity::Public);
    narrow
        .attenuate(
            oneiron::authority::SlipCaveat {
                scope: Some(scope),
                ..Default::default()
            },
            &read_key,
        )
        .unwrap();
    let third = http_post_bound(
        &server,
        addr,
        "/v1/core/mutate",
        r#"{"value":1}"#,
        "shared-key",
        &narrow,
        &read_key,
    )
    .await;
    assert_eq!(status(&third), 200);
    assert_ne!(body(&first), body(&third));
    let replay = http_post_bound(
        &server,
        addr,
        "/v1/core/mutate",
        r#"{"value":1}"#,
        "shared-key",
        &narrow,
        &read_key,
    )
    .await;
    assert_eq!(body(&third), body(&replay));
    handle.abort();
}

/// The non-core fallback is owner-grade only: a scoped delegation token
/// cannot drive an idempotent mutation on a route with no CoreAuth plane.
#[tokio::test]
async fn non_core_route_rejects_scoped_token_and_accepts_owner_grade() {
    let store = test_store(Arc::new(SystemClock));
    let counter = Arc::new(AtomicUsize::new(0));
    let (addr, handle) = spawn_counted_app_with_config(
        store.store.clone(),
        counter.clone(),
        SyncServerConfig {
            auth_secret: Some("secret".to_owned()),
            ..Default::default()
        },
    )
    .await;

    let server = SyncServer::new(
        store.store.vault.clone(),
        SyncServerConfig {
            auth_secret: Some("secret".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let (scoped, key) = crate::test_credentials::credential(&server, "scope=core:write");
    let rejected = http_post_bound(
        &server,
        addr,
        "/mutate",
        r#"{"value":1}"#,
        "scoped-key",
        &scoped,
        &key,
    )
    .await;
    assert_eq!(status(&rejected), 401);
    assert_eq!(counter.load(Ordering::SeqCst), 0);

    let (owner, owner_key) = crate::test_credentials::credential(&server, "jti=owner-noncore");
    let accepted = http_post_bound(
        &server,
        addr,
        "/mutate",
        r#"{"value":1}"#,
        "owner-key",
        &owner,
        &owner_key,
    )
    .await;
    assert_eq!(status(&accepted), 200);
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    handle.abort();
}

#[tokio::test]
async fn malformed_idempotency_key_does_not_preempt_auth_failure() {
    let store = test_store(Arc::new(SystemClock));
    let counter = Arc::new(AtomicUsize::new(0));
    let (addr, handle) = spawn_counted_app_with_config(
        store.store.clone(),
        counter.clone(),
        SyncServerConfig {
            auth_secret: Some("secret".to_owned()),
            allow_unauthenticated: false,
            ..Default::default()
        },
    )
    .await;

    let response = http_post(addr, r#"{"value":1}"#, "", None).await;

    assert_eq!(status(&response), 401);
    assert_eq!(counter.load(Ordering::SeqCst), 0);

    handle.abort();
}
