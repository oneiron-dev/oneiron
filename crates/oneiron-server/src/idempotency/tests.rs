use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::Extension;
use axum::http::header::SET_COOKIE;
use axum::middleware;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::config::SyncServerConfig;
use crate::error::{ApiErrorDetails, ErrorCode};

struct ManualClock {
    now_secs: Mutex<u64>,
}

impl ManualClock {
    fn new(now_secs: u64) -> Self {
        Self {
            now_secs: Mutex::new(now_secs),
        }
    }

    fn advance(&self, duration: Duration) {
        let mut now = self.now_secs.lock().unwrap();
        *now += duration.as_secs();
    }
}

impl IdempotencyClock for ManualClock {
    fn now_secs(&self) -> u64 {
        *self.now_secs.lock().unwrap()
    }
}

async fn counted_handler(
    Extension(counter): Extension<Arc<AtomicUsize>>,
) -> Json<serde_json::Value> {
    let count = counter.fetch_add(1, Ordering::SeqCst) + 1;
    Json(json!({ "count": count }))
}

async fn spawn_counted_app(
    store: IdempotencyStore,
    counter: Arc<AtomicUsize>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    spawn_counted_app_with_config(
        store,
        counter,
        SyncServerConfig {
            allow_unauthenticated: true,
            ..Default::default()
        },
    )
    .await
}

async fn spawn_counted_app_with_config(
    store: IdempotencyStore,
    counter: Arc<AtomicUsize>,
    config: SyncServerConfig,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let server = Arc::new(SyncServer::new(store.vault.clone(), config).unwrap());
    let state = IdempotencyLayerState { server, store };
    let app = Router::new()
        .route("/mutate", post(counted_handler))
        // Same handler on a core-auth path: that prefix is what switches the
        // middleware from the owner-grade fallback to CoreAuth partitioning.
        .route("/v1/core/mutate", post(counted_handler))
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
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let auth_header = credential
        .map(|credential| format!("Authorization: Bearer {credential}\r\n"))
        .unwrap_or_default();
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

#[test]
fn header_name_literal_is_pinned() {
    assert_eq!(IDEMPOTENCY_KEY_HEADER, "Idempotency-Key");
}

#[tokio::test]
async fn replay_short_circuits_handler_and_returns_byte_identical_body() {
    let store = test_store(Arc::new(SystemClock));
    let counter = Arc::new(AtomicUsize::new(0));
    let (addr, handle) = spawn_counted_app(store.store.clone(), counter.clone()).await;

    let first = http_post(addr, r#"{"value":1}"#, "replay-key", None).await;
    let second = http_post(addr, r#"{"value":1}"#, "replay-key", None).await;

    assert_eq!(status(&first), 200);
    assert_eq!(status(&second), 200);
    assert_eq!(body(&first), body(&second));
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    handle.abort();
}

#[tokio::test]
async fn same_key_different_body_conflicts_without_handler_execution() {
    let store = test_store(Arc::new(SystemClock));
    let counter = Arc::new(AtomicUsize::new(0));
    let (addr, handle) = spawn_counted_app(store.store.clone(), counter.clone()).await;

    let first = http_post(addr, r#"{"value":1}"#, "conflict-key", None).await;
    let second = http_post(addr, r#"{"value":2}"#, "conflict-key", None).await;

    assert_eq!(status(&first), 200);
    assert_eq!(status(&second), 409);
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    let error: ApiError = serde_json::from_slice(body(&second)).unwrap();
    assert_eq!(error.code(), ErrorCode::IdempotencyReplayConflict);
    assert!(matches!(
        error.details(),
        ApiErrorDetails::IdempotencyReplayConflict { idempotency_key }
            if idempotency_key.as_deref() == Some("conflict-key")
    ));
    assert!(!error.suggestions().is_empty());

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

    let read = crate::auth::mint_core_token_v2("secret", "scope=core:read");
    let write = crate::auth::mint_core_token_v2("secret", "scope=core:write");
    let first = http_post_to(
        addr,
        "/v1/core/mutate",
        r#"{"value":1}"#,
        "shared-key",
        Some(&read),
    )
    .await;
    let second = http_post_to(
        addr,
        "/v1/core/mutate",
        r#"{"value":1}"#,
        "shared-key",
        Some(&write),
    )
    .await;

    assert_eq!(status(&first), 200);
    assert_eq!(status(&second), 200);
    assert_eq!(counter.load(Ordering::SeqCst), 2);
    assert_ne!(body(&first), body(&second));

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

    let scoped = crate::auth::mint_core_token_v2("secret", "scope=core:write");
    let rejected = http_post(addr, r#"{"value":1}"#, "scoped-key", Some(&scoped)).await;
    assert_eq!(status(&rejected), 401);
    assert_eq!(counter.load(Ordering::SeqCst), 0);

    let accepted = http_post(addr, r#"{"value":1}"#, "owner-key", Some("secret")).await;
    assert_eq!(status(&accepted), 200);
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    handle.abort();
}

/// In dev mode every non-core caller shares the anonymous partition: there is
/// no authenticated identity to separate them by.
#[tokio::test]
async fn dev_mode_non_core_callers_share_the_anonymous_partition() {
    let store = test_store(Arc::new(SystemClock));
    let counter = Arc::new(AtomicUsize::new(0));
    let (addr, handle) = spawn_counted_app(store.store.clone(), counter.clone()).await;

    let first = http_post(addr, r#"{"value":1}"#, "shared-key", None).await;
    let second = http_post(addr, r#"{"value":1}"#, "shared-key", None).await;

    assert_eq!(status(&first), 200);
    assert_eq!(status(&second), 200);
    assert_eq!(counter.load(Ordering::SeqCst), 1, "second call must replay");
    assert_eq!(body(&first), body(&second));

    handle.abort();
}

#[test]
fn ttl_literal_and_expiry_window_are_pinned() {
    assert_eq!(IDEMPOTENCY_TTL.as_secs(), 86_400);

    let clock = Arc::new(ManualClock::new(1_000));
    let store = test_store(clock.clone());
    let cache_key = store_key("principal", "ttl-key");
    let response = CachedHttpResponse {
        status: StatusCode::CREATED,
        headers: HeaderMap::new(),
        body: b"created".to_vec(),
    };
    store
        .store
        .insert(&cache_key, b"body".to_vec(), response)
        .unwrap();

    clock.advance(IDEMPOTENCY_TTL - Duration::from_secs(1));
    assert!(matches!(
        store.store.lookup(&cache_key, b"body").unwrap(),
        IdempotencyLookup::Replay(_)
    ));

    clock.advance(Duration::from_secs(2));
    assert!(matches!(
        store.store.lookup(&cache_key, b"body").unwrap(),
        IdempotencyLookup::Miss
    ));
    assert!(
        store
            .store
            .vault
            .sync_state_get(&cache_key)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn keyed_locks_allow_distinct_keys_to_run_concurrently() {
    let locks = Arc::new(IdempotencyLockTable::default());
    let _first = locks.lock("first-key").await;
    let _second = tokio::time::timeout(Duration::from_millis(100), locks.lock("second-key"))
        .await
        .unwrap();

    assert!(
        tokio::time::timeout(Duration::from_millis(50), locks.lock("first-key"))
            .await
            .is_err()
    );
}

#[test]
fn cached_replay_preserves_duplicate_response_headers() {
    let mut headers = HeaderMap::new();
    headers.append(SET_COOKIE, HeaderValue::from_static("first=1"));
    headers.append(SET_COOKIE, HeaderValue::from_static("second=2"));
    let cached = CachedHttpResponse {
        status: StatusCode::OK,
        headers,
        body: b"ok".to_vec(),
    };

    let stored = StoredIdempotencyEntry::from_cached(1, b"body".to_vec(), cached);
    let replay = CachedHttpResponse::try_from(stored).unwrap();
    let values = replay
        .headers
        .get_all(SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(values, vec!["first=1", "second=2"]);
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

#[tokio::test]
async fn oversized_idempotent_request_is_rejected_before_handler() {
    let store = test_store(Arc::new(SystemClock));
    let counter = Arc::new(AtomicUsize::new(0));
    let (addr, handle) = spawn_counted_app(store.store.clone(), counter.clone()).await;
    let body = "x".repeat(IDEMPOTENCY_MAX_REQUEST_BODY_BYTES + 1);

    let response = http_post(addr, &body, "large-body-key", None).await;

    assert_eq!(status(&response), 413);
    assert_eq!(counter.load(Ordering::SeqCst), 0);

    handle.abort();
}
