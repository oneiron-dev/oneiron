use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::api::check_auth;
use crate::config::SyncServerConfig;
use crate::error::ApiError;
use crate::server::SyncServer;

pub(crate) const IDEMPOTENCY_KEY_HEADER: &str = "Idempotency-Key";
pub(crate) const IDEMPOTENCY_TTL: Duration = Duration::from_secs(86_400);

const IDEMPOTENCY_SYNC_STATE_PREFIX: &str = "http:idempotency:";
const IDEMPOTENCY_MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;
const IDEMPOTENCY_MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024;
const SHARED_SECRET_PRINCIPAL: &str = "shared-secret";
const ANONYMOUS_PRINCIPAL: &str = "anonymous";

#[derive(Clone)]
pub(crate) struct IdempotencyLayerState {
    server: Arc<SyncServer>,
    store: IdempotencyStore,
}

impl IdempotencyLayerState {
    pub(crate) fn new(server: Arc<SyncServer>) -> Self {
        Self {
            store: IdempotencyStore::new(server.vault().clone()),
            server,
        }
    }
}

#[derive(Clone)]
struct IdempotencyStore {
    vault: Arc<oneiron::Vault>,
    clock: Arc<dyn IdempotencyClock>,
    locks: Arc<IdempotencyLockTable>,
}

impl IdempotencyStore {
    fn new(vault: Arc<oneiron::Vault>) -> Self {
        Self {
            vault,
            clock: Arc::new(SystemClock),
            locks: Arc::new(IdempotencyLockTable::default()),
        }
    }

    #[cfg(test)]
    fn with_clock(vault: Arc<oneiron::Vault>, clock: Arc<dyn IdempotencyClock>) -> Self {
        Self {
            vault,
            clock,
            locks: Arc::new(IdempotencyLockTable::default()),
        }
    }

    fn now_secs(&self) -> u64 {
        self.clock.now_secs()
    }

    async fn lock_for(&self, store_key: &str) -> IdempotencyKeyGuard {
        self.locks.lock(store_key).await
    }

    fn lookup(
        &self,
        store_key: &str,
        request_body: &[u8],
    ) -> Result<IdempotencyLookup, IdempotencyStoreError> {
        let Some(raw) = self
            .vault
            .sync_state_get(store_key)
            .map_err(IdempotencyStoreError::storage)?
        else {
            return Ok(IdempotencyLookup::Miss);
        };

        let stored: StoredIdempotencyEntry =
            rmp_serde::from_slice(&raw).map_err(IdempotencyStoreError::decode)?;
        if self.now_secs().saturating_sub(stored.created_at_secs) >= IDEMPOTENCY_TTL.as_secs() {
            self.vault
                .sync_state_delete(store_key)
                .map_err(IdempotencyStoreError::storage)?;
            return Ok(IdempotencyLookup::Miss);
        }
        if stored.request_body != request_body {
            return Ok(IdempotencyLookup::Conflict);
        }

        Ok(IdempotencyLookup::Replay(stored.try_into()?))
    }

    fn insert(
        &self,
        store_key: &str,
        request_body: Vec<u8>,
        response: CachedHttpResponse,
    ) -> Result<(), IdempotencyStoreError> {
        let stored = StoredIdempotencyEntry::from_cached(self.now_secs(), request_body, response);
        let raw = rmp_serde::to_vec(&stored).map_err(IdempotencyStoreError::encode)?;
        self.vault
            .sync_state_put(store_key, &raw)
            .map_err(IdempotencyStoreError::storage)
    }
}

#[derive(Default)]
struct IdempotencyLockTable {
    slots: tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl IdempotencyLockTable {
    async fn lock(self: &Arc<Self>, store_key: &str) -> IdempotencyKeyGuard {
        let slot = {
            let mut slots = self.slots.lock().await;
            slots
                .entry(store_key.to_owned())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let guard = slot.clone().lock_owned().await;
        IdempotencyKeyGuard {
            store_key: store_key.to_owned(),
            slot,
            table: self.clone(),
            guard: Some(guard),
        }
    }
}

struct IdempotencyKeyGuard {
    store_key: String,
    slot: Arc<tokio::sync::Mutex<()>>,
    table: Arc<IdempotencyLockTable>,
    guard: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl Drop for IdempotencyKeyGuard {
    fn drop(&mut self) {
        self.guard.take();
        if Arc::strong_count(&self.slot) != 2 {
            return;
        }
        let Ok(mut slots) = self.table.slots.try_lock() else {
            return;
        };
        let Some(slot) = slots.get(&self.store_key) else {
            return;
        };
        if Arc::ptr_eq(slot, &self.slot) && Arc::strong_count(&self.slot) == 2 {
            slots.remove(&self.store_key);
        }
    }
}

enum IdempotencyLookup {
    Miss,
    Replay(CachedHttpResponse),
    Conflict,
}

#[derive(Clone)]
struct CachedHttpResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl CachedHttpResponse {
    fn into_response(self) -> Response {
        let mut response = Response::new(Body::from(self.body));
        *response.status_mut() = self.status;
        *response.headers_mut() = self.headers;
        response
    }
}

#[derive(Serialize, Deserialize)]
struct StoredIdempotencyEntry {
    created_at_secs: u64,
    request_body: Vec<u8>,
    status: u16,
    headers: Vec<(String, Vec<u8>)>,
    response_body: Vec<u8>,
}

impl StoredIdempotencyEntry {
    fn from_cached(
        created_at_secs: u64,
        request_body: Vec<u8>,
        cached: CachedHttpResponse,
    ) -> Self {
        let mut headers = Vec::with_capacity(cached.headers.len());
        for (name, value) in &cached.headers {
            headers.push((name.as_str().to_owned(), value.as_bytes().to_vec()));
        }

        Self {
            created_at_secs,
            request_body,
            status: cached.status.as_u16(),
            headers,
            response_body: cached.body,
        }
    }
}

impl TryFrom<StoredIdempotencyEntry> for CachedHttpResponse {
    type Error = IdempotencyStoreError;

    fn try_from(stored: StoredIdempotencyEntry) -> Result<Self, Self::Error> {
        let mut headers = HeaderMap::new();
        for (name, value) in stored.headers {
            let name =
                HeaderName::from_bytes(name.as_bytes()).map_err(IdempotencyStoreError::header)?;
            let value = HeaderValue::from_bytes(&value).map_err(IdempotencyStoreError::header)?;
            headers.append(name, value);
        }

        Ok(Self {
            status: StatusCode::from_u16(stored.status).map_err(IdempotencyStoreError::status)?,
            headers,
            body: stored.response_body,
        })
    }
}

trait IdempotencyClock: Send + Sync {
    fn now_secs(&self) -> u64;
}

struct SystemClock;

impl IdempotencyClock for SystemClock {
    fn now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
    }
}

#[derive(Debug)]
struct IdempotencyStoreError {
    message: String,
}

impl IdempotencyStoreError {
    fn storage(error: oneiron::Error) -> Self {
        Self {
            message: format!("idempotency store error: {error}"),
        }
    }

    fn encode(error: rmp_serde::encode::Error) -> Self {
        Self {
            message: format!("idempotency encode error: {error}"),
        }
    }

    fn decode(error: rmp_serde::decode::Error) -> Self {
        Self {
            message: format!("idempotency decode error: {error}"),
        }
    }

    fn header(error: impl fmt::Display) -> Self {
        Self {
            message: format!("idempotency cached header error: {error}"),
        }
    }

    fn status(error: impl fmt::Display) -> Self {
        Self {
            message: format!("idempotency cached status error: {error}"),
        }
    }
}

impl fmt::Display for IdempotencyStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

pub(crate) async fn idempotency_middleware(
    State(state): State<IdempotencyLayerState>,
    request: Request,
    next: Next,
) -> Response {
    let has_idempotency_header = request.headers().contains_key(IDEMPOTENCY_KEY_HEADER);
    if has_idempotency_header && check_auth(request.headers(), &state.server.config).is_err() {
        return ApiError::unauthorized().into_response();
    }

    let key = match idempotency_key(request.headers()) {
        IdempotencyKey::Present(key) => key,
        IdempotencyKey::Absent => return next.run(request).await,
        IdempotencyKey::Invalid => return invalid_key_response(),
    };

    let principal = principal_from_headers(request.headers(), &state.server.config);
    let store_key = store_key(&principal, &key);
    let (parts, body) = request.into_parts();
    let body = match to_bytes(body, IDEMPOTENCY_MAX_REQUEST_BODY_BYTES).await {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(error = %error, "failed to read idempotent request body");
            return StatusCode::PAYLOAD_TOO_LARGE.into_response();
        }
    };
    let request_body = body.to_vec();

    let _guard = state.store.lock_for(&store_key).await;
    match state.store.lookup(&store_key, &request_body) {
        Ok(IdempotencyLookup::Replay(response)) => return response.into_response(),
        Ok(IdempotencyLookup::Conflict) => return conflict_response(&key),
        Ok(IdempotencyLookup::Miss) => {}
        Err(error) => {
            tracing::error!(error = %error, "failed to read idempotency cache");
            return ApiError::internal_server_error("failed to read idempotency cache")
                .into_response();
        }
    }

    let request = Request::from_parts(parts, Body::from(request_body.clone()));
    let response = next.run(request).await;
    let (parts, body) = response.into_parts();
    let body = match to_bytes(body, IDEMPOTENCY_MAX_RESPONSE_BODY_BYTES).await {
        Ok(body) => body,
        Err(error) => {
            tracing::error!(error = %error, "failed to read idempotent response body");
            return ApiError::internal_server_error("failed to read idempotent response body")
                .into_response();
        }
    };
    let response_body = body.to_vec();
    let cached = CachedHttpResponse {
        status: parts.status,
        headers: parts.headers.clone(),
        body: response_body.clone(),
    };

    if let Err(error) = state.store.insert(&store_key, request_body, cached) {
        tracing::error!(error = %error, "failed to persist idempotency response");
        return ApiError::internal_server_error("failed to persist idempotency response")
            .into_response();
    }

    Response::from_parts(parts, Body::from(response_body))
}

enum IdempotencyKey {
    Absent,
    Present(String),
    Invalid,
}

fn idempotency_key(headers: &HeaderMap) -> IdempotencyKey {
    let Some(value) = headers.get(IDEMPOTENCY_KEY_HEADER) else {
        return IdempotencyKey::Absent;
    };
    match value.to_str() {
        Ok(value) if !value.is_empty() => IdempotencyKey::Present(value.to_owned()),
        Ok(_) | Err(_) => IdempotencyKey::Invalid,
    }
}

fn principal_from_headers(headers: &HeaderMap, config: &SyncServerConfig) -> String {
    if config.auth_secret.is_some() {
        return SHARED_SECRET_PRINCIPAL.to_owned();
    }

    headers
        .get("x-oneiron-secret")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(|value| format!("dev-secret:{value}"))
        .unwrap_or_else(|| ANONYMOUS_PRINCIPAL.to_owned())
}

fn conflict_response(key: &str) -> Response {
    ApiError::idempotency_replay_conflict(Some(key)).into_response()
}

fn invalid_key_response() -> Response {
    ApiError::invalid_header(IDEMPOTENCY_KEY_HEADER).into_response()
}

fn store_key(principal: &str, key: &str) -> String {
    format!(
        "{IDEMPOTENCY_SYNC_STATE_PREFIX}{}:{}",
        hex(principal.as_bytes()),
        hex(key.as_bytes())
    )
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
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

    async fn http_post(
        addr: SocketAddr,
        body: &str,
        key: &str,
        principal: Option<&str>,
    ) -> Vec<u8> {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let principal_header = principal
            .map(|principal| format!("x-oneiron-secret: {principal}\r\n"))
            .unwrap_or_default();
        let request = format!(
            "POST /mutate HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\nIdempotency-Key: {key}\r\n{principal_header}\r\n{body}",
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
        let vault =
            Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
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

        let first = http_post(addr, r#"{"value":1}"#, "replay-key", Some("principal-a")).await;
        let second = http_post(addr, r#"{"value":1}"#, "replay-key", Some("principal-a")).await;

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

        let first = http_post(addr, r#"{"value":1}"#, "conflict-key", Some("principal-a")).await;
        let second = http_post(addr, r#"{"value":2}"#, "conflict-key", Some("principal-a")).await;

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

    #[tokio::test]
    async fn same_key_and_body_are_isolated_by_principal() {
        let store = test_store(Arc::new(SystemClock));
        let counter = Arc::new(AtomicUsize::new(0));
        let (addr, handle) = spawn_counted_app(store.store.clone(), counter.clone()).await;

        let first = http_post(addr, r#"{"value":1}"#, "shared-key", Some("principal-a")).await;
        let second = http_post(addr, r#"{"value":1}"#, "shared-key", Some("principal-b")).await;

        assert_eq!(status(&first), 200);
        assert_eq!(status(&second), 200);
        assert_eq!(counter.load(Ordering::SeqCst), 2);
        assert_ne!(body(&first), body(&second));

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

        let response = http_post(addr, &body, "large-body-key", Some("principal-a")).await;

        assert_eq!(status(&response), 413);
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        handle.abort();
    }
}
