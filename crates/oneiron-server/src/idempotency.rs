use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::api::check_auth;
use crate::config::SyncServerConfig;
use crate::server::SyncServer;

pub(crate) const IDEMPOTENCY_KEY_HEADER: &str = "Idempotency-Key";
pub(crate) const IDEMPOTENCY_TTL: Duration = Duration::from_secs(86_400);

const IDEMPOTENCY_SYNC_STATE_PREFIX: &str = "http:idempotency:";
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
    gate: Arc<tokio::sync::Mutex<()>>,
}

impl IdempotencyStore {
    fn new(vault: Arc<oneiron::Vault>) -> Self {
        Self {
            vault,
            clock: Arc::new(SystemClock),
            gate: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    #[cfg(test)]
    fn with_clock(vault: Arc<oneiron::Vault>, clock: Arc<dyn IdempotencyClock>) -> Self {
        Self {
            vault,
            clock,
            gate: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    fn now_secs(&self) -> u64 {
        self.clock.now_secs()
    }

    async fn lock(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.gate.lock().await
    }

    fn lookup(
        &self,
        principal: &str,
        key: &str,
        request_body: &[u8],
    ) -> Result<IdempotencyLookup, IdempotencyStoreError> {
        let store_key = store_key(principal, key);
        let Some(raw) = self
            .vault
            .sync_state_get(&store_key)
            .map_err(IdempotencyStoreError::storage)?
        else {
            return Ok(IdempotencyLookup::Miss);
        };

        let stored: StoredIdempotencyEntry =
            rmp_serde::from_slice(&raw).map_err(IdempotencyStoreError::decode)?;
        if self.now_secs().saturating_sub(stored.created_at_secs) >= IDEMPOTENCY_TTL.as_secs() {
            return Ok(IdempotencyLookup::Miss);
        }
        if stored.request_body != request_body {
            return Ok(IdempotencyLookup::Conflict);
        }

        Ok(IdempotencyLookup::Replay(stored.try_into()?))
    }

    fn insert(
        &self,
        principal: &str,
        key: &str,
        request_body: Vec<u8>,
        response: CachedHttpResponse,
    ) -> Result<(), IdempotencyStoreError> {
        let stored = StoredIdempotencyEntry::from_cached(self.now_secs(), request_body, response);
        let raw = rmp_serde::to_vec(&stored).map_err(IdempotencyStoreError::encode)?;
        self.vault
            .sync_state_put(&store_key(principal, key), &raw)
            .map_err(IdempotencyStoreError::storage)
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
            headers.insert(name, value);
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

#[derive(Serialize)]
struct StructuredError {
    error_code: &'static str,
    human_message: &'static str,
    recovery_suggestion: &'static str,
}

pub(crate) async fn idempotency_middleware(
    State(state): State<IdempotencyLayerState>,
    request: Request,
    next: Next,
) -> Response {
    let key = match idempotency_key(request.headers()) {
        IdempotencyKey::Present(key) => key,
        IdempotencyKey::Absent => return next.run(request).await,
        IdempotencyKey::Invalid => return invalid_key_response(),
    };

    if let Err(status) = check_auth(request.headers(), &state.server.config) {
        return status.into_response();
    }

    let principal = principal_from_headers(request.headers(), &state.server.config);
    let (parts, body) = request.into_parts();
    let body = match to_bytes(body, usize::MAX).await {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(error = %error, "failed to read idempotent request body");
            return StatusCode::PAYLOAD_TOO_LARGE.into_response();
        }
    };
    let request_body = body.to_vec();

    let _guard = state.store.lock().await;
    match state.store.lookup(&principal, &key, &request_body) {
        Ok(IdempotencyLookup::Replay(response)) => return response.into_response(),
        Ok(IdempotencyLookup::Conflict) => return conflict_response(),
        Ok(IdempotencyLookup::Miss) => {}
        Err(error) => {
            tracing::error!(error = %error, "failed to read idempotency cache");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    let request = Request::from_parts(parts, Body::from(request_body.clone()));
    let response = next.run(request).await;
    let (parts, body) = response.into_parts();
    let body = match to_bytes(body, usize::MAX).await {
        Ok(body) => body,
        Err(error) => {
            tracing::error!(error = %error, "failed to read idempotent response body");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let response_body = body.to_vec();
    let cached = CachedHttpResponse {
        status: parts.status,
        headers: parts.headers.clone(),
        body: response_body.clone(),
    };

    if let Err(error) = state.store.insert(&principal, &key, request_body, cached) {
        tracing::error!(error = %error, "failed to persist idempotency response");
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

fn conflict_response() -> Response {
    json_error(
        StatusCode::CONFLICT,
        "idempotency_key_conflict",
        "This Idempotency-Key was already used with a different request body.",
        "Retry with the original request body, or send a new Idempotency-Key for a new mutation.",
    )
}

fn invalid_key_response() -> Response {
    json_error(
        StatusCode::BAD_REQUEST,
        "invalid_idempotency_key",
        "Idempotency-Key must be a non-empty visible header value.",
        "Send a non-empty Idempotency-Key header, or omit it for a non-idempotent request.",
    )
}

fn json_error(
    status: StatusCode,
    error_code: &'static str,
    human_message: &'static str,
    recovery_suggestion: &'static str,
) -> Response {
    let body = serde_json::to_vec(&StructuredError {
        error_code,
        human_message,
        recovery_suggestion,
    })
    .unwrap_or_else(|_| b"{}".to_vec());
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
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
    use axum::middleware;
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::config::SyncServerConfig;

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
        let server = Arc::new(
            SyncServer::new(
                store.vault.clone(),
                SyncServerConfig {
                    allow_unauthenticated: true,
                    ..Default::default()
                },
            )
            .unwrap(),
        );
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
        stream.read_to_end(&mut response).await.unwrap();
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
        let body = std::str::from_utf8(body(&second)).unwrap();
        assert!(body.contains(r#""error_code":"idempotency_key_conflict""#));
        assert!(body.contains(r#""human_message":"#));
        assert!(body.contains(r#""recovery_suggestion":"#));

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
        let response = CachedHttpResponse {
            status: StatusCode::CREATED,
            headers: HeaderMap::new(),
            body: b"created".to_vec(),
        };
        store
            .store
            .insert("principal", "ttl-key", b"body".to_vec(), response)
            .unwrap();

        clock.advance(IDEMPOTENCY_TTL - Duration::from_secs(1));
        assert!(matches!(
            store.store.lookup("principal", "ttl-key", b"body").unwrap(),
            IdempotencyLookup::Replay(_)
        ));

        clock.advance(Duration::from_secs(2));
        assert!(matches!(
            store.store.lookup("principal", "ttl-key", b"body").unwrap(),
            IdempotencyLookup::Miss
        ));
    }
}
