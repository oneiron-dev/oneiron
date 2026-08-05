use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{Body, to_bytes};
use axum::extract::{OriginalUri, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::auth::{CoreAuth, require_owner_auth};
use crate::config::SyncServerConfig;
use crate::error::{ApiError, EnvelopedApiError};
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
    let is_core_auth_route = is_core_auth_route(request_path(&request));
    let revoked = state.server.vault().as_ref();
    let core_auth = is_core_auth_route
        .then(|| CoreAuth::from_headers(request.headers(), &state.server.config, revoked));
    let auth_ok = match &core_auth {
        Some(Ok(auth)) => !auth.principal().is_empty(),
        Some(Err(_)) => false,
        None => require_owner_auth(request.headers(), &state.server.config, revoked).is_ok(),
    };
    if has_idempotency_header && !auth_ok {
        return api_error_response(ApiError::unauthorized(), is_core_auth_route);
    }

    let key = match idempotency_key(request.headers()) {
        IdempotencyKey::Present(key) => key,
        IdempotencyKey::Absent => return next.run(request).await,
        IdempotencyKey::Invalid => return invalid_key_response(is_core_auth_route),
    };

    let principal = match &core_auth {
        Some(Ok(auth)) => auth.idempotency_principal(),
        Some(Err(_)) => {
            return api_error_response(ApiError::unauthorized(), is_core_auth_route);
        }
        None => principal_for_non_core_route(&state.server.config),
    };
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
        Ok(IdempotencyLookup::Conflict) => return conflict_response(&key, is_core_auth_route),
        Ok(IdempotencyLookup::Miss) => {}
        Err(error) => {
            tracing::error!(error = %error, "failed to read idempotency cache");
            return api_error_response(
                ApiError::internal_server_error("failed to read idempotency cache"),
                is_core_auth_route,
            );
        }
    }

    let request = Request::from_parts(parts, Body::from(request_body.clone()));
    let response = next.run(request).await;
    let (parts, body) = response.into_parts();
    let body = match to_bytes(body, IDEMPOTENCY_MAX_RESPONSE_BODY_BYTES).await {
        Ok(body) => body,
        Err(error) => {
            tracing::error!(error = %error, "failed to read idempotent response body");
            return api_error_response(
                ApiError::internal_server_error("failed to read idempotent response body"),
                is_core_auth_route,
            );
        }
    };
    let response_body = body.to_vec();

    // Only a successful outcome is durable enough to replay for the TTL. A
    // failure is a verdict about state the caller can fix — a route rejection
    // on an identity that is still provisioning, a downstream that was briefly
    // unavailable — and caching it pins that verdict for a day: the retry that
    // would now succeed replays the stale error instead, and the caller's only
    // escape is inventing a new key, which defeats the header. Replaying is a
    // promise not to run the effect twice, not a promise to freeze a refusal.
    if parts.status < StatusCode::BAD_REQUEST {
        let cached = CachedHttpResponse {
            status: parts.status,
            headers: parts.headers.clone(),
            body: response_body.clone(),
        };

        if let Err(error) = state.store.insert(&store_key, request_body, cached) {
            tracing::error!(error = %error, "failed to persist idempotency response");
            return api_error_response(
                ApiError::internal_server_error("failed to persist idempotency response"),
                is_core_auth_route,
            );
        }
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

fn request_path(request: &Request) -> &str {
    request
        .extensions()
        .get::<OriginalUri>()
        .map_or_else(|| request.uri().path(), |uri| uri.0.path())
}

fn is_core_auth_route(path: &str) -> bool {
    path.starts_with("/v1/core/") || path.starts_with("/v1/companion/")
}

/// Idempotency principal for non-core routes.
///
/// A configured secret means every caller here is the same owner-grade
/// principal; without one the server is in unauthenticated dev mode and all
/// callers share the anonymous principal. There is no per-caller partition to
/// derive, and the previous header-derived one was never a boundary — any
/// client could pick its own.
fn principal_for_non_core_route(config: &SyncServerConfig) -> String {
    if config.auth_secret.is_some() {
        SHARED_SECRET_PRINCIPAL.to_owned()
    } else {
        ANONYMOUS_PRINCIPAL.to_owned()
    }
}

fn conflict_response(key: &str, is_core_route: bool) -> Response {
    api_error_response(
        ApiError::idempotency_replay_conflict(Some(key)),
        is_core_route,
    )
}

fn invalid_key_response(is_core_route: bool) -> Response {
    api_error_response(
        ApiError::invalid_header(IDEMPOTENCY_KEY_HEADER),
        is_core_route,
    )
}

fn api_error_response(error: ApiError, is_core_route: bool) -> Response {
    if is_core_route {
        EnvelopedApiError::from(error).into_response()
    } else {
        error.into_response()
    }
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
mod tests;
