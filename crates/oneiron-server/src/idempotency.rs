use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{Body, to_bytes};
use axum::extract::{OriginalUri, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use oneiron::store::IdempotencyEntry as StoredIdempotencyEntry;

use crate::auth::{CoreAuth, require_owner_auth};
use crate::config::SyncServerConfig;
use crate::error::{ApiError, EnvelopedApiError};
use crate::server::SyncServer;

pub(crate) const IDEMPOTENCY_KEY_HEADER: &str = "Idempotency-Key";
pub(crate) const IDEMPOTENCY_TTL: Duration = Duration::from_secs(86_400);

const IDEMPOTENCY_SYNC_STATE_PREFIX: &str = "http:idempotency:";
/// A keyed request's body is read up to axum's default extractor limit, the
/// keyed routes' own, so the layer cuts short no body its route would accept
/// (FIX 6056, rule 5). A keyed outcome is kept whole, whatever its size.
const ROUTE_BODY_LIMIT_BYTES: usize = 2 * 1024 * 1024;
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

    /// The server a route's own keyed layer admits its caller against.
    pub(crate) fn server(&self) -> &SyncServer {
        &self.server
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
        request_target: &str,
        request_body: &[u8],
    ) -> Result<IdempotencyLookup, IdempotencyStoreError> {
        let Some(raw) = self
            .vault
            .sync_state_get(store_key)
            .map_err(IdempotencyStoreError::storage)?
        else {
            return Ok(IdempotencyLookup::Miss);
        };

        let stored = StoredIdempotencyEntry::decode(&raw).map_err(IdempotencyStoreError::decode)?;
        // Expiry is a delete, never an erase: the entry's instance keeps its
        // key, and the binding goes at the next checkpoint (KS-2B2).
        if self.now_secs().saturating_sub(stored.created_at_secs) >= IDEMPOTENCY_TTL.as_secs() {
            self.vault
                .sync_state_delete(store_key)
                .map_err(IdempotencyStoreError::storage)?;
            return Ok(IdempotencyLookup::Miss);
        }
        // An erase of an owner took the request and the response: the entry
        // answers that, never a miss, until it expires (KS-2B2).
        if stored.erased {
            return Ok(IdempotencyLookup::Erased);
        }
        if stored.request_body != request_body
            || stored
                .request_target
                .as_deref()
                .is_some_and(|target| target != request_target)
        {
            return Ok(IdempotencyLookup::Conflict);
        }

        // An intent no outcome settled: the first run never finished (FIX
        // 9527).
        if stored.status == intent::INTENT_STATUS {
            return Ok(IdempotencyLookup::Interrupted);
        }
        let response = CachedHttpResponse::of_stored(stored)?;
        Ok(IdempotencyLookup::Replay(response))
    }
}

#[derive(Default)]
struct IdempotencyLockTable {
    slots: tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Where the expiry reclaim's next page starts (FIX 5951).
    sweep: reclaim::SweepCursor,
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
    /// An erase of an owner took the cached response (KS-2B2).
    Erased,
    /// The first request's intent stands with no outcome (FIX 9527).
    Interrupted,
}

#[derive(Clone)]
struct CachedHttpResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
    /// The rows the handler derived `body` from ([`ServedRows`]).
    rows: Vec<oneiron::EntityId>,
    /// The rows a replay re-admits ([`ServedRows::admit`]).
    admit: Option<Vec<oneiron::EntityId>>,
    /// [`ServedRows::sources`], kept as the entry's source stamps.
    sources: Vec<oneiron::EntityId>,
}

/// The rows a response was derived from, as its handler listed them while it
/// derived the response. A keyed response keeps them beside its cached
/// bytes, and a replay's release judges them (DEC-0005).
#[derive(Clone, Debug, Default)]
pub(crate) struct ServedRows {
    pub(crate) rows: Vec<oneiron::EntityId>,
    /// The rows the response named beyond its documents: an identity it
    /// addressed, a notification it delivered, a rider outcome or a pack
    /// source. A replay goes out only while the caller's read, as it stands
    /// then, still reads each of them. `None` when the handler could not list
    /// them all: a route that keeps them never replays such a response.
    pub(crate) admit: Option<Vec<oneiron::EntityId>>,
    /// The rows whose words the response carries without naming them, such
    /// as the CLAIMs a board's standing block was compiled from (FIX 8148).
    /// They are kept as the entry's source stamps, so an erase of one retires
    /// the response, and the route's release admits each again.
    pub(crate) sources: Vec<oneiron::EntityId>,
}

/// A cached success as its release judges it.
pub(crate) struct Replay<'a> {
    pub(crate) body: &'a [u8],
    pub(crate) rows: &'a [oneiron::EntityId],
    /// [`ServedRows::admit`]; `None` as well for an entry written before it
    /// was kept.
    pub(crate) admit: Option<&'a [oneiron::EntityId]>,
    /// [`ServedRows::sources`]; empty for an entry that kept none.
    pub(crate) sources: &'a [oneiron::EntityId],
}

/// Whether the caller's read, as it stands now, still reads every row a
/// replay re-admits: one snapshot, every claim status, so a settled outcome
/// the caller was shown still counts. Denied and missing rows alike refuse.
pub(crate) fn replay_admits(
    server: &SyncServer,
    auth: Option<&CoreAuth>,
    admit: &[oneiron::EntityId],
) -> Result<bool, ApiError> {
    if admit.is_empty() {
        return Ok(true);
    }
    let Some(auth) = auth else {
        return Ok(false);
    };
    let read = crate::api::scoped_read_for_core_auth(&server.vault, auth)?;
    read.recorded_lane()
        .and_then(|read| read.all_refs_readable(admit))
        .map_err(|error| {
            tracing::error!(kind = ?error.kind(), "idempotent replay admission failed");
            ApiError::internal_server_error("idempotent replay admission failed")
        })
}

impl CachedHttpResponse {
    fn replay(&self) -> Replay<'_> {
        Replay {
            body: &self.body,
            rows: &self.rows,
            admit: self.admit.as_deref(),
            sources: &self.sources,
        }
    }

    fn into_response(self) -> Response {
        let mut response = Response::new(Body::from(self.body));
        *response.status_mut() = self.status;
        *response.headers_mut() = self.headers;
        response
    }
}

impl CachedHttpResponse {
    /// The entry this response is kept as: its time, the request it
    /// answers, and its owners' stamps, the caller's among them.
    fn into_stored(
        self,
        created_at_secs: u64,
        request_target: String,
        request_body: Vec<u8>,
        stamp: caller::EntryStamp,
    ) -> StoredIdempotencyEntry {
        let mut headers = Vec::with_capacity(self.headers.len());
        for (name, value) in &self.headers {
            headers.push((name.as_str().to_owned(), value.as_bytes().to_vec()));
        }
        StoredIdempotencyEntry {
            created_at_secs,
            request_body,
            status: self.status.as_u16(),
            headers,
            response_body: self.body,
            request_target: Some(request_target),
            served_rows: self.rows.iter().map(oneiron::EntityId::to_hex).collect(),
            replay_admits: self
                .admit
                .map(|admit| admit.iter().map(oneiron::EntityId::to_hex).collect()),
            stamps: oneiron::store::ResponseStamps {
                actor: stamp.caller,
                sources: self.sources,
                ..Default::default()
            },
            erased: false,
            erase_drops: stamp.erase_drops,
        }
    }

    /// The response a kept entry replays.
    fn of_stored(stored: StoredIdempotencyEntry) -> Result<Self, IdempotencyStoreError> {
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
            rows: stored
                .served_rows
                .iter()
                .map(|id| oneiron::EntityId::from_hex(id))
                .collect::<Result<_, _>>()
                .map_err(IdempotencyStoreError::rows)?,
            admit: stored
                .replay_admits
                .map(|admit| {
                    admit
                        .iter()
                        .map(|id| oneiron::EntityId::from_hex(id))
                        .collect::<Result<_, _>>()
                })
                .transpose()
                .map_err(IdempotencyStoreError::rows)?,
            sources: stored.stamps.sources,
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

    fn decode(error: oneiron::Error) -> Self {
        Self {
            message: format!("idempotency decode error: {error}"),
        }
    }

    fn header(error: impl fmt::Display) -> Self {
        Self {
            message: format!("idempotency cached header error: {error}"),
        }
    }

    fn rows(error: impl fmt::Display) -> Self {
        Self {
            message: format!("idempotency cached rows error: {error}"),
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
    idempotent(state, request, next, |server, auth, replay| {
        let admitted = replay_admits(server, auth, replay.admit.unwrap_or_default());
        match admitted {
            Ok(true) => None,
            Ok(false) => Some(api_error_response(
                ApiError::invalid_state(Some("idempotent_replay_unreadable")),
                true,
            )),
            Err(error) => Some(api_error_response(error, true)),
        }
    })
    .await
}

/// The idempotency layer. `release` sees a cached success before it is
/// replayed, with the caller's authority as it stands now: a response it
/// returns is sent in the cached one's place, and the cached entry stays.
async fn idempotent(
    state: IdempotencyLayerState,
    mut request: Request,
    next: Next,
    release: impl FnOnce(&SyncServer, Option<&CoreAuth>, &Replay<'_>) -> Option<Response>,
) -> Response {
    let has_idempotency_header = request.headers().contains_key(IDEMPOTENCY_KEY_HEADER);
    let is_core_auth_route = is_core_auth_route(request_path(&request));
    let locality = crate::auth::caller_locality(request.headers(), request.extensions());
    // A replay goes to the machine the request's connection proved (mesh PR2b).
    let peer = crate::auth::proved_peer(request.headers(), request.extensions());
    let revoked = state.server.vault().as_ref();
    // A managed vault's legacy keyed route keys on its own caller too (FIX
    // 5123), the one its handler's owner-grade gate takes, never a principal
    // every caller shares.
    let legacy_caller = !is_core_auth_route && state.server.managed_issuer.is_some();
    let core_auth = if is_core_auth_route || legacy_caller {
        // The route's own caller (FIX 5201): on a managed vault, the owner
        // its supervisor attested reads and replays under his own partition.
        let (parts, body) = request.into_parts();
        let auth = CoreAuth::for_request(&parts, &state.server).await;
        request = Request::from_parts(parts, body);
        Some(auth.map(|auth| auth.at(locality)))
    } else {
        None
    };
    // Any other route's own owner gate, whose verdict also names the
    // partition of a verified individual caller (FIX 5404).
    let owner_auth = core_auth
        .is_none()
        .then(|| require_owner_auth(request.headers(), &state.server.config, revoked));
    let auth_ok = match &core_auth {
        Some(Ok(auth)) if legacy_caller => auth.is_owner_grade(),
        Some(Ok(auth)) => !auth.principal().is_empty(),
        Some(Err(_)) => false,
        None => owner_auth.as_ref().is_some_and(Result::is_ok),
    };
    if has_idempotency_header && !auth_ok {
        return api_error_response(ApiError::unauthorized(), is_core_auth_route);
    }

    let key = match idempotency_key(request.headers()) {
        IdempotencyKey::Present(key) => key,
        IdempotencyKey::Absent => return next.run(request).await,
        IdempotencyKey::Invalid => return invalid_key_response(is_core_auth_route),
    };

    // A verified individual on any other route keys its entries under its
    // own partition (FIX 5404) and stamps them as its own (FIX 7357).
    let (individual, individual_stamp) = owner_auth
        .as_ref()
        .and_then(|auth| auth.as_ref().ok())
        .and_then(|auth| caller::individual_partition(auth, request.headers()))
        .unzip();
    let principal = match &core_auth {
        Some(Ok(auth)) => auth.idempotency_principal(),
        Some(Err(_)) => {
            return api_error_response(ApiError::unauthorized(), is_core_auth_route);
        }
        None => individual.unwrap_or_else(|| principal_for_non_core_route(&state.server.config)),
    };
    let store_key = store_key(&principal, &key);
    let target = request_target(&request);
    let (parts, body) = request.into_parts();
    let body = match to_bytes(body, ROUTE_BODY_LIMIT_BYTES).await {
        Ok(body) => body,
        Err(_) => {
            tracing::warn!(
                reason = "body_read_failed",
                "failed to read idempotent request body"
            );
            return StatusCode::PAYLOAD_TOO_LARGE.into_response();
        }
    };
    let request_body = body.to_vec();

    // Each keyed admission reclaims one page of expired entries (FIX 5951).
    state.store.reclaim_expired_page().await;
    let _guard = state.store.lock_for(&store_key).await;
    match state.store.lookup(&store_key, &target, &request_body) {
        Ok(IdempotencyLookup::Replay(response)) => {
            // A legacy route's caller keys its partition alone; its replay
            // stays the legacy one.
            let auth = core_auth
                .as_ref()
                .filter(|_| is_core_auth_route)
                .and_then(|auth| auth.as_ref().ok());
            // Every keyed core route is an owner act: a cached one replays
            // only to a caller that may act now, so a hosted operator's root
            // is refused before any cached success (FIX 2222).
            if let Some(auth) = auth
                && let Err(error) =
                    crate::api::host_action::require_host_owner_act(&state.server, auth)
            {
                return api_error_response(error, is_core_auth_route);
            }
            if let Some(refused) = release(&state.server, auth, &response.replay()) {
                return refused;
            }
            // Whatever the route, a replay off this device names no row a
            // device-local world keeps now (DEC-0005). Its write is not
            // repeated.
            if crate::device_local::replay_withheld(
                state.server.vault(),
                oneiron::settings::ReadDestination::at(locality, peer),
                &response.body,
                &response.rows,
            ) {
                return api_error_response(
                    ApiError::invalid_state(Some("idempotent_replay_unreadable")),
                    is_core_auth_route,
                );
            }
            return response.into_response();
        }
        Ok(IdempotencyLookup::Conflict) => return conflict_response(&key, is_core_auth_route),
        // Never a miss and never a second run: the request's effect stands,
        // and the response it had is gone (KS-2B2).
        Ok(IdempotencyLookup::Erased) => {
            return api_error_response(
                ApiError::invalid_state(Some("idempotent_response_erased")),
                is_core_auth_route,
            );
        }
        Ok(IdempotencyLookup::Interrupted) => {
            return api_error_response(intent::outcome_unknown(), is_core_auth_route);
        }
        Ok(IdempotencyLookup::Miss) => {}
        Err(_) => {
            tracing::error!(
                reason = "idempotency_cache_read_failed",
                "failed to read idempotency cache"
            );
            return api_error_response(
                ApiError::internal_server_error("failed to read idempotency cache"),
                is_core_auth_route,
            );
        }
    }

    // The caller owns the response beside the rows it served: its
    // principal's entity, when its credential names one (KS-2B2), a verified
    // individual's on any other route (FIX 7357). Its intent is stamped so.
    let stamp = core_auth
        .as_ref()
        .and_then(|auth| auth.as_ref().ok())
        .map(caller::EntryStamp::core)
        .or(individual_stamp)
        .unwrap_or_default();
    // FIX 9527: the intent is kept before the route runs, so a run that never
    // finishes leaves a row a retry finds, never a miss that acts again. No
    // effect has run when it cannot be kept.
    if state
        .store
        .insert_intent(&store_key, target.clone(), request_body.clone(), stamp)
        .is_err()
    {
        tracing::error!(
            reason = "idempotency_intent_write_failed",
            "failed to persist idempotency intent"
        );
        return api_error_response(
            ApiError::internal_server_error("failed to persist idempotency intent"),
            is_core_auth_route,
        );
    }

    let request = Request::from_parts(parts, Body::from(request_body.clone()));
    let response = next.run(request).await;
    let (parts, body) = response.into_parts();
    // The outcome is read whole: a large success is kept and answered, never
    // turned into a failure after its effect landed (FIX 6056). A body that
    // does not read leaves the intent, so a retry is not run again.
    let body = match to_bytes(body, usize::MAX).await {
        Ok(body) => body,
        Err(_) => {
            tracing::error!(
                reason = "body_read_failed",
                "failed to read idempotent response body"
            );
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
        let served = parts
            .extensions
            .get::<ServedRows>()
            .cloned()
            .unwrap_or_default();
        let cached = CachedHttpResponse {
            status: parts.status,
            headers: parts.headers.clone(),
            body: response_body.clone(),
            rows: served.rows,
            admit: served.admit,
            sources: served.sources,
        };
        // The effect landed: its success is answered even when its outcome
        // is not kept. The intent then stays, so a retry learns the outcome
        // is unknown rather than acting again (FIX 6056, 9527).
        if state
            .store
            .settle(&store_key, target, request_body, cached, stamp)
            .is_err()
        {
            tracing::error!(
                reason = "idempotency_cache_write_failed",
                "failed to persist idempotency response; its intent stands"
            );
        }
    } else if state.store.release_intent(&store_key).is_err() {
        tracing::error!(
            reason = "idempotency_intent_release_failed",
            "failed to release an idempotency intent after a failure"
        );
    }

    Response::from_parts(parts, Body::from(response_body))
}

/// The idempotency layer for a route that mutates in one request form only.
/// A keyed request's body tells the form: the mutating form takes the layer,
/// with `release` judging each replay; any other form runs as if the layer
/// were absent, never cached and never replayed. The body is read up to
/// axum's default extractor limit, so no body the route would accept is cut
/// short.
pub(crate) async fn idempotency_for_mutating_form(
    state: IdempotencyLayerState,
    request: Request,
    next: Next,
    mutates: impl FnOnce(&[u8]) -> bool,
    release: impl FnOnce(&SyncServer, Option<&CoreAuth>, &Replay<'_>) -> Option<Response>,
) -> Response {
    if !request.headers().contains_key(IDEMPOTENCY_KEY_HEADER) {
        return next.run(request).await;
    }
    let (parts, body) = request.into_parts();
    let body = match to_bytes(body, ROUTE_BODY_LIMIT_BYTES).await {
        Ok(body) => body,
        Err(_) => {
            tracing::warn!(
                reason = "body_read_failed",
                "failed to read keyed request body"
            );
            return StatusCode::PAYLOAD_TOO_LARGE.into_response();
        }
    };
    let mutating = mutates(&body);
    let request = Request::from_parts(parts, Body::from(body));
    if mutating {
        idempotent(state, request, next, release).await
    } else {
        next.run(request).await
    }
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

/// The method and target (path and query) a request names, as routed.
fn request_target(request: &Request) -> String {
    let uri = request
        .extensions()
        .get::<OriginalUri>()
        .map_or_else(|| request.uri(), |uri| &uri.0);
    let target = uri
        .path_and_query()
        .map_or_else(|| uri.path(), axum::http::uri::PathAndQuery::as_str);
    format!("{} {target}", request.method())
}

fn is_core_auth_route(path: &str) -> bool {
    path.starts_with("/v1/core/") || path.starts_with("/v1/companion/")
}

/// Idempotency principal for non-core routes whose caller presents no
/// verified individual credential ([`caller::individual_principal`] keys one
/// that does under its own, FIX 5404).
///
/// A configured secret means every such caller here is the same owner-grade
/// principal; without one the server is in unauthenticated dev mode and all
/// such callers share the anonymous principal. Nothing in their requests
/// names a caller to partition by, and the previous header-derived one was
/// never a boundary — any client could pick its own.
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

mod caller;
mod intent;
mod reclaim;

#[cfg(test)]
mod tests;
