//! HTTP request admission, keyed replay, and response capture.
//! Keeps the per-key guard through handler execution and durable insertion.
//! Storage, clocks, replay vocabulary, and reclamation stay in the parent.

use super::{
    ANONYMOUS_PRINCIPAL, ApiError, Body, CachedHttpResponse, CoreAuth, EnvelopedApiError,
    HeaderMap, IDEMPOTENCY_KEY_HEADER, IDEMPOTENCY_MAX_REQUEST_BODY_BYTES,
    IDEMPOTENCY_MAX_RESPONSE_BODY_BYTES, IDEMPOTENCY_SYNC_STATE_PREFIX, IdempotencyLayerState,
    IdempotencyLookup, IntoResponse, Next, OriginalUri, Replay, Request, Response,
    SHARED_SECRET_PRINCIPAL, ServedRows, State, StatusCode, SyncServer, SyncServerConfig, caller,
    replay_admits, require_owner_auth, to_bytes,
};

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
    let body = match to_bytes(body, IDEMPOTENCY_MAX_REQUEST_BODY_BYTES).await {
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

    let request = Request::from_parts(parts, Body::from(request_body.clone()));
    let response = next.run(request).await;
    let (parts, body) = response.into_parts();
    let body = match to_bytes(body, IDEMPOTENCY_MAX_RESPONSE_BODY_BYTES).await {
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

        // The caller owns the response beside the rows it served: its
        // principal's entity, when its credential names one (KS-2B2), a
        // verified individual's on any other route (FIX 7357).
        let stamp = core_auth
            .as_ref()
            .and_then(|auth| auth.as_ref().ok())
            .map(caller::EntryStamp::core)
            .or(individual_stamp)
            .unwrap_or_default();
        if let Err(_error) = state
            .store
            .insert(&store_key, target, request_body, cached, stamp)
        {
            tracing::error!(
                reason = "idempotency_cache_write_failed",
                "failed to persist idempotency response"
            );
            return api_error_response(
                ApiError::internal_server_error("failed to persist idempotency response"),
                is_core_auth_route,
            );
        }
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
    const ROUTE_BODY_LIMIT_BYTES: usize = 2 * 1024 * 1024;
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
