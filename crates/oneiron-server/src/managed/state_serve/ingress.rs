//! Managed HTTP ingress and the reap freeze gate.
//! Builds managed routers and holds request admission through completion.
//! Managed state and shutdown definitions remain in the parent module.

use super::{
    Arc, Body, CarriedConnection, CarrierPaused, IntoResponse, Json, ManagedCarrierContext,
    ManagedError, ManagedIngress, ManagedState, ManagedWidenAction, ManagedWidenHolder, Method,
    Next, Request, Response, Router, State, StatusCode, Surface, SyncServer, UPGRADE, WriteKind,
    build_app, is_read_only, middleware, owner_attestable, to_bytes, writes_frozen_body,
};

impl ManagedCarrierContext {
    /// `routes` behind managed ingress and the reap freeze, as the served
    /// app is ([`with_managed_requests`]): each request through them is
    /// admitted on its own, and its handler finishes in a task that owns
    /// that admission.
    pub(crate) fn admit_requests(&self, routes: Router) -> Router {
        with_managed_requests(routes, Arc::clone(&self.0))
    }

    /// Runs `action`, one write the socket makes outside any request (a
    /// receipt), under a served write's admission, released as it returns;
    /// `action` does not await. While the vault is frozen for reap nothing
    /// runs, and the pause a served write gets is returned instead.
    pub(crate) fn admit_receipt<T>(&self, action: impl FnOnce() -> T) -> Result<T, CarrierPaused> {
        let _admission = self.0.admit(WriteKind::OwnerWrite).map_err(CarrierPaused)?;
        Ok(action())
    }

    /// Marks `request` as a call the socket carries, so the task its
    /// admission finishes in runs as the socket's connection (FIX 811),
    /// not as a fresh one.
    pub(crate) fn carry<B>(&self, request: &mut axum::http::Request<B>) {
        request
            .extensions_mut()
            .insert(CarriedConnection(crate::api::call_receipt::connection_id()));
    }
}

/// Builds the surface managed mode serves: the ordinary app, behind the reap
/// freeze.
///
/// The gate is a layer over the whole router rather than a call inside each
/// write handler, and that placement is the fail-closed half of it. It sits
/// ahead of routing, so a write route added next year, a method this build does
/// not recognise, and a request that matches no route at all are all refused
/// while frozen without anyone having to remember this module exists. Nothing
/// can be let through by forgetting to call [`ManagedState::guard_write`],
/// because no handler is where the calling happens.
///
/// Only managed mode builds this. [`crate::build_app`] is untouched, so an
/// unmanaged serve carries no extra layer and behaves exactly as it did.
pub fn build_managed_app(server: Arc<SyncServer>, state: Arc<ManagedState>) -> Router {
    with_managed_requests(build_app(server), state)
}

/// `router` behind managed ingress and the reap freeze: the served app
/// ([`build_managed_app`]), and the routes a held MCP socket runs each of
/// its calls through (FIX 5128).
fn with_managed_requests(router: Router, state: Arc<ManagedState>) -> Router {
    let freeze = middleware::from_fn_with_state(state, refuse_frozen_writes);
    router.layer(freeze)
}

/// The managed artifact origin: this vault's `/a/`, and its names on its
/// internal authority, `<vault_id>.artifact.invalid` (FIX 6716,
/// `oneiron_vault_contract::artifact_origin`), behind the API's freeze gate.
pub(in crate::managed) fn build_managed_artifact_app(
    server: Arc<SyncServer>,
    state: Arc<ManagedState>,
) -> Router {
    let freeze = middleware::from_fn_with_state(state, refuse_frozen_artifact_writes);
    crate::build_artifact_app(server).layer(freeze)
}

/// The freeze gate on the served path.
///
/// Consulted per request, before the handler runs: once `prepare_reap` has
/// flipped the flag, anything that could mutate the vault is answered with the
/// typed refusal instead of reaching storage. That is what turns
/// `quiescent: true` from an advisory into something a supervisor can reap
/// against — without it the engine keeps committing durable writes after
/// reporting that it stopped.
///
/// Admitted mutations keep a guard through extraction and handler completion.
/// Upgrades also leave a sync-session stamp: their subsequent frames do not
/// pass through HTTP middleware.
async fn refuse_frozen_writes(
    State(state): State<Arc<ManagedState>>,
    request: Request,
    next: Next,
) -> Response {
    freeze_gate(state, Surface::Api, request, next).await
}

/// [`refuse_frozen_writes`] on the artifact listener.
async fn refuse_frozen_artifact_writes(
    State(state): State<Arc<ManagedState>>,
    request: Request,
    next: Next,
) -> Response {
    freeze_gate(state, Surface::Artifact, request, next).await
}

/// The freeze gate, and managed ingress before it, for a request that reached
/// `surface`.
async fn freeze_gate(
    state: Arc<ManagedState>,
    surface: Surface,
    mut request: Request,
    next: Next,
) -> Response {
    if state.server.managed_issuer.is_some() {
        request.extensions_mut().insert(ManagedIngress);
        // The widen answer routes need the SUPERVISOR'S holder action, not
        // the host root. Verify the account-authenticated assertion against
        // the per-spawn secret and the exact request body before removing
        // it. Unverified headers never become extensions.
        if request.method() == Method::POST
            && matches!(
                request.uri().path(),
                "/v1/core/consent/widen/accept" | "/v1/core/consent/widen/reject"
            )
        {
            let assertion = request
                .headers()
                .get("x-oneiron-managed-widen-action")
                .and_then(|value| value.to_str().ok())
                .and_then(|text| serde_json::from_str::<ManagedWidenAction>(text).ok());
            if let Some(assertion) = assertion {
                let (parts, body) = request.into_parts();
                let Ok(bytes) = to_bytes(body, 2 * 1024 * 1024).await else {
                    return StatusCode::PAYLOAD_TOO_LARGE.into_response();
                };
                request = Request::from_parts(parts, Body::from(bytes.clone()));
                if state.ledger.verify_widen_action(&assertion, &bytes)
                    && let Ok(holder) = oneiron::EntityId::from_hex(&assertion.holder_ref)
                {
                    request.extensions_mut().insert(ManagedWidenHolder(holder));
                }
            }
        }
        // A request the supervisor attests is the vault owner's own
        // (`ManagedOwnerAction`), on every route whose body the buffer holds
        // (staged on the vault's disk past it, FIX 5619), and on every route
        // whose body streams once that body is staged there (`owner_stage`):
        // verified the same way, over the method, path, raw query, placing
        // headers and exact body, before any handler runs. A verified one
        // names the owner, as a request extension the credential reads; one
        // that does not verify is refused, never served as the host's root.
        let staged = match surface {
            Surface::Api => {
                super::attested_routes::staged_route(request.method(), request.uri().path())
            }
            Surface::Artifact => None,
        };
        if staged.is_some() || owner_attestable(surface, request.method(), request.uri().path()) {
            let assertion = request
                .headers()
                .get(oneiron_vault_contract::MANAGED_OWNER_ACTION_HEADER)
                .and_then(|value| value.to_str().ok())
                .and_then(|text| {
                    serde_json::from_str::<oneiron_vault_contract::ManagedOwnerAction>(text).ok()
                });
            if let Some(assertion) = &assertion
                && let Some(staged) = staged
            {
                let ceiling = staged.ceiling();
                request = match super::owner_stage::verify_staged(
                    &state.server,
                    &state.ledger,
                    assertion,
                    request,
                    ceiling,
                )
                .await
                {
                    Ok(request) => request,
                    Err(refusal) => return refusal,
                };
            } else if let Some(assertion) = assertion {
                request = match super::owner_stage::verify_held(
                    &state.server,
                    &state.ledger,
                    &assertion,
                    request,
                )
                .await
                {
                    Ok(request) => request,
                    Err(refusal) => return refusal,
                };
            } else if request
                .headers()
                .contains_key(oneiron_vault_contract::MANAGED_OWNER_ACTION_HEADER)
            {
                return owner_attestation_refused(request.uri().path());
            }
        }
        request
            .headers_mut()
            .remove("x-oneiron-managed-widen-action");
        request
            .headers_mut()
            .remove(oneiron_vault_contract::MANAGED_OWNER_ACTION_HEADER);
        // A caller's own slip, its holder proof and its machine claim go on
        // unchanged: the child verifies them, spends the proof once, and the
        // caller stays itself (WILL-PLAN L14 row 01). Any other bearer
        // terminated at the supervisor; a legacy or dev claim never selects a
        // principal, so a request with neither a slip nor an attestation is
        // anonymous: only the public doors serve it, never as the host's root
        // (FIX 2222).
        crate::auth::forward_caller_credentials(request.headers_mut());
    }
    if is_read_only(&request) {
        return run_admitted_request(state, request, next).await;
    }
    let admission = match state.admit(WriteKind::OwnerWrite) {
        Ok(admission) => admission,
        Err(error) => return writes_frozen_response(&error),
    };
    // A dropped response waiter must not release admission while a handler's
    // spawn_blocking write is still running. The owned task finishes the handler.
    // A call a held socket carries finishes there as that socket's connection.
    let carried = request
        .extensions()
        .get::<CarriedConnection>()
        .map(|carried| carried.0);
    tokio::spawn(async move {
        let _admission = admission;
        let run = run_admitted_request(state, request, next);
        match carried {
            Some(connection) => crate::api::call_receipt::on_connection(connection, run).await,
            None => run.await,
        }
    })
    .await
    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// The answer to an owner attestation managed ingress could not verify on
/// `path`: refused, named, with nothing served in the owner's place.
pub(in crate::managed) fn owner_attestation_refused(path: &str) -> Response {
    let error = crate::auth::owner_attestation_refused();
    if path.starts_with("/v1/") {
        crate::error::EnvelopedApiError::from(error).into_response()
    } else {
        error.into_response()
    }
}

async fn run_admitted_request(
    state: Arc<ManagedState>,
    mut request: Request,
    next: Next,
) -> Response {
    if request.headers().contains_key(UPGRADE) {
        // Admitted, and out of sight from here on. A freeze with one of these
        // behind it is not quiescent, and `prepare_reap` is where that is
        // answered for — this gate cannot refuse a frame it never sees.
        state.admit_sync_upgrade();
        // A held MCP socket admits each call it carries here again, and each
        // receipt it writes outside one (FIX 5128).
        request
            .extensions_mut()
            .insert(ManagedCarrierContext(Arc::clone(&state)));
    }
    // Observation does not wake the vault. Explicit lifecycle calls own their
    // transition so their completion receipt reports what they actually did.
    let lifecycle_observation = match (request.method().as_str(), request.uri().path()) {
        ("GET", "/api/health") => true,
        ("POST", path) => matches!(
            path,
            "/v1/core/facade/vault.slim.policy"
                | "/v1/core/facade/vault.slim.state"
                | "/v1/core/facade/vault.slim.resume_step"
                | "/v1/core/facade/vault.slim.drop_heavy"
                | "/v1/core/facade/vault.slim.resume"
        ),
        _ => false,
    };
    if !lifecycle_observation && let Err(error) = state.server.vault().resume_from_slim_on_inbound()
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
    }
    next.run(request).await
}

/// Renders the typed refusal for the wire.
///
/// The message is the error's own `Display`, so the served refusal and the
/// object-level one cannot drift apart. 503 because the refusal is temporary by
/// construction: `reap_abort` lifts it and the same request succeeds. The
/// fields beside it name the bound (K18): the service's vault lifecycle
/// allocation while it prepares a reap, what waits, what lifts it, and that a
/// self-hosted vault has no such limit. Each comes from the same
/// [`REAP_PAUSE_REFUSAL`](super::REAP_PAUSE_REFUSAL) a ctl refusal carries,
/// so the two cannot drift.
fn writes_frozen_response(error: &ManagedError) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(writes_frozen_body(error)),
    )
        .into_response()
}
