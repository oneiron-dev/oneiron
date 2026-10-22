//! Keyed run-tree interventions (FIX 6056).
//!
//! `POST /v1/core/run-tree/intervene` with an `Idempotency-Key` takes the
//! keyed mutation layer, partitioned by its caller as every keyed core route
//! is: the intent is kept before the act, and the act's reply after it, so a
//! retried or concurrent intervention under one key runs once. That holds
//! for a pause, a resume, an immediate cancel and a cancel that became a
//! Proposed claim alike, whose replay names the same claim. No request or
//! reply size bounds it beyond the route's own extractor. A replay names the
//! effect as it was kept, and its run tree is projected again under the
//! caller's read authority as it stands then (FIX 8220): a caller that no
//! longer reads run trees gets the effect with no tree. A request with no
//! key acts as before. So does a keyed one from a caller the layer would
//! refuse to replay to as an owner act (a host root that may not act as the
//! owner), which keeps the intervention it has today.

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use serde_json::Value;

use super::scoped::intervention_tree;
use crate::api::host_action::require_host_owner_act;
use crate::auth::CoreAuth;
use crate::idempotency::{
    IDEMPOTENCY_KEY_HEADER, IdempotencyLayerState, Replay, idempotency_for_mutating_form,
};
use crate::server::SyncServer;

/// The keyed layer for run-tree interventions.
pub(crate) async fn intervene_idempotency(
    State(state): State<IdempotencyLayerState>,
    request: Request,
    next: Next,
) -> Response {
    if !request.headers().contains_key(IDEMPOTENCY_KEY_HEADER) {
        return next.run(request).await;
    }
    let (parts, body) = request.into_parts();
    let unkeyed = match CoreAuth::for_request(&parts, state.server()).await {
        Ok(auth) => require_host_owner_act(state.server(), &auth).is_err(),
        Err(_) => false,
    };
    let request = Request::from_parts(parts, body);
    if unkeyed {
        return next.run(request).await;
    }
    idempotency_for_mutating_form(state, request, next, |_| true, reproject_tree).await
}

/// A kept intervention reply as it goes out again: its effect, attempt, run
/// and claim as kept, its tree projected again for `auth` now. A reply that
/// names no run (a Proposed claim's, or a row with none) carries no tree and
/// replays as kept.
fn reproject_tree(
    server: &SyncServer,
    auth: Option<&CoreAuth>,
    replay: &Replay<'_>,
) -> Option<Response> {
    let mut reply: Value = serde_json::from_slice(replay.body).ok()?;
    let run_id = reply.get("run_id")?.as_str()?.to_owned();
    let attempt_id = reply
        .get("job_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let tree = auth.and_then(|auth| intervention_tree(server, auth, &run_id, &attempt_id));
    reply["tree"] = serde_json::to_value(tree).ok()?;
    let bytes = serde_json::to_vec(&reply).ok()?;
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Some(response)
}
