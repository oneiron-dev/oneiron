//! OF-181: a host-rendered lens card's events, against the frame this server
//! holds for it ([`crate::lens_frames`]).
//!
//! `vault.lenses.default`'s host door ([`vault_lenses_default`]) renders the
//! card and records its frame before the answer leaves. `POST
//! /v1/core/lens-frames/{card_id}/events` then takes one client event and
//! its idempotency key. The event names only what was touched: the frame,
//! the exact render the client was handed and the card's current `$state`
//! are the host's, found under the fresh credential's idempotency principal
//! and locality, so only the caller that rendered a card drives it. The
//! event is validated against them under the credential's own read; a
//! deterministic tool then meets the verb scope and record admission an
//! action call of its command meets, and runs through the app's one
//! executor as the credential's action. A local patch moves the held
//! `$state` and dispatches nothing. A model round trip is refused: it is not
//! served yet.
//!
//! `DELETE /v1/core/lens-frames/{card_id}` closes the card and frees its
//! frame. A card this server does not hold (closed, evicted at the memory
//! floor, or held before a restart) answers `NOT_FOUND`: render it again.
use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{Extensions, HeaderMap, StatusCode};
use axum::response::Json;
use axum::routing::{delete, post};
use oneiron::EntityId;
use oneiron::claim::ScopedReadResult;
use oneiron::lens::{
    GeneratedUiActionEvent, GeneratedUiSurfaceCapabilities, GeneratedUiValidatedAction,
    LensDefaultRequest, LensFrameCard, LensRenderId,
};
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_INVALID_STATE, MEMORY_CODE_NOT_FOUND, MemoryResult,
};
use serde::Deserialize;

use super::action_routes::{action_bound, execute_validated_ui, require_action_scope};
use super::host_doors::internal;
use super::{FacadeApiError, facade_actor, facade_input, facade_json};
use crate::api::credential_memory;
use crate::auth::{CoreAuth, CoreScope};
use crate::server::SyncServer;

pub(crate) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/v1/core/lens-frames/{card_id}/events", post(event))
        .route("/v1/core/lens-frames/{card_id}", delete(close))
}

/// `vault.lenses.default` on this server: the default lens read under the
/// credential's own key at its locality, lowered once for the whole atom
/// kit, its frame held for the card's events before the answer leaves.
/// Beside it, the rows its reads listed.
pub(crate) async fn vault_lenses_default(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LensDefaultRequest,
) -> (MemoryResult<ScopedReadResult<LensFrameCard>>, Vec<EntityId>) {
    let (actor, class) = match facade_actor(auth) {
        Ok(bound) => bound,
        Err(refusal) => return (Err(refusal.into_memory_error()), Vec::new()),
    };
    let rendered = {
        let server = Arc::clone(server);
        let auth = auth.clone();
        tokio::task::spawn_blocking(move || {
            let producers = oneiron::memory::ProducerRows::default();
            let rendered = credential_memory(&server.vault, Some(&auth), actor, class)
                .at(auth.locality())
                .listing_producers(&producers)
                .lenses_default_framed(input);
            (rendered, producers.take())
        })
        .await
    };
    let Ok((rendered, listed)) = rendered else {
        return (Err(internal("vault.lenses.default")), Vec::new());
    };
    let answer = rendered.and_then(|ScopedReadResult { value, receipt }| {
        let (frame, card) = value.lower(&GeneratedUiSurfaceCapabilities::all_atom_kit())?;
        server
            .lens_frames
            .record(auth, frame, card.render.clone())?;
        Ok(ScopedReadResult {
            value: card,
            receipt,
        })
    });
    (answer, listed)
}

/// One event's body: the client's event, and the key its dispatch replays
/// under.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct UiEventRequest {
    event: GeneratedUiActionEvent,
    idempotency_key: String,
}

async fn event(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(card_id): Path<String>,
    headers: HeaderMap,
    extensions: Extensions,
    payload: Result<Json<serde_json::Value>, JsonRejection>,
) -> Result<Json<serde_json::Value>, FacadeApiError> {
    // The card came from a read; what its actions write meets its own scope.
    auth.require(CoreScope::Read)?;
    let request: UiEventRequest = facade_input(facade_json(payload)?)?;
    if request.event.card_id.as_str() != card_id {
        return Err(FacadeApiError::new(
            StatusCode::BAD_REQUEST,
            MEMORY_CODE_BAD_REQUEST,
            "the event names another card than its path",
            ["Send each event to its own card's path."],
        ));
    }
    let (actor, class) = facade_actor(&auth)?;
    let held = server
        .lens_frames
        .card(&auth, &request.event.card_id)
        .ok_or_else(rerender)?;
    // One event on a card at a time, from its validation to its effect.
    let mut state = held.state.lock().await;
    let validated = {
        let server = Arc::clone(&server);
        let auth = auth.clone();
        let held = Arc::clone(&held);
        let current = state.clone();
        let event = request.event;
        tokio::task::spawn_blocking(move || {
            credential_memory(&server.vault, Some(&auth), actor, class)
                .at(auth.locality())
                .lens_frame_event(&held.frame, &held.render, &current, &event)
        })
        .await
        .map_err(|_| internal("a lens frame event"))??
    };
    let answer = match validated {
        GeneratedUiValidatedAction::Local { state: next, .. } => {
            if !server.lens_frames.restate(&auth, &held, &next) {
                return Err(rerender());
            }
            let answer = serde_json::json!({ "$state": &next });
            *state = next;
            answer
        }
        GeneratedUiValidatedAction::DeterministicTool { .. } => {
            dispatch_tool(
                &server,
                &auth,
                headers,
                extensions,
                validated,
                request.idempotency_key,
            )
            .await?
        }
        GeneratedUiValidatedAction::ModelRoundTrip { .. } => {
            return Err(FacadeApiError::new(
                StatusCode::NOT_IMPLEMENTED,
                MEMORY_CODE_INVALID_STATE,
                "a model round-trip lens event is not served yet",
                ["Only a card's local and deterministic-tool actions run here."],
            ));
        }
    };
    drop(state);
    Ok(Json(answer))
}

/// A validated deterministic tool: the verb scope and record admission an
/// action call of its command meets, then the app's one executor under the
/// credential's binding. Its answer is an action call's.
async fn dispatch_tool(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    validated: GeneratedUiValidatedAction,
    key: String,
) -> Result<serde_json::Value, FacadeApiError> {
    if let GeneratedUiValidatedAction::DeterministicTool { action, .. } = &validated {
        require_action_scope(auth, action.command().as_str())?;
    }
    let bound = action_bound(server, auth)?.ok_or_else(|| {
        FacadeApiError::forbidden(
            "an action runs under the credential's own read key",
            ["Present a verified slip paired to this principal."],
        )
    })?;
    let dispatch = execute_validated_ui(server, headers, extensions, bound, validated, key).await?;
    Ok(serde_json::json!({
        "outcome": dispatch.outcome_value().map_err(engine)?,
        "readReceipt": dispatch.read_receipt,
    }))
}

async fn close(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(card_id): Path<String>,
) -> Result<Json<serde_json::Value>, FacadeApiError> {
    auth.require(CoreScope::Read)?;
    let closed =
        LensRenderId::new(card_id).is_ok_and(|card| server.lens_frames.close(&auth, &card));
    Ok(Json(serde_json::json!({ "closed": closed })))
}

/// A card this server holds no frame for: closed, evicted at the memory
/// floor, or held before a restart.
fn rerender() -> FacadeApiError {
    FacadeApiError::new(
        StatusCode::NOT_FOUND,
        MEMORY_CODE_NOT_FOUND,
        "this server holds no frame for this card; re-render the lens",
        ["Render the lens again and send its events to the card that render returns."],
    )
}

fn engine(error: oneiron::Error) -> FacadeApiError {
    crate::api::error_map::core_engine_error("lens frame event", error).into()
}
