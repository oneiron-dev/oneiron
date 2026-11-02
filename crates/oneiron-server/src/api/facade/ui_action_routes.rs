//! OF-181: a host-rendered lens card's events, against the frame this server
//! holds for it ([`crate::lens_frames`]).
//!
//! `vault.lenses.default`'s host door ([`vault_lenses_default`]) renders the
//! card and records its frame before the answer leaves. `POST
//! /v1/core/lens-frames/{card_id}/events` then takes one client event, its
//! idempotency key and an optional `selectedContext`. The event names only
//! what was touched: the frame, the exact render the client was handed and
//! the card's current `$state` are the host's, found by the card id alone.
//!
//! The credential that clicks a card authors its action (FIX 3267, Engine
//! ruling 10-19): a card id locates the host-held manifest and never lends
//! its renderer's authority. The event is validated against the frame under
//! the clicking credential's own read, every backing ref the action uses
//! proved again on it, and the validated action's emitter is the clicker. A
//! deterministic tool then meets the verb scope and record admission an
//! action call of its command meets, and runs through the app's one
//! executor as the clicker's action; a live-run verb acts for the run that
//! rendered the card, through the clicker's own attachment to it (FIX 2652),
//! never the renderer's. A local patch moves the held `$state` and
//! dispatches nothing. A model round trip goes back to the agent that
//! rendered the card, as its next turn
//! ([`crate::ai_host::queue_lens_callback`]), labelled with who pressed it:
//! it answers `202 {"queued", "callbackId"}`, and a card a person's view or
//! a system job rendered answers `409`. Closing a card stays with the
//! credential that rendered it, and retiring it with its run.
//!
//! `selectedContext` (FIX 3268) names selections the clicker made on this
//! card (`vault.lenses.select`'s `selectionRef`s), each a host-held
//! [`oneiron::lens::LensReadHandle`]. On a model round trip each is proved
//! again under the held render and the clicker's read before the callback is
//! queued, and rides it as context: never approval or action authority. Any
//! other action ignores it (CALLS "3268 lens selected context").
//!
//! A deterministic tool's reply states its dispatched verb's call receipt in
//! `x-oneiron-receipt-ref`, exactly as that verb's own reply stated it,
//! recorded, `none; no-record` or nothing, on its success and its refusal
//! alike (FIX 2887); the lens route writes no receipt of its own. A local
//! patch, a queued callback and a close dispatch no verb and state none.
//!
//! A managed vault's attested owner drives the cards it rendered the same
//! way: render, event and close are each attested at managed ingress, and a
//! tool binds through [`action_bound`] (WILL-PLAN L13 row 01).
//!
//! `DELETE /v1/core/lens-frames/{card_id}` closes the card and frees its
//! frame. A card this server does not hold (closed, evicted at the memory
//! floor, or held before a restart) answers `NOT_FOUND`: render it again.
use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{Extensions, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{delete, post};
use oneiron::EntityId;
use oneiron::claim::ScopedReadResult;
use oneiron::code_run::live_run::is_live_run_verb;
use oneiron::lens::{
    GeneratedUiActionEvent, GeneratedUiStreamProfile, GeneratedUiSurfaceCapabilities,
    GeneratedUiValidatedAction, LensDefaultRequest, LensFrameCard, LensRenderId,
};
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_INVALID_STATE, MEMORY_CODE_NOT_FOUND, MemoryError,
    MemoryResult,
};
use serde::Deserialize;

use super::action_routes::{
    ActionBound, action_bound, bind_card_run, execute_validated_ui, require_action_scope,
};
use super::host_doors::support::internal;
use super::{FacadeApiError, facade_actor, facade_input, facade_json};
use crate::ai_host::LensCallback;
use crate::api::call_receipt::CallStamp;
use crate::api::credential_memory;
use crate::auth::{CoreAuth, CoreScope};
use crate::lens_frames::{CardOwner, HeldCard};
use crate::server::SyncServer;

pub(crate) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/v1/core/lens-frames/{card_id}/events", post(event))
        .route("/v1/core/lens-frames/{card_id}", delete(close))
}

/// `vault.lenses.default` on this server: the default lens read under the
/// credential's own key at its locality, lowered once for the surface the
/// call names (FIX 7969: its input's own `surface`, else `client_surface`,
/// the profile its MCP call declared), else for the whole atom kit, its
/// frame held beside exactly that render for the card's events before the
/// answer leaves.
/// Beside it, the rows its reads listed. A run-held render (`owner`, FIX
/// 2612) holds its card for its creating run and subscription, replacing
/// the card that run last rendered for it; any other holds it unowned.
pub(crate) async fn vault_lenses_default(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    owner: Option<CardOwner>,
    client_surface: Option<GeneratedUiSurfaceCapabilities>,
    input: LensDefaultRequest,
) -> (MemoryResult<ScopedReadResult<LensFrameCard>>, Vec<EntityId>) {
    let (actor, class) = match facade_actor(server, auth) {
        Ok(bound) => bound,
        Err(refusal) => return (Err(refusal.into_memory_error()), Vec::new()),
    };
    let surface = input.surface.clone().or(client_surface).unwrap_or_default();
    let rendered = {
        let server = Arc::clone(server);
        let auth = auth.clone();
        super::clock_ingress::run_blocking(move || {
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
        let (frame, card) = value.lower(&surface)?;
        match owner {
            Some(owner) => {
                server.lens_frames.replace_for_subscription(
                    auth,
                    frame,
                    card.render.clone(),
                    owner,
                )?;
            }
            None => server
                .lens_frames
                .record(auth, frame, card.render.clone())?,
        }
        Ok(ScopedReadResult {
            value: card,
            receipt,
        })
    });
    (answer, listed)
}

/// One event's body: the client's event, the key its dispatch replays
/// under, the selections the clicker made on the card, by the
/// `selectionRef` each `vault.lenses.select` answered (FIX 3268), and the
/// stream profile its answer is framed in (FIX 11399).
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct UiEventRequest {
    event: GeneratedUiActionEvent,
    idempotency_key: String,
    #[serde(default)]
    selected_context: Vec<String>,
    /// The stream profile this event's answer is framed in: a
    /// patch-profile caller takes the card's refinement beside a local
    /// action's `$state`. Omitted, the answer is today's plain JSON.
    #[serde(default)]
    stream: GeneratedUiStreamProfile,
}

/// One event on a held card. A deterministic tool's reply states its
/// dispatched verb's call receipt as that verb's reply stated it (FIX
/// 2887); every other reply states none.
async fn event(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(card_id): Path<String>,
    headers: HeaderMap,
    extensions: Extensions,
    payload: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let mut stamp = CallStamp::Unrecorded;
    let answer = event_answer(
        auth, server, card_id, headers, extensions, payload, &mut stamp,
    )
    .await;
    let mut response = answer.into_response();
    stamp.stamp_header(&mut response);
    response
}

async fn event_answer(
    auth: CoreAuth,
    server: Arc<SyncServer>,
    card_id: String,
    headers: HeaderMap,
    extensions: Extensions,
    payload: Result<Json<serde_json::Value>, JsonRejection>,
    stamp: &mut CallStamp,
) -> Result<(StatusCode, Json<serde_json::Value>), FacadeApiError> {
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
    let (actor, class) = facade_actor(&server, &auth)?;
    // The card id locates the held manifest; the clicker's own read proves
    // the event (FIX 3267).
    let held = server
        .lens_frames
        .card(&request.event.card_id)
        .ok_or_else(rerender)?;
    // One event on a card at a time, from its validation to its effect.
    let mut state = held.state.lock().await;
    // The stream profile this event's caller asked its answer framed in
    // (FIX 11399): a patch-profile caller takes its refinement beside it.
    let stream = request.stream;
    let validated = {
        let server = Arc::clone(&server);
        let auth = auth.clone();
        let held = Arc::clone(&held);
        let current = state.clone();
        let event = request.event;
        let selected = request.selected_context;
        super::clock_ingress::run_blocking(move || -> MemoryResult<GeneratedUiValidatedAction> {
            let memory =
                credential_memory(&server.vault, Some(&auth), actor, class).at(auth.locality());
            let validated = memory.lens_frame_event(&held.frame, &held.render, &current, &event)?;
            // A selection is context for a model round trip alone; any other
            // action ignores it (CALLS "3268 lens selected context").
            let (emitter, callback) = match validated {
                GeneratedUiValidatedAction::ModelRoundTrip { emitter, callback } => {
                    (emitter, callback)
                }
                other => return Ok(other),
            };
            let selected = selected
                .iter()
                .map(|selection_ref| {
                    server
                        .lens_frames
                        .selection(&auth, &held, selection_ref)
                        .ok_or_else(unselected)
                })
                .collect::<MemoryResult<Vec<_>>>()?;
            let callback = memory.lens_frame_selected_context(
                &held.frame,
                &held.render,
                callback,
                selected,
            )?;
            Ok(GeneratedUiValidatedAction::ModelRoundTrip { emitter, callback })
        })
        .await
        .map_err(|_| internal("a lens frame event"))??
    };
    let answer = match validated {
        GeneratedUiValidatedAction::Local { state: next, .. } => {
            if !server.lens_frames.restate(&held, &next) {
                return Err(rerender());
            }
            // A patch-profile caller (FIX 11399) also takes the refinement
            // its held card needs: the whole card with its moved `$state` on
            // the card's first change, a patch from the render its last
            // answer left it holding after that. Every other caller answers
            // as today.
            let refinement = (stream == GeneratedUiStreamProfile::Patch).then(|| {
                let mut new = held.render.clone();
                new.state = next.clone();
                if *state == held.render.state {
                    return new.state_snapshot_segment();
                }
                let mut previous = held.render.clone();
                previous.state = state.clone();
                new.state_patch_segment(&previous)
                    .unwrap_or_else(|_| new.state_snapshot_segment())
            });
            let answer = match &refinement {
                Some(refinement) => {
                    serde_json::json!({ "$state": &next, "refinement": refinement })
                }
                None => serde_json::json!({ "$state": &next }),
            };
            *state = next;
            answer
        }
        GeneratedUiValidatedAction::DeterministicTool { .. } => {
            let (answer, stamped) = dispatch_tool(
                &server,
                &auth,
                &held,
                headers,
                extensions,
                validated,
                request.idempotency_key,
            )
            .await;
            *stamp = stamped;
            answer?
        }
        GeneratedUiValidatedAction::ModelRoundTrip { emitter, callback } => {
            // The round trip goes to the agent that rendered the card,
            // labelled with its author, the clicker.
            let rendered_by = held.frame.principal().clone();
            let server = Arc::clone(&server);
            let credential = auth.idempotency_principal();
            let key = request.idempotency_key;
            let queued = super::clock_ingress::run_blocking(move || {
                crate::ai_host::queue_lens_callback(
                    &server.vault,
                    &credential,
                    &rendered_by,
                    &emitter,
                    &callback,
                    &key,
                )
            })
            .await
            .map_err(|_| internal("a lens callback"))?
            .map_err(engine)?;
            return match queued {
                LensCallback::Queued {
                    callback_id,
                    queued,
                } => Ok((
                    StatusCode::ACCEPTED,
                    Json(serde_json::json!({ "queued": queued, "callbackId": callback_id })),
                )),
                LensCallback::NoAgent => Err(FacadeApiError::new(
                    StatusCode::CONFLICT,
                    MEMORY_CODE_INVALID_STATE,
                    "no agent rendered this card, so its model round trip has no turn to go to",
                    ["Only a card an agent rendered sends a model round trip back to it."],
                )),
                LensCallback::KeyReused => Err(FacadeApiError::new(
                    StatusCode::CONFLICT,
                    MEMORY_CODE_INVALID_STATE,
                    "this idempotency key already sent another callback on this card",
                    ["Send each new event under a new idempotency key."],
                )),
            };
        }
    };
    drop(state);
    Ok((StatusCode::OK, Json(answer)))
}

/// A validated deterministic tool: the verb scope and record admission an
/// action call of its command meets, then the app's one executor under the
/// clicking credential's binding. Its answer is an action call's, beside
/// what its verb-table row's reply stated of its call receipt (FIX 2887).
async fn dispatch_tool(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    held: &Arc<HeldCard>,
    headers: HeaderMap,
    extensions: Extensions,
    validated: GeneratedUiValidatedAction,
    key: String,
) -> (Result<serde_json::Value, FacadeApiError>, CallStamp) {
    let (bound, key) = match tool_bound(server, auth, held, &headers, &extensions, &validated, key)
    {
        Ok(bound) => bound,
        Err(refused) => return (Err(refused), CallStamp::Unrecorded),
    };
    let (dispatch, stamp) =
        execute_validated_ui(server, headers, extensions, bound, validated, key).await;
    let answer = dispatch.and_then(|dispatch| {
        Ok(serde_json::json!({
            "outcome": dispatch.outcome_value().map_err(engine)?,
            "readReceipt": dispatch.read_receipt,
        }))
    });
    (answer, stamp)
}

/// What a validated tool runs under, and its key: the clicking credential's
/// binding, and for a live-run verb the run that rendered `held` (FIX 2652),
/// through this credential's own attachment to it, under that run's action
/// key. A person pressing an agent's live card attaches first.
fn tool_bound(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    held: &Arc<HeldCard>,
    headers: &HeaderMap,
    extensions: &Extensions,
    validated: &GeneratedUiValidatedAction,
    key: String,
) -> Result<(ActionBound, String), FacadeApiError> {
    let mut live = false;
    if let GeneratedUiValidatedAction::DeterministicTool { action, .. } = validated {
        require_action_scope(auth, action.command().as_str())?;
        live = is_live_run_verb(action.command().as_str());
    }
    // The owner act records where this request's own headers say he spoke
    // from (FIX 4625).
    let surface = crate::api::owner_routes::machine_routes::act_surface_admitted(
        server, auth, headers, extensions,
    );
    let mut bound = action_bound(server, auth, surface)?.ok_or_else(|| {
        FacadeApiError::forbidden(
            "an action runs under the credential's own read key",
            ["Present a verified slip paired to this principal."],
        )
    })?;
    let key = if live {
        let creator_run = server.lens_frames.creator_run(held);
        bind_card_run(server, auth, &mut bound, creator_run.as_deref(), &key)?
    } else {
        key
    };
    Ok((bound, key))
}

/// Closes a held card for the credential that rendered it; a card it did
/// not render answers `{"closed": false}` and stays held.
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

/// A `selectedContext` ref this credential selected nothing under on this
/// card.
fn unselected() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_NOT_FOUND,
        "this caller made no such selection on this card; select again",
        &["Select through vault.lenses.select on this card and send its selectionRef."],
    )
}

fn engine(error: oneiron::Error) -> FacadeApiError {
    crate::api::error_map::core_engine_error("lens frame event", error).into()
}
