//! OF-181: the app's one action layer over HTTP, for both its callers.
//!
//! `GET /v1/core/actions` lists the verbs of the app's one table
//! ([`oneiron::code_run::actions::ActionRegistry::app`]). `POST
//! /v1/core/actions/{verb}` runs one as the credential's own principal: a
//! person's app button (a human view) or an agent's call (an agent task). The
//! credential binds the actor, the principal's read key and the owner proof;
//! the body names only the arguments and the idempotency key.
//!
//! MCP's `invoke_action` tool runs an action through the same
//! [`invoke_action`], under the credential its connector header selected,
//! at its connection.
//!
//! A verb-table action runs through [`row_door::FacadeRowDoor`]: its row's generated
//! facade route, in process, under this request's own headers and connection.
//! It meets the scope, admission, room turn, gate and call receipt that a
//! direct `/v1/core/facade/<row>` call meets, so neither caller holds through
//! an action any authority the row's own call lacks.
//!
//! A REST route whose write is a verb-table row runs it here too, through
//! [`execute_facade_row`], when the credential binds an action at all
//! ([`action_bound`]; [`rest_action_bound`] for a REST write): its button and
//! an agent's call meet one executor. The write's whole body rides as one
//! structured argument, and a refusal answers with the row's own words.
//!
//! A memory run row (`vault.search`, `vault.claims.put`,
//! `vault.claims.supersede`, `vault.edges.put`) has no facade route; the
//! registry runs it as the typed call a code run makes. It meets the scope
//! and record bounds `execute_code` and `vault.recall` meet, and the door
//! hands the run the credential's read key: a search reads, and an edge's
//! target is checked, as the credential reads.
mod execution;
mod row_door;

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{Extensions, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use oneiron::authority::ActSurface;
use oneiron::code_run::actions::{ActionArgument, ActionDispatch, ActionJson, AgentActionCall};
use oneiron::code_run::live_run::{LiveRunCredential, is_live_run_verb};
use oneiron::code_run::{SelfDispatchOutcome, SelfFailedResult};
use oneiron::consent::AuthenticatedOwner;
use oneiron::lens::{GeneratedUiValidatedAction, SelfUiActionId};
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_INTERNAL, MEMORY_CODE_INVALID_STATE, MemoryError,
};
use oneiron::task_verb::sdk::{AgentVerb, RunVerb};
use oneiron::{EdgeActorClass, EntityId, WriteActor};
use serde::Deserialize;

use self::execution::{execute, execute_stamped, run_bound, run_bound_stamped};
use super::{FacadeApiError, facade_actor, facade_input, facade_json, owner_authorship};
use crate::actions::SharedActionExecutor;
use crate::api::call_receipt::CallStamp;
use crate::api::owner_routes::machine_routes::act_surface_admitted;
use crate::auth::{CoreAuth, CoreScope};
use crate::server::{LiveRunCaller, LiveRunRefusal, ResolvedLiveRun, SyncServer};

pub(crate) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/v1/core/actions", get(list))
        .route("/v1/core/actions/{verb}", post(invoke))
        .route("/v1/core/live-runs/{run}/attach", post(attach_live_run))
}

/// One action call's body. The verb is the path's; the principal is the
/// credential's.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct ActionRequest {
    pub(crate) args: Vec<ActionArgument>,
    pub(crate) idempotency_key: String,
    /// The live run the action acts for (OF-181), as its attach answered.
    #[serde(default)]
    pub(crate) live_run: Option<String>,
}

/// An attach's optional body.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AttachRequest {
    /// Take the run's attachment over from another credential of its own
    /// agent (FIX 2651).
    #[serde(default)]
    rebind: bool,
}

async fn list(auth: CoreAuth) -> Result<Json<serde_json::Value>, FacadeApiError> {
    auth.require(CoreScope::Read)?;
    let actions: Vec<_> = app()?.definitions().collect();
    Ok(Json(serde_json::json!({ "actions": actions })))
}

/// One action call. Its reply states, success and refusal alike, the call
/// receipt its verb-table row's reply stated (FIX 5275): the action route
/// writes none of its own, and a reply no row ran for states nothing.
async fn invoke(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(verb): Path<String>,
    headers: HeaderMap,
    extensions: Extensions,
    payload: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let request = match facade_json(payload).and_then(facade_input::<ActionRequest>) {
        Ok(request) => request,
        Err(refused) => return refused.into_response(),
    };
    let (answer, stamp) = invoke_action(&server, &auth, headers, extensions, verb, request).await;
    let mut response = answer.map(Json).into_response();
    stamp.stamp_header(&mut response);
    response
}

/// Runs action `verb` of the app's table under `auth`, as `request` names
/// it, and answers its outcome and read receipt, beside what its verb-table
/// row's reply stated of its call receipt (FIX 5275). Its verb-table rows
/// run through their own routes under `headers` and `extensions`, the
/// caller's own request and connection. `POST /v1/core/actions/{verb}` and
/// MCP's `invoke_action` tool both run an action here: one scope check, one
/// binding, one live-run resolution and key, one held run.
pub(crate) async fn invoke_action(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    verb: String,
    request: ActionRequest,
) -> (Result<serde_json::Value, FacadeApiError>, CallStamp) {
    let (dispatch, stamp) =
        invoke_action_stamped(server, auth, headers, extensions, None, verb, request).await;
    let answer = dispatch.and_then(|dispatch| {
        Ok(serde_json::json!({
            "outcome": dispatch.outcome_value().map_err(engine)?,
            "readReceipt": dispatch.read_receipt,
        }))
    });
    (answer, stamp)
}

/// The same action admission and execution, retaining the typed outcome for
/// the generated public run doors. Given `credential`, its verb-table rows
/// run as that caller rather than through a request's headers and
/// connection ([`execute`]).
pub(super) async fn invoke_action_dispatch(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    credential: Option<CoreAuth>,
    verb: String,
    request: ActionRequest,
) -> Result<ActionDispatch, FacadeApiError> {
    invoke_action_stamped(server, auth, headers, extensions, credential, verb, request)
        .await
        .0
}

/// [`invoke_action_dispatch`], beside the stamp its verb-table row's reply
/// stated: unrecorded for an action refused before it ran.
async fn invoke_action_stamped(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    credential: Option<CoreAuth>,
    verb: String,
    request: ActionRequest,
) -> (Result<ActionDispatch, FacadeApiError>, CallStamp) {
    // An owner's erase or revoke reads the restriction-only clock through
    // its admission and its rows (FIX 11524), as its direct call does; any
    // other action runs as it is. This covers the callers that bypass the
    // binding door's own mark.
    let restrictive = super::clock_ingress::restrictive_action(server, &verb, &request.args);
    super::clock_ingress::scoped(restrictive, async {
        let admitted = admit_action(server, auth, &headers, &extensions, verb, request);
        let (bound, call) = match admitted {
            Ok(admitted) => admitted,
            Err(refused) => return (Err(refused), CallStamp::Unrecorded),
        };
        execute_stamped(server, headers, extensions, bound, credential, call).await
    })
    .await
}

/// An action call's scope check, binding, live-run resolution and key: what
/// it runs under, and the call, before anything runs.
fn admit_action(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    headers: &HeaderMap,
    extensions: &Extensions,
    verb: String,
    request: ActionRequest,
) -> Result<(ActionBound, AgentActionCall), FacadeApiError> {
    require_action_scope(auth, &verb)?;
    let verb_id = SelfUiActionId::new(verb).map_err(|_| {
        FacadeApiError::new(
            StatusCode::NOT_FOUND,
            MEMORY_CODE_BAD_REQUEST,
            "no action has this name",
            ["List the app's actions at GET /v1/core/actions."],
        )
    })?;
    // A credential that names no principal meets the facade's own refusal.
    facade_actor(server, auth)?;
    // Where the owner spoke from: a linked machine this request's own
    // headers prove, else the header-less rule (FIX 4625).
    let surface = act_surface_admitted(server, auth, headers, extensions);
    let mut bound = action_bound(server, auth, surface)?.ok_or_else(|| {
        FacadeApiError::forbidden(
            "an action runs under the credential's own read key",
            ["Present a verified slip paired to this principal."],
        )
    })?;
    // OF-181: a live-run handle resolves to its registered run, for this
    // credential only, and namespaces the action's key; a live-run row
    // names one.
    let idempotency_key = match request.live_run {
        Some(handle) => {
            let run = server
                .live_runs
                .resolve(&handle, live_run_caller(&bound, auth))
                .map_err(refused)?;
            let key = run.action_key(&request.idempotency_key).map_err(engine)?;
            bound.live_run = Some(run);
            key
        }
        None if is_live_run_verb(verb_id.as_str()) => {
            return Err(refused(LiveRunRefusal::Required));
        }
        None => request.idempotency_key,
    };
    let call = AgentActionCall {
        verb_id,
        args: request.args,
        idempotency_key,
    };
    Ok((bound, call))
}

/// The scope and record admission an action of `verb` meets, wherever its
/// call comes from (an action call, a lens card's event). A verb-table or
/// run row that only reads needs only read; any other action is an effect.
/// The row's own route re-checks its scope in any case. A run row has no
/// route, so its record bounds are checked here: a search reads on the
/// credential's lane, as `vault.recall` does, and a write commits at once,
/// as `execute_code` does.
pub(super) fn require_action_scope(auth: &CoreAuth, verb: &str) -> Result<(), FacadeApiError> {
    let run_row = RunVerb::from_name(verb);
    let writes = AgentVerb::from_name(verb)
        .map(AgentVerb::writes)
        .or(run_row.map(RunVerb::writes))
        .unwrap_or(true);
    auth.require(if writes {
        CoreScope::Write
    } else {
        CoreScope::Read
    })?;
    match run_row {
        Some(row) if row.writes() => auth.require_unrestricted_record_scope()?,
        Some(_) => auth.require_lane_record_scope()?,
        None => {}
    }
    Ok(())
}

/// What one action runs under: the credential's principal and class, its
/// read key at the caller's locality, and the owner's proof when the
/// credential carries one.
pub(crate) struct ActionBound {
    actor: EntityId,
    class: EdgeActorClass,
    key: oneiron::claim::ScopedReadActorKey,
    owner: Option<AuthenticatedOwner>,
    /// Where the owner spoke from, for an owner setting's act record: the
    /// surface the caller derived from its own request (FIX 4625).
    surface: Option<ActSurface>,
    /// The live run the action acts for, resolved from its handle.
    live_run: Option<ResolvedLiveRun>,
}

/// What `auth` binds an action to. `None`: the credential names no
/// principal, or presents no verified slip with read authority, so no
/// action runs under it. A self-hosted root, or the dev mode, binds the
/// owner its host action names, with that owner's guarded key at the
/// caller's locality and the owner's proof; a hosted operator's root is
/// refused, never left to a fallback (FIX 2222). A managed vault's attested
/// owner binds its request's own proof (WILL-PLAN L13 row 01). `surface` is
/// where the owner's say-so reached this install, as the caller read it from
/// its own request ([`act_surface`] over its headers, or
/// [`super::owner_binding::act_surface`] for a call that carries none; FIX
/// 4625): an owner act records it, and no rule reads it.
pub(crate) fn action_bound(
    server: &SyncServer,
    auth: &CoreAuth,
    surface: ActSurface,
) -> Result<Option<ActionBound>, FacadeApiError> {
    let (actor, class, key, owner) =
        if let Some(action) = crate::api::host_action::facade_host_action(server, auth)? {
            let actor = action.actor();
            let key = action.read_key().at(auth.locality());
            let owner = owner_authorship(auth, server)?;
            (actor.entity_ref(), actor.actor_class(), key, owner)
        } else {
            let Ok((actor, class)) = facade_actor(server, auth) else {
                return Ok(None);
            };
            match super::owner_binding::managed_owner_binding(server, auth)? {
                Some(bound) => (bound.actor, bound.class, bound.key, Some(bound.owner)),
                None => {
                    let Some(proof) = auth.verified_slip() else {
                        return Ok(None);
                    };
                    let Some(key) = server.vault.credential_read_key(proof).map_err(engine)? else {
                        return Ok(None);
                    };
                    let owner = owner_authorship(auth, server)?;
                    (actor, class, key.at(auth.locality()), owner)
                }
            }
        };
    Ok(Some(ActionBound {
        actor,
        class,
        key,
        owner,
        surface: Some(surface),
        live_run: None,
    }))
}

impl ActionBound {
    /// The actor an action under this binding writes as.
    pub(crate) fn writes_as(&self) -> WriteActor {
        WriteActor::new(self.actor, self.class)
    }
}

/// What a REST write of `input` runs under as one action, if it runs as
/// one: a credential [`action_bound`] binds (a person, an agent or a system
/// job), on a request that names no room turn, with an input that fits one
/// structured action argument (the row route's own body ceiling, past the
/// REST route's). Every other write runs its row's own door, as its REST
/// route always admitted it. The route chooses here, before it writes; a
/// refused action is never written again another way. A hosted operator's
/// root gets its typed refusal here, before any branch (FIX 8210): a room
/// turn's header or an oversized input never lets it reach a row's door.
pub(crate) fn rest_action_bound<T: serde::Serialize>(
    server: &SyncServer,
    auth: &CoreAuth,
    headers: &HeaderMap,
    extensions: &Extensions,
    input: &T,
) -> Result<Option<ActionBound>, FacadeApiError> {
    crate::api::host_action::facade_host_action(server, auth)?;
    if headers.contains_key(super::ROOM_TURN_HEADER) {
        return Ok(None);
    }
    let Some(bound) = action_bound(
        server,
        auth,
        act_surface_admitted(server, auth, headers, extensions),
    )?
    else {
        return Ok(None);
    };
    Ok(action_json(input)?.map(|_| bound))
}

/// `input` as one structured action argument; `None` past its ceiling.
fn action_json<T: serde::Serialize>(input: &T) -> Result<Option<ActionJson>, FacadeApiError> {
    let value = serde_json::to_value(input).map_err(|_| internal())?;
    Ok(ActionJson::new(value).ok())
}

/// Runs a lens card's validated event under `bound`, as an action call
/// runs: its deterministic tool through the app's table, its verb-table row
/// through its own route under this request's headers and connection. The
/// event's emitter is the clicking credential's principal, the author of
/// the card's action (FIX 3267); `key` is its idempotency key. Beside the
/// dispatch, the stamp the row's reply stated of its call receipt, on its
/// success and its refusal alike (FIX 2887): the lens route states it again,
/// writing no receipt of its own.
pub(super) async fn execute_validated_ui(
    server: &Arc<SyncServer>,
    headers: HeaderMap,
    extensions: Extensions,
    bound: ActionBound,
    event: GeneratedUiValidatedAction,
    key: String,
) -> (Result<ActionDispatch, FacadeApiError>, CallStamp) {
    run_bound_stamped(
        server,
        headers,
        extensions,
        bound,
        None,
        move |executor, vault, writer, binding| {
            executor.execute_ui_bound(vault, writer, &event, &key, binding)
        },
    )
    .await
}

/// Runs the result-set door's already validated action under its caller's
/// credential. SDK rows meet the normal generated facade admission, as a
/// socket call under that same credential does.
pub(super) async fn execute_result_set_action(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    held: &Arc<crate::lens_frames::HeldCard>,
    event: GeneratedUiValidatedAction,
    key: String,
) -> Result<ActionDispatch, FacadeApiError> {
    let GeneratedUiValidatedAction::DeterministicTool { action, .. } = &event else {
        return Err(internal());
    };
    require_action_scope(auth, action.command().as_str())?;
    // A held card's event carries no request headers.
    let surface = super::owner_binding::act_surface(auth);
    let mut bound = action_bound(server, auth, surface)?.ok_or_else(|| {
        FacadeApiError::forbidden(
            "an action runs under the credential's own read key",
            ["Present a verified slip paired to this principal."],
        )
    })?;
    let key = if is_live_run_verb(action.command().as_str()) {
        let creator_run = server.lens_frames.creator_run(held);
        bind_card_run(server, auth, &mut bound, creator_run.as_deref(), &key)?
    } else {
        key
    };
    run_bound(
        server,
        HeaderMap::new(),
        Extensions::new(),
        bound,
        Some(auth.clone()),
        move |executor, vault, writer, binding| {
            executor.execute_ui_bound(vault, writer, &event, &key, binding)
        },
    )
    .await
}

/// `POST /v1/core/live-runs/{run}/attach` (OF-181): attaches this credential
/// to the live run `run` and answers `{"liveRun": <handle>}`, to this caller
/// only. It needs the verified credential and write admission an action
/// needs, from the run's own agent, while the run's runner holds its lease.
/// An optional `{"rebind": true}` body takes the attachment over from
/// another credential of that agent (FIX 2651).
async fn attach_live_run(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(run): Path<String>,
    payload: Result<Option<Json<AttachRequest>>, JsonRejection>,
) -> Result<Json<serde_json::Value>, FacadeApiError> {
    auth.require(CoreScope::Write)?;
    facade_actor(&server, &auth)?;
    let rebind = payload
        .transpose()
        .map(facade_json)
        .transpose()?
        .is_some_and(|request| request.rebind);
    let handle = attach_run_as(&server, &auth, &run, rebind).await?;
    Ok(Json(serde_json::json!({ "liveRun": handle })))
}

/// The attach operation shared by the REST route and its verb-table door.
pub(super) async fn attach_run_as(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    run: &str,
    rebind: bool,
) -> Result<String, FacadeApiError> {
    auth.require(CoreScope::Write)?;
    facade_actor(server, auth)?;
    // An attach is no owner act; its binding keeps the header-less surface.
    let surface = super::owner_binding::act_surface(auth);
    let bound = action_bound(server, auth, surface)?.ok_or_else(|| {
        FacadeApiError::forbidden(
            "a live run attaches the credential's own read key",
            ["Present a verified slip paired to the run's agent."],
        )
    })?;
    let run = EntityId::from_hex(run).map_err(|_| refused(LiveRunRefusal::Invalid))?;
    let caller = live_run_caller(&bound, auth);
    // OF-181: the run's guard, waited for briefly while an entry or an
    // action holds it, then held through the attach.
    let attaching = server
        .live_runs
        .attaching(run, caller)
        .await
        .map_err(refused)?;
    let runs = Arc::clone(&server.live_runs);
    let vault = Arc::clone(&server.vault);
    let handle = super::clock_ingress::run_blocking(move || runs.attach(&vault, attaching, rebind))
        .await
        .map_err(|_| internal())?
        .map_err(engine)?
        .map_err(refused)?;
    Ok(handle)
}

/// Binds `bound` to the live run that rendered a lens card, for an event on
/// it whose tool is a live-run verb (FIX 2652): `creator_run`, the card's
/// creating run, resolved for this credential only (the run's own agent,
/// attached to it now), as a `liveRun` handle resolves for an action. Its
/// answer is the event's key, namespaced as that run's action key. A card
/// no run rendered answers `live_run_unavailable`.
pub(super) fn bind_card_run(
    server: &SyncServer,
    auth: &CoreAuth,
    bound: &mut ActionBound,
    creator_run: Option<&str>,
    key: &str,
) -> Result<String, FacadeApiError> {
    let run = creator_run
        .and_then(|run| EntityId::from_hex(run).ok())
        .ok_or_else(|| refused(LiveRunRefusal::Unavailable))?;
    let run = server
        .live_runs
        .resolve_run(run, live_run_caller(bound, auth))
        .map_err(refused)?;
    let key = run.action_key(key).map_err(engine)?;
    bound.live_run = Some(run);
    Ok(key)
}

/// Who a live-run handle is attached to or resolved for: the credential's
/// actor, and its idempotency identity at its locality.
fn live_run_caller(bound: &ActionBound, auth: &CoreAuth) -> LiveRunCaller {
    LiveRunCaller {
        actor: bound.writes_as(),
        credential: LiveRunCredential::of(&auth.idempotency_principal(), auth.locality()),
    }
}

fn refused(refusal: LiveRunRefusal) -> FacadeApiError {
    FacadeApiError::new(
        refusal.status(),
        refusal.code(),
        refusal.message(),
        [refusal.suggestion()],
    )
}

/// Runs verb-table row `row` on `input` as one action under `bound`, as
/// `POST /v1/core/actions/<row>` runs it: the REST route whose write is the
/// row calls this. The row's JSON output; a refusal answers with the code,
/// words and suggestions the row's route refused with, a replayed one with
/// those its action's record kept.
pub(crate) async fn execute_facade_row<T: serde::Serialize>(
    server: &Arc<SyncServer>,
    headers: HeaderMap,
    extensions: Extensions,
    bound: ActionBound,
    row: AgentVerb,
    input: &T,
    idempotency_key: String,
) -> Result<serde_json::Value, FacadeApiError> {
    let input = action_json(input)?.ok_or_else(|| {
        FacadeApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            MEMORY_CODE_BAD_REQUEST,
            "the write is larger than one action argument",
            ["Send a smaller body."],
        )
    })?;
    let call = AgentActionCall {
        verb_id: SelfUiActionId::new(row.as_str()).map_err(engine)?,
        args: vec![ActionArgument::Json(input)],
        idempotency_key,
    };
    let dispatch = execute(server, headers, extensions, bound, None, call).await?;
    match dispatch.outcome {
        SelfDispatchOutcome::AgentVerb(answer) => Ok(answer.output),
        SelfDispatchOutcome::Denied(denied) => Err(match dispatch.refusal {
            Some(row) => {
                let suggestions: Vec<&str> = row.suggestions.iter().map(String::as_str).collect();
                let mut refusal = MemoryError::new(&row.code, row.message, &suggestions);
                refusal.reason_codes = row.reason_codes;
                refusal
            }
            None => MemoryError::new(&denied.outcome, "the action was refused", &[]),
        }
        .into()),
        SelfDispatchOutcome::Failed(failed) => Err(failed_outcome(row.as_str(), failed).into()),
        _ => Err(internal()),
    }
}

/// The error an action of `verb` answers for its `Failed` outcome (FIX
/// 5351). A live-run row fails on its run's own state (a team, a workflow, a
/// planner, a fold the run stands in), so its call answers `INVALID_STATE`
/// (409) with the run's words; any other row's failure stays `INTERNAL`.
pub(super) fn failed_outcome(verb: &str, failed: SelfFailedResult) -> MemoryError {
    if is_live_run_verb(verb) {
        MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            failed.error,
            &["Read the run's state, then call again once it allows the act."],
        )
    } else {
        MemoryError::new(MEMORY_CODE_INTERNAL, failed.error, &[])
    }
}

/// The action key of a REST write: the request's `Idempotency-Key`, bound to
/// the credential that sent it and to `row`, so a retry replays its action;
/// with none, a fresh key, as an unkeyed request is a fresh write.
pub(crate) fn rest_action_key(
    server: &SyncServer,
    auth: &CoreAuth,
    headers: &HeaderMap,
    row: AgentVerb,
) -> Result<String, FacadeApiError> {
    let Some(sent) = headers.get(crate::idempotency::IDEMPOTENCY_KEY_HEADER) else {
        return Ok(format!(
            "rest:{}:{}",
            row.as_str(),
            server.vault.new_entity_id().map_err(engine)?.to_hex()
        ));
    };
    let principal = auth.idempotency_principal();
    let mut hasher = blake3::Hasher::new();
    for part in [principal.as_bytes(), sent.as_bytes()] {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    Ok(format!(
        "rest:{}:{}",
        row.as_str(),
        hasher.finalize().to_hex()
    ))
}

fn app() -> Result<&'static SharedActionExecutor, FacadeApiError> {
    SharedActionExecutor::app().map_err(engine)
}

/// The action's engine failure as its caller reads it: a verb hook's stop on
/// one of its rows as that stop, as the row's own route answers it (FIX
/// 1450), any other failure as the engine's error.
fn engine(error: oneiron::Error) -> FacadeApiError {
    if matches!(error, oneiron::Error::VerbHook(_)) {
        return MemoryError::from(error).into();
    }
    crate::api::error_map::core_engine_error("action", error).into()
}

fn internal() -> FacadeApiError {
    FacadeApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        MEMORY_CODE_INTERNAL,
        "the action did not finish",
        ["Retry with the same idempotency key."],
    )
}
