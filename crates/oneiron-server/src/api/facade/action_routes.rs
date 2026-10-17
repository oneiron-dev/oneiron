//! OF-181: the app's one action layer over HTTP, for both its callers.
//!
//! `GET /v1/core/actions` lists the verbs of the app's one table
//! ([`oneiron::code_run::actions::ActionRegistry::app`]). `POST
//! /v1/core/actions/{verb}` runs one as the credential's own principal: a
//! person's app button (a human view) or an agent's call (an agent task). The
//! credential binds the actor, the principal's read key and the owner proof;
//! the body names only the arguments and the idempotency key.
//!
//! A verb-table action runs through [`FacadeRowDoor`]: its row's generated
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
use std::sync::{Arc, Mutex, PoisonError};

use axum::Router;
use axum::body::Body;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Request, State};
use axum::http::{Extensions, HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::actions::{
    ActionArgument, ActionDispatch, ActionHostBinding, ActionJson, AgentActionCall,
};
use oneiron::code_run::live_run::{LiveRunCredential, is_live_run_verb};
use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, AgentVerbRefusalWords, RunCall,
    SelfAgentVerbCall, SelfDispatchOutcome, SelfEffect,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::lens::{GeneratedUiValidatedAction, LensPrincipalBinding, SelfUiActionId};
use oneiron::memory::{
    HostWriteOrigin, MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_INTERNAL, MemoryError,
};
use oneiron::task_verb::sdk::{AgentVerb, RunVerb};
use oneiron::{EdgeActorClass, EntityId, WriteActor};
use serde::Deserialize;
use tower::ServiceExt;

use super::{FacadeApiError, facade_actor, facade_input, facade_json, owner_authorship};
use crate::actions::SharedActionExecutor;
use crate::auth::{CoreAuth, CoreScope};
use crate::server::{HeldLiveRun, LiveRunCaller, LiveRunRefusal, ResolvedLiveRun, SyncServer};

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
struct ActionRequest {
    args: Vec<ActionArgument>,
    idempotency_key: String,
    /// The live run the action acts for (OF-181), as its attach answered.
    #[serde(default)]
    live_run: Option<String>,
}

async fn list(auth: CoreAuth) -> Result<Json<serde_json::Value>, FacadeApiError> {
    auth.require(CoreScope::Read)?;
    let actions: Vec<_> = app()?.definitions().collect();
    Ok(Json(serde_json::json!({ "actions": actions })))
}

async fn invoke(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(verb): Path<String>,
    headers: HeaderMap,
    extensions: Extensions,
    payload: Result<Json<serde_json::Value>, JsonRejection>,
) -> Result<Json<serde_json::Value>, FacadeApiError> {
    require_action_scope(&auth, &verb)?;
    let request: ActionRequest = facade_input(facade_json(payload)?)?;
    let verb_id = SelfUiActionId::new(verb).map_err(|_| {
        FacadeApiError::new(
            StatusCode::NOT_FOUND,
            MEMORY_CODE_BAD_REQUEST,
            "no action has this name",
            ["List the app's actions at GET /v1/core/actions."],
        )
    })?;
    // A credential that names no principal meets the facade's own refusal.
    facade_actor(&auth)?;
    let mut bound = action_bound(&server, &auth)?.ok_or_else(|| {
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
                .resolve(&handle, live_run_caller(&bound, &auth))
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
    let dispatch = execute(&server, headers, extensions, bound, call).await?;
    Ok(Json(serde_json::json!({
        "outcome": dispatch.outcome_value().map_err(engine)?,
        "readReceipt": dispatch.read_receipt,
    })))
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
    /// The live run the action acts for, resolved from its handle.
    live_run: Option<ResolvedLiveRun>,
}

/// What `auth` binds an action to. `None`: the credential names no
/// principal, or presents no verified slip with read authority, so no
/// action runs under it.
pub(crate) fn action_bound(
    server: &SyncServer,
    auth: &CoreAuth,
) -> Result<Option<ActionBound>, FacadeApiError> {
    let Ok((actor, class)) = facade_actor(auth) else {
        return Ok(None);
    };
    let Some(proof) = auth.verified_slip() else {
        return Ok(None);
    };
    let Some(key) = server.vault.credential_read_key(proof).map_err(engine)? else {
        return Ok(None);
    };
    Ok(Some(ActionBound {
        actor,
        class,
        key: key.at(auth.locality()),
        owner: owner_authorship(auth, server)?,
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
/// refused action is never written again another way.
pub(crate) fn rest_action_bound<T: serde::Serialize>(
    server: &SyncServer,
    auth: &CoreAuth,
    headers: &HeaderMap,
    input: &T,
) -> Result<Option<ActionBound>, FacadeApiError> {
    if headers.contains_key(super::ROOM_TURN_HEADER) {
        return Ok(None);
    }
    let Some(bound) = action_bound(server, auth)? else {
        return Ok(None);
    };
    Ok(action_json(input)?.map(|_| bound))
}

/// `input` as one structured action argument; `None` past its ceiling.
fn action_json<T: serde::Serialize>(input: &T) -> Result<Option<ActionJson>, FacadeApiError> {
    let value = serde_json::to_value(input).map_err(|_| internal())?;
    Ok(ActionJson::new(value).ok())
}

/// Runs `call` from the app's table under `bound`, its verb-table rows
/// through their own routes under this request's headers and connection.
async fn execute(
    server: &Arc<SyncServer>,
    headers: HeaderMap,
    extensions: Extensions,
    bound: ActionBound,
    call: AgentActionCall,
) -> Result<ActionDispatch, FacadeApiError> {
    let ActionBound {
        actor, class, key, ..
    } = &bound;
    let principal = match class {
        EdgeActorClass::Agent => {
            LensPrincipalBinding::agent_task(actor.to_hex(), key.clone(), vec![key.clone()])
        }
        EdgeActorClass::System => {
            LensPrincipalBinding::system_job(actor.to_hex(), key.clone(), vec![key.clone()])
        }
        EdgeActorClass::Human => {
            LensPrincipalBinding::human_view(actor.to_hex(), key.clone(), vec![key.clone()])
        }
    }
    .map_err(engine)?;
    run_bound(
        server,
        headers,
        extensions,
        bound,
        move |executor, vault, writer, binding| {
            executor.execute_call(vault, writer, &principal, &call, binding)
        },
    )
    .await
}

/// Runs a lens card's validated event under `bound`, as an action call
/// runs: its deterministic tool through the app's table, its verb-table row
/// through its own route under this request's headers and connection. The
/// event's emitter is the held frame's principal; `key` is its idempotency
/// key.
pub(super) async fn execute_validated_ui(
    server: &Arc<SyncServer>,
    headers: HeaderMap,
    extensions: Extensions,
    bound: ActionBound,
    event: GeneratedUiValidatedAction,
    key: String,
) -> Result<ActionDispatch, FacadeApiError> {
    run_bound(
        server,
        headers,
        extensions,
        bound,
        move |executor, vault, writer, binding| {
            executor.execute_ui_bound(vault, writer, &event, &key, binding)
        },
    )
    .await
}

/// Runs `run` on a blocking thread with the app's table, the vault, the
/// actor `bound` writes as, and its host binding: the verb door over this
/// request and the credential's read key, and the owner's proof.
async fn run_bound<F>(
    server: &Arc<SyncServer>,
    headers: HeaderMap,
    extensions: Extensions,
    bound: ActionBound,
    run: F,
) -> Result<ActionDispatch, FacadeApiError>
where
    F: FnOnce(
            &SharedActionExecutor,
            &oneiron::Vault,
            WriteActor,
            ActionHostBinding<'_>,
        ) -> oneiron::Result<ActionDispatch>
        + Send
        + 'static,
{
    let ActionBound {
        actor,
        class,
        key,
        owner,
        live_run,
    } = bound;
    let door: Arc<dyn AgentVerbDoor> =
        Arc::new(FacadeRowDoor::new(server, headers, extensions, key));
    let executor = app()?;
    // OF-181: the live run's guard, waited for briefly while an entry or
    // another action holds it, taken before the action and held through it,
    // with the run's lease read again under it.
    let held = match &live_run {
        Some(run) => Some(
            run.hold(&server.live_runs, &server.vault)
                .await
                .map_err(engine)?
                .map_err(refused)?,
        ),
        None => None,
    };
    let vault = Arc::clone(&server.vault);
    tokio::task::spawn_blocking(move || {
        let binding = ActionHostBinding {
            verb_door: Some(door),
            owner: owner.as_ref(),
            live_run: held.as_ref().map(HeldLiveRun::proof),
            planner: None,
        };
        run(executor, &vault, WriteActor::new(actor, class), binding)
    })
    .await
    .map_err(|_| internal())?
    .map_err(engine)
}

/// `POST /v1/core/live-runs/{run}/attach` (OF-181): attaches this credential
/// to the live run `run` and answers `{"liveRun": <handle>}`, to this caller
/// only. It needs the verified credential and write admission an action
/// needs, from the run's own agent, while the run's runner holds its lease.
async fn attach_live_run(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(run): Path<String>,
) -> Result<Json<serde_json::Value>, FacadeApiError> {
    auth.require(CoreScope::Write)?;
    facade_actor(&auth)?;
    let bound = action_bound(&server, &auth)?.ok_or_else(|| {
        FacadeApiError::forbidden(
            "a live run attaches the credential's own read key",
            ["Present a verified slip paired to the run's agent."],
        )
    })?;
    let run = EntityId::from_hex(&run).map_err(|_| refused(LiveRunRefusal::Invalid))?;
    let caller = live_run_caller(&bound, &auth);
    // OF-181: the run's guard, waited for briefly while an entry or an
    // action holds it, then held through the attach.
    let attaching = server
        .live_runs
        .attaching(run, caller)
        .await
        .map_err(refused)?;
    let runs = Arc::clone(&server.live_runs);
    let vault = Arc::clone(&server.vault);
    let handle = tokio::task::spawn_blocking(move || runs.attach(&vault, attaching))
        .await
        .map_err(|_| internal())?
        .map_err(engine)?
        .map_err(refused)?;
    Ok(Json(serde_json::json!({ "liveRun": handle })))
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
    let dispatch = execute(server, headers, extensions, bound, call).await?;
    match dispatch.outcome {
        SelfDispatchOutcome::AgentVerb(answer) => Ok(answer.output),
        SelfDispatchOutcome::Denied(denied) => Err(match dispatch.refusal {
            Some(row) => {
                let suggestions: Vec<&str> = row.suggestions.iter().map(String::as_str).collect();
                MemoryError::new(&row.code, row.message, &suggestions)
            }
            None => MemoryError::new(&denied.outcome, "the action was refused", &[]),
        }
        .into()),
        SelfDispatchOutcome::Failed(failed) => {
            Err(MemoryError::new(MEMORY_CODE_INTERNAL, failed.error, &[]).into())
        }
        _ => Err(internal()),
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

fn engine(error: oneiron::Error) -> FacadeApiError {
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

/// The verb door of one action call. Each verb-table row runs as its own
/// generated facade route, in process, under the request's own headers and
/// connection, so it meets exactly what a direct call of the row meets.
///
/// The row writes as the credential, as its direct call does: an action is
/// its caller's own call, not a run's generated write, so the run origin the
/// dispatcher offers is not the row's source.
///
/// A memory run row reads with `read_key`, the credential's own read key
/// at the caller's locality, which this request was admitted on.
///
/// A row's refusal keeps the words its route answered with in `refused`,
/// which the action's record keeps beside its code; the guest sees only the
/// code.
struct FacadeRowDoor {
    rows: Router,
    headers: HeaderMap,
    extensions: Extensions,
    runtime: tokio::runtime::Handle,
    read_key: ScopedReadActorKey,
    refused: Mutex<Option<AgentVerbRefusalWords>>,
}

/// A row that did not answer: no route words it.
fn unfinished() -> AgentVerbRefusalWords {
    AgentVerbRefusalWords {
        code: MEMORY_CODE_INTERNAL.to_owned(),
        message: "the action did not finish".to_owned(),
        suggestions: Vec::new(),
    }
}

impl FacadeRowDoor {
    fn new(
        server: &Arc<SyncServer>,
        headers: HeaderMap,
        extensions: Extensions,
        read_key: ScopedReadActorKey,
    ) -> Self {
        Self {
            rows: super::recorded_facade_routes(Arc::clone(server)).with_state(Arc::clone(server)),
            headers,
            extensions,
            runtime: tokio::runtime::Handle::current(),
            read_key,
            refused: Mutex::new(None),
        }
    }

    /// The row's reply: its JSON on success, else its refusal as answered.
    async fn answer(
        rows: Router,
        request: Request,
    ) -> Result<serde_json::Value, AgentVerbRefusalWords> {
        let refused = unfinished;
        let response = match rows.oneshot(request).await {
            Ok(response) => response,
            Err(never) => match never {},
        };
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .map_err(|_| refused())?;
        let body = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).map_err(|_| refused())?
        };
        if status.is_success() {
            return Ok(body);
        }
        let text = |pointer: &str| {
            body.pointer(pointer)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        };
        let fallback = unfinished();
        Err(AgentVerbRefusalWords {
            code: text("/error/code").unwrap_or(fallback.code),
            message: text("/error/message").unwrap_or(fallback.message),
            suggestions: body
                .pointer("/error/suggestions")
                .and_then(serde_json::Value::as_array)
                .map(|all| {
                    all.iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
        })
    }
}

impl FacadeRowDoor {
    /// Posts the row to its facade route. The step's invocation rides as
    /// `x-oneiron-invocation`, so the route's verb hooks fire once for it.
    fn post_row(
        &self,
        call: &SelfAgentVerbCall,
        invocation: oneiron::runtime_hooks::InvocationId,
    ) -> Result<AgentVerbAnswer, AgentVerbRefusal> {
        let refused = || AgentVerbRefusal {
            code: MEMORY_CODE_INTERNAL.to_owned(),
        };
        let body = serde_json::to_vec(&call.input).map_err(|_| refused())?;
        let mut request = axum::http::Request::post(format!("/{}", call.verb.as_str()))
            .body(Body::from(body))
            .map_err(|_| refused())?;
        *request.headers_mut() = self.headers.clone();
        request.headers_mut().remove(header::CONTENT_LENGTH);
        if let Ok(value) = HeaderValue::from_str(&invocation.to_hex()) {
            request.headers_mut().insert("x-oneiron-invocation", value);
        }
        request.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        *request.extensions_mut() = self.extensions.clone();
        // The dispatcher holds this blocking thread while the row runs on
        // the server runtime, as a request of its own would.
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let rows = self.rows.clone();
        self.runtime.spawn(async move {
            let _ = sender.send(Self::answer(rows, request).await);
        });
        let output = receiver.recv().map_err(|_| refused())?.map_err(|row| {
            let code = row.code.clone();
            *self.refused.lock().unwrap_or_else(PoisonError::into_inner) = Some(row);
            AgentVerbRefusal { code }
        })?;
        Ok(AgentVerbAnswer { output, rows: None })
    }
}

impl AgentVerbDoor for FacadeRowDoor {
    fn call(
        &self,
        call: &SelfAgentVerbCall,
        _origin: &HostWriteOrigin,
        invocation: oneiron::runtime_hooks::InvocationId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        Ok(self.post_row(call, invocation))
    }

    /// The typed actions keep their own ceiling and owner proof; this door
    /// adds nothing to them. A search reads on the credential's lane, and an
    /// edge's target is placed only when that lane reads it (DEC-0005).
    fn admit_run_call(
        &self,
        call: RunCall,
    ) -> Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        Ok(matches!(
            call,
            RunCall::Bridge(SelfEffect::MemorySearch | SelfEffect::MemoryPutEdge)
        )
        .then(|| self.read_key.clone()))
    }

    fn refusal_words(&self) -> Option<AgentVerbRefusalWords> {
        self.refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}
