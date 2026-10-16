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
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Request, State};
use axum::http::{Extensions, HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::actions::{ActionArgument, ActionHostBinding, AgentActionCall};
use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, RunCall, SelfAgentVerbCall,
};
use oneiron::lens::{LensPrincipalBinding, SelfUiActionId};
use oneiron::memory::{HostWriteOrigin, MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_INTERNAL};
use oneiron::task_verb::sdk::AgentVerb;
use oneiron::{EdgeActorClass, WriteActor};
use serde::Deserialize;
use tower::ServiceExt;

use super::{FacadeApiError, facade_actor, facade_input, facade_json, owner_authorship};
use crate::actions::SharedActionExecutor;
use crate::auth::{CoreAuth, CoreScope};
use crate::server::SyncServer;

pub(crate) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/v1/core/actions", get(list))
        .route("/v1/core/actions/{verb}", post(invoke))
}

/// One action call's body. The verb is the path's; the principal is the
/// credential's.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ActionRequest {
    args: Vec<ActionArgument>,
    idempotency_key: String,
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
    // A verb-table row that only reads needs only read; any other action is
    // an effect. The row's own route re-checks its scope in any case.
    let writes = AgentVerb::from_name(&verb).is_none_or(AgentVerb::writes);
    auth.require(if writes {
        CoreScope::Write
    } else {
        CoreScope::Read
    })?;
    let request: ActionRequest = facade_input(facade_json(payload)?)?;
    let verb_id = SelfUiActionId::new(verb).map_err(|_| {
        FacadeApiError::new(
            StatusCode::NOT_FOUND,
            MEMORY_CODE_BAD_REQUEST,
            "no action has this name",
            ["List the app's actions at GET /v1/core/actions."],
        )
    })?;
    let (actor, class) = facade_actor(&auth)?;
    let unbound = || {
        FacadeApiError::forbidden(
            "an action runs under the credential's own read key",
            ["Present a verified slip paired to this principal."],
        )
    };
    let proof = auth.verified_slip().ok_or_else(unbound)?;
    let key = server
        .vault
        .credential_read_key(proof)
        .map_err(engine)?
        .ok_or_else(unbound)?
        .at(auth.locality());
    let principal = match class {
        EdgeActorClass::Agent => {
            LensPrincipalBinding::agent_task(actor.to_hex(), key.clone(), vec![key])
        }
        _ => LensPrincipalBinding::human_view(actor.to_hex(), key.clone(), vec![key]),
    }
    .map_err(engine)?;
    let owner = owner_authorship(&auth, &server)?;
    let door: Arc<dyn AgentVerbDoor> = Arc::new(FacadeRowDoor::new(&server, headers, extensions));
    let call = AgentActionCall {
        verb_id,
        args: request.args,
        idempotency_key: request.idempotency_key,
    };
    let executor = app()?;
    let vault = Arc::clone(&server.vault);
    let dispatch = tokio::task::spawn_blocking(move || {
        let binding = ActionHostBinding {
            verb_door: Some(door),
            owner: owner.as_ref(),
        };
        executor.execute_call(
            &vault,
            WriteActor::new(actor, class),
            &principal,
            &call,
            binding,
        )
    })
    .await
    .map_err(|_| internal())?
    .map_err(engine)?;
    Ok(Json(serde_json::json!({
        "outcome": dispatch.outcome_value().map_err(engine)?,
        "readReceipt": dispatch.read_receipt,
    })))
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
struct FacadeRowDoor {
    rows: Router,
    headers: HeaderMap,
    extensions: Extensions,
    runtime: tokio::runtime::Handle,
}

impl FacadeRowDoor {
    fn new(server: &Arc<SyncServer>, headers: HeaderMap, extensions: Extensions) -> Self {
        Self {
            rows: super::recorded_facade_routes(Arc::clone(server)).with_state(Arc::clone(server)),
            headers,
            extensions,
            runtime: tokio::runtime::Handle::current(),
        }
    }

    /// The row's reply: its JSON on success, else its refusal's own code.
    async fn answer(rows: Router, request: Request) -> Result<serde_json::Value, AgentVerbRefusal> {
        let refused = || AgentVerbRefusal {
            code: MEMORY_CODE_INTERNAL.to_owned(),
        };
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
        Err(AgentVerbRefusal {
            code: body
                .pointer("/error/code")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(MEMORY_CODE_INTERNAL)
                .to_owned(),
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
        let output = receiver.recv().map_err(|_| refused())??;
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
    /// adds nothing to them.
    fn admit_run_call(
        &self,
        _call: RunCall,
    ) -> Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        Ok(None)
    }
}
