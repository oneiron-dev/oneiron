//! JSON-RPC envelope types and request dispatch.

use super::{
    ensure_mcp_actor_matches, execute_mcp_tool, mcp_actor_result, mcp_admit_scoped_call,
    mcp_error_response, mcp_params, mcp_validated_call_args, resolve_mcp_gateway_actor,
};
use crate::api::facade::{self, DoorClaim};
use crate::auth::Locality;
use crate::mcp::McpCacheHint;
use crate::mcp::McpPageBudget;
use crate::mcp::McpResolvedActor;
use crate::mcp::McpResultMetadata;
use crate::mcp::McpRetrievalHealth;
use crate::mcp::McpSurfaceMode;
use crate::server::SyncServer;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::header::AUTHORIZATION;
use axum::http::{Extensions, HeaderMap, HeaderValue};
use axum::response::IntoResponse;
use axum::response::Json;
use axum::response::Response;
use oneiron::claim::CallerLocality;
use oneiron::runtime_hooks::InvocationId;
use oneiron::runtime_hooks::verb::InvocationOutcome;
use serde::Deserialize;
use serde_json::Value;
use serde_json::json;
use std::sync::Arc;

pub(crate) const MCP_CREDENTIAL_HEADER: &str = "x-oneiron-mcp-credential";

pub(crate) const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

#[derive(Debug, Deserialize)]
pub(crate) struct McpJsonRpcRequest {
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct McpToolCallParams {
    pub(super) name: String,
    #[serde(default)]
    pub(super) arguments: Value,
    /// The call's MCP metadata; `oneiron/invocation` names the logical verb
    /// its verb hooks fire once for (ARCH-0080 §3).
    #[serde(default, rename = "_meta")]
    pub(super) meta: Option<serde_json::Map<String, Value>>,
}

/// The `_meta` key a `tools/call` names its invocation under: 32 hex digits.
pub(crate) const MCP_INVOCATION_META: &str = "oneiron/invocation";

impl McpToolCallParams {
    /// The invocation the call names in `_meta`, if any.
    fn invocation(&self) -> Result<Option<oneiron::runtime_hooks::InvocationId>, McpGatewayError> {
        let Some(named) = self
            .meta
            .as_ref()
            .and_then(|meta| meta.get(MCP_INVOCATION_META))
        else {
            return Ok(None);
        };
        named
            .as_str()
            .and_then(oneiron::runtime_hooks::InvocationId::parse_hex)
            .map(Some)
            .ok_or_else(|| {
                McpGatewayError::new(
                    -32602,
                    "tool_args_invalid",
                    "_meta.oneiron/invocation is 32 lowercase hex digits",
                )
                .with_field("_meta")
            })
    }
}

#[derive(Debug)]
pub(crate) struct McpGatewayError {
    pub(super) code: i64,
    pub(super) kind: &'static str,
    pub(super) message: String,
    pub(super) field: Option<String>,
    pub(super) vault_read: Option<Box<oneiron::code_run::vault_read::VaultReadError>>,
    /// Set only by the stale-write-verb-target refusal (ONE-1936); surfaces as
    /// `error.data.successor_short_id` so a client reads a FIELD instead of
    /// parsing the message.
    pub(super) successor_short_id: Option<String>,
    /// The effective scope the refusal was made under, present for every
    /// actor-derived error (ONE-1704). Absent only before a credential
    /// resolves, where there is no scope yet to state.
    // Boxed for SIZE only: inline, this one payload made the whole error 168
    // bytes, so every `Result<_, McpGatewayError>` in this module carried it.
    // The indirection is private — `mcp_error_response` moves the same `Value`
    // back out under the same key, so nothing on the wire moves.
    pub(super) effective_scope: Option<Box<Value>>,
    /// The bound a request field passed and the bytes it carried, surfaced
    /// as `error.data.max_bytes` and `error.data.received_bytes`. Boxed for
    /// size, as `effective_scope` is.
    pub(super) byte_bound: Option<Box<(usize, usize)>>,
    /// A `WRONG_ROOT` refusal's correction, surfaced as `error.data.attempted`,
    /// `error.data.replacement` and `error.data.schemaRef`.
    pub(super) wrong_root: Option<Box<oneiron::memory::MemoryWrongRoot>>,
    /// The refused `tools/call`'s lasting receipt (OF-538), surfaced as
    /// `error.data.receipt_ref` (and `error.data.no_record` for the anonymous
    /// exception). Boxed for size, as `effective_scope` is.
    pub(super) call_receipt: Option<Box<crate::api::call_receipt::CallStamp>>,
    /// A verb hook's stop (ARCH-0080 §3), surfaced as `error.data.hook`; a
    /// code-mode door hands it back to the run as the typed stop.
    pub(super) hook: Option<Box<oneiron::runtime_hooks::VerbHookStop>>,
}

impl McpGatewayError {
    pub(super) fn new(code: i64, kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            kind,
            message: message.into(),
            field: None,
            vault_read: None,
            successor_short_id: None,
            effective_scope: None,
            byte_bound: None,
            wrong_root: None,
            call_receipt: None,
            hook: None,
        }
    }

    /// A request field past a byte bound (`[limits]`): the typed tool error
    /// names the field, the bound and the bytes received.
    pub(super) fn payload_too_large(
        field: impl Into<String>,
        max_bytes: usize,
        received_bytes: usize,
    ) -> Self {
        let mut error = Self::new(
            -32602,
            "payload_too_large",
            "a request field exceeds its byte bound",
        )
        .with_field(field);
        error.byte_bound = Some(Box::new((max_bytes, received_bytes)));
        error
    }

    pub(super) fn with_field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
    }

    pub(super) fn with_successor_short_id(mut self, successor_short_id: impl Into<String>) -> Self {
        self.successor_short_id = Some(successor_short_id.into());
        self
    }

    fn with_effective_scope(mut self, actor: &McpResolvedActor) -> Self {
        self.effective_scope = Some(Box::new(crate::mcp::mcp_effective_scope_value(
            &actor.scope,
        )));
        self
    }
}

/// One request's actor plus the endpoint it arrived on.
///
/// The mode is REGISTRATION state carried down from the route, never something
/// the request could select. Everything that already spoke `McpResolvedActor`
/// still does, through `Deref`.
#[derive(Clone, Debug)]
pub(crate) struct McpCallContext {
    pub(crate) actor: McpResolvedActor,
    pub(crate) mode: McpSurfaceMode,
    pub(crate) request_id: String,
    /// Where this request's writes land (`write_facet::landing_facet`),
    /// judged once from the session it names.
    pub(crate) landing: Result<Option<oneiron::EntityId>, crate::api::write_facet::LandingRefused>,
    /// The logical verb this request runs, when it named one: its verb hooks
    /// fire once for it, however many wrappers it crosses (ARCH-0080 §3).
    pub(crate) invocation: Option<oneiron::runtime_hooks::InvocationId>,
    /// The off-record session the request names, bound to its rows' memory
    /// surface: inside an anonymous one a reference refusal writes no
    /// receipt, as the call writes none (OF-063, OF-538).
    pub(crate) off_record_session: Option<String>,
    /// The room the request's room turn names (`x-oneiron-room-turn`), as
    /// the facade reads it: the room the caller's board renders as ROOM and
    /// reads its MEMORIES in, once the caller's own read admits it (FIX
    /// 1051). Never guessed from anything else.
    pub(crate) room_turn: Option<oneiron::EntityId>,
    /// The drain's permit, on a call settlement runs again (ARCH-0080 §3
    /// Ask): its row's pre chain enters as the drain's run of it. Never a
    /// request's.
    pub(crate) drain: Option<oneiron::runtime_hooks::verb::VerbAskDrainPermit>,
}

impl std::ops::Deref for McpCallContext {
    type Target = McpResolvedActor;

    fn deref(&self) -> &Self::Target {
        &self.actor
    }
}

impl McpCallContext {
    /// The closed metadata envelope for one result on this endpoint.
    pub(super) fn metadata(
        &self,
        health: McpRetrievalHealth,
        page: McpPageBudget,
        help: Vec<String>,
        cache: Option<McpCacheHint>,
    ) -> Value {
        // The facet a write lands in rides the result's scope.
        let mut scope = self.actor.scope.clone();
        if let Ok(Some(facet)) = self.landing {
            scope.facet_ref = Some(facet);
        }
        McpResultMetadata::new(
            self.request_id.clone(),
            self.mode,
            scope,
            health,
            page,
            help,
            cache,
        )
        .to_value()
    }
}

/// The PRIMARY endpoint: the truthful `setup_oneiron` catalog. `execute_code`
/// is not registered in this release; direct requests receive its typed
/// unavailable refusal at the shared name-resolution door. `connection` is
/// the request's own (its peer, the machine its binding proved): an action's
/// rows run under it.
pub(crate) async fn mcp_gateway(
    headers: HeaderMap,
    Locality(locality): Locality,
    State(server): State<Arc<SyncServer>>,
    connection: Extensions,
    body: Bytes,
) -> impl IntoResponse {
    mcp_endpoint(
        McpSurfaceMode::Primary,
        headers,
        locality,
        connection,
        server,
        body,
    )
    .await
}

/// The TOOL-FIRST endpoint: one generated tool per exported verb row.
///
/// A separately registered host endpoint, not a mode switch: nothing on the
/// wire moves a connection between this router entry and the primary one.
pub(crate) async fn mcp_tool_first_gateway(
    headers: HeaderMap,
    Locality(locality): Locality,
    State(server): State<Arc<SyncServer>>,
    connection: Extensions,
    body: Bytes,
) -> impl IntoResponse {
    mcp_endpoint(
        McpSurfaceMode::ToolFirst,
        headers,
        locality,
        connection,
        server,
        body,
    )
    .await
}

/// A reply no `tools/call` receipt covers is its connection's (FIX 811): a
/// parse or envelope error, an invocation claim's refusal, `initialize`,
/// `tools/list`, `oneiron/wakes`, an unknown method, and a `tools/call`
/// refused before its credential resolved. A refusal states the ref in
/// `error.data.receipt_ref`, as a refused call does; every such reply states
/// it in `x-oneiron-receipt-ref`. A result's body is left as it is, so
/// `tools/list` stays the same bytes for every credential.
fn mcp_connection_stamp(
    server: &SyncServer,
    headers: &HeaderMap,
    method: &str,
    body: &[u8],
    answered: &mut Result<Value, McpGatewayError>,
) -> crate::api::call_receipt::CallStamp {
    let (outcome, result_digest) = match &*answered {
        Ok(result) => (
            oneiron::receipt::CallOutcome::Ok,
            Some(oneiron::receipt::call_json_digest(result)),
        ),
        Err(error) => (
            oneiron::receipt::CallOutcome::Refused {
                code: error.kind.to_owned(),
            },
            Some(oneiron::receipt::call_refusal_digest(
                error.kind,
                &error.message,
            )),
        ),
    };
    let anonymous = crate::api::call_receipt::in_anonymous_session(server, headers, None);
    let stamp = crate::api::call_receipt::record(
        server,
        anonymous,
        crate::api::call_receipt::connection_call(
            oneiron::receipt::CallTransport::Mcp,
            method.to_owned(),
            outcome,
            oneiron::receipt::call_bytes_digest(body),
            result_digest,
        ),
    );
    if let Err(error) = answered {
        error.call_receipt = Some(Box::new(stamp.clone()));
    }
    stamp
}

/// One JSON-RPC reply: its result, or its error.
fn mcp_envelope(id: Value, answered: Result<Value, McpGatewayError>) -> Value {
    match answered {
        Ok(result) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result,
        }),
        Err(error) => mcp_error_response(id, error),
    }
}

/// The HTTP reply: a connection's receipt in `x-oneiron-receipt-ref`, or,
/// for a reply a `tools/call` receipt covers (or a replay of one), the mark
/// that its door answered it.
fn mcp_http_reply(reply: Value, stamp: Option<&crate::api::call_receipt::CallStamp>) -> Response {
    let mut response = Json(reply).into_response();
    match stamp {
        Some(stamp) => stamp.stamp_header(&mut response),
        None => {
            response
                .extensions_mut()
                .insert(crate::api::call_receipt::DoorAnswered);
        }
    }
    response
}

/// An envelope refused before any method ran, as its connection's reply.
fn mcp_connection_refusal(
    server: &SyncServer,
    headers: &HeaderMap,
    method: &str,
    body: &[u8],
    id: Value,
    error: McpGatewayError,
) -> Response {
    let mut refused = Err(error);
    let stamp = mcp_connection_stamp(server, headers, method, body, &mut refused);
    mcp_http_reply(mcp_envelope(id, refused), Some(&stamp))
}

async fn mcp_endpoint(
    mode: McpSurfaceMode,
    headers: HeaderMap,
    locality: CallerLocality,
    connection: Extensions,
    server: Arc<SyncServer>,
    body: Bytes,
) -> Response {
    let raw: Value = match serde_json::from_slice(&body) {
        Ok(raw) => raw,
        Err(error) => {
            return mcp_connection_refusal(
                &server,
                &headers,
                "mcp",
                &body,
                Value::Null,
                McpGatewayError::new(-32700, "parse_error", error.to_string()),
            );
        }
    };
    let id = raw.get("id").cloned().unwrap_or(Value::Null);
    let request = match serde_json::from_value::<McpJsonRpcRequest>(raw) {
        Ok(request) => request,
        Err(error) => {
            return mcp_connection_refusal(
                &server,
                &headers,
                "mcp",
                &body,
                id,
                McpGatewayError::new(-32600, "invalid_request", error.to_string()),
            );
        }
    };
    let id = request.id.clone().unwrap_or(id);

    // The envelope above is routed from a `Value`, which rounds a JSON number
    // through `f64`. Tool arguments are decoded against the ADVERTISED schema
    // instead, so their ORIGINAL spelling is read back out of the request bytes
    // and carried to that decoder unrounded (ONE-1704 repair).
    let raw_arguments = crate::mcp::mcp_raw_call_arguments(&body);
    // A `tools/call` that names its invocation claims it for the whole
    // request (OF-580): a second call naming it for the same call waits for
    // this one's reply and gets it, under its own id; one naming it for
    // another call is refused at once.
    let claim = match mcp_named_invocation(&request) {
        None => None,
        Some(invocation) => {
            let call =
                mcp_invocation_body(mode, locality, &headers, &request, raw_arguments.as_deref());
            match facade::claim_door_invocation(&server, invocation, call).await {
                DoorClaim::Run(claim) => Some(claim),
                DoorClaim::Answered(outcome) => {
                    let mut reply = outcome.body;
                    if let Some(reply) = reply.as_object_mut() {
                        reply.insert("id".to_owned(), id);
                    }
                    // The replay states the first call's receipt.
                    return mcp_http_reply(reply, None);
                }
                DoorClaim::InFlight => {
                    return mcp_connection_refusal(
                        &server,
                        &headers,
                        &request.method,
                        &body,
                        id,
                        McpGatewayError::new(
                            -32020,
                            facade::INVOCATION_IN_FLIGHT,
                            "another request is still running this invocation; retry with it once the first call returns",
                        ),
                    );
                }
                DoorClaim::Conflict => {
                    return mcp_connection_refusal(
                        &server,
                        &headers,
                        &request.method,
                        &body,
                        id,
                        McpGatewayError::new(
                            -32020,
                            facade::INVOCATION_CONFLICT,
                            "this invocation id names a different call",
                        ),
                    );
                }
            }
        }
    };
    let method = request.method.clone();
    let mut result = handle_mcp_request(
        mode,
        &headers,
        locality,
        &connection,
        &server,
        request,
        raw_arguments.as_deref(),
    )
    .await;
    // A `tools/call` that reached its door carries its own receipt; every
    // other reply is the connection's (FIX 811).
    let covered = match &result {
        Ok(_) => method == "tools/call",
        Err(error) => error.call_receipt.is_some(),
    };
    let stamp =
        (!covered).then(|| mcp_connection_stamp(&server, &headers, &method, &body, &mut result));
    let reply = mcp_envelope(id, result);
    if let Some(claim) = claim {
        let mut saved = reply.clone();
        if let Some(saved) = saved.as_object_mut() {
            saved.remove("id");
        }
        claim.finish(InvocationOutcome {
            status: 200,
            body: saved,
        });
    }
    mcp_http_reply(reply, stamp.as_ref())
}

/// The invocation a `tools/call` names in `_meta`, when it names a valid
/// one; a malformed one is left to the call's own refusal.
fn mcp_named_invocation(request: &McpJsonRpcRequest) -> Option<InvocationId> {
    if request.method != "tools/call" {
        return None;
    }
    request
        .params
        .as_ref()?
        .get("_meta")?
        .get(MCP_INVOCATION_META)?
        .as_str()
        .and_then(InvocationId::parse_hex)
}

/// The call a claimed MCP invocation names: the endpoint, the credential
/// headers and session the actor resolves from, where the caller sits, and
/// the call itself.
fn mcp_invocation_body(
    mode: McpSurfaceMode,
    locality: CallerLocality,
    headers: &HeaderMap,
    request: &McpJsonRpcRequest,
    raw_arguments: Option<&str>,
) -> [u8; 32] {
    let header = |name: &str| headers.get(name).map_or(&[][..], HeaderValue::as_bytes);
    let params =
        oneiron::receipt::call_json_digest(request.params.as_ref().unwrap_or(&Value::Null));
    facade::invocation_body(
        None,
        locality,
        &[
            b"mcp".as_slice(),
            mode.as_str().as_bytes(),
            header(MCP_CREDENTIAL_HEADER),
            header(AUTHORIZATION.as_str()),
            header(crate::api::write_facet::SESSION_HEADER),
            request.method.as_bytes(),
            params.as_bytes(),
            raw_arguments.unwrap_or_default().as_bytes(),
        ],
    )
}

/// OF-538's one MCP door: records a `tools/call` once it has answered, in its
/// own write transaction, and states the receipt on the reply, success or
/// refusal alike: `structuredContent.meta.receipt_ref` on a result,
/// `error.data.receipt_ref` on a refusal. A call inside an anonymous
/// off-record session records nothing and states `receipt_ref: null` with
/// `no_record: true`.
fn mcp_call_receipt(
    server: &SyncServer,
    actor: &McpResolvedActor,
    tool: String,
    request_digest: String,
    inputs: Option<oneiron::receipt::ActionInputs>,
    anonymous: bool,
    called: Result<Value, McpGatewayError>,
) -> Result<Value, McpGatewayError> {
    let (outcome, result_digest) = match &called {
        // A `reveal.wait` reply is digested with its value masked (OF-560).
        Ok(result) => (
            oneiron::receipt::CallOutcome::Ok,
            Some(oneiron::receipt::call_json_digest(
                oneiron::task_verb::sdk::masked_reveal_reply(&tool, result)
                    .as_ref()
                    .unwrap_or(result),
            )),
        ),
        Err(error) => (
            oneiron::receipt::CallOutcome::Refused {
                code: error.kind.to_owned(),
            },
            Some(oneiron::receipt::call_refusal_digest(
                error.kind,
                &error.message,
            )),
        ),
    };
    let stamp = crate::api::call_receipt::record(
        server,
        anonymous,
        oneiron::receipt::CallReceiptInput {
            transport: oneiron::receipt::CallTransport::Mcp,
            verb: tool,
            actor_ref: actor.actor_ref.to_hex(),
            actor_class: actor.actor_class.gate_actor_class().to_owned(),
            credential_ref: actor
                .auth
                .as_ref()
                .and_then(crate::api::call_receipt::credential_ref),
            outcome,
            request_digest,
            result_digest,
            inputs,
            served: Vec::new(),
        },
    );
    match called {
        Ok(mut result) => {
            crate::mcp::mcp_stamp_call_receipt(&mut result, &stamp);
            Ok(result)
        }
        Err(mut error) => {
            error.call_receipt = Some(Box::new(stamp));
            Err(error)
        }
    }
}

/// The stable request id a result or refusal is keyed by.
pub(super) fn mcp_request_id(id: &Value) -> String {
    match id {
        Value::String(id) => id.clone(),
        Value::Null => "null".to_owned(),
        other => other.to_string(),
    }
}

pub(crate) async fn handle_mcp_request(
    mode: McpSurfaceMode,
    headers: &HeaderMap,
    locality: CallerLocality,
    connection: &Extensions,
    server: &Arc<SyncServer>,
    request: McpJsonRpcRequest,
    raw_arguments: Option<&str>,
) -> Result<Value, McpGatewayError> {
    if request.jsonrpc != "2.0" {
        return Err(
            McpGatewayError::new(-32600, "invalid_request", "jsonrpc must be \"2.0\"")
                .with_field("jsonrpc"),
        );
    }
    let request_id = mcp_request_id(request.id.as_ref().unwrap_or(&Value::Null));

    match request.method.as_str() {
        "initialize" => {
            let actor =
                resolve_mcp_gateway_actor(mode, &request_id, headers, locality, server).await?;
            // It states the credential's scope, so it is released as every
            // result is (DEC-0005).
            let result = json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "serverInfo": {
                    "name": crate::mcp::MCP_SERVER_NAME,
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "capabilities": {
                    "tools": { "listChanged": false },
                },
                "surfaceMode": mode.as_str(),
                "executeCodeAdmitted": matches!(mode, McpSurfaceMode::Primary)
                    && super::admission::mcp_execute_code_admitted(server, &actor),
                "instructions": "Oneiron MCP exposes foreign-client tools over the same read and write Gate as the REST core surface. Use tools/list for the tools THIS endpoint registered and tools/call to call one. A call runs as this credential's actor; it need not name one, and an actor block that names anyone else is refused.",
                "actor": mcp_actor_result(&actor),
            });
            super::device_release::mcp_release_result(server, &actor, &[], false, result)
        }
        "notifications/initialized" => Ok(json!({})),
        "oneiron/wakes" => {
            let actor =
                resolve_mcp_gateway_actor(mode, &request_id, headers, locality, server).await?;
            super::wakes::poll(server, &actor, request.params).await
        }
        // Deliberately actor-free: a listing that echoed the caller back would
        // not be byte-identical across credentials, and the whole point of an
        // immutable registration is that it is the same bytes for everyone.
        // The credential is still REQUIRED, just never reflected.
        "tools/list" => {
            let _actor =
                resolve_mcp_gateway_actor(mode, &request_id, headers, locality, server).await?;
            Ok(json!({
                "surfaceMode": mode.as_str(),
                "tools": server.mcp_surface(mode).listing(),
            }))
        }
        "tools/call" => {
            let actor =
                resolve_mcp_gateway_actor(mode, &request_id, headers, locality, server).await?;
            // OF-538: what the call's receipt states of its request, taken
            // before the params are consumed.
            let tool = request
                .params
                .as_ref()
                .and_then(|params| params.get("name"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let request_digest =
                oneiron::receipt::call_json_digest(request.params.as_ref().unwrap_or(&Value::Null));
            // OF-568: what the call reads, captured before it runs.
            let inputs =
                crate::api::call_receipt::action_inputs(server, &tool, request.params.as_ref());
            // OF-063: only a caller whose principal is verified in the
            // session keeps no record, judged on arrival and again before the
            // receipt is written. The configured root maps to the actor it
            // acts through (FIX 2271), the one its rows' surfaces bind.
            let principal = crate::api::call_receipt::mcp_session_principal(
                actor.auth.as_ref(),
                actor.actor_ref,
            );
            let anonymous =
                crate::api::call_receipt::in_anonymous_session(server, headers, principal);
            let called: Result<Value, McpGatewayError> = async {
                let params: McpToolCallParams = mcp_params(request.params, "params")?;
                let actor = McpCallContext {
                    invocation: params.invocation()?,
                    ..actor.clone()
                };
                let args = mcp_validated_call_args(server, mode, params, raw_arguments, &actor)?;
                ensure_mcp_actor_matches(&args, &actor)?;
                mcp_admit_scoped_call(server, &args, &actor)?;
                execute_mcp_tool(server, args, &actor, headers, connection).await
            }
            .await;
            // ONE-1704 M4: ONE chokepoint. Everything inside that block happened
            // AFTER the credential resolved, so every refusal it can produce —
            // decode, validation, actor mismatch, bound-verb or scope refusal,
            // scoped-grant refusal, board/task dispatch, projection, facade, or
            // engine failure — leaves with the effective scope attached. Only
            // failures before this point are legitimately scope-less. Each is
            // released as a result is, by the rows its words and its scope
            // name (DEC-0005).
            let called = called.map_err(|error| {
                super::device_release::mcp_release_error(
                    server,
                    &actor,
                    Some(&[]),
                    error.with_effective_scope(&actor),
                )
            });
            let anonymous = anonymous
                || crate::api::call_receipt::in_anonymous_session(server, headers, principal);
            mcp_call_receipt(
                server,
                &actor,
                tool,
                request_digest,
                inputs,
                anonymous,
                called,
            )
        }
        _ => Err(McpGatewayError::new(
            -32601,
            "method_not_found",
            format!("unsupported MCP method {}", request.method),
        )
        .with_field("method")),
    }
}
