use super::CORE_MAX_LIST_LIMIT;
use super::hydrate_short_id_response;
use super::parse_entity_id_param;
use super::parse_short_ref;
use super::unix_seconds_now;
use crate::error::ApiError;
use crate::error::ApiErrorDetails;
use crate::error::ErrorCode;
use crate::mcp::McpActorClass;
use crate::mcp::McpActorMetadata;
use crate::mcp::McpAskToolArgs;
use crate::mcp::McpCacheHint;
use crate::mcp::McpConnectorActorResolutionError;
use crate::mcp::McpEditToolArgs;
use crate::mcp::McpEditVerb;
use crate::mcp::McpPageBudget;
use crate::mcp::McpPageCursorState;
use crate::mcp::McpPageSnapshot;
use crate::mcp::McpResolvedActor;
use crate::mcp::McpResultMetadata;
use crate::mcp::McpRetrievalHealth;
use crate::mcp::McpRoutedAskToolArgs;
use crate::mcp::McpSurfaceMode;
use crate::mcp::McpToolName;
use crate::mcp::McpToolValidationError;
use crate::mcp::McpValidatedToolArgs;
use crate::mcp::McpVerbToolArgs;
use crate::projection;
use crate::projection::View;
use crate::server::SyncServer;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use axum::response::IntoResponse;
use axum::response::Json;
use oneiron::EdgeKind;
use oneiron::ErrorKind;
use serde::Deserialize;
use serde::de::DeserializeOwned;
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
    name: String,
    #[serde(default)]
    arguments: Value,
}

#[derive(Debug)]
pub(crate) struct McpGatewayError {
    code: i64,
    kind: &'static str,
    message: String,
    field: Option<String>,
    /// Set only by the stale-write-verb-target refusal (ONE-1936); surfaces as
    /// `error.data.successor_short_id` so a client reads a FIELD instead of
    /// parsing the message.
    successor_short_id: Option<String>,
    /// The effective scope the refusal was made under, present for every
    /// actor-derived error (ONE-1704). Absent only before a credential
    /// resolves, where there is no scope yet to state.
    // Boxed for SIZE only: inline, this one payload made the whole error 168
    // bytes, so every `Result<_, McpGatewayError>` in this module carried it.
    // The indirection is private — `mcp_error_response` moves the same `Value`
    // back out under the same key, so nothing on the wire moves.
    effective_scope: Option<Box<Value>>,
}

impl McpGatewayError {
    fn new(code: i64, kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            kind,
            message: message.into(),
            field: None,
            successor_short_id: None,
            effective_scope: None,
        }
    }

    fn with_field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
    }

    fn with_successor_short_id(mut self, successor_short_id: impl Into<String>) -> Self {
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
#[derive(Debug)]
pub(crate) struct McpCallContext {
    pub(crate) actor: McpResolvedActor,
    pub(crate) mode: McpSurfaceMode,
    pub(crate) request_id: String,
}

impl std::ops::Deref for McpCallContext {
    type Target = McpResolvedActor;

    fn deref(&self) -> &Self::Target {
        &self.actor
    }
}

impl McpCallContext {
    /// The closed metadata envelope for one result on this endpoint.
    fn metadata(
        &self,
        health: McpRetrievalHealth,
        page: McpPageBudget,
        help: Vec<String>,
        cache: Option<McpCacheHint>,
    ) -> Value {
        McpResultMetadata::new(
            self.request_id.clone(),
            self.mode,
            self.actor.scope.clone(),
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
/// unavailable refusal at the shared name-resolution door.
pub(crate) async fn mcp_gateway(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    body: Bytes,
) -> impl IntoResponse {
    mcp_endpoint(McpSurfaceMode::Primary, headers, server, body).await
}

/// The TOOL-FIRST endpoint: one generated tool per exported verb row.
///
/// A separately registered host endpoint, not a mode switch: nothing on the
/// wire moves a connection between this router entry and the primary one.
pub(crate) async fn mcp_tool_first_gateway(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    body: Bytes,
) -> impl IntoResponse {
    mcp_endpoint(McpSurfaceMode::ToolFirst, headers, server, body).await
}

async fn mcp_endpoint(
    mode: McpSurfaceMode,
    headers: HeaderMap,
    server: Arc<SyncServer>,
    body: Bytes,
) -> Json<Value> {
    let raw: Value = match serde_json::from_slice(&body) {
        Ok(raw) => raw,
        Err(error) => {
            return Json(mcp_error_response(
                Value::Null,
                McpGatewayError::new(-32700, "parse_error", error.to_string()),
            ));
        }
    };
    let id = raw.get("id").cloned().unwrap_or(Value::Null);
    let request = match serde_json::from_value::<McpJsonRpcRequest>(raw) {
        Ok(request) => request,
        Err(error) => {
            return Json(mcp_error_response(
                id,
                McpGatewayError::new(-32600, "invalid_request", error.to_string()),
            ));
        }
    };
    let id = request.id.clone().unwrap_or(id);

    // The envelope above is routed from a `Value`, which rounds a JSON number
    // through `f64`. Tool arguments are decoded against the ADVERTISED schema
    // instead, so their ORIGINAL spelling is read back out of the request bytes
    // and carried to that decoder unrounded (ONE-1704 repair).
    let raw_arguments = crate::mcp::mcp_raw_call_arguments(&body);
    let result =
        handle_mcp_request(mode, &headers, &server, request, raw_arguments.as_deref()).await;
    Json(match result {
        Ok(result) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result,
        }),
        Err(error) => mcp_error_response(id, error),
    })
}

/// The stable request id a result or refusal is keyed by.
fn mcp_request_id(id: &Value) -> String {
    match id {
        Value::String(id) => id.clone(),
        Value::Null => "null".to_owned(),
        other => other.to_string(),
    }
}

pub(crate) async fn handle_mcp_request(
    mode: McpSurfaceMode,
    headers: &HeaderMap,
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
            let actor = resolve_mcp_gateway_actor(mode, &request_id, headers, server).await?;
            Ok(json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "serverInfo": {
                    "name": crate::mcp::MCP_SERVER_NAME,
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "capabilities": {
                    "tools": { "listChanged": false },
                },
                "surfaceMode": mode.as_str(),
                "instructions": "Oneiron MCP exposes foreign-client tools over the same read and write Gate as the REST core surface. Use tools/list for the tools THIS endpoint registered and tools/call with connector actor metadata matching this authenticated credential.",
                "actor": mcp_actor_result(&actor),
            }))
        }
        "notifications/initialized" => Ok(json!({})),
        // Deliberately actor-free: a listing that echoed the caller back would
        // not be byte-identical across credentials, and the whole point of an
        // immutable registration is that it is the same bytes for everyone.
        // The credential is still REQUIRED, just never reflected.
        "tools/list" => {
            let _actor = resolve_mcp_gateway_actor(mode, &request_id, headers, server).await?;
            Ok(json!({
                "surfaceMode": mode.as_str(),
                "tools": crate::mcp::registered_surface(mode).listing(),
            }))
        }
        "tools/call" => {
            let actor = resolve_mcp_gateway_actor(mode, &request_id, headers, server).await?;
            let called: Result<Value, McpGatewayError> = async {
                let params: McpToolCallParams = mcp_params(request.params, "params")?;
                let args = mcp_validated_call_args(mode, params, raw_arguments)?;
                ensure_mcp_actor_matches(&args, &actor)?;
                mcp_admit_scoped_call(server, &args, &actor)?;
                execute_mcp_tool(server, args, &actor).await
            }
            .await;
            // ONE-1704 M4: ONE chokepoint. Everything inside that block happened
            // AFTER the credential resolved, so every refusal it can produce —
            // decode, validation, actor mismatch, bound-verb or scope refusal,
            // scoped-grant refusal, board/task dispatch, projection, facade, or
            // engine failure — leaves with the effective scope attached. Only
            // failures before this point are legitimately scope-less.
            called.map_err(|error| error.with_effective_scope(&actor))
        }
        _ => Err(McpGatewayError::new(
            -32601,
            "method_not_found",
            format!("unsupported MCP method {}", request.method),
        )
        .with_field("method")),
    }
}

/// The IMMUTABLE connector ceiling, applied BEFORE any executor runs.
///
/// Four intersections happen here and nowhere else (ONE-1704 M3):
///
/// 1. the registered bound-verb ceiling against the tool this call named;
/// 2. the registered world/facet against every entity the call ADDRESSES,
///    through the engine's own scoped-read admission plus the target's own
///    `world` key and `FacetOf` edges;
/// 3. the registered subscription ceiling against a STREAM routing request;
/// 4. the registered world/facet against every call whose EXECUTION carries no
///    scope of its own.
///
/// The fourth is the ONE-1704 B3 close: this admission no longer answers `Ok`
/// for every non-verb call. `execute_code` builds an actor-wide gated write and
/// `tasks.create` writes through the actor-wide memory facade, so neither can
/// be narrowed downstream; under a world- OR facet-narrowed credential both are
/// refused here, fail-closed, with the two axes enforced independently. There is
/// no scoped-positive service for narrowed credentials in this release, and a
/// refusal is the truthful shape of that.
///
/// A caller echo can only ever narrow. Nothing a caller sends creates
/// authority, and a refusal here happens before dispatch, not after.
pub(crate) fn mcp_admit_scoped_call(
    server: &Arc<SyncServer>,
    args: &McpValidatedToolArgs,
    actor: &McpCallContext,
) -> Result<(), McpGatewayError> {
    let tool_name = mcp_called_tool_name(args);
    if !actor.admits_tool(tool_name) {
        return Err(McpGatewayError::new(
            -32020,
            "mcp_verb_not_bound",
            format!("{tool_name} is not bound to this connector credential"),
        )
        .with_field("name"));
    }
    let verb = match args {
        // Setup reads a board that is ALREADY narrowed to this credential's
        // ceiling row by row (`mcp_scoped_tasks_section`), so it is the one
        // call a narrowed credential may make unchanged.
        McpValidatedToolArgs::Setup(_) => return Ok(()),
        // Unreachable from either registered wire surface (B1/B2), and refused
        // here too rather than admitted by omission.
        McpValidatedToolArgs::ExecuteCode(_) => {
            return mcp_admit_unscoped_execution(actor, crate::mcp::MCP_EXECUTE_CODE_TOOL, "name");
        }
        McpValidatedToolArgs::Verb(verb) => verb,
        // The retired plain-verb adapters carry no scope projection either, so
        // a narrowed credential is refused on them by the same rule. After M1
        // no wire name resolves onto them at all.
        _ => return mcp_admit_unscoped_execution(actor, tool_name, "name"),
    };
    if let Some(scopes) = verb.payload.arguments.scopes.as_ref() {
        mcp_admit_subscription_scopes(actor, scopes)?;
    }
    if let Some(task_ref) = verb.payload.arguments.task_ref.as_deref() {
        let id = parse_entity_id_param(task_ref, "arguments.task_ref").map_err(mcp_api_error)?;
        mcp_admit_scoped_entity(server, actor, &id, "arguments.task_ref")?;
    }
    if matches!(verb.tool.binding, crate::mcp::McpVerbBinding::TasksCreate) {
        mcp_admit_unscoped_execution(actor, verb.tool.name, "arguments.spec")?;
    }
    Ok(())
}

/// Refuses one call whose EXECUTION cannot carry this credential's scope.
///
/// Vault-wide credentials are unaffected — an actor-wide execution is exactly
/// their ceiling. A world- or facet-narrowed credential is refused, and the two
/// axes are independent: a world-only credential and a facet-only credential
/// each reach this on their own, neither inferred from the other.
fn mcp_admit_unscoped_execution(
    actor: &McpCallContext,
    tool_name: &str,
    field: &'static str,
) -> Result<(), McpGatewayError> {
    let scope = &actor.scope;
    let axis = match (scope.world_ref.is_some(), scope.facet_ref.is_some()) {
        (false, false) => return Ok(()),
        (true, false) => "world",
        (false, true) => "facet",
        (true, true) => "world and facet",
    };
    Err(McpGatewayError::new(
        -32020,
        "mcp_scope_refused",
        format!(
            "{tool_name} executes outside this credential's {axis} ceiling and is refused: this \
             release carries no scope through that execution"
        ),
    )
    .with_field(field))
}

/// The registered tool name one validated call resolved to.
fn mcp_called_tool_name(args: &McpValidatedToolArgs) -> &'static str {
    match args {
        McpValidatedToolArgs::Setup(_) => crate::mcp::MCP_SETUP_TOOL,
        McpValidatedToolArgs::ExecuteCode(_) => crate::mcp::MCP_EXECUTE_CODE_TOOL,
        McpValidatedToolArgs::Verb(verb) => verb.tool.name,
        // Unreachable from the wire after M1: no unlisted name resolves.
        _ => "",
    }
}

/// Intersects a caller's requested STREAM categories with the ceiling this
/// credential was ATTACHED under.
fn mcp_admit_subscription_scopes(
    actor: &McpCallContext,
    requested: &[crate::mcp::McpSubscriptionScope],
) -> Result<(), McpGatewayError> {
    let asked = requested
        .iter()
        .copied()
        .map(crate::mcp::McpSubscriptionScope::engine)
        .collect::<std::collections::BTreeSet<_>>();
    let admitted = actor.admitted_subscriptions(&asked);
    if admitted == asked {
        return Ok(());
    }
    Err(McpGatewayError::new(
        -32020,
        "mcp_scope_refused",
        "a requested subscription category is outside this credential's scope ceiling",
    )
    .with_field("arguments.scopes"))
}

/// Admits ONE caller-addressed entity against the registered world/facet.
///
/// Every axis is read from the store, not from the request: the actor-scoped
/// read lane decides readability, the target claim's own `world` key decides
/// world membership, and its `FacetOf` edges decide facet membership.
fn mcp_admit_scoped_entity(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    id: &oneiron::EntityId,
    field: &'static str,
) -> Result<(), McpGatewayError> {
    let scoped_read = mcp_scoped_read(&server.vault, actor)?;
    let readable = scoped_read
        .is_entity_readable(id)
        .map_err(|error| mcp_engine_error("mcp scope admission read failed", error))?;
    if !readable || !mcp_scope_covers_entity(&scoped_read, &actor.scope, id)? {
        return Err(McpGatewayError::new(
            -32020,
            "mcp_scope_refused",
            "the addressed entity is outside this credential's world/facet scope",
        )
        .with_field(field));
    }
    Ok(())
}

/// True when the registered world/facet ceiling covers this entity.
///
/// A vault-wide credential covers everything. A facet-scoped credential covers
/// only rows that actually carry the `FacetOf` edge to that facet.
///
/// ONE-1704 B5: the world axis is now symmetric with that facet axis, and it
/// applies to EVERY addressed row rather than to CLAIMs alone. Only a CLAIM
/// carries a `world` key, so a task/entity row that carries none cannot be
/// PROVEN in this credential's world and is refused; a CLAIM is covered exactly
/// when its own `world` key is this credential's world. No world projection is
/// invented for non-claim rows here — a projection is engine scope, and until
/// one exists the fail-closed answer is the only true one. Prerelease law: the
/// admission is narrowed outright, with no compatibility carve-out for the rows
/// the old CLAIM-only check let through.
fn mcp_scope_covers_entity(
    scoped_read: &oneiron::claim::ScopedRead<'_>,
    scope: &crate::mcp::McpConnectorScope,
    id: &oneiron::EntityId,
) -> Result<bool, McpGatewayError> {
    if let Some(world_ref) = scope.world_ref {
        let entity_type = scoped_read
            .vault()
            .get_entity_type(id)
            .map_err(|error| mcp_engine_error("mcp scope type read failed", error))?;
        if entity_type != Some(oneiron::registry::ENTITY_TYPE_CLAIM) {
            return Ok(false);
        }
        let claim = scoped_read
            .vault()
            .get_claim(id)
            .map_err(|error| mcp_engine_error("mcp scope world read failed", error))?;
        let Some(claim) = claim else {
            return Ok(false);
        };
        if claim.world != Some(world_ref) {
            return Ok(false);
        }
    }
    if let Some(facet_ref) = scope.facet_ref {
        let edges = scoped_read
            .edges_out(id)
            .map_err(|error| mcp_engine_error("mcp scope facet read failed", error))?
            .unwrap_or_default();
        let carries_facet = edges
            .iter()
            .any(|edge| edge.kind == EdgeKind::FacetOf && edge.target == facet_ref);
        if !carries_facet {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Resolves one `tools/call` name against THIS endpoint's registration.
///
/// The registered surface is the WHOLE callable surface (ONE-1704 M1). There is
/// no second resolution step: a tool the other endpoint registered, and every
/// retired `oneiron.*` plain-verb name, is `unknown_tool` here even though its
/// argument catalog still exists in this process. Nothing falls back, so no
/// unadvertised name can reach an executor or bypass the result envelope.
fn mcp_validated_call_args(
    mode: McpSurfaceMode,
    params: McpToolCallParams,
    raw_arguments: Option<&str>,
) -> Result<McpValidatedToolArgs, McpGatewayError> {
    let Some(tool) = crate::mcp::registered_surface(mode).resolve(&params.name) else {
        if params.name == crate::mcp::MCP_EXECUTE_CODE_TOOL {
            return Err(mcp_execute_code_unavailable());
        }
        return Err(McpGatewayError::new(
            -32602,
            "unknown_tool",
            format!(
                "{name} is not registered on the {mode} Oneiron MCP endpoint",
                name = params.name,
                mode = mode.as_str(),
            ),
        )
        .with_field("name"));
    };
    // The wire's own bytes when this call arrived over HTTP; the routed
    // `Value` only when it did not (ONE-1704 repair).
    let arguments = raw_arguments.map_or_else(
        || crate::mcp::McpToolArguments::from(params.arguments),
        crate::mcp::McpToolArguments::from_raw_json,
    );
    crate::mcp::validate_mcp_endpoint_tool_args(tool, arguments).map_err(mcp_tool_validation_error)
}

/// The ONE stable typed refusal a direct `execute_code` call receives
/// (ONE-1704 B2).
///
/// It is raised at the single name-resolution chokepoint both routes share, so
/// it lands BEFORE arguments decode, before admission, and before any executor:
/// no run is created, no durable run handle is minted, no `Waiting` is
/// published, and no `resume` block or `terminal:false` advancement claim can
/// reach the wire, under full or narrowed credentials on either endpoint.
///
/// This is the FINAL release posture, not a placeholder for a host that is
/// about to appear: `execute_code` is not shipped in this release, and the
/// refusal says exactly that instead of the generic `unknown_tool` a retired
/// name would otherwise get.
fn mcp_execute_code_unavailable() -> McpGatewayError {
    McpGatewayError::new(
        -32020,
        crate::mcp::MCP_EXECUTE_CODE_UNAVAILABLE_CODE,
        format!(
            "{tool} is not shipped in this release: it is registered on no endpoint and no run \
             was created",
            tool = crate::mcp::MCP_EXECUTE_CODE_TOOL,
        ),
    )
    .with_field("name")
}

pub(crate) async fn resolve_mcp_gateway_actor(
    mode: McpSurfaceMode,
    request_id: &str,
    headers: &HeaderMap,
    server: &Arc<SyncServer>,
) -> Result<McpCallContext, McpGatewayError> {
    let credential = mcp_connector_credential(headers)?;
    let registry = server.mcp_registry.lock().await;
    let actor = registry
        .resolve(&credential, unix_seconds_now(), |actor_class, actor_ref| {
            server
                .vault
                .gate_actor_ceiling_exists(actor_class, actor_ref)
                .unwrap_or(false)
        })
        .map_err(mcp_actor_resolution_error)?;
    Ok(McpCallContext {
        actor,
        mode,
        request_id: request_id.to_owned(),
    })
}

pub(crate) fn mcp_connector_credential(headers: &HeaderMap) -> Result<String, McpGatewayError> {
    if let Some(value) = headers
        .get(MCP_CREDENTIAL_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Ok(value.to_owned());
    }

    let Some(value) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return Err(McpGatewayError::new(
            -32001,
            "mcp_auth_required",
            "missing MCP connector credential",
        ));
    };
    let value = value.trim_start();
    let Some((scheme, credential)) = value.split_once(char::is_whitespace) else {
        return Err(McpGatewayError::new(
            -32001,
            "mcp_auth_required",
            "Authorization must use Bearer credentials",
        )
        .with_field("authorization"));
    };
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(McpGatewayError::new(
            -32001,
            "mcp_auth_required",
            "Authorization must use Bearer credentials",
        )
        .with_field("authorization"));
    }
    let credential = credential.trim();
    if credential.is_empty() {
        return Err(McpGatewayError::new(
            -32001,
            "mcp_auth_required",
            "MCP connector credential must not be empty",
        )
        .with_field("authorization"));
    }
    Ok(credential.to_owned())
}

pub(crate) fn mcp_actor_resolution_error(
    error: McpConnectorActorResolutionError,
) -> McpGatewayError {
    let kind = match error {
        McpConnectorActorResolutionError::UnknownCredential => "mcp_credential_unknown",
        McpConnectorActorResolutionError::ExpiredCredential => "mcp_credential_expired",
        McpConnectorActorResolutionError::RevokedCredential => "mcp_credential_revoked",
        McpConnectorActorResolutionError::MissingActorCeiling => "mcp_actor_ceiling_missing",
    };
    McpGatewayError::new(-32001, kind, error.to_string())
}

pub(crate) fn mcp_params<T: DeserializeOwned>(
    params: Option<Value>,
    field: &'static str,
) -> Result<T, McpGatewayError> {
    let params = params.ok_or_else(|| {
        McpGatewayError::new(-32602, "invalid_params", "params are required").with_field(field)
    })?;
    serde_json::from_value(params).map_err(|error| {
        McpGatewayError::new(-32602, "invalid_params", error.to_string()).with_field(field)
    })
}

pub(crate) fn mcp_tool_validation_error(error: McpToolValidationError) -> McpGatewayError {
    match error {
        McpToolValidationError::Decode { tool, message } => McpGatewayError::new(
            -32602,
            "tool_args_invalid",
            format!("{tool} arguments could not be decoded: {message}"),
        ),
        McpToolValidationError::Field {
            tool,
            field,
            message,
        } => McpGatewayError::new(
            -32602,
            "tool_args_invalid",
            format!("{tool}.{field}: {message}"),
        )
        .with_field(field),
    }
}

pub(crate) fn ensure_mcp_actor_matches(
    args: &McpValidatedToolArgs,
    resolved: &McpResolvedActor,
) -> Result<(), McpGatewayError> {
    let actor = mcp_validated_actor(args);
    if actor.actor_ref != resolved.actor_ref.to_hex() {
        return Err(McpGatewayError::new(
            -32602,
            "mcp_actor_mismatch",
            "tool actor_ref must match the authenticated connector actor",
        )
        .with_field("actor.actor_ref"));
    }
    if mcp_actor_class_wire(actor.actor_class) != resolved.gate_actor_class {
        return Err(McpGatewayError::new(
            -32602,
            "mcp_actor_mismatch",
            "tool actor_class must match the authenticated connector actor class",
        )
        .with_field("actor.actor_class"));
    }
    if actor.gate_actor_ref != resolved.gate_actor_ref {
        return Err(McpGatewayError::new(
            -32602,
            "mcp_actor_mismatch",
            "tool gate_actor_ref must match the authenticated connector actor",
        )
        .with_field("actor.gate_actor_ref"));
    }
    if mcp_actor_class_wire(actor.gate_actor_class) != resolved.gate_actor_class {
        return Err(McpGatewayError::new(
            -32602,
            "mcp_actor_mismatch",
            "tool gate_actor_class must match the authenticated connector actor class",
        )
        .with_field("actor.gate_actor_class"));
    }
    let scope = &resolved.scope;
    if actor.scope.world_ref.as_deref()
        != scope
            .world_ref
            .as_ref()
            .map(oneiron::EntityId::to_hex)
            .as_deref()
    {
        return Err(McpGatewayError::new(
            -32602,
            "mcp_actor_mismatch",
            "tool actor.scope.world_ref must match the authenticated connector scope",
        )
        .with_field("actor.scope.world_ref"));
    }
    if actor.scope.facet_ref.as_deref()
        != scope
            .facet_ref
            .as_ref()
            .map(oneiron::EntityId::to_hex)
            .as_deref()
    {
        return Err(McpGatewayError::new(
            -32602,
            "mcp_actor_mismatch",
            "tool actor.scope.facet_ref must match the authenticated connector scope",
        )
        .with_field("actor.scope.facet_ref"));
    }
    Ok(())
}

pub(crate) fn mcp_validated_actor(args: &McpValidatedToolArgs) -> &McpActorMetadata {
    match args {
        McpValidatedToolArgs::Nav(args) => &args.actor,
        McpValidatedToolArgs::Read(args) => &args.actor,
        McpValidatedToolArgs::Edit(args) => &args.actor,
        McpValidatedToolArgs::Ask(args) => &args.actor,
        McpValidatedToolArgs::RoutedAsk(args) => &args.actor,
        McpValidatedToolArgs::Calendar(args) => &args.actor,
        McpValidatedToolArgs::Book(args) => args.actor(),
        McpValidatedToolArgs::Setup(args) => &args.actor,
        McpValidatedToolArgs::ExecuteCode(args) => &args.actor,
        McpValidatedToolArgs::Verb(args) => &args.payload.actor,
    }
}

/// Dispatches one VALIDATED endpoint tool call.
///
/// Only the three ONE-1704 arms — setup, execute_code, and one generated verb —
/// are reachable from the wire: after M1 nothing resolves a retired
/// `oneiron.*` name, so the plain-verb arms below are private adapters over the
/// same gated vault API with no callable wire name. They are kept as the shared
/// bodies the internal surface still uses, not as a second catalog.
pub(crate) async fn execute_mcp_tool(
    server: &Arc<SyncServer>,
    args: McpValidatedToolArgs,
    actor: &McpCallContext,
) -> Result<Value, McpGatewayError> {
    match args {
        McpValidatedToolArgs::Nav(args) => execute_mcp_nav(server, args, actor),
        McpValidatedToolArgs::Read(args) => execute_mcp_read(server, args, actor),
        McpValidatedToolArgs::Edit(args) => execute_mcp_edit(server, *args, actor),
        McpValidatedToolArgs::Ask(args) => Ok(mcp_ask_result(args, actor)),
        McpValidatedToolArgs::RoutedAsk(args) => Ok(mcp_routed_ask_result(args, actor)),
        McpValidatedToolArgs::Calendar(args) => execute_mcp_calendar(server, args, actor),
        McpValidatedToolArgs::Book(args) => execute_mcp_book(server, *args, actor).await,
        McpValidatedToolArgs::Setup(args) => execute_mcp_setup(server, *args, actor).await,
        McpValidatedToolArgs::ExecuteCode(args) => {
            execute_mcp_execute_code(server, *args, actor).await
        }
        McpValidatedToolArgs::Verb(args) => execute_mcp_generated_verb(server, *args, actor).await,
    }
}

/// Dispatches `oneiron.book`.
///
/// Three things happen here and nowhere else on the MCP side, in this order:
///
/// 1. the caller's claimed actor has already been matched against the
///    authenticated connector credential by [`ensure_mcp_actor_matches`];
/// 2. a LIVE `StandingOutboundGrantScope::ScopedMcp` for this server, this
///    tool, this principal, this operation, and this payload data class must
///    authorize the call — a missing, revoked, wrong-principal, wrong-tool,
///    over-ceiling, or not-allowlisted grant fails BEFORE the shared executor;
/// 3. the shared executor runs, and it — not this file — makes the one and
///    only BK-06 admission call.
///
/// A scoped grant authorizes the tool call and nothing else. Confirm,
/// reschedule, and cancel side effects continue through the lifecycle and
/// outbound dispatch paths their own tickets own.
pub(crate) async fn execute_mcp_book(
    server: &Arc<SyncServer>,
    args: crate::mcp::McpBookToolArgs,
    actor: &McpResolvedActor,
) -> Result<Value, McpGatewayError> {
    let op = args.operation.op();
    authorize_scoped_mcp_book(server, &args, actor)?;

    let page_token = args.page_token.clone();
    let request = args.into_operation_request();
    let response = super::booking::execute_booking_operation_for_mcp(
        server,
        &page_token,
        request,
        actor.actor_ref,
        mcp_source_ip(),
    )
    .await
    .map_err(mcp_booking_error)?;

    let mut structured = serde_json::to_value(&response).map_err(|error| {
        McpGatewayError::new(
            -32603,
            "internal_error",
            format!("booking response does not serialize: {error}"),
        )
    })?;
    if let Some(object) = structured.as_object_mut() {
        object.insert(
            "tool".to_owned(),
            Value::String(McpToolName::Book.as_str().to_owned()),
        );
        object.insert("actor".to_owned(), mcp_actor_result(actor));
    }
    Ok(json!({
        "content": [mcp_text_content(format!("book {op} completed"))],
        "structuredContent": structured,
        "isError": false,
    }))
}

/// The MCP door's source address for admission keying.
///
/// The gateway terminates a JSON-RPC call whose connection info this app does
/// not carry, so the loopback address plus the resolved connector actor is the
/// key material. The actor is what actually separates two agents' budgets, and
/// the executor mixes it in for both transports identically.
fn mcp_source_ip() -> std::net::IpAddr {
    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
}

/// Requires a live scoped-MCP standing grant for this exact call.
///
/// The grant is named by the consent envelope's `approval_ref` and read
/// through the engine's own store; the decision is the engine's own
/// [`oneiron::outbound_consent::evaluate_scoped_mcp_call`]. Nothing is
/// re-implemented here — this only assembles the call axes.
fn authorize_scoped_mcp_book(
    server: &SyncServer,
    args: &crate::mcp::McpBookToolArgs,
    actor: &McpResolvedActor,
) -> Result<(), McpGatewayError> {
    let grant_ref = args.consent.approval_ref.as_deref().ok_or_else(|| {
        scoped_grant_error("oneiron.book requires a live scoped-MCP grant reference")
    })?;
    let grant_id = oneiron::EntityId::from_hex(grant_ref)
        .map_err(|_| scoped_grant_error("scoped-MCP grant reference is not a grant id"))?;
    let grant = server
        .vault
        .get_standing_outbound_grant(&grant_id)
        .map_err(|_| scoped_grant_error("scoped-MCP grant could not be read"))?
        .ok_or_else(|| scoped_grant_error("scoped-MCP grant does not exist"))?;

    if grant.status != oneiron::outbound_grant::StandingOutboundGrantStatus::Active
        || grant.revoked_at.is_some()
    {
        return Err(scoped_grant_error("scoped-MCP grant is not live"));
    }
    if grant.principal_ref != actor.actor_ref.to_hex()
        && grant.principal_ref != actor.gate_actor_ref
    {
        return Err(scoped_grant_error(
            "scoped-MCP grant belongs to another principal",
        ));
    }
    let scoped = grant.scope.scoped_mcp_grant().ok_or_else(|| {
        scoped_grant_error("grant is not a payload-aware scoped-MCP authorization")
    })?;

    // The call axes are the tool's own, derived from the args themselves, so
    // the gateway asserts nothing the caller could have shaped.
    let call = args.scoped_mcp_call();
    match oneiron::outbound_consent::evaluate_scoped_mcp_call(scoped, call.as_call()) {
        oneiron::outbound_consent::ScopedMcpConsentDecision::AutoFire => Ok(()),
        oneiron::outbound_consent::ScopedMcpConsentDecision::Escalate(reason) => {
            Err(scoped_grant_error(format!(
                "scoped-MCP grant does not authorize this booking call: {reason:?}"
            )))
        }
    }
}

fn scoped_grant_error(message: impl Into<String>) -> McpGatewayError {
    McpGatewayError::new(-32020, "scoped_mcp_grant_required", message)
        .with_field("consent.approval_ref")
}

/// Maps the shared executor's typed error onto the gateway's JSON-RPC
/// vocabulary, preserving the machine-readable code the HTTP door returns.
fn mcp_booking_error(error: ApiError) -> McpGatewayError {
    let code = match error.details() {
        ApiErrorDetails::BadRequest { .. } => -32602,
        ApiErrorDetails::NotFound { .. } => -32004,
        ApiErrorDetails::Unauthorized | ApiErrorDetails::Forbidden { .. } => -32020,
        ApiErrorDetails::InvalidState { .. } => -32020,
        _ => -32603,
    };
    McpGatewayError::new(code, "booking_operation_failed", error.message().to_owned())
}

/// Dispatches `oneiron.calendar`.
///
/// Every arm goes through [`oneiron::Memory`] — the calendar dialect owns
/// no vault access of its own, so the actor binding, the scoped-read lane, and
/// the outbound gate are all the engine's, not a second server-side copy. The
/// invite arm in particular reaches the connector only via `schedule_outbound`;
/// there is no direct execution path in this file.
pub(crate) fn execute_mcp_calendar(
    server: &SyncServer,
    args: crate::mcp::McpCalendarToolArgs,
    actor: &McpResolvedActor,
) -> Result<Value, McpGatewayError> {
    let op = args.operation.op();
    let facade = server.vault.memory(actor.actor_ref, actor.actor_class);

    let mut structured = match args.operation {
        crate::mcp::McpCalendarOperation::Read { event_ref } => {
            let item = facade
                .calendar_read(&oneiron::CalendarReadRequest { event_ref })
                .map_err(mcp_facade_error)?;
            json!({ "found": item.is_some(), "item": item })
        }
        crate::mcp::McpCalendarOperation::Search {
            calendars,
            range,
            text,
            limit,
        } => {
            let items = facade
                .calendar_search(&oneiron::CalendarSearchRequest {
                    calendars: calendar_selectors(calendars),
                    range: range.map(|range| oneiron::CalendarRangeDto {
                        start: range.start,
                        end: range.end,
                    }),
                    text,
                    limit: limit.unwrap_or(CORE_MAX_LIST_LIMIT as u32),
                })
                .map_err(mcp_facade_error)?;
            json!({ "count": items.len(), "items": items })
        }
        crate::mcp::McpCalendarOperation::Freebusy { calendars, range } => {
            let intervals = facade
                .calendar_freebusy(
                    &calendar_selectors(calendars),
                    oneiron::TimeRange {
                        start: range.start,
                        end: range.end,
                    },
                )
                .map_err(mcp_facade_error)?;
            json!({ "count": intervals.len(), "intervals": intervals })
        }
        crate::mcp::McpCalendarOperation::Invite {
            method,
            uid,
            sequence,
            ics_blob_ref,
            recipient,
        } => {
            let receipt = facade
                .calendar_invite(&oneiron::CalendarInviteSurfaceInput {
                    method,
                    uid,
                    sequence,
                    ics_blob_ref,
                    recipient,
                })
                .map_err(mcp_facade_error)?;
            json!({ "receipt": receipt })
        }
    };

    if let Some(object) = structured.as_object_mut() {
        object.insert(
            "tool".to_owned(),
            Value::String(McpToolName::Calendar.as_str().to_owned()),
        );
        object.insert("op".to_owned(), Value::String(op.to_owned()));
        object.insert("actor".to_owned(), mcp_actor_result(actor));
    }
    Ok(json!({
        "content": [mcp_text_content(format!("calendar {op} completed"))],
        "structuredContent": structured,
        "isError": false,
    }))
}

fn calendar_selectors(
    selectors: Vec<crate::mcp::McpCalendarSelector>,
) -> Vec<oneiron::CalendarSel> {
    selectors
        .into_iter()
        .map(|selector| oneiron::CalendarSel {
            system: selector.system,
        })
        .collect()
}

/// Maps a typed engine facade error onto the gateway's JSON-RPC vocabulary.
pub(crate) fn mcp_facade_error(error: oneiron::MemoryError) -> McpGatewayError {
    let code = match error.code.as_str() {
        oneiron::MEMORY_CODE_NOT_FOUND => -32004,
        oneiron::MEMORY_CODE_FORBIDDEN | oneiron::MEMORY_CODE_INVALID_STATE => -32020,
        oneiron::MEMORY_CODE_INTERNAL => -32603,
        _ => -32602,
    };
    // A facade refusal carrying a successor keeps the same stable kind and
    // typed data the engine-error path emits (ONE-1936) — one vocabulary for
    // one condition, whichever door reported it.
    match error.successor_short_id {
        Some(successor_short_id) => {
            McpGatewayError::new(code, "write_verb_target_stale", error.message)
                .with_successor_short_id(successor_short_id)
        }
        None => McpGatewayError::new(code, "facade_error", error.message),
    }
}

pub(crate) fn execute_mcp_nav(
    server: &SyncServer,
    args: crate::mcp::McpNavToolArgs,
    actor: &McpResolvedActor,
) -> Result<Value, McpGatewayError> {
    let scoped_read = mcp_scoped_read(&server.vault, actor)?;
    let limit = args.limit.unwrap_or(10).min(CORE_MAX_LIST_LIMIT as u32) as usize;
    match args.mode {
        crate::mcp::McpNavMode::Search => {
            let query = args.query.as_deref().ok_or_else(|| {
                McpGatewayError::new(
                    -32602,
                    "tool_args_invalid",
                    "oneiron.nav query is required for search mode",
                )
                .with_field("query")
            })?;
            let results = scoped_read
                .search_text(query, limit)
                .map_err(|error| mcp_engine_error("mcp nav search failed", error))?;
            let items = results
                .into_iter()
                .map(|result| {
                    projection::project_search_result(scoped_read.vault(), result, View::Summary)
                        .map_err(|error| mcp_engine_error("mcp nav projection failed", error))
                })
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
            Ok(json!({
                "content": [mcp_text_content(format!("{} result(s)", items.len()))],
                "structuredContent": {
                    "tool": McpToolName::Nav.as_str(),
                    "mode": "search",
                    "items": items,
                },
                "isError": false,
            }))
        }
        _ => Ok(json!({
            "content": [mcp_text_content("navigation mode accepted")],
            "structuredContent": {
                "tool": McpToolName::Nav.as_str(),
                "mode": format!("{:?}", args.mode).to_ascii_lowercase(),
                "status": "accepted",
            },
            "isError": false,
        })),
    }
}

pub(crate) fn execute_mcp_read(
    server: &SyncServer,
    args: crate::mcp::McpReadToolArgs,
    actor: &McpResolvedActor,
) -> Result<Value, McpGatewayError> {
    let scoped_read = mcp_scoped_read(&server.vault, actor)?;
    if let Some(entity_ref) = args.target.entity_ref.as_deref() {
        let id = parse_entity_id_param(entity_ref, "target.entity_ref").map_err(mcp_api_error)?;
        let item = scoped_read
            .get_entity_parts(&id)
            .map_err(|error| mcp_engine_error("mcp read failed", error))?
            .map(|(entity_type, learned_at, body)| {
                projection::project_entity_parts(&id, entity_type, learned_at, &body, View::Full)
            });
        return Ok(json!({
            "content": [mcp_text_content(if item.is_some() { "entity found" } else { "entity not found" })],
            "structuredContent": {
                "tool": McpToolName::Read.as_str(),
                "target": { "entity_ref": entity_ref },
                "found": item.is_some(),
                "item": item,
            },
            "isError": false,
        }));
    }
    if let Some(short_ref) = args.target.short_ref.as_deref() {
        let (short_id, content_hash) = parse_short_ref(short_ref).map_err(mcp_api_error)?;
        let item = hydrate_short_id_response(&scoped_read, short_id, content_hash, View::Full)
            .map_err(mcp_api_error)?;
        return Ok(json!({
            "content": [mcp_text_content(if item.is_some() { "short ref found" } else { "short ref not found" })],
            "structuredContent": {
                "tool": McpToolName::Read.as_str(),
                "target": { "short_ref": short_ref },
                "found": item.is_some(),
                "item": item,
            },
            "isError": false,
        }));
    }
    Ok(json!({
        "content": [mcp_text_content("context pack reference accepted")],
        "structuredContent": {
            "tool": McpToolName::Read.as_str(),
            "target": { "context_pack": args.target.context_pack },
        },
        "isError": false,
    }))
}

pub(crate) fn execute_mcp_edit(
    server: &SyncServer,
    args: McpEditToolArgs,
    actor: &McpResolvedActor,
) -> Result<Value, McpGatewayError> {
    if args.dry_run {
        // A dry run that skipped the guard would report "validated" for an
        // edit the real call is about to refuse. It reports the SAME stale
        // condition and writes nothing (ONE-1936).
        mcp_guard_lifecycle_target(&server.vault, &args)?;
        return Ok(mcp_edit_receipt(
            &args,
            actor,
            None,
            "validated",
            "dry_run",
            "edit validated",
        ));
    }

    match args.verb {
        McpEditVerb::ProposeClaim => execute_mcp_propose_claim(server, &args, actor),
        McpEditVerb::AttestEdgeProvenance
        | McpEditVerb::SupersedeClaim
        | McpEditVerb::RetractClaim
        | McpEditVerb::ProposeEntity
        | McpEditVerb::PostTask
        | McpEditVerb::ReportTask
        | McpEditVerb::ChannelSend => execute_mcp_proposed_control_record(server, &args, actor),
    }
}

pub(crate) fn execute_mcp_propose_claim(
    server: &SyncServer,
    args: &McpEditToolArgs,
    actor: &McpResolvedActor,
) -> Result<Value, McpGatewayError> {
    let id = mcp_idempotency_entity_id("claim", args, actor);
    if let Some(receipt) = mcp_existing_edit_receipt(
        server,
        args,
        actor,
        id,
        "immediate_proposed_claim",
        "claim replayed",
    )? {
        return Ok(receipt);
    }

    let candidate = mcp_claim_candidate_from_args(args)?;
    let envelope = mcp_write_envelope(args, actor, "immediate_proposed_claim")?;
    let learned_at = unix_seconds_now();
    let occurred = oneiron::TimeRange {
        start: learned_at,
        end: learned_at,
    };
    server
        .vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, occurred, learned_at)
        .commit()
        .map_err(|error| mcp_engine_error("mcp propose_claim failed", error))?;

    Ok(mcp_edit_receipt(
        args,
        actor,
        Some(id),
        "proposed",
        "immediate_proposed_claim",
        "claim proposed",
    ))
}

pub(crate) fn execute_mcp_proposed_control_record(
    server: &SyncServer,
    args: &McpEditToolArgs,
    actor: &McpResolvedActor,
) -> Result<Value, McpGatewayError> {
    let lifecycle = mcp_edit_lifecycle(args.verb);
    let id = mcp_idempotency_entity_id("proposal", args, actor);
    if let Some(receipt) =
        mcp_existing_edit_receipt(server, args, actor, id, lifecycle, "edit replayed")?
    {
        return Ok(receipt);
    }

    let target = mcp_lifecycle_target_id(args)?;
    let candidate = mcp_control_record_candidate(args, actor, lifecycle)?;
    let envelope = mcp_write_envelope(args, actor, lifecycle)?;
    let learned_at = unix_seconds_now();
    let occurred = oneiron::TimeRange {
        start: learned_at,
        end: learned_at,
    };
    // Guard and proposal share ONE write transaction. Checking the target in
    // its own transaction and then opening a second one to write is exactly
    // the grounding-read race this ticket closes: the target could move in
    // between. On a stale target the transaction rolls back, so no proposal
    // Claim, no gate receipt, and no idempotency row commits.
    let verb = args.verb;
    server
        .vault
        .with_write_txn(|wtxn| {
            if let Some(target) = target {
                match verb {
                    McpEditVerb::AttestEdgeProvenance => server
                        .vault
                        .require_named_provenance_target_active_in(&*wtxn, &target)?,
                    _ => {
                        server
                            .vault
                            .require_named_claim_target_active_in(&*wtxn, &target)?;
                    }
                }
            }
            server
                .vault
                .batch_in()
                .claim_candidate(&id, candidate, &envelope, occurred, learned_at)
                .apply(wtxn)
        })
        .map_err(|error| mcp_engine_error("mcp proposed control record failed", error))?;

    Ok(mcp_edit_receipt(
        args,
        actor,
        Some(id),
        "proposed",
        lifecycle,
        "edit proposed",
    ))
}

/// The engine id of the lifecycle target this verb NAMES, if it names one.
/// The field name travels with the error so a bad ref points at the argument
/// the caller actually wrote.
pub(crate) fn mcp_lifecycle_target_id(
    args: &McpEditToolArgs,
) -> Result<Option<oneiron::EntityId>, McpGatewayError> {
    let Some(target_ref) = args.lifecycle_target_ref() else {
        return Ok(None);
    };
    let field = match args.verb {
        McpEditVerb::RetractClaim => "claim_id",
        _ => "old_claim_id",
    };
    parse_entity_id_param(target_ref, field)
        .map(Some)
        .map_err(mcp_api_error)
}

/// Guards the verb's named lifecycle target on its OWN read transaction.
///
/// This is the DRY-RUN door only: it reports the stale condition without
/// writing. A path that goes on to write must guard inside the transaction it
/// writes in — see [`execute_mcp_proposed_control_record`].
pub(crate) fn mcp_guard_lifecycle_target(
    vault: &oneiron::Vault,
    args: &McpEditToolArgs,
) -> Result<(), McpGatewayError> {
    let Some(target) = mcp_lifecycle_target_id(args)? else {
        return Ok(());
    };
    // Edge-provenance wrappers pick their current head by D14 cohort
    // precedence, not by a Supersedes chain, so attest has its own guard.
    match args.verb {
        McpEditVerb::AttestEdgeProvenance => vault.require_named_provenance_target_active(&target),
        _ => vault.require_named_claim_target_active(&target).map(|_| ()),
    }
    .map_err(|error| mcp_engine_error("mcp edit target guard failed", error))
}

pub(crate) fn mcp_claim_candidate_from_args(
    args: &McpEditToolArgs,
) -> Result<oneiron::ClaimCandidate, McpGatewayError> {
    let value =
        oneiron::companion_value_from_json(mcp_required_json(args.value.as_ref(), "value")?)
            .map_err(|error| mcp_engine_error("mcp claim value conversion failed", error))?;
    let mut candidate = oneiron::ClaimCandidate::new(
        mcp_required_str(args.predicate.as_deref(), "predicate")?,
        mcp_claim_subject(args.subject.as_ref())?,
        value,
        mcp_required_f32(args.confidence, "confidence")?,
    );
    if let Some(evidence) = args.evidence.as_ref() {
        candidate = candidate.with_evidence(
            oneiron::companion_value_from_json(evidence)
                .map_err(|error| mcp_engine_error("mcp claim evidence conversion failed", error))?,
        );
    }
    if let Some(salience) = args.salience {
        candidate = candidate.with_salience(salience);
    }
    candidate = candidate.with_validity(args.valid_from, args.valid_to);
    if let Some(world_ref) = args.world.as_deref() {
        candidate =
            candidate.with_world(parse_entity_id_param(world_ref, "world").map_err(mcp_api_error)?);
    }
    if let Some(scope) = args.scope.as_ref() {
        candidate = candidate.with_scope(
            oneiron::companion_value_from_json(scope)
                .map_err(|error| mcp_engine_error("mcp claim scope conversion failed", error))?,
        );
    }
    Ok(candidate)
}

pub(crate) fn mcp_control_record_candidate(
    args: &McpEditToolArgs,
    actor: &McpResolvedActor,
    lifecycle: &'static str,
) -> Result<oneiron::ClaimCandidate, McpGatewayError> {
    let arguments = serde_json::to_value(args).map_err(|error| {
        McpGatewayError::new(
            -32603,
            "mcp_args_serialize_failed",
            format!("failed to serialize MCP edit arguments: {error}"),
        )
    })?;
    let value = oneiron::companion_value_from_json(&json!({
        "verb": mcp_edit_verb_name(args.verb),
        "idempotency_key": args.idempotency_key,
        "lifecycle": lifecycle,
        "arguments": arguments,
    }))
    .map_err(|error| mcp_engine_error("mcp control record value conversion failed", error))?;
    Ok(oneiron::ClaimCandidate::new(
        format!("mcp.proposal.{}", mcp_edit_verb_name(args.verb)),
        oneiron::ClaimSubject::Entity(actor.actor_ref),
        value,
        1.0,
    ))
}

pub(crate) fn mcp_write_envelope(
    args: &McpEditToolArgs,
    actor: &McpResolvedActor,
    lifecycle: &'static str,
) -> Result<oneiron::WriteEnvelope, McpGatewayError> {
    let provenance = oneiron::WriteProvenance::new(
        oneiron::companion_value_from_json(&json!({
            "surface": "mcp",
            "tool": McpToolName::Edit.as_str(),
            "verb": mcp_edit_verb_name(args.verb),
            "idempotency_key": args.idempotency_key,
            "lifecycle": lifecycle,
            "consent": {
                "policy_ref": args.consent.policy_ref,
                "purpose": args.consent.purpose,
                "approval_ref": args.consent.approval_ref,
                "consent_receipt_ref": args.consent.consent_receipt_ref,
                "require_human_approval": args.consent.require_human_approval,
            }
        }))
        .map_err(|error| mcp_engine_error("mcp provenance conversion failed", error))?,
    )
    .map_err(|error| mcp_engine_error("mcp provenance invalid", error))?;
    Ok(oneiron::WriteEnvelope::new(
        actor.write_actor(),
        oneiron::ClaimSource::ToolOutput,
        provenance,
        oneiron::ClaimApprovalStatus::Proposed,
    ))
}

pub(crate) fn mcp_claim_subject(
    subject: Option<&crate::mcp::McpEditSubject>,
) -> Result<oneiron::ClaimSubject, McpGatewayError> {
    let subject = subject.ok_or_else(|| {
        McpGatewayError::new(-32602, "tool_args_invalid", "subject is required")
            .with_field("subject")
    })?;
    match (subject.entity.as_deref(), subject.edge.as_ref()) {
        (Some(entity), None) => Ok(oneiron::ClaimSubject::Entity(
            parse_entity_id_param(entity, "subject.entity").map_err(mcp_api_error)?,
        )),
        (None, Some(edge)) => Ok(oneiron::ClaimSubject::Edge {
            source: parse_entity_id_param(&edge.source, "subject.edge.source")
                .map_err(mcp_api_error)?,
            kind: EdgeKind::try_from_u8(edge.kind).ok_or_else(|| {
                McpGatewayError::new(
                    -32602,
                    "tool_args_invalid",
                    "subject.edge.kind is not a registered edge kind",
                )
                .with_field("subject.edge.kind")
            })?,
            target: parse_entity_id_param(&edge.target, "subject.edge.target")
                .map_err(mcp_api_error)?,
        }),
        _ => Err(McpGatewayError::new(
            -32602,
            "tool_args_invalid",
            "subject must include exactly one of entity or edge",
        )
        .with_field("subject")),
    }
}

pub(crate) fn mcp_required_str<'a>(
    value: Option<&'a str>,
    field: &'static str,
) -> Result<&'a str, McpGatewayError> {
    value.ok_or_else(|| {
        McpGatewayError::new(-32602, "tool_args_invalid", format!("{field} is required"))
            .with_field(field)
    })
}

pub(crate) fn mcp_required_json<'a>(
    value: Option<&'a Value>,
    field: &'static str,
) -> Result<&'a Value, McpGatewayError> {
    value.ok_or_else(|| {
        McpGatewayError::new(-32602, "tool_args_invalid", format!("{field} is required"))
            .with_field(field)
    })
}

pub(crate) fn mcp_required_f32(
    value: Option<f32>,
    field: &'static str,
) -> Result<f32, McpGatewayError> {
    value.ok_or_else(|| {
        McpGatewayError::new(-32602, "tool_args_invalid", format!("{field} is required"))
            .with_field(field)
    })
}

pub(crate) fn mcp_edit_receipt(
    args: &McpEditToolArgs,
    actor: &McpResolvedActor,
    proposal_id: Option<oneiron::EntityId>,
    status: &'static str,
    lifecycle: &'static str,
    message: &'static str,
) -> Value {
    let mut structured = json!({
        "tool": McpToolName::Edit.as_str(),
        "verb": mcp_edit_verb_name(args.verb),
        "idempotency_key": args.idempotency_key,
        "status": status,
        "lifecycle": lifecycle,
        "forced_source": "tool_output",
        "forced_approval": "proposed",
        "dryRun": args.dry_run,
        "actor": mcp_actor_result(actor),
    });
    if let Some(proposal_id) = proposal_id
        && let Some(object) = structured.as_object_mut()
    {
        object.insert("id".to_owned(), Value::String(proposal_id.to_hex()));
        object.insert(
            "proposal_id".to_owned(),
            Value::String(proposal_id.to_hex()),
        );
    }
    json!({
        "content": [mcp_text_content(message)],
        "structuredContent": structured,
        "isError": false,
    })
}

pub(crate) fn mcp_existing_edit_receipt(
    server: &SyncServer,
    args: &McpEditToolArgs,
    actor: &McpResolvedActor,
    id: oneiron::EntityId,
    lifecycle: &'static str,
    message: &'static str,
) -> Result<Option<Value>, McpGatewayError> {
    let existing = server
        .vault
        .get_claim(&id)
        .map_err(|error| mcp_engine_error("mcp edit replay lookup failed", error))?;
    Ok(existing.map(|_| mcp_edit_receipt(args, actor, Some(id), "replayed", lifecycle, message)))
}

/// The retained edit adapter's idempotency row id.
///
/// Routed through the ONE central derivation (ONE-1704 M3) so this adapter and
/// the `execute_code` run handle cannot drift into two identity rules: the
/// credential fingerprint and the whole immutable connector scope are mixed in
/// there, not here.
pub(crate) fn mcp_idempotency_entity_id(
    namespace: &'static str,
    args: &McpEditToolArgs,
    actor: &McpResolvedActor,
) -> oneiron::EntityId {
    crate::mcp::mcp_scoped_identity_id(
        namespace,
        &format!(
            "{verb}\u{1f}{key}",
            verb = mcp_edit_verb_name(args.verb),
            key = args.idempotency_key,
        ),
        actor,
    )
}

pub(crate) fn mcp_edit_lifecycle(verb: McpEditVerb) -> &'static str {
    match verb {
        McpEditVerb::ProposeClaim => "immediate_proposed_claim",
        McpEditVerb::SupersedeClaim | McpEditVerb::RetractClaim | McpEditVerb::ProposeEntity => {
            "deferred_proposed"
        }
        McpEditVerb::AttestEdgeProvenance
        | McpEditVerb::PostTask
        | McpEditVerb::ReportTask
        | McpEditVerb::ChannelSend => "proposed_control_record",
    }
}

pub(crate) fn mcp_edit_verb_name(verb: McpEditVerb) -> &'static str {
    match verb {
        McpEditVerb::ProposeClaim => "propose_claim",
        McpEditVerb::AttestEdgeProvenance => "attest_edge_provenance",
        McpEditVerb::SupersedeClaim => "supersede_claim",
        McpEditVerb::RetractClaim => "retract_claim",
        McpEditVerb::ProposeEntity => "propose_entity",
        McpEditVerb::PostTask => "post_task",
        McpEditVerb::ReportTask => "report_task",
        McpEditVerb::ChannelSend => "channel_send",
    }
}

pub(crate) fn mcp_ask_result(args: McpAskToolArgs, actor: &McpResolvedActor) -> Value {
    json!({
        "content": [mcp_text_content("ask accepted")],
        "structuredContent": {
            "tool": McpToolName::Ask.as_str(),
            "status": "accepted",
            "query": args.query,
            "context_pack": args.context_pack,
            "effort": args.effort,
            "citation_mode": args.citation_mode,
            "actor": mcp_actor_result(actor),
        },
        "isError": false,
    })
}

pub(crate) fn mcp_routed_ask_result(args: McpRoutedAskToolArgs, actor: &McpResolvedActor) -> Value {
    json!({
        "content": [mcp_text_content("routed ask accepted")],
        "structuredContent": {
            "tool": McpToolName::RoutedAsk.as_str(),
            "status": "accepted",
            "query": args.query,
            "context_pack": args.context_pack,
            "route": args.route,
            "effort": args.effort,
            "citation_mode": args.citation_mode,
            "actor": mcp_actor_result(actor),
        },
        "isError": false,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// ONE-1704 — endpoint tool execution
// ═══════════════════════════════════════════════════════════════════════════

/// How one result relates to this connector's queued STREAM state.
#[derive(Debug)]
enum McpCarrierPolicy {
    /// An ordinary result: drain AT MOST ONE pending frame beside it.
    Drain,
    /// This result carries its OWN freshly minted keyframe. `Some` is a frame
    /// the producer has not enqueued yet (setup mints one outside the
    /// registry); `None` is one the producer already enqueued (the engine's own
    /// `board.refresh` does). Either way the queue behind it is EXPLICITLY
    /// superseded and then drained, so no older carrier rides beside a fresh
    /// keyframe and none is left stranded.
    ///
    /// Only a result that states a keyframe the caller has NOT already been
    /// given may say this. A paged producer states its keyframe on page ONE;
    /// its continuations restate that same retained frame and therefore
    /// [`McpCarrierPolicy::Drain`] instead — re-superseding on an already
    /// delivered keyframe destroys the transitions queued behind it.
    FreshKeyframe(Option<oneiron::context_board::BoardStreamFrame>),
}

/// The ONE post-success result chokepoint (ONE-1704 M7 / B4).
///
/// Every actor-derived tool result leaves through here and this is the only
/// place a CARRIER frame is drained, `tasks.*` included. A queued frame
/// therefore rides the NEXT arbitrary successful result exactly once, and a
/// remainder the engine's coalescer kept behind it rides the one after that.
/// No branch hand-builds an envelope beside this one: after M1 there is no
/// unlisted executor left that could.
///
/// ONE-1704 B4: a world- or facet-NARROWED connection is delivered ZERO carrier
/// frames here. The engine's router matches a carrier subscription by category
/// and actor equality only, so two credentials for one actor with disjoint
/// worlds or facets are eligible for the same events; until the router can
/// filter those axes, the truthful delivery for a narrowed connection is none
/// at all. This is a delivery ceiling, not a discard: the server takes no
/// payload for such a connection, so nothing the engine queued is destroyed
/// here. Vault-wide connections are untouched.
async fn mcp_endpoint_result(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    message: impl Into<String>,
    structured: Value,
    policy: McpCarrierPolicy,
) -> Value {
    let carrier = if actor.scope.is_narrow() {
        None
    } else {
        let mut registry = server.mcp_registry.lock().await;
        match policy {
            McpCarrierPolicy::Drain => registry.next_carrier_frame(&actor.stream_connection),
            McpCarrierPolicy::FreshKeyframe(minted) => {
                if let Some(frame) = minted {
                    registry.enqueue_stream_frame(&actor.stream_connection, frame);
                }
                let _superseded = registry.next_carrier_frame(&actor.stream_connection);
                None
            }
        }
    };
    let mut result = json!({
        "content": mcp_negotiated_content(message.into(), &structured),
        "structuredContent": structured,
        "isError": false,
    });
    if let Some(frame) = carrier
        && let Some(object) = result.as_object_mut()
    {
        object.insert(
            "carrier".to_owned(),
            json!({ "class": "carrier", "frame": frame }),
        );
    }
    result
}

/// The result data a client reads over the NEGOTIATED protocol.
///
/// [`MCP_PROTOCOL_VERSION`] is what this server negotiates, and its
/// `CallToolResult` carries `content` alone — `structuredContent` is a later
/// protocol addition. A result that put its data ONLY there handed a conforming
/// client one sentence of prose and no data at all (ONE-1704 repair). The same
/// typed structured payload is therefore ALSO stated as protocol text content,
/// serialized canonically so the bytes are stable, while `structuredContent`
/// stays exactly as it was for clients that read it.
///
/// The carrier frame is deliberately not folded in: it is stream data BESIDE
/// the result, and mixing it into the tool's own content would be the carrier
/// leak the envelope keeps out.
fn mcp_negotiated_content(message: String, structured: &Value) -> Value {
    json!([
        mcp_text_content(message),
        mcp_text_content(crate::mcp::mcp_canonical_json(structured)),
    ])
}

fn mcp_board_frame_error(error: oneiron::context_board::BoardFrameError) -> McpGatewayError {
    McpGatewayError::new(-32603, "board_render_failed", error.to_string())
}

fn mcp_setup_payload_error(error: crate::mcp::McpSetupPayloadError) -> McpGatewayError {
    McpGatewayError::new(-32603, "board_render_failed", error.to_string())
}

fn mcp_surface_construction_error(
    error: crate::mcp::McpSurfaceConstructionError,
) -> McpGatewayError {
    McpGatewayError::new(-32603, "board_render_failed", error.to_string())
}

fn mcp_board_verb_error(error: oneiron::board_verb::BoardVerbError) -> McpGatewayError {
    McpGatewayError::new(-32020, "verb_dispatch_failed", format!("{error:?}"))
}

/// One connector's CURRENT board: the sections, the state-derived snapshot
/// epoch, and the scope label the header states.
struct McpBoardState {
    sections: Vec<oneiron::context_board::BoardSection>,
    scope_label: String,
    /// The monotonic snapshot epoch this exact state owns (ONE-1704 M5).
    epoch: u64,
    /// TASKS rows the credential's REQUESTED SCOPE ceiling removed.
    scope_omitted: usize,
    /// TASKS rows the engine's own render row cap truncated away. A page
    /// WINDOW fact, kept apart from the scope fact above (ONE-1704 repair).
    window_truncated: usize,
    /// False when the producer's own TASK scan stopped at its cap, so the
    /// truncation count above is a lower bound rather than a census.
    source_exhausted: bool,
}

impl McpBoardState {
    /// The COMPLETE omission facts this rendered board carries, on both axes
    /// and with the producer's own exhaustion bit.
    ///
    /// Every consumer of a board's honesty reads it from here, so no caller can
    /// derive a result fact from one axis while the board states two.
    const fn omissions(&self) -> McpBoardOmissions {
        McpBoardOmissions {
            scope_omitted: self.scope_omitted,
            window_truncated: self.window_truncated,
            source_exhausted: self.source_exhausted,
        }
    }
}

/// Reads the current board for one connector and fences it to a STATE epoch.
///
/// The epoch is minted by the registry from a hash of the rendered state, not
/// from a clock: a call a minute later over identical state gets the SAME
/// epoch, and a mutation a millisecond later gets the next one. The registry
/// RETAINS that snapshot, so a later `board.expand`/`board.refresh` fences
/// against the exact snapshot setup returned.
async fn mcp_current_board(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
) -> Result<McpBoardState, McpGatewayError> {
    let (sections, omissions) = mcp_board_sections(server, actor)?;
    let scope_label = crate::mcp::mcp_effective_scope_label(&actor.scope);
    let state_hash =
        crate::mcp::mcp_board_state_hash(&scope_label, &mcp_board_state_rows(&sections));
    let epoch = {
        let mut registry = server.mcp_registry.lock().await;
        registry.board_snapshot_epoch(&actor.stream_connection, state_hash)
    };
    Ok(McpBoardState {
        sections,
        scope_label,
        epoch,
        scope_omitted: omissions.scope_omitted,
        window_truncated: omissions.window_truncated,
        source_exhausted: omissions.source_exhausted,
    })
}

/// What one rendered board did NOT show, on its two independent axes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct McpBoardOmissions {
    /// Rows the REQUESTED ACTOR SCOPE removed.
    pub(crate) scope_omitted: usize,
    /// Rows the producer's own render window truncated away.
    pub(crate) window_truncated: usize,
    pub(crate) source_exhausted: bool,
}

impl McpBoardOmissions {
    /// The retrieval health these omission facts force, in the SAME meanings
    /// every other producer states ([`crate::mcp::McpPageSource::health`]).
    ///
    /// ONE-1704 repair: a board that withheld rows on EITHER axis is not
    /// healthy, and a board whose own TASK scan stopped at its cap is degraded
    /// rather than partial, because it does not know what it skipped. Reading
    /// only the scope axis let a board the render WINDOW had truncated be
    /// reported healthy, which told a caller an incomplete working set was the
    /// whole one.
    ///
    /// `produced` is not a health axis — [`crate::mcp::McpPageSource::health`]
    /// reads only the two omission counts and the exhaustion bit — so the row
    /// count is deliberately not restated here.
    pub(crate) const fn health(self) -> McpRetrievalHealth {
        crate::mcp::McpPageSource::scoped_window(
            0,
            self.scope_omitted,
            self.window_truncated,
            self.source_exhausted,
        )
        .health()
    }
}

/// Every board row, in section order: the exact material the snapshot epoch is
/// the epoch OF.
fn mcp_board_state_rows(sections: &[oneiron::context_board::BoardSection]) -> Vec<String> {
    let mut rows = Vec::new();
    for section in sections {
        rows.push(section.name().to_owned());
        rows.extend(section.pinned_rows().iter().cloned());
        rows.extend(section.detail_rows().iter().cloned());
    }
    rows
}

/// The board sections the primary keyframe renders over.
///
/// TASKS comes from the engine's own gated `tasks.check` facade, NARROWED to
/// this credential's world/facet ceiling before it ever reaches the renderer,
/// so a board a narrow connector reads is never the actor-wide board. The
/// pinned VERBS section restates the generated grammar as board state.
fn mcp_board_sections(
    server: &Arc<SyncServer>,
    actor: &McpResolvedActor,
) -> Result<(Vec<oneiron::context_board::BoardSection>, McpBoardOmissions), McpGatewayError> {
    let verbs = crate::mcp::generated_verb_tools().map_err(mcp_surface_construction_error)?;
    let verb_section = crate::mcp::mcp_verb_board_section(&verbs).map_err(mcp_board_frame_error)?;
    let facade = server.vault.memory(actor.actor_ref, actor.actor_class);
    let tasks = facade.tasks_check().map_err(mcp_facade_error)?;
    let (tasks, scope_omitted) = mcp_scoped_tasks_section(server, actor, tasks)?;
    // The engine's own footer states the render WINDOW's truncation and
    // whether its scan was exhausted. That is a different fact from the scope
    // filtering above, and the two are carried separately from here on.
    let omissions = McpBoardOmissions {
        scope_omitted,
        window_truncated: tasks
            .overflow
            .map_or(0, |overflow| overflow.known_omitted_rows),
        source_exhausted: tasks
            .overflow
            .is_none_or(|overflow| overflow.source_exhausted),
    };
    let agents = oneiron::context_board::render_agents_section(&[], &[]);
    let [tasks_section, agents_section] =
        oneiron::context_board::assemble_task_agent_sections(&tasks, &agents)
            .map_err(mcp_board_frame_error)?;
    Ok((vec![verb_section, tasks_section, agents_section], omissions))
}

/// Narrows one TASKS section to the credential's registered world/facet.
///
/// A vault-wide credential is unchanged and pays nothing. A NARROWED one keeps
/// only rows the store itself says the scope covers; the count it removed is
/// returned so the page metadata can state the omission instead of hiding it.
fn mcp_scoped_tasks_section(
    server: &Arc<SyncServer>,
    actor: &McpResolvedActor,
    section: oneiron::context_board::TasksSection,
) -> Result<(oneiron::context_board::TasksSection, usize), McpGatewayError> {
    if !actor.scope.is_narrow() {
        return Ok((section, 0));
    }
    let scoped_read = mcp_scoped_read(&server.vault, actor)?;
    let mut kept = Vec::with_capacity(section.rows.len());
    let mut omitted = 0_usize;
    for row in section.rows {
        if mcp_scope_admits_row(&scoped_read, &actor.scope, &row.id)? {
            kept.push(row);
        } else {
            omitted += 1;
        }
    }
    Ok((
        oneiron::context_board::TasksSection {
            rows: kept,
            overflow: section.overflow,
        },
        omitted,
    ))
}

/// True when the registered scope covers the row this board id names.
///
/// A row whose id is not an entity id cannot be proven in scope, so a narrowed
/// credential does not see it: this fails closed.
fn mcp_scope_admits_row(
    scoped_read: &oneiron::claim::ScopedRead<'_>,
    scope: &crate::mcp::McpConnectorScope,
    row_id: &str,
) -> Result<bool, McpGatewayError> {
    let Ok(id) = oneiron::EntityId::from_hex(row_id) else {
        return Ok(false);
    };
    let readable = scoped_read
        .is_entity_readable(&id)
        .map_err(|error| mcp_engine_error("mcp board row admission failed", error))?;
    Ok(readable && mcp_scope_covers_entity(scoped_read, scope, &id)?)
}

/// What a caller can actually DO next on this endpoint.
///
/// ONE-1704 B1: every line is true of the release that is shipping. There is no
/// `execute_code` lane to point at, so none is offered.
fn mcp_setup_help() -> Vec<String> {
    vec![
        "register the tool-first endpoint for one generated tool per verb".to_owned(),
        "execute_code is not shipped in this release; a direct call is refused with \
         execute_code_unavailable"
            .to_owned(),
        "a More result carries an opaque cursor; send it back as page.cursor with the same \
         arguments"
            .to_owned(),
    ]
}

/// The whole grammar list the setup result pages over.
fn mcp_setup_grammar_rows(structured: &Value) -> Vec<Value> {
    structured
        .get("verb_grammar")
        .and_then(|grammar| grammar.get("verbs"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// ENFORCES the resolved page window on the grammar list, in place.
fn mcp_cap_setup_grammar(structured: &mut Value, rows: Vec<Value>, page: &McpPageBudget) {
    let capped = page.cap(rows);
    if let Some(grammar) = structured
        .get_mut("verb_grammar")
        .and_then(Value::as_object_mut)
    {
        grammar.insert("verbs".to_owned(), Value::Array(capped));
    }
}

/// The pre-dispatch page state. A live cursor is consumed here, before the
/// producer is allowed to call a facade or mutate a registry. Its retained
/// snapshot is then used directly for the continuation, so no second producer
/// read can replace page one's result.
#[derive(Clone, Debug)]
struct McpPageDispatchState {
    continuation: Option<McpPageCursorState>,
    continuable: bool,
    producer_epoch: Option<u64>,
}

/// Verifies or rejects page.cursor before any producer dispatch.
///
/// A cursor on a one-row/non-continuable operation is refused at this door.
/// For a continuable operation, successful consumption returns the exact
/// producer snapshot retained with the handle. A mismatch returns before any
/// facade, board dispatcher, stream operation, or vault write, and consumes
/// nothing — this connection's other live continuations survive a refusal.
///
/// The fence is the IMMUTABLE snapshot RETAINED with the handle, never the
/// latest board epoch (ONE-1704 repair). A continued page is served from that
/// retained producer result, so a board mutation somewhere else between page
/// one and page two cannot make page two wrong — and refusing it there simply
/// destroyed a valid enumeration. Connector, tool, argument, and producer
/// identity stay bound: the registry checks all four against the retained row.
async fn mcp_preflight_page(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    tool: &str,
    argument_digest: [u8; 32],
    request: Option<&crate::mcp::McpPageRequest>,
    continuable: bool,
) -> Result<McpPageDispatchState, McpGatewayError> {
    let Some(cursor) = request.and_then(|page| page.cursor.as_deref()) else {
        return Ok(McpPageDispatchState {
            continuation: None,
            continuable,
            producer_epoch: None,
        });
    };
    if !continuable {
        return Err(mcp_page_cursor_error(
            crate::mcp::McpPageCursorError::Unsupported,
        ));
    }
    let mut registry = server.mcp_registry.lock().await;
    // Read only: this lookup does not render a board or touch stream state.
    let state = registry
        .consume_page_cursor_state(
            &actor.stream_connection,
            tool,
            argument_digest,
            None,
            cursor,
        )
        .map_err(mcp_page_cursor_error)?;
    if state.snapshot.is_none() {
        // Registry-only callers may mint an old position-only handle, but the
        // gateway cannot safely dispatch it: without the retained producer set
        // there is no exact continuation to return.
        return Err(mcp_page_cursor_error(
            crate::mcp::McpPageCursorError::SnapshotMismatch,
        ));
    }
    Ok(McpPageDispatchState {
        continuation: Some(state),
        continuable,
        producer_epoch: None,
    })
}

/// Resolves one page after the producer has either supplied a fresh snapshot or
/// the pre-dispatch door has supplied its retained one.
async fn mcp_resolve_page(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    tool: &str,
    argument_digest: [u8; 32],
    request: Option<&crate::mcp::McpPageRequest>,
    dispatch: &McpPageDispatchState,
    snapshot: &McpPageSnapshot,
) -> Result<McpPageBudget, McpGatewayError> {
    let mut registry = server.mcp_registry.lock().await;
    let snapshot_epoch = dispatch.continuation.as_ref().map_or_else(
        || dispatch.producer_epoch.unwrap_or(0),
        |continuation| continuation.snapshot_epoch,
    );
    let mut page = if dispatch.continuable {
        McpPageBudget::resolve_page(
            request,
            snapshot.source,
            dispatch
                .continuation
                .as_ref()
                .map_or(0, |state| state.position),
        )
    } else {
        McpPageBudget::resolve(request, snapshot.source)
    };
    if let Some(position) = page.successor_position() {
        let cursor = registry.mint_page_cursor_with_snapshot(
            &actor.stream_connection,
            tool,
            argument_digest,
            snapshot_epoch,
            position,
            Some(snapshot.clone()),
        );
        page.attach_cursor(cursor);
    }
    Ok(page)
}

fn mcp_page_cursor_error(error: crate::mcp::McpPageCursorError) -> McpGatewayError {
    McpGatewayError::new(-32602, error.error_code(), error.to_string()).with_field("page.cursor")
}

/// `setup_oneiron`: board keyframe + verb grammar + instructions, in ONE
/// result.
pub(crate) async fn execute_mcp_setup(
    server: &Arc<SyncServer>,
    args: crate::mcp::McpSetupToolArgs,
    actor: &McpCallContext,
) -> Result<Value, McpGatewayError> {
    // Bind BEFORE any board/facade read. A presented cursor is consumed only
    // after its connector/tool/arguments checks pass against the row retained
    // with it, and its retained producer result is then used directly below.
    let argument_digest = crate::mcp::mcp_page_argument_digest(&args);
    let mut dispatch = mcp_preflight_page(
        server,
        actor,
        crate::mcp::MCP_SETUP_TOOL,
        argument_digest,
        args.page.as_ref(),
        true,
    )
    .await?;
    let (mut structured, keyframe, health, snapshot, producer_epoch) = if let Some(continuation) =
        dispatch.continuation.as_ref()
    {
        let snapshot = continuation.snapshot.clone().ok_or_else(|| {
            mcp_page_cursor_error(crate::mcp::McpPageCursorError::SnapshotMismatch)
        })?;
        let keyframe = snapshot.keyframe.clone().ok_or_else(|| {
            mcp_page_cursor_error(crate::mcp::McpPageCursorError::SnapshotMismatch)
        })?;
        (
            snapshot.output.clone(),
            keyframe,
            snapshot.health,
            snapshot,
            None,
        )
    } else {
        // No cursor: this is page one, so produce and retain the exact
        // un-capped grammar/result before resolving its window.
        let board = mcp_current_board(server, actor).await?;
        // The GRAMMAR rows this page partitions are complete, but the health
        // this result states is the BOARD's, and the board has two omission
        // axes plus its own exhaustion bit. Deriving it from scope omission
        // alone reported a keyframe the render window had truncated — or one
        // whose TASK scan stopped at its cap — as healthy (ONE-1704 repair).
        let health = board.omissions().health();
        let header = oneiron::context_board::BoardBlockHeader {
            epoch: board.epoch,
            scope: board.scope_label,
        };
        let payload =
            crate::mcp::mcp_setup_payload(&header, &board.sections, args.board_budget_request())
                .map_err(mcp_setup_payload_error)?;
        let keyframe = oneiron::context_board::BoardStreamFrame {
            epoch: board.epoch,
            kind: oneiron::context_board::FrameKind::Keyframe(payload.board.text.clone()),
        };
        let structured = payload.to_value();
        let source = crate::mcp::McpPageSource::complete(mcp_setup_grammar_rows(&structured).len());
        let snapshot = McpPageSnapshot {
            output: structured.clone(),
            source,
            health,
            keyframe: Some(keyframe.clone()),
        };
        (structured, keyframe, health, snapshot, Some(board.epoch))
    };
    dispatch.producer_epoch = producer_epoch;
    let page = mcp_resolve_page(
        server,
        actor,
        crate::mcp::MCP_SETUP_TOOL,
        argument_digest,
        args.page.as_ref(),
        &dispatch,
        &snapshot,
    )
    .await?;
    let grammar_rows = mcp_setup_grammar_rows(&structured);
    mcp_cap_setup_grammar(&mut structured, grammar_rows, &page);
    if let Some(object) = structured.as_object_mut() {
        object.insert(
            "tool".to_owned(),
            Value::String(crate::mcp::MCP_SETUP_TOOL.to_owned()),
        );
        object.insert("actor".to_owned(), mcp_actor_result(actor));
        object.insert(
            "meta".to_owned(),
            actor.metadata(health, page, mcp_setup_help(), args.cache),
        );
    }
    // ONE-1704 carrier repair: PAGE ONE carries the keyframe it just minted and
    // supersedes the queue behind it. A CONTINUATION restates the SAME retained
    // keyframe page one already delivered, so treating it as fresh re-enqueued a
    // DUPLICATE: that push cleared the same-epoch delta rows queued behind it in
    // the engine's coalescer and was then consumed as the superseded drain, so
    // the continuation carried nothing and every later result had lost the
    // transition. A continuation is an ordinary result — it drains AT MOST ONE
    // already-queued carrier and re-enqueues nothing.
    let carrier_policy = if dispatch.continuation.is_some() {
        McpCarrierPolicy::Drain
    } else {
        McpCarrierPolicy::FreshKeyframe(Some(keyframe))
    };
    Ok(mcp_endpoint_result(
        server,
        actor,
        "board keyframe, verb grammar, and instructions returned",
        structured,
        carrier_policy,
    )
    .await)
}

/// `execute_code`: ONE durable REPL run, through the INJECTED host.
///
/// UNREACHABLE FROM THE WIRE in this release (ONE-1704 B1/B2). `execute_code`
/// is registered on neither endpoint and a direct call is refused at
/// [`mcp_execute_code_unavailable`] before this body could be entered, so no run
/// is created and the `resume` handle below never reaches a caller. The body is
/// kept as the private adapter over the injected host seam — the same shape M1
/// left the retired plain-verb adapters in — and NOT as a second catalog.
///
/// The gateway evaluates nothing and owns no dispatch loop. The bound host
/// constructs `HostSelfDispatcher`/`GatedActorWrite` and enters the existing
/// sandbox/REPL provider through `EngineNativeExecutor`, which owns every step,
/// replay row, and terminal marker. With no host bound this fails CLOSED.
pub(crate) async fn execute_mcp_execute_code(
    server: &Arc<SyncServer>,
    args: crate::mcp::McpExecuteCodeToolArgs,
    actor: &McpCallContext,
) -> Result<Value, McpGatewayError> {
    if args.page.as_ref().is_some_and(|page| page.cursor.is_some()) {
        return Err(mcp_page_cursor_error(
            crate::mcp::McpPageCursorError::Unsupported,
        ));
    }

    let host = crate::mcp::mcp_code_execution_host()
        .ok_or_else(|| mcp_code_execution_error(&crate::mcp::McpCodeExecutionError::HostUnbound))?;
    let run_id = crate::mcp::mcp_code_run_id(&args.run_ref, actor);
    let outcome = host
        .execute(crate::mcp::McpCodeExecutionRequest {
            vault: Arc::clone(&server.vault),
            actor,
            run_ref: &args.run_ref,
            task: &args.task,
            run_id,
        })
        .await
        .map_err(|error| mcp_code_execution_error(&error))?;

    let steps = outcome
        .replay_record
        .bridge_calls
        .iter()
        .map(|call| {
            json!({
                "seq": call.seq,
                "effect": call.effect.as_str(),
                "outcome": mcp_bridge_outcome_value(&call.outcome),
            })
        })
        .collect::<Vec<_>>();
    let terminal = matches!(
        outcome.status,
        oneiron::engine_executor::EngineExecutorStatus::Complete
    );
    // Non-continuable: the step log is a run's own, not a re-enumerable
    // producer set, so a non-terminal page here states
    // `continuation_unavailable` instead of minting a handle nothing consumes.
    let page = McpPageBudget::resolve(
        args.page.as_ref(),
        crate::mcp::McpPageSource::truncated(steps.len(), 0, terminal),
    );
    let steps = page.cap(steps);
    let structured = json!({
        "tool": crate::mcp::MCP_EXECUTE_CODE_TOOL,
        "schema_version": crate::mcp::MCP_CODE_RUN_SCHEMA_VERSION,
        "run_ref": args.run_ref,
        // The persisted run handle: the durable replay record this run id
        // addresses is the resume door, and re-entering it is one call.
        "run_id": run_id.to_hex(),
        "resume": {
            "tool": crate::mcp::MCP_EXECUTE_CODE_TOOL,
            "run_ref": args.run_ref,
            "run_id": run_id.to_hex(),
            "terminal": terminal,
        },
        "steps_run": outcome.steps_run,
        "bridge_calls": outcome.replay_record.bridge_calls.len(),
        "steps": steps,
        "result": mcp_executor_status_value(&outcome.status),
        "actor": mcp_actor_result(actor),
        "meta": actor.metadata(
            mcp_code_run_health(&outcome.status),
            page,
            mcp_code_run_help(&outcome.status),
            args.cache,
        ),
    });
    Ok(mcp_endpoint_result(
        server,
        actor,
        "execute_code run recorded",
        structured,
        McpCarrierPolicy::Drain,
    )
    .await)
}

fn mcp_code_execution_error(error: &crate::mcp::McpCodeExecutionError) -> McpGatewayError {
    let code = match error {
        crate::mcp::McpCodeExecutionError::HostUnbound => -32020,
        crate::mcp::McpCodeExecutionError::RunBinding(_)
        | crate::mcp::McpCodeExecutionError::Run(_) => -32603,
    };
    McpGatewayError::new(code, error.error_code(), error.to_string())
}

/// The health a run's own terminal state forces. A parked or yielded run has
/// not finished, and says so.
fn mcp_code_run_health(
    status: &oneiron::engine_executor::EngineExecutorStatus,
) -> McpRetrievalHealth {
    match status {
        oneiron::engine_executor::EngineExecutorStatus::Complete => McpRetrievalHealth::Healthy,
        oneiron::engine_executor::EngineExecutorStatus::Waiting(_)
        | oneiron::engine_executor::EngineExecutorStatus::Yielded { .. } => {
            McpRetrievalHealth::Partial
        }
        oneiron::engine_executor::EngineExecutorStatus::HardStepLimitReached => {
            McpRetrievalHealth::Degraded
        }
    }
}

/// What a caller can actually DO next. Every line here is true of the durable
/// run this result describes.
fn mcp_code_run_help(status: &oneiron::engine_executor::EngineExecutorStatus) -> Vec<String> {
    match status {
        oneiron::engine_executor::EngineExecutorStatus::Complete => {
            vec!["this durable run is complete; a new run_ref starts a new run".to_owned()]
        }
        oneiron::engine_executor::EngineExecutorStatus::Waiting(_) => vec![
            "this run is parked on a durable wait and persisted under run_id".to_owned(),
            "call execute_code again with the same run_ref to re-enter the persisted run"
                .to_owned(),
        ],
        oneiron::engine_executor::EngineExecutorStatus::Yielded { .. } => vec![
            "this run yielded at its soft step limit; the same run_ref continues it".to_owned(),
        ],
        oneiron::engine_executor::EngineExecutorStatus::HardStepLimitReached => {
            vec!["this run reached its hard step limit and will not continue".to_owned()]
        }
    }
}

fn mcp_durable_wait_value(wait: &oneiron::code_run::SelfDurableWait) -> Value {
    json!({
        "kind": "durable_wait",
        "wait_id": wait.wait_id.to_hex(),
        "effect": wait.effect.as_str(),
        "reason": mcp_durable_wait_reason(wait.reason),
        "prompt": wait.prompt,
    })
}

fn mcp_durable_wait_reason(reason: oneiron::code_run::SelfDurableWaitReason) -> &'static str {
    match reason {
        oneiron::code_run::SelfDurableWaitReason::HumanInput => "human_input",
        oneiron::code_run::SelfDurableWaitReason::DestructiveEffect => "destructive_effect",
        oneiron::code_run::SelfDurableWaitReason::OutboundEffect => "outbound_effect",
        oneiron::code_run::SelfDurableWaitReason::PeerResult => "peer_result",
    }
}

/// The executor status as typed wire data. `Waiting` stays `Waiting`.
fn mcp_executor_status_value(status: &oneiron::engine_executor::EngineExecutorStatus) -> Value {
    match status {
        oneiron::engine_executor::EngineExecutorStatus::Complete => {
            json!({ "status": "complete" })
        }
        oneiron::engine_executor::EngineExecutorStatus::Waiting(wait) => json!({
            "status": "waiting",
            "wait": mcp_durable_wait_value(wait),
        }),
        oneiron::engine_executor::EngineExecutorStatus::Yielded { next_step_seq } => json!({
            "status": "yielded",
            "next_step_seq": next_step_seq,
        }),
        oneiron::engine_executor::EngineExecutorStatus::HardStepLimitReached => {
            json!({ "status": "hard_step_limit_reached" })
        }
    }
}

/// One recorded bridge-call outcome as JSON, entry for entry.
///
/// `CodeRunBridgeCall.outcome` is the MessagePack value the engine's replay
/// record stores, so it cannot enter `json!` directly. Every arm states the
/// value it was handed: no entry is dropped, replaced by a placeholder, or
/// rendered as debug text. `Binary` is the recorder's entity-id form — it
/// stores `EntityId::as_bytes` — so it becomes the same lowercase hex
/// `EntityId::to_hex` puts on this wire everywhere else, which is what keeps a
/// step's `wait_id` equal to the `wait_id` under `result.wait`.
fn mcp_bridge_outcome_value(outcome: &rmpv::Value) -> Value {
    match outcome {
        rmpv::Value::Nil => Value::Null,
        rmpv::Value::Boolean(flag) => Value::Bool(*flag),
        rmpv::Value::Integer(number) => number
            .as_i64()
            .map(Value::from)
            .or_else(|| number.as_u64().map(Value::from))
            .unwrap_or(Value::Null),
        rmpv::Value::F32(number) => Value::from(f64::from(*number)),
        rmpv::Value::F64(number) => Value::from(*number),
        // A non-UTF-8 MessagePack string is bytes, so it is stated as hex like
        // any other byte string instead of collapsing to null.
        rmpv::Value::String(text) => text.as_str().map_or_else(
            || Value::String(super::hex_bytes(text.as_bytes())),
            |text| Value::String(text.to_owned()),
        ),
        rmpv::Value::Binary(bytes) => Value::String(super::hex_bytes(bytes)),
        rmpv::Value::Array(values) => {
            Value::Array(values.iter().map(mcp_bridge_outcome_value).collect())
        }
        rmpv::Value::Map(entries) => Value::Object(
            entries
                .iter()
                .map(|(key, value)| {
                    // The recorder writes string keys only; anything else keeps
                    // its JSON text so no entry can be erased.
                    let key = match mcp_bridge_outcome_value(key) {
                        Value::String(key) => key,
                        key => key.to_string(),
                    };
                    (key, mcp_bridge_outcome_value(value))
                })
                .collect(),
        ),
        // The recorder emits no ext values; the tag is kept beside its bytes so
        // this arm cannot silently drop one either.
        rmpv::Value::Ext(tag, bytes) => Value::Array(vec![
            Value::from(*tag),
            Value::String(super::hex_bytes(bytes)),
        ]),
    }
}

// ─── tool-first: one generated tool per exported verb row ──────────────────

/// The live board one board verb reads, assembled from the same sections the
/// primary keyframe renders. The engine's `dispatch_board_verb` owns every
/// board semantic; this only supplies the current view.
struct McpLiveBoard {
    /// The world this view was BUILT for, taken from the registered credential
    /// scope. `read_current` refuses any other, so the scope argument is
    /// enforced rather than ignored.
    world: oneiron::EntityId,
    view: oneiron::board_verb::LiveBoardView,
}

impl oneiron::board_verb::LiveBoardSource for McpLiveBoard {
    fn read_current(
        &self,
        scope: &oneiron::board_verb::BoardWorldScope,
    ) -> Result<oneiron::board_verb::LiveBoardView, oneiron::board_verb::BoardVerbError> {
        if scope.world() != self.world {
            return Err(oneiron::board_verb::BoardVerbError::Source(format!(
                "board world scope {requested} is not the scope this view was built for",
                requested = scope.world().to_hex(),
            )));
        }
        Ok(self.view.clone())
    }
}

/// The world one connector's board is read under.
///
/// Taken from the REGISTERED scope; a vault-wide credential reads its own
/// actor's board. Nothing a caller sends reaches this.
fn mcp_board_world(actor: &McpResolvedActor) -> oneiron::EntityId {
    actor.scope.world_ref.unwrap_or(actor.actor_ref)
}

fn mcp_live_board(
    actor: &McpResolvedActor,
    board: &McpBoardState,
) -> Result<McpLiveBoard, McpGatewayError> {
    let header = oneiron::context_board::BoardBlockHeader {
        epoch: board.epoch,
        scope: board.scope_label.clone(),
    };
    let render = oneiron::board_verb::render_current_keyframe(
        &header,
        &board.sections,
        oneiron::context_board::BoardBudgetRequest {
            harness_default_tok: crate::mcp::MCP_BOARD_BUDGET_TOK,
            caller_limit_tok: None,
            explicit_override_tok: None,
        },
    )
    .map_err(mcp_board_frame_error)?;

    let mut rows = std::collections::BTreeMap::new();
    let mut expansions = std::collections::BTreeMap::new();
    for section in &board.sections {
        let lines = section
            .pinned_rows()
            .iter()
            .chain(section.detail_rows())
            .cloned()
            .collect::<Vec<_>>();
        for (index, line) in lines.iter().enumerate() {
            rows.insert(format!("{}:{index}", section.name()), line.clone());
        }
        expansions.insert(section.name().to_owned(), lines);
    }
    Ok(McpLiveBoard {
        world: mcp_board_world(actor),
        view: oneiron::board_verb::LiveBoardView {
            snapshot: oneiron::context_board::BoardSnapshot {
                epoch: board.epoch,
                keyframe: render.text,
                rows,
            },
            expansions,
        },
    })
}

fn mcp_board_verb_call(
    args: &crate::mcp::McpVerbToolArgs,
) -> Result<oneiron::board_verb::BoardVerbCall, McpGatewayError> {
    let arguments = &args.payload.arguments;
    let scopes = || {
        arguments
            .scopes
            .iter()
            .flatten()
            .map(|scope| scope.engine())
            .collect::<std::collections::BTreeSet<_>>()
    };
    match args.tool.binding {
        crate::mcp::McpVerbBinding::BoardExpand => Ok(oneiron::board_verb::BoardVerbCall::Expand {
            key: arguments.key.clone().unwrap_or_default(),
            frame_epoch: arguments.frame_epoch,
        }),
        crate::mcp::McpVerbBinding::BoardRefresh => {
            Ok(oneiron::board_verb::BoardVerbCall::Refresh {
                frame_epoch: arguments.frame_epoch,
            })
        }
        crate::mcp::McpVerbBinding::BoardSubscribe => {
            Ok(oneiron::board_verb::BoardVerbCall::Subscribe { scopes: scopes() })
        }
        crate::mcp::McpVerbBinding::BoardUnsubscribe => {
            Ok(oneiron::board_verb::BoardVerbCall::Unsubscribe { scopes: scopes() })
        }
        _ => Err(mcp_verb_family_error(args)),
    }
}

fn mcp_verb_family_error(args: &crate::mcp::McpVerbToolArgs) -> McpGatewayError {
    McpGatewayError::new(
        -32603,
        "verb_dispatch_failed",
        format!(
            "{name} is not dispatched by the {family} verb executor",
            name = args.tool.name,
            family = args.tool.family.as_str(),
        ),
    )
}

fn mcp_board_verb_output_value(output: &oneiron::board_verb::BoardVerbOutput) -> Value {
    match output {
        oneiron::board_verb::BoardVerbOutput::Expanded { key, lines } => json!({
            "kind": "expanded",
            "key": key,
            "lines": lines,
        }),
        oneiron::board_verb::BoardVerbOutput::Frame(frame) => json!({
            "kind": "frame",
            "frame": frame,
        }),
        oneiron::board_verb::BoardVerbOutput::Subscription(receipt) => json!({
            "kind": "subscription",
            "connection": receipt.connection,
            "active": receipt.active,
        }),
    }
}

/// `board.*`: dispatched by the engine's own verb dispatcher, over this
/// connector's process-local STREAM state and the STATE-fenced board snapshot.
async fn execute_mcp_board_verb(
    server: &Arc<SyncServer>,
    args: &crate::mcp::McpVerbToolArgs,
    actor: &McpCallContext,
) -> Result<(Value, crate::mcp::McpPageSource, McpCarrierPolicy, u64), McpGatewayError> {
    let board = mcp_current_board(server, actor).await?;
    let omissions = board.omissions();
    let source = mcp_live_board(actor, &board)?;
    let scope = oneiron::board_verb::BoardWorldScope::single(mcp_board_world(actor));
    let call = mcp_board_verb_call(args)?;
    let mints_keyframe = matches!(args.tool.binding, crate::mcp::McpVerbBinding::BoardRefresh);

    let output = {
        let mut registry = server.mcp_registry.lock().await;
        let mut context = oneiron::board_verb::BoardVerbContext {
            connection: &actor.stream_connection,
            scope: &scope,
            source: &source,
            streams: registry.streams_mut(),
            budget: oneiron::context_board::BoardBudgetRequest {
                harness_default_tok: crate::mcp::MCP_BOARD_BUDGET_TOK,
                caller_limit_tok: None,
                explicit_override_tok: None,
            },
        };
        oneiron::board_verb::dispatch_board_verb(&mut context, call)
    }
    .map_err(mcp_board_verb_error)?;

    let value = mcp_board_verb_output_value(&output);
    let page_source = mcp_board_verb_page_source(args.tool.binding, &value, omissions);
    // A verb that just minted a fresh keyframe returns it as the RESULT; the
    // central chokepoint supersedes and drains the queue behind it, so it is
    // never also attached as a carrier beside itself and nothing is stranded.
    let carrier = if mints_keyframe {
        McpCarrierPolicy::FreshKeyframe(None)
    } else {
        McpCarrierPolicy::Drain
    };
    Ok((value, page_source, carrier, board.epoch))
}

/// What this board verb actually produced, what the REQUESTED SCOPE removed,
/// and what the board's own render window truncated.
///
/// ONE-1704 repair: the two are reported on separate axes, and only the section
/// the omissions are OF carries them. A `board.expand` of `VERBS` is not partial
/// because a TASKS row was outside the credential's ceiling, and rows the render
/// row cap dropped are a window fact rather than a scope one.
pub(crate) fn mcp_board_verb_page_source(
    binding: crate::mcp::McpVerbBinding,
    output: &Value,
    omissions: McpBoardOmissions,
) -> crate::mcp::McpPageSource {
    match binding {
        crate::mcp::McpVerbBinding::BoardExpand => {
            let produced = output
                .get("lines")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            if output.get("key").and_then(Value::as_str) == Some(MCP_BOARD_TASKS_SECTION) {
                crate::mcp::McpPageSource::scoped_window(
                    produced,
                    omissions.scope_omitted,
                    omissions.window_truncated,
                    omissions.source_exhausted,
                )
            } else {
                crate::mcp::McpPageSource::complete(produced)
            }
        }
        // A refresh renders the WHOLE board, so both axes apply to it.
        crate::mcp::McpVerbBinding::BoardRefresh => crate::mcp::McpPageSource::scoped_window(
            1,
            omissions.scope_omitted,
            omissions.window_truncated,
            omissions.source_exhausted,
        ),
        // A subscription receipt is one row and states itself completely.
        _ => crate::mcp::McpPageSource::complete(1),
    }
}

/// The board section the TASKS producer's omissions belong to.
pub(crate) const MCP_BOARD_TASKS_SECTION: &str = "TASKS";

/// `tasks.*`: dispatched through the engine's gated TASKS facades, under the
/// credential's own world/facet ceiling.
fn execute_mcp_tasks_verb(
    server: &Arc<SyncServer>,
    args: &crate::mcp::McpVerbToolArgs,
    actor: &McpResolvedActor,
) -> Result<(Value, crate::mcp::McpPageSource), McpGatewayError> {
    let facade = server.vault.memory(actor.actor_ref, actor.actor_class);
    let arguments = &args.payload.arguments;
    match args.tool.binding {
        crate::mcp::McpVerbBinding::TasksCheck => {
            let section = facade.tasks_check().map_err(mcp_facade_error)?;
            let (section, scope_omitted) = mcp_scoped_tasks_section(server, actor, section)?;
            // The footer type is `oneiron::context_board::tasks::TasksOverflow`,
            // whose module is private and which `context_board` does not
            // re-export, so the method item cannot be named from this crate.
            // Matching states the same optional line without a closure.
            let overflow_line = match section.overflow {
                Some(overflow) => overflow.line(),
                None => None,
            };
            // The producer's OWN honesty bits decide the end marker and the
            // health: a capped scan is degraded and non-terminal, never a
            // hard-coded healthy/complete. The render cap's omissions are a
            // WINDOW fact and stay apart from the requested scope's filtering
            // (ONE-1704 repair), so a caller can tell which one withheld rows.
            let window_truncated = section
                .overflow
                .map_or(0, |overflow| overflow.known_omitted_rows);
            let exhausted = section
                .overflow
                .is_none_or(|overflow| overflow.source_exhausted);
            let rows = section
                .rows
                .iter()
                .map(|row| {
                    json!({
                        "id": row.id,
                        "line": row.line,
                        "status": row.status.as_str(),
                        "is_intent": row.is_intent,
                    })
                })
                .collect::<Vec<_>>();
            let source = crate::mcp::McpPageSource::scoped_window(
                rows.len(),
                scope_omitted,
                window_truncated,
                exhausted,
            );
            Ok((
                json!({
                    "kind": "tasks_section",
                    "count": rows.len(),
                    "rows": rows,
                    "overflow": overflow_line,
                }),
                source,
            ))
        }
        // A direct expand by id is a READ producer with an enumerable row set,
        // so its whole result is retained and paged like any other continuable
        // read (ONE-1704 repair). It inherits no board scan cap, so it states
        // its own set complete.
        crate::mcp::McpVerbBinding::TasksExpand => {
            let lines = facade
                .tasks_expand(mcp_task_ref(arguments)?)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(lines.len());
            Ok((json!({ "kind": "expanded", "lines": lines }), source))
        }
        crate::mcp::McpVerbBinding::TasksAck => {
            let receipt = facade
                .tasks_ack(mcp_task_ref(arguments)?)
                .map_err(mcp_facade_error)?;
            Ok((
                json!({
                    "kind": "ack_receipt",
                    "task_ref": receipt.task_ref.to_hex(),
                    "acked": receipt.acked,
                }),
                crate::mcp::McpPageSource::complete(1),
            ))
        }
        crate::mcp::McpVerbBinding::TasksCancel => {
            let receipt = facade
                .tasks_cancel(oneiron::task_verb::TaskCancelTarget::Task(mcp_task_ref(
                    arguments,
                )?))
                .map_err(mcp_facade_error)?;
            Ok((
                json!({
                    "kind": "cancel_receipt",
                    "approval": receipt.approval.as_str(),
                    "effected": receipt.effected,
                    "proposal_ref": receipt.proposal_ref.map(|id| id.to_hex()),
                    "gate_decision_ref": receipt.gate_decision_ref,
                    "status": receipt
                        .status
                        .as_ref()
                        .map(|status| format!("{status:?}").to_ascii_lowercase()),
                }),
                crate::mcp::McpPageSource::complete(1),
            ))
        }
        crate::mcp::McpVerbBinding::TasksCreate => {
            let spec = arguments.spec.as_ref().ok_or_else(|| {
                McpGatewayError::new(-32602, "tool_args_invalid", "spec is required")
                    .with_field("arguments.spec")
            })?;
            let spec = oneiron::task_verb::TaskCreateSpec::new(
                oneiron::companion_value_from_json(spec).map_err(|error| {
                    mcp_engine_error("mcp tasks.create spec conversion failed", error)
                })?,
                arguments.label.clone(),
                Some(actor.actor_ref),
                Some(unix_seconds_now()),
            );
            let receipt = facade.tasks_create(&spec).map_err(mcp_facade_error)?;
            Ok((
                json!({
                    "kind": "create_receipt",
                    "task_ref": receipt.task_ref.map(|id| id.to_hex()),
                    "proposal_ref": receipt.proposal_ref.map(|id| id.to_hex()),
                    "approval": receipt.approval.as_str(),
                    "effected": receipt.effected,
                }),
                crate::mcp::McpPageSource::complete(1),
            ))
        }
        _ => Err(mcp_verb_family_error(args)),
    }
}

fn mcp_task_ref(
    arguments: &crate::mcp::McpVerbArguments,
) -> Result<oneiron::EntityId, McpGatewayError> {
    let task_ref = arguments.task_ref.as_deref().ok_or_else(|| {
        McpGatewayError::new(-32602, "tool_args_invalid", "task_ref is required")
            .with_field("arguments.task_ref")
    })?;
    parse_entity_id_param(task_ref, "arguments.task_ref").map_err(mcp_api_error)
}

/// One GENERATED verb tool call.
pub(crate) async fn execute_mcp_generated_verb(
    server: &Arc<SyncServer>,
    args: McpVerbToolArgs,
    actor: &McpCallContext,
) -> Result<Value, McpGatewayError> {
    let argument_digest = crate::mcp::mcp_page_argument_digest(&args.payload);
    // Every continuable READ producer, and only those: a mutating or one-row
    // verb refuses a cursor at the pre-dispatch door below. `tasks.expand` is a
    // read whose rows are an enumerable set, so it continues under the same
    // retained-snapshot protocol as the board/task pages (ONE-1704 repair).
    let continuable = matches!(
        args.tool.binding,
        crate::mcp::McpVerbBinding::BoardExpand
            | crate::mcp::McpVerbBinding::TasksCheck
            | crate::mcp::McpVerbBinding::TasksExpand
    );
    // This is deliberately before the board/tasks producer. A cursor presented
    // to a mutating or one-row verb is refused here, so it cannot hide a write
    // behind a later ToolMismatch/ArgumentsMismatch response.
    let mut dispatch = mcp_preflight_page(
        server,
        actor,
        args.tool.name,
        argument_digest,
        args.payload.page.as_ref(),
        continuable,
    )
    .await?;
    let (mut output, health, carrier, snapshot, producer_epoch) =
        if let Some(continuation) = dispatch.continuation.as_ref() {
            let snapshot = continuation.snapshot.clone().ok_or_else(|| {
                mcp_page_cursor_error(crate::mcp::McpPageCursorError::SnapshotMismatch)
            })?;
            let carrier = match snapshot.keyframe.clone() {
                Some(keyframe) => McpCarrierPolicy::FreshKeyframe(Some(keyframe)),
                None => McpCarrierPolicy::Drain,
            };
            (
                snapshot.output.clone(),
                snapshot.health,
                carrier,
                snapshot,
                None,
            )
        } else {
            let (output, source, carrier, producer_epoch) = match args.tool.family {
                crate::mcp::McpVerbFamily::Board => {
                    let (output, source, carrier, epoch) =
                        execute_mcp_board_verb(server, &args, actor).await?;
                    (output, source, carrier, Some(epoch))
                }
                crate::mcp::McpVerbFamily::Tasks => {
                    // Establish the board epoch before reading a continuable
                    // task set. The result itself is retained below, so a
                    // later continuation never re-reads mutable task rows.
                    let producer_epoch = if continuable {
                        Some(mcp_current_board(server, actor).await?.epoch)
                    } else {
                        None
                    };
                    let (output, source) = execute_mcp_tasks_verb(server, &args, actor)?;
                    (output, source, McpCarrierPolicy::Drain, producer_epoch)
                }
            };
            let snapshot = McpPageSnapshot {
                output: output.clone(),
                source,
                health: source.health(),
                keyframe: None,
            };
            (output, source.health(), carrier, snapshot, producer_epoch)
        };
    dispatch.producer_epoch = producer_epoch;
    let page = mcp_resolve_page(
        server,
        actor,
        args.tool.name,
        argument_digest,
        args.payload.page.as_ref(),
        &dispatch,
        &snapshot,
    )
    .await?;
    // The granted budget is ENFORCED here, not merely reported.
    mcp_cap_verb_rows(&mut output, &page);
    let structured = json!({
        "tool": args.tool.name,
        "family": args.tool.family.as_str(),
        "verb": args.tool.verb,
        "output": output,
        "actor": mcp_actor_result(actor),
        "meta": actor.metadata(
            health,
            page,
            vec!["call setup_oneiron on the primary endpoint for the whole grammar".to_owned()],
            args.payload.cache,
        ),
    });
    Ok(mcp_endpoint_result(
        server,
        actor,
        format!("{} completed", args.tool.name),
        structured,
        carrier,
    )
    .await)
}

/// Caps whichever row array this verb result pages over, in place.
///
/// A result that states `granted` and then ships more rows than that is the
/// fail-open this closes; the row count it reports is the count it returned.
fn mcp_cap_verb_rows(output: &mut Value, page: &McpPageBudget) {
    for key in ["rows", "lines"] {
        let Some(rows) = output.get(key).and_then(Value::as_array).cloned() else {
            continue;
        };
        let capped = page.cap(rows);
        let Some(object) = output.as_object_mut() else {
            return;
        };
        if object.contains_key("count") {
            object.insert("count".to_owned(), Value::from(capped.len()));
        }
        object.insert(key.to_owned(), Value::Array(capped));
        return;
    }
}

pub(crate) fn mcp_scoped_read<'a>(
    vault: &'a oneiron::Vault,
    actor: &McpResolvedActor,
) -> Result<oneiron::claim::ScopedRead<'a>, McpGatewayError> {
    let key = oneiron::claim::ScopedReadActorKey::with_actor_class(
        &actor.gate_actor_ref,
        actor.gate_actor_class,
    )
    .ok_or_else(|| {
        McpGatewayError::new(
            -32003,
            "mcp_actor_invalid",
            "resolved actor cannot be used as a scoped read key",
        )
    })?;
    Ok(vault.scoped_read(key))
}

pub(crate) fn mcp_actor_result(actor: &McpResolvedActor) -> Value {
    json!({
        "actor_ref": actor.actor_ref.to_hex(),
        "actor_class": actor.gate_actor_class,
        "gate_actor_ref": actor.gate_actor_ref,
        "gate_actor_class": actor.gate_actor_class,
        "scope": {
            "world_ref": actor.scope.world_ref.map(|id| id.to_hex()),
            "facet_ref": actor.scope.facet_ref.map(|id| id.to_hex()),
        },
    })
}

pub(crate) fn mcp_actor_class_wire(actor_class: McpActorClass) -> &'static str {
    match actor_class {
        McpActorClass::Human => "human",
        McpActorClass::Agent => "agent",
    }
}

pub(crate) fn mcp_text_content(text: impl Into<String>) -> Value {
    json!({
        "type": "text",
        "text": text.into(),
    })
}

pub(crate) fn mcp_api_error(error: ApiError) -> McpGatewayError {
    let code = match error.code() {
        ErrorCode::BadRequest => -32602,
        ErrorCode::NotFound => -32004,
        ErrorCode::InvalidState => -32020,
        ErrorCode::InternalServerError => -32603,
        _ => -32000,
    };
    let mut gateway = McpGatewayError::new(code, error.code().as_str(), error.message());
    if let ApiErrorDetails::BadRequest { field } = error.details()
        && let Some(field) = field
    {
        gateway = gateway.with_field(field.clone());
    }
    gateway
}

pub(crate) fn mcp_engine_error(context: &'static str, error: oneiron::Error) -> McpGatewayError {
    // ONE-1936: a stale write-verb target gets its own stable kind, not the
    // generic engine_error bucket, and carries the current head as data. The
    // caller re-gets that ref and decides again; nothing was written.
    if let oneiron::Error::WriteVerbTargetStale {
        successor_short_id, ..
    } = &error
    {
        return McpGatewayError::new(-32020, "write_verb_target_stale", error.to_string())
            .with_successor_short_id(successor_short_id.clone());
    }
    match error.kind() {
        ErrorKind::GateWriteRejected => {
            McpGatewayError::new(-32020, "gate_write_rejected", error.to_string())
        }
        ErrorKind::GateConsentStale => {
            McpGatewayError::new(-32020, "gate_consent_stale", error.to_string())
        }
        ErrorKind::EntityNotFound => {
            McpGatewayError::new(-32004, "entity_not_found", error.to_string())
        }
        _ => McpGatewayError::new(-32603, "engine_error", format!("{context}: {error}")),
    }
}

/// Every structured refusal states the same four things: the machine code, the
/// human sentence, what to do next, and which request under which scope.
pub(crate) fn mcp_error_response(id: Value, error: McpGatewayError) -> Value {
    let mut data = json!({
        "kind": error.kind,
        "error_code": error.kind,
        "human_message": error.message,
        "recovery_suggestions": crate::mcp::mcp_recovery_suggestions(error.kind),
        "request_id": mcp_request_id(&id),
    });
    if let Some(field) = error.field
        && let Some(object) = data.as_object_mut()
    {
        object.insert("field".to_owned(), Value::String(field));
    }
    if let Some(successor_short_id) = error.successor_short_id
        && let Some(object) = data.as_object_mut()
    {
        object.insert(
            "successor_short_id".to_owned(),
            Value::String(successor_short_id),
        );
    }
    if let Some(effective_scope) = error.effective_scope
        && let Some(object) = data.as_object_mut()
    {
        object.insert("effective_scope".to_owned(), *effective_scope);
    }
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": error.code,
            "message": error.message,
            "data": data,
        },
    })
}
