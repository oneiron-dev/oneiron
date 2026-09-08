//! JSON-RPC envelope types and request dispatch.

use super::{
    ensure_mcp_actor_matches, execute_mcp_tool, mcp_actor_result, mcp_admit_scoped_call,
    mcp_error_response, mcp_params, mcp_validated_call_args, resolve_mcp_gateway_actor,
};
use crate::mcp::McpCacheHint;
use crate::mcp::McpPageBudget;
use crate::mcp::McpResolvedActor;
use crate::mcp::McpResultMetadata;
use crate::mcp::McpRetrievalHealth;
use crate::mcp::McpSurfaceMode;
use crate::server::SyncServer;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::response::Json;
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
}

#[derive(Debug)]
pub(crate) struct McpGatewayError {
    pub(super) code: i64,
    pub(super) kind: &'static str,
    pub(super) message: String,
    pub(super) field: Option<String>,
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
}

impl McpGatewayError {
    pub(super) fn new(code: i64, kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            kind,
            message: message.into(),
            field: None,
            successor_short_id: None,
            effective_scope: None,
        }
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
    pub(super) fn metadata(
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
