//! Tool execution dispatch across actors.

use super::{
    MCP_CREDENTIAL_HEADER, McpCallContext, McpGatewayError, execute_mcp_calendar, execute_mcp_edit,
    execute_mcp_execute_code, execute_mcp_generated_verb, execute_mcp_nav, execute_mcp_read,
    execute_mcp_setup, mcp_actor_class_wire, mcp_actor_result, mcp_ask_result,
    mcp_routed_ask_result, mcp_text_content,
};
use crate::api::unix_seconds_now;
use crate::error::ApiError;
use crate::error::ApiErrorDetails;
use crate::mcp::McpActorMetadata;
use crate::mcp::McpConnectorActorResolutionError;
use crate::mcp::McpResolvedActor;
use crate::mcp::McpSurfaceMode;
use crate::mcp::McpToolName;
use crate::mcp::McpToolValidationError;
use crate::mcp::McpValidatedToolArgs;
use crate::server::SyncServer;
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use serde::de::DeserializeOwned;
use serde_json::Value;
use serde_json::json;
use std::sync::Arc;

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
