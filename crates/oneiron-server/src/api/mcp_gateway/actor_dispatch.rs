//! Tool execution dispatch across actors.

use super::{
    MCP_CREDENTIAL_HEADER, McpCallContext, McpGatewayError, execute_mcp_execute_code,
    execute_mcp_generated_verb, execute_mcp_setup, mcp_actor_class_wire,
};
use crate::api::unix_seconds_now;
use crate::mcp::McpActorMetadata;
use crate::mcp::McpConnectorActorResolutionError;
use crate::mcp::McpResolvedActor;
use crate::mcp::McpSurfaceMode;
use crate::mcp::McpToolValidationError;
use crate::mcp::McpValidatedToolArgs;
use crate::server::SyncServer;
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use oneiron::federation::{ScopeAxis, ScopeId};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::sync::Arc;

pub(crate) async fn resolve_mcp_gateway_actor(
    mode: McpSurfaceMode,
    request_id: &str,
    headers: &HeaderMap,
    server: &Arc<SyncServer>,
) -> Result<McpCallContext, McpGatewayError> {
    let credential = mcp_connector_credential(headers)?;
    let registry = server.mcp_registry.lock().await;
    let mut actor = registry
        .resolve(&credential, unix_seconds_now(), |actor_class, actor_ref| {
            server
                .vault
                .gate_actor_ceiling_exists(actor_class, actor_ref)
                .unwrap_or(false)
        })
        .map_err(mcp_actor_resolution_error)?;
    drop(registry);
    // The connector header selects a registered instrument, not another
    // principal. Verify that exact instrument with its holder proof; never
    // borrow an unrelated Authorization header's owner privileges.
    let mut proof_headers = headers.clone();
    proof_headers.insert(
        AUTHORIZATION,
        format!("Bearer {credential}")
            .parse()
            .map_err(|_| mcp_proof_error())?,
    );
    let auth = crate::auth::CoreAuth::from_headers(
        &proof_headers,
        &server.config,
        server.vault().as_ref(),
    )
    .map_err(|_| mcp_proof_error())?;
    let proof = auth.verified_slip().ok_or_else(mcp_proof_error)?;
    // Only the actual configured root may act through its host-registered
    // actor. Every client is bound to the paired holder and verified class.
    if !(auth.principal_ref().is_none() && auth.is_owner_grade())
        && (auth.principal_ref() != Some(actor.gate_actor_ref.as_str())
            || auth.actor_class() != Some(actor.gate_actor_class))
    {
        return Err(mcp_proof_error());
    }
    if auth.org_ref().is_some() || !proof.allows_verb("read") {
        return Err(mcp_proof_error());
    }
    // The legacy registry can represent only all or one world/facet. Refuse
    // a wider registration instead of silently projecting away verifier bounds.
    let axis = |id: Option<oneiron::EntityId>| {
        id.map_or(ScopeAxis::All, |id| {
            ScopeAxis::Some(std::collections::BTreeSet::from([ScopeId(id)]))
        })
    };
    if !axis(actor.scope.world_ref).is_narrowing_of(&proof.scope().worlds)
        || !axis(actor.scope.facet_ref).is_narrowing_of(&proof.scope().facets)
    {
        return Err(mcp_proof_error());
    }
    actor.auth = Some(auth);
    Ok(McpCallContext {
        actor,
        mode,
        request_id: request_id.to_owned(),
    })
}

fn mcp_proof_error() -> McpGatewayError {
    McpGatewayError::new(
        -32001,
        "mcp_auth_required",
        "the registered connector requires its live paired holder proof",
    )
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
        McpValidatedToolArgs::Setup(args) => &args.actor,
        McpValidatedToolArgs::ExecuteCode(args) => &args.actor,
        McpValidatedToolArgs::Verb(args) => &args.payload.actor,
    }
}

/// Dispatches one VALIDATED endpoint tool call: setup, execute_code, or one
/// generated verb (ONE-1704). Nothing resolves a retired `oneiron.*` name.
pub(crate) async fn execute_mcp_tool(
    server: &Arc<SyncServer>,
    args: McpValidatedToolArgs,
    actor: &McpCallContext,
) -> Result<Value, McpGatewayError> {
    match &args {
        McpValidatedToolArgs::Verb(verb) => {
            mcp_verb_gate(server, verb.tool, &verb.payload.arguments, actor)?;
        }
        // Setup renders filtered board rows; execute_code may write.
        McpValidatedToolArgs::Setup(_) => mcp_credential_gate(server, actor, true, false)?,
        McpValidatedToolArgs::ExecuteCode(_) => mcp_credential_gate(server, actor, false, true)?,
    }
    match args {
        McpValidatedToolArgs::Setup(args) => execute_mcp_setup(server, *args, actor).await,
        McpValidatedToolArgs::ExecuteCode(args) => {
            execute_mcp_execute_code(server, *args, actor).await
        }
        McpValidatedToolArgs::Verb(args) => execute_mcp_generated_verb(server, *args, actor).await,
    }
}

/// One generated verb's credential gate, whichever door the call arrived at.
///
/// Board/task lists are explicitly filtered row by row. Task detail/write
/// facades have no recursive proof projection, so they require an unrestricted
/// record scope instead of dropping caveats. A filtered read that names one
/// task reads that task's card, which is task detail too. `describe(self)`
/// renders the whole run brief, not filtered rows, so it takes the same guard.
pub(crate) fn mcp_verb_gate(
    server: &Arc<SyncServer>,
    tool: crate::mcp::McpGeneratedVerbTool,
    arguments: &crate::mcp::McpVerbArguments,
    actor: &McpCallContext,
) -> Result<(), McpGatewayError> {
    let filtered_read =
        tool.filtered_read() && arguments.task_ref.is_none() && arguments.self_target != Some(true);
    mcp_credential_gate(server, actor, filtered_read, tool.writes())
}

/// The connector credential is live, inside its record bounds unless the call
/// is a filtered list, and holds Read or Write for what the call does.
fn mcp_credential_gate(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    filtered_read: bool,
    writes: bool,
) -> Result<(), McpGatewayError> {
    let auth = actor.auth.as_ref().ok_or_else(mcp_proof_error)?;
    if !auth.credential_is_live(server.vault().as_ref()) {
        return Err(mcp_proof_error());
    }
    if !filtered_read {
        auth.require_unrestricted_record_scope().map_err(|_| {
            McpGatewayError::new(
                -32020,
                "mcp_scope_unprojectable",
                "this facade cannot project the credential's record bounds",
            )
        })?;
    }
    auth.require(if writes {
        crate::auth::CoreScope::Write
    } else {
        crate::auth::CoreScope::Read
    })
    .map_err(|_| mcp_proof_error())
}
