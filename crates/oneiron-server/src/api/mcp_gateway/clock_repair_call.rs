//! An MCP `tools/call` of the owner's authority clock repair whose caller
//! the repair's own writer judges (FIX 11190, FIX 11202): one the binding
//! door left unjudged over a damaged floor, or a held MCP socket's call
//! while this handle's authority readings refuse — a managed vault's
//! owner's, or a slip socket's upgrade-verified slip (FIX 11525). It runs
//! before any caller is resolved or any invocation claimed, since each of
//! those reads the clock it repairs, and after the call's params, metadata
//! and arguments are checked as every tool call's are.
//! `deferred_caller` and `repair_call` are its call surface.

use std::sync::Arc;

use axum::http::header::AUTHORIZATION;
use axum::http::{Extensions, HeaderMap};
use oneiron::authority::ClockRepairCaller;
use serde_json::{Value, json};

use super::{
    MCP_CREDENTIAL_HEADER, McpGatewayError, McpToolCallParams, ensure_mcp_actor_matches,
    mcp_agent_verb_input, mcp_facade_error, mcp_params, mcp_text_content, mcp_validated_call_args,
};
use crate::api::clock_ingress;
use crate::mcp::{McpConnectorScope, McpResolvedActor, McpSurfaceMode, McpValidatedToolArgs};
use crate::server::SyncServer;

/// The repair's caller for a `tools/call` naming `params`'s tool, when its
/// writer judges it: the binding door left it unjudged, or it came on a
/// held MCP socket while the floor refuses readings — a managed owner's,
/// with no credential of its own, whose verified session holder is the
/// evidence, or a slip's, whose upgrade's verified slip rides the request
/// (FIX 11525). `None` for every other call, which takes the gateway's own
/// path.
pub(super) fn deferred_caller(
    server: &SyncServer,
    headers: &HeaderMap,
    connection: &Extensions,
    params: Option<&Value>,
) -> Option<ClockRepairCaller> {
    let tool = params
        .and_then(|params| params.get("name"))
        .and_then(Value::as_str);
    if tool != Some(clock_ingress::REPAIR_VERB) {
        return None;
    }
    if clock_ingress::repair_marked(connection) {
        return clock_ingress::request_repair_caller(server, headers, connection, true);
    }
    // A slip socket's repair call (FIX 11525): the slip its upgrade
    // verified, carried on the request, while the floor refuses readings.
    // The repair's writer judges it; nothing here re-verifies on the
    // damaged clock, which would refuse before it.
    if let Some(carried) = connection.get::<clock_ingress::McpSocketSlip>() {
        if server.vault().authority_clock_refuses_readings().unwrap_or(false) {
            return Some(ClockRepairCaller::verified(carried.slip().clone()));
        }
    }
    let holder = super::owner_call::session_owner(connection, server)?;
    let credentialed =
        headers.contains_key(MCP_CREDENTIAL_HEADER) || headers.contains_key(AUTHORIZATION);
    (!credentialed
        && server
            .vault()
            .authority_clock_refuses_readings()
            .unwrap_or(false))
    .then(|| ClockRepairCaller::managed_owner(holder))
}

/// The repair for `caller`, asked by `params` on `mode`: the params, their
/// invocation and hook metadata, the registered tool and its arguments
/// checked as every tool call's are, the actor they name held to the person
/// the caller says it is (whom the writer then proves), and the input the
/// arguments assemble checked as the row checks it; then the repair's own
/// answer as the tool's structured output, or its typed refusal.
pub(super) async fn repair_call(
    server: &Arc<SyncServer>,
    mode: McpSurfaceMode,
    params: Option<Value>,
    raw_arguments: Option<&str>,
    caller: ClockRepairCaller,
) -> Result<Value, McpGatewayError> {
    let params: McpToolCallParams = mcp_params(params, "params")?;
    params.invocation()?;
    params.hook_ask()?;
    let person = caller.person().ok_or_else(|| {
        mcp_facade_error(oneiron::MemoryError::new(
            oneiron::MEMORY_CODE_FORBIDDEN,
            format!("{} is the vault owner's", clock_ingress::REPAIR_VERB),
            &["Present the owner's own verified, unattenuated credential."],
        ))
    })?;
    let scope = McpConnectorScope::vault_wide();
    let actor = McpResolvedActor {
        auth: None,
        actor_ref: person,
        actor_class: oneiron::EdgeActorClass::Human,
        gate_actor_class: oneiron::EdgeActorClass::Human.gate_actor_class(),
        gate_actor_ref: person.to_hex(),
        stream_connection: super::owner_call::owner_stream_connection(person),
        bound_verbs: None,
        subscription_ceiling: scope.subscription_ceiling(),
        scope,
    };
    let args = mcp_validated_call_args(server, mode, params, raw_arguments, &actor)?;
    ensure_mcp_actor_matches(&args, &actor)?;
    let McpValidatedToolArgs::Verb(verb) = &args else {
        return Err(McpGatewayError::new(
            -32602,
            "unknown_tool",
            format!(
                "{} is not a verb tool on this endpoint",
                clock_ingress::REPAIR_VERB
            ),
        )
        .with_field("name"));
    };
    let input = mcp_agent_verb_input(verb.tool.name, &verb.payload.arguments)?;
    oneiron::task_verb::sdk::validate_input(clock_ingress::REPAIR_VERB, &input)
        .map_err(mcp_facade_error)?;
    let output = clock_ingress::repair(server, caller)
        .await
        .map_err(mcp_facade_error)?;
    let output = serde_json::to_value(output).map_err(|_| {
        McpGatewayError::new(
            -32603,
            "engine_error",
            "typed agent result cannot be encoded",
        )
    })?;
    Ok(json!({
        "content": [mcp_text_content(format!("{} completed", clock_ingress::REPAIR_VERB))],
        "structuredContent": {
            "tool": clock_ingress::REPAIR_VERB,
            "verb": clock_ingress::REPAIR_VERB,
            "output": output,
        },
    }))
}
