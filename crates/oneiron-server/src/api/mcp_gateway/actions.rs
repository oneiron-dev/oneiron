//! `invoke_action` (OF-181): one action of the app's table over MCP, run by
//! the one door `POST /v1/core/actions/{verb}` runs it through
//! ([`invoke_action`]).
//!
//! The action runs as the credential the connector header selected, as the
//! call's verified auth at its connection: the principal, read key,
//! idempotency identity and locality an HTTP call with that credential has.
//! So a live-run handle that credential attached over HTTP at the same
//! locality resolves here, and another credential meets the resolver's own
//! refusals. Its verb-table rows run through their own routes under this
//! request's headers, the selected credential as their bearer, and its
//! connection.
//!
//! A handle is per call: no attach tool, and no run a session holds.

use std::sync::Arc;

use axum::http::{Extensions, HeaderMap, StatusCode};
use serde_json::{Value, json};

use super::actor_dispatch::{mcp_proof_error, mcp_proof_headers};
use super::{
    McpCallContext, McpCarrierPolicy, McpGatewayError, mcp_actor_result, mcp_endpoint_result,
    mcp_facade_error, mcp_release_result,
};
use crate::api::facade::FacadeApiError;
use crate::api::facade::action_routes::{ActionRequest, invoke_action};
use crate::mcp::{
    MCP_INVOKE_ACTION_TOOL, McpInvokeActionToolArgs, McpPageBudget, McpPageSource,
    McpRetrievalHealth,
};
use crate::server::{LiveRunRefusal, SyncServer};

/// One `invoke_action` call: the action `args` names, under `actor`'s
/// verified auth, its rows under `headers` and `connection`, the request's
/// own. Its result is released as every result is.
pub(crate) async fn execute_mcp_invoke_action(
    server: &Arc<SyncServer>,
    args: McpInvokeActionToolArgs,
    actor: &McpCallContext,
    headers: &HeaderMap,
    connection: &Extensions,
) -> Result<Value, McpGatewayError> {
    let auth = actor.auth.as_ref().ok_or_else(mcp_proof_error)?;
    let request = ActionRequest {
        args: args.args,
        idempotency_key: args.idempotency_key,
        live_run: args.live_run,
    };
    let output = invoke_action(
        server,
        auth,
        mcp_proof_headers(headers)?,
        connection.clone(),
        args.verb.clone(),
        request,
    )
    .await
    .map_err(mcp_action_error)?;
    let structured = json!({
        "tool": MCP_INVOKE_ACTION_TOOL,
        "verb": args.verb,
        "output": output,
        "actor": mcp_actor_result(actor),
        "meta": actor.metadata(
            McpRetrievalHealth::Healthy,
            McpPageBudget::resolve(None, McpPageSource::complete(1)),
            vec!["list the app's actions at GET /v1/core/actions".to_owned()],
            None,
        ),
    });
    let result = mcp_endpoint_result(
        server,
        actor,
        format!("{} completed", args.verb),
        structured,
        McpCarrierPolicy::Drain,
    )
    .await;
    mcp_release_result(server, actor, &[], false, result)
}

/// An action's refusal as the gateway's: a live-run refusal keeps its own
/// code as its kind, and any other is reported as every typed facade
/// refusal is.
fn mcp_action_error(error: FacadeApiError) -> McpGatewayError {
    let error = error.into_memory_error();
    match LiveRunRefusal::from_code(&error.code) {
        Some(refusal) => {
            let code = if refusal.status() == StatusCode::BAD_REQUEST {
                -32602
            } else {
                -32020
            };
            McpGatewayError::new(code, refusal.code(), error.message)
        }
        None => mcp_facade_error(error),
    }
}
