//! How an admitted MCP tool call executes: its params, its validation and its dispatch.
//! `execute_mcp_tool` and `mcp_params` are its call surface.
//! `crate::mcp` defines the validated tool args and errors forwarded here.

use super::*;

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

/// Dispatches one VALIDATED endpoint tool call: setup, execute_code, an
/// action, or one generated verb (ONE-1704). Nothing resolves a retired
/// `oneiron.*` name. `headers` and `connection` are the request's own: an
/// action's rows run under them.
pub(crate) async fn execute_mcp_tool(
    server: &Arc<SyncServer>,
    args: McpValidatedToolArgs,
    actor: &McpCallContext,
    headers: &HeaderMap,
    connection: &Extensions,
) -> Result<Value, McpGatewayError> {
    match &args {
        McpValidatedToolArgs::Verb(verb) => {
            mcp_verb_gate(server, verb.tool, &verb.payload.arguments, actor)?;
        }
        // Setup renders filtered board rows; execute_code persists its run
        // at once, whatever the program does.
        McpValidatedToolArgs::Setup(_) => {
            mcp_credential_gate(
                server,
                actor,
                McpRecordBounds::Filtered,
                McpCallEffect::Reads,
            )?;
        }
        // A result read takes the credential its run was admitted on.
        McpValidatedToolArgs::ExecuteCode(_) | McpValidatedToolArgs::ReadResult(_) => {
            mcp_execute_code_gate(server, actor)?;
        }
        // A live credential: the action door itself requires its verb's
        // scope and record bounds, as for an HTTP action, and each
        // verb-table row meets its own route's under the same credential.
        McpValidatedToolArgs::InvokeAction(_) => {
            mcp_credential_gate(
                server,
                actor,
                McpRecordBounds::Filtered,
                McpCallEffect::Reads,
            )?;
        }
    }
    // Each arm's future on the heap: the match would otherwise be as large
    // as its largest arm, inline in every caller's (FIX 12072).
    match args {
        McpValidatedToolArgs::Setup(args) => {
            Box::pin(execute_mcp_setup(server, *args, actor)).await
        }
        McpValidatedToolArgs::ExecuteCode(args) => {
            Box::pin(execute_mcp_execute_code(server, *args, actor)).await
        }
        McpValidatedToolArgs::ReadResult(args) => {
            Box::pin(execute_mcp_read_result(server, *args, actor)).await
        }
        McpValidatedToolArgs::InvokeAction(args) => {
            Box::pin(super::actions::execute_mcp_invoke_action(
                server, *args, actor, headers, connection,
            ))
            .await
        }
        McpValidatedToolArgs::Verb(args) => {
            Box::pin(execute_mcp_generated_verb(server, *args, actor)).await
        }
    }
}
