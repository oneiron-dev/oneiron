//! Tool-first projections of the engine-owned typed read table.

use super::{McpGatewayError, mcp_scoped_read};
use crate::mcp::{McpResolvedActor, McpVerbBinding, McpVerbToolArgs};
use crate::server::SyncServer;
use oneiron::code_run::vault_read::{
    InProcessVaultReadAdapter, VaultReadClient, VaultReadError, VaultReadMethod,
};
use serde_json::{Value, json};
use std::sync::Arc;

pub(super) fn execute(
    server: &Arc<SyncServer>,
    args: &McpVerbToolArgs,
    actor: &McpResolvedActor,
) -> Result<Value, McpGatewayError> {
    let McpVerbBinding::Memory(method) = args.tool.binding else {
        return Err(super::mcp_verb_family_error(args));
    };
    let body = args.payload.arguments.request.clone().ok_or_else(|| {
        McpGatewayError::new(-32602, "tool_args_invalid", "native request is required")
            .with_field("arguments.request")
    })?;
    let reader = mcp_scoped_read(&server.vault, actor)?;
    let adapter = InProcessVaultReadAdapter::new(&server.vault, reader.actor_key().clone());
    macro_rules! call {
        ($name:ident) => {{
            let request = serde_json::from_value(body).map_err(|_| {
                McpGatewayError::new(
                    -32602,
                    "tool_args_invalid",
                    "request does not match the native method schema",
                )
                .with_field("arguments.request")
            })?;
            let response = adapter.$name(request).map_err(native_error)?;
            serde_json::to_value(response).map_err(|_| {
                McpGatewayError::new(-32603, "engine_error", "native response cannot be encoded")
            })?
        }};
    }
    let response = match method {
        VaultReadMethod::Query => call!(query),
        VaultReadMethod::ContextPack => call!(context_pack),
        VaultReadMethod::Hydrate => call!(hydrate),
        VaultReadMethod::HydrateMany => call!(hydrate_many),
        VaultReadMethod::MemoryTimeline => call!(memory_timeline),
        VaultReadMethod::Ask => call!(ask),
        VaultReadMethod::CodeSearch => call!(code_search),
        VaultReadMethod::CodeExecute => call!(code_execute),
    };
    Ok(json!({ "kind": "vault_read", "method": method, "response": response }))
}

fn native_error(mut error: VaultReadError) -> McpGatewayError {
    let mut result = match &error {
        VaultReadError::InvalidRequest { field, reason, .. } => {
            McpGatewayError::new(-32602, "tool_args_invalid", reason.clone())
                .with_field(format!("arguments.request.{field}"))
        }
        VaultReadError::RuntimeUnavailable { .. } => McpGatewayError::new(
            -32020,
            "runtime_unavailable",
            "this engine method has no runtime in the current contract",
        ),
        VaultReadError::Engine { engine_code, .. } if engine_code == "NOT_FOUND" => {
            McpGatewayError::new(-32004, "entity_not_found", "requested entity was not found")
        }
        _ => McpGatewayError::new(-32603, "engine_error", "native memory read failed"),
    };
    // Keep typed identity without exposing internal filesystem/policy details.
    if let VaultReadError::Engine {
        engine_code,
        message,
        ..
    } = &mut error
    {
        *message = if engine_code == "NOT_FOUND" {
            "requested entity was not found"
        } else {
            "native memory read failed"
        }
        .to_owned();
    }
    result.vault_read = Some(Box::new(error));
    result
}
