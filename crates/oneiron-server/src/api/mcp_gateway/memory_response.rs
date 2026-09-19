//! Tool-first projections of the engine-owned typed read table.

use super::{McpGatewayError, mcp_engine_error, mcp_scoped_read};
use crate::mcp::{McpResolvedActor, McpVerbBinding, McpVerbToolArgs};
use crate::server::SyncServer;
use oneiron::code_run::vault_read::{
    CoreEntityRecord, CoreHydrateResponse, CoreHydrateStatus, InProcessVaultReadAdapter,
    VaultReadClient, VaultReadError, VaultReadMethod, View,
};
use oneiron::context_board::CapabilityHit;
use serde_json::{Value, json};
use std::sync::Arc;

/// All observations are staged from typed, post-limit results. No failed
/// adapter call, encoding failure, or partial batch commits a read-set event.
pub(super) async fn execute(
    server: &Arc<SyncServer>,
    args: &McpVerbToolArgs,
    actor: &McpResolvedActor,
) -> Result<(Value, Vec<CapabilityHit>), McpGatewayError> {
    let produced = execute_read(server, args, actor)?;
    if !produced.served.is_empty() {
        let mut target = super::board_observations::read_set(server, actor).await;
        let reader = mcp_scoped_read(&server.vault, actor)?;
        let mut staged = target.clone();
        for observation in produced.served {
            if let Some(body) = observation.skill_body {
                staged.observe_snapshot(
                    &reader,
                    observation.id,
                    oneiron::registry::ENTITY_TYPE_SKILL,
                    &body,
                    true,
                )
            } else {
                staged.observe_rows(&reader, &[observation.id])
            }
            .map_err(|error| mcp_engine_error("mcp session observation failed", error))?;
        }
        *target = staged;
    }
    Ok((produced.output, produced.capabilities))
}

struct MemoryRead {
    output: Value,
    served: Vec<ReadObservation>,
    capabilities: Vec<CapabilityHit>,
}

fn execute_read(
    server: &SyncServer,
    args: &McpVerbToolArgs,
    actor: &McpResolvedActor,
) -> Result<MemoryRead, McpGatewayError> {
    let McpVerbBinding::Memory(method) = args.tool.binding else {
        return Err(super::mcp_verb_family_error(args));
    };
    let body = args.payload.arguments.request.clone().ok_or_else(|| {
        McpGatewayError::new(-32602, "tool_args_invalid", "native request is required")
            .with_field("arguments.request")
    })?;
    let reader = mcp_scoped_read(&server.vault, actor)?;
    let adapter = InProcessVaultReadAdapter::new(&server.vault, reader.actor_key().clone());
    let mut served = Vec::new();
    let mut capabilities = Vec::new();
    macro_rules! call {
        ($name:ident) => {{ encode(adapter.$name(request(body)?).map_err(native_error)?)? }};
    }
    let response = match method {
        VaultReadMethod::Query => {
            let request: oneiron::code_run::vault_read::CoreQueryRequest = request(body)?;
            let full = request.view == Some(View::Full);
            let response = adapter.query(request).map_err(native_error)?;
            for row in &response.items {
                served.push(observation(row, full)?);
            }
            encode(response)?
        }
        VaultReadMethod::ContextPack => {
            let response = adapter.context_pack(request(body)?).map_err(native_error)?;
            capabilities.clone_from(&response.0.capabilities);
            for row in response.0.results.iter().chain(&response.0.neighbors) {
                let id = parse_returned_id(&row.id)?;
                // Only a complete typed SKILL body is a load. Metadata and
                // field selections that cannot decode the record stay rows.
                let skill_body = if row.entity_type == oneiron::registry::ENTITY_TYPE_SKILL {
                    row.fields
                        .as_ref()
                        .and_then(|fields| rmp_serde::to_vec_named(fields).ok())
                        .filter(|body| oneiron::skill::decode_skill_record(body).is_ok())
                } else {
                    None
                };
                served.push(ReadObservation { id, skill_body });
            }
            encode(response)?
        }
        VaultReadMethod::Hydrate => {
            let request: oneiron::code_run::vault_read::CoreHydrateRequest = request(body)?;
            let full = request.view.unwrap_or(View::Full) == View::Full;
            let response = adapter.hydrate(request).map_err(native_error)?;
            observe_hydrate(&response, full, &mut served)?;
            encode(response)?
        }
        VaultReadMethod::HydrateMany => {
            let request: oneiron::code_run::vault_read::CoreBatchShortIdHydrateRequest =
                request(body)?;
            let full = request.view.unwrap_or(View::Full) == View::Full;
            let response = adapter.hydrate_many(request).map_err(native_error)?;
            for item in &response.results {
                if let Some(response) = &item.result {
                    observe_hydrate(response, full, &mut served)?;
                }
            }
            encode(response)?
        }
        // Timelines return metadata, not bodies or discovery rows.
        VaultReadMethod::MemoryTimeline => call!(memory_timeline),
        VaultReadMethod::Ask => call!(ask),
        VaultReadMethod::CodeSearch => call!(code_search),
        VaultReadMethod::CodeExecute => call!(code_execute),
    };
    let output = json!({ "kind": "vault_read", "method": method, "response": response });
    Ok(MemoryRead {
        output,
        served,
        capabilities,
    })
}

struct ReadObservation {
    id: oneiron::EntityId,
    skill_body: Option<Vec<u8>>,
}

fn observation(row: &CoreEntityRecord, full: bool) -> Result<ReadObservation, McpGatewayError> {
    let id = parse_returned_id(&row.id)?;
    let skill_body = if full && row.entity_type == oneiron::registry::ENTITY_TYPE_SKILL {
        row.body
            .as_ref()
            .map(rmp_serde::to_vec_named)
            .transpose()
            .map_err(|_| {
                McpGatewayError::new(
                    -32603,
                    "engine_error",
                    "native skill body cannot be encoded",
                )
            })?
    } else {
        None
    };
    Ok(ReadObservation { id, skill_body })
}

fn observe_hydrate(
    response: &CoreHydrateResponse,
    full: bool,
    served: &mut Vec<ReadObservation>,
) -> Result<(), McpGatewayError> {
    if response.status == CoreHydrateStatus::Live
        && let Some(row) = &response.item
    {
        served.push(observation(row, full)?);
    }
    Ok(())
}

fn parse_returned_id(id: &str) -> Result<oneiron::EntityId, McpGatewayError> {
    oneiron::EntityId::from_hex(id)
        .map_err(|error| mcp_engine_error("native response id is invalid", error))
}

fn request<T: serde::de::DeserializeOwned>(body: Value) -> Result<T, McpGatewayError> {
    serde_json::from_value(body).map_err(|_| {
        McpGatewayError::new(
            -32602,
            "tool_args_invalid",
            "request does not match the native method schema",
        )
        .with_field("arguments.request")
    })
}

fn encode<T: serde::Serialize>(response: T) -> Result<Value, McpGatewayError> {
    serde_json::to_value(response).map_err(|_| {
        McpGatewayError::new(-32603, "engine_error", "native response cannot be encoded")
    })
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
