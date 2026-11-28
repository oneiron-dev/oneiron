//! Integration-test door to the MCP code-mode admission of a recorded verb.

use std::sync::Arc;

use axum::http::Extensions;
use oneiron::EntityId;
use oneiron::code_run::{AgentVerbDoor, AgentVerbRefusal};
use oneiron::task_verb::sdk::AgentVerb;

use super::mcp_code_mode_verbs::{ProgramAuthor, TestCredential, credential_headers};
use crate::api::{McpCodeModeVerbs, resolve_mcp_gateway_actor};
use crate::mcp::McpSurfaceMode;
use crate::server::SyncServer;

/// Checks a verb's recorded answer under the credential and author of a run.
///
/// # Errors
///
/// The test credential's holder proof or gateway actor could not be resolved.
pub async fn admit_recorded_verb(
    server: &Arc<SyncServer>,
    credential: &TestCredential,
    run: EntityId,
    verb: AgentVerb,
    author: ProgramAuthor,
) -> anyhow::Result<Result<(), AgentVerbRefusal>> {
    let headers = credential_headers(server.vault(), credential)?;
    let context = resolve_mcp_gateway_actor(
        McpSurfaceMode::Primary,
        "recorded-answer-recheck",
        &headers,
        &Extensions::new(),
        oneiron::claim::CallerLocality::OnDevice,
        server,
    )
    .await
    .map_err(|error| anyhow::anyhow!("the door credential did not resolve: {error:?}"))?;
    let door = McpCodeModeVerbs::new(server, &context, run);
    let door = match author {
        ProgramAuthor::Caller => door.authored_by_caller(),
        ProgramAuthor::EngineModel => door.authored_by_engine_model(),
    };
    Ok(door.admit_recorded_verb(verb))
}
