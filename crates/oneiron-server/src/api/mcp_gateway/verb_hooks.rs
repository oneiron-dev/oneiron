//! The verb-hook boundary of an MCP row (ARCH-0080 §3), as the generated
//! dispatch crosses it: the row door's own admission first, then the pre
//! chain under the caller's read key, with a rewrite re-admitted as the
//! connector's own call would be.

use std::sync::Arc;

use oneiron::claim::ScopedReadActorKey;
use oneiron::memory::{Memory, RewriteAdmit};
use oneiron::runtime_hooks::{VerbCall, VerbHookPre};
use serde_json::Value;

use super::actor_dispatch::{mcp_tool_validation_error, mcp_verb_gate};
use super::admission::mcp_admit_scoped_verb;
use super::tasks_response::mcp_agent_verb_arguments;
use super::{McpCallContext, McpGatewayError, mcp_facade_error};
use crate::mcp::{McpEndpointTool, McpSurfaceMode, registered_surface};
use crate::server::SyncServer;

/// The pre chain of MCP row `tool` over its `input`, for `actor` calling
/// through `memory`. A host-door row, and whole-vault export, meet their
/// door's admission before any hook fires. The hooks read under the
/// memory's key, capped by their grant. A rewrite must pass the row's input
/// check, then the projection, scoped admission and credential gate the
/// connector's own call of the tool meets, for the same actor, at each
/// Rewrite. The memory is read before the returned future first waits, so
/// the future holds none of it.
pub(crate) fn mcp_row_hooks_pre<'a>(
    server: &'a Arc<SyncServer>,
    tool: &'a str,
    actor: &'a McpCallContext,
    memory: &Memory<'_>,
    input: Value,
) -> impl Future<Output = Result<VerbHookPre, McpGatewayError>> + Send + use<'a> {
    let admitted = mcp_hooks_admitted(server, tool, actor, memory);
    let invocation = memory.invocation();
    async move {
        let (reader, check) = admitted?;
        crate::api::facade::row_hooks_pre_with(
            server,
            reader,
            check,
            actor.actor_ref,
            actor.actor_class,
            invocation,
            tool,
            input,
        )
        .await
        .map_err(mcp_facade_error)
    }
}

/// The door's admission of `tool` for `actor`, then what only a hook reads,
/// built only when one may run: the memory's key and the rewrite admission.
fn mcp_hooks_admitted(
    server: &Arc<SyncServer>,
    tool: &str,
    actor: &McpCallContext,
    memory: &Memory<'_>,
) -> Result<(Option<ScopedReadActorKey>, Option<RewriteAdmit>), McpGatewayError> {
    if let Some(auth) = actor.auth.as_ref() {
        if tool == "vault.export" && !auth.is_owner_grade() {
            return Err(McpGatewayError::new(
                -32020,
                "forbidden",
                "full-vault export requires owner authority",
            ));
        }
        crate::api::facade::row_door_admits(server, auth, tool).map_err(mcp_facade_error)?;
    }
    if !VerbCall::may_run(&server.vault, tool) {
        return Ok((None, None));
    }
    let reader = VerbCall::reader_of(memory, tool).map_err(mcp_facade_error)?;
    Ok((reader, Some(mcp_rewrite_admit(server, tool, actor))))
}

/// The admission a connector's own call of `tool` meets, run on a hook's
/// rewritten args for the same actor. A row no generated tool carries
/// admits no rewrite.
fn mcp_rewrite_admit(server: &Arc<SyncServer>, tool: &str, actor: &McpCallContext) -> RewriteAdmit {
    let generated = match registered_surface(McpSurfaceMode::ToolFirst).resolve(tool) {
        Some(McpEndpointTool::Verb(generated)) => Some(generated),
        _ => None,
    };
    let (server, actor) = (Arc::clone(server), actor.clone());
    Arc::new(move |_: &str, rewritten: &Value| {
        let refused = |error: McpGatewayError| format!("{}: {}", error.kind, error.message);
        let Some(tool) = generated else {
            return Err("no MCP tool carries this row to re-admit its args".to_owned());
        };
        let arguments = mcp_agent_verb_arguments(tool.name, rewritten).map_err(refused)?;
        arguments
            .validate(tool.name, tool)
            .map_err(|error| refused(mcp_tool_validation_error(error)))?;
        mcp_admit_scoped_verb(&server, tool, &arguments, &actor).map_err(refused)?;
        mcp_verb_gate(&server, tool, &arguments, &actor).map_err(refused)
    })
}
