//! The MCP door of a transport-only row (`host_door_transport_only`, FIX
//! HOOK-TRANSCRIPT-IMPORT-PAST-CARRIER). `vault.imports.hook_transcript_part`
//! crosses no verb hook chain of its own: its call meets the tool admission
//! any call of the row meets before this door, its input check, the hosted
//! operator's refusal and the row's owner proof; then its part is staged.
//! The last part runs the whole request as one call of
//! `vault.imports.hook_transcript` through the one dispatcher every MCP door
//! shares, after the tool admission a call of that verb meets, under the
//! invocation its upload minted, so that verb's hooks judge the request
//! once and the view its post hooks leave comes back as `imported`.

use oneiron::ingest::history::HookTranscriptPartRequest;
use oneiron::runtime_hooks::VerbHookStop;

use super::{McpCallContext, McpCarrierPolicy, McpCodeRun, McpGatewayError, McpServed};
use super::{
    SyncServer, Value, execute_agent_verb_input, mcp_agent_verb_arguments, mcp_facade_error,
};
use crate::api::facade::host_doors::{
    HOOK_TRANSCRIPT_VERB, HookTranscriptStaged, hook_transcript_landing_view,
    stage_hook_transcript_part,
};
use crate::mcp::{McpEndpointTool, McpPageSource, try_registered_surface};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// What a row of the MCP dispatcher answers.
type McpRowAnswer = (
    Value,
    McpPageSource,
    McpCarrierPolicy,
    Option<u64>,
    Option<String>,
);

/// The row a transport-only door serves.
const HOOK_TRANSCRIPT_PART_TOOL: &str = "vault.imports.hook_transcript_part";

fn invalid() -> McpGatewayError {
    McpGatewayError::new(
        -32602,
        "tool_args_invalid",
        "invalid typed agent-verb argument",
    )
}

/// Runs the transport-only row `tool` on `input` for `actor`, its tool call
/// admitted: no hook chain of its own; what it carries runs as a call of
/// another verb through [`execute_agent_verb_input`], whose hooks judge it.
/// The future is boxed as a trait object: the dispatcher it runs through
/// runs it.
pub(super) fn execute_transport_row<'a>(
    server: &'a Arc<SyncServer>,
    tool: &'a str,
    input: Value,
    actor: &'a McpCallContext,
    run: Option<McpCodeRun>,
    served: &'a mut McpServed,
    board_hooks: &'a mut Option<super::board_setup::McpBoardHooks>,
) -> Pin<Box<dyn Future<Output = Result<McpRowAnswer, McpGatewayError>> + Send + 'a>> {
    Box::pin(transport_row(
        server,
        tool,
        input,
        actor,
        run,
        served,
        board_hooks,
    ))
}

/// [`execute_transport_row`]'s run.
async fn transport_row(
    server: &Arc<SyncServer>,
    tool: &str,
    input: Value,
    actor: &McpCallContext,
    run: Option<McpCodeRun>,
    served: &mut McpServed,
    board_hooks: &mut Option<super::board_setup::McpBoardHooks>,
) -> Result<McpRowAnswer, McpGatewayError> {
    if tool != HOOK_TRANSCRIPT_PART_TOOL {
        return Err(invalid());
    }
    let auth = actor.auth.as_ref().ok_or_else(invalid)?;
    // The typed decode runs before the input check, as a generated host
    // door's does, so a field of the wrong shape is refused naming what was
    // wrong in reason codes (FIX CODE-MODE-DENIAL-REASONS; review round 2 of
    // #10553: the check refused it with none). The check, the hosted
    // operator's refusal and the owner proof still run after it, in order.
    let part: HookTranscriptPartRequest = serde::Deserialize::deserialize(&input)
        .map_err(|error| McpGatewayError::typed_input_refused(&error))?;
    oneiron::task_verb::sdk::validate_input(tool, &input).map_err(mcp_facade_error)?;
    crate::api::facade::facade_transport_admits(server, auth, tool)
        .map_err(|refusal| mcp_facade_error(refusal.into_memory_error()))?;
    let (landing, request) =
        match stage_hook_transcript_part(server, auth, &part).map_err(mcp_facade_error)? {
            // Derived from no row: `served` lists none.
            HookTranscriptStaged::Open(view) => {
                return Ok((
                    encoded(&view)?,
                    McpPageSource::complete(1),
                    McpCarrierPolicy::Drain,
                    None,
                    None,
                ));
            }
            HookTranscriptStaged::Landing(landing, request) => (landing, request),
        };
    let mut whole = actor.clone();
    whole.invocation = Some(landing.invocation);
    match whole_verb_call(server, request, &whole, run, served, board_hooks).await {
        Ok((imported, source, carrier, epoch, hook_notice)) => {
            let view = hook_transcript_landing_view(landing, &part.upload, imported);
            Ok((encoded(&view)?, source, carrier, epoch, hook_notice))
        }
        Err(refusal) => {
            landing.answered(matches!(
                refusal.hook.as_deref(),
                Some(VerbHookStop::Pending { .. })
            ));
            Err(refusal)
        }
    }
}

/// One call of [`HOOK_TRANSCRIPT_VERB`] on `request` for `actor`, after the
/// tool admission a `tools/call` of that verb meets on the actor's surface.
async fn whole_verb_call(
    server: &Arc<SyncServer>,
    request: Value,
    actor: &McpCallContext,
    run: Option<McpCodeRun>,
    served: &mut McpServed,
    board_hooks: &mut Option<super::board_setup::McpBoardHooks>,
) -> Result<McpRowAnswer, McpGatewayError> {
    let surface = try_registered_surface(actor.mode)
        .map_err(crate::api::mcp_gateway::admission::mcp_surface_unavailable)?;
    let Some(McpEndpointTool::Verb(tool)) = surface.resolve(HOOK_TRANSCRIPT_VERB) else {
        return Err(McpGatewayError::new(
            -32601,
            "unknown_tool",
            format!("{HOOK_TRANSCRIPT_VERB} is not a tool of this surface"),
        ));
    };
    let arguments = mcp_agent_verb_arguments(tool.name, &request)?;
    arguments
        .validate(tool.name, tool)
        .map_err(crate::api::mcp_gateway::actor_dispatch::mcp_tool_validation_error)?;
    crate::api::mcp_gateway::admission::mcp_admit_scoped_verb(server, tool, &arguments, actor)?;
    crate::api::mcp_gateway::actor_dispatch::mcp_verb_gate(server, tool, &arguments, actor)?;
    execute_agent_verb_input(server, tool.name, request, actor, run, served, board_hooks).await
}

/// A part's answer as the dispatcher's value.
fn encoded(
    view: &oneiron::ingest::history::HookTranscriptPartView,
) -> Result<Value, McpGatewayError> {
    serde_json::to_value(view).map_err(|_| {
        McpGatewayError::new(
            -32603,
            "engine_error",
            "typed agent result cannot be encoded",
        )
    })
}
