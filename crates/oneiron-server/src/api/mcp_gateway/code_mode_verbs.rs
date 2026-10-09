//! Code mode's `self.memory.<verb>`: the SDK verb table through the tool door.
//!
//! A code-mode verb call is the `tools/call` of that verb by the same
//! connector credential. Its input projects onto the tool's arguments for the
//! same argument rules, scoped admission and credential gate, then takes the
//! one generated dispatcher every MCP door shares. Code mode holds no
//! authority a direct tool call lacks; only the paging envelope is left out,
//! since the guest receives the verb's whole output.

use super::actor_dispatch::{mcp_tool_validation_error, mcp_verb_gate};
use super::admission::mcp_admit_scoped_verb;
use super::tasks_response::{execute_agent_verb_input, mcp_agent_verb_arguments};
use super::{McpCallContext, McpGatewayError};
use crate::mcp::{McpEndpointTool, McpSurfaceMode, registered_surface};
use crate::server::SyncServer;
use oneiron::code_run::{AgentVerbDoor, AgentVerbRefusal, SelfAgentVerbCall};
use serde_json::Value;
use std::sync::Arc;

/// The verb door one `execute_code` run binds, under that call's connector.
pub(crate) struct McpCodeModeVerbs {
    server: Arc<SyncServer>,
    actor: McpCallContext,
    runtime: tokio::runtime::Handle,
}

impl McpCodeModeVerbs {
    /// Binds the door to the server runtime the `execute_code` call arrived on.
    pub(crate) fn new(server: &Arc<SyncServer>, actor: &McpCallContext) -> Self {
        Self {
            server: Arc::clone(server),
            actor: actor.clone(),
            runtime: tokio::runtime::Handle::current(),
        }
    }
}

impl AgentVerbDoor for McpCodeModeVerbs {
    fn call(&self, call: &SelfAgentVerbCall) -> Result<Value, AgentVerbRefusal> {
        // The run's worker thread drives its own reactor; the verb runs on the
        // server runtime, as a tool call would, and the worker waits for it.
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let server = Arc::clone(&self.server);
        let actor = self.actor.clone();
        let verb = call.verb.as_str();
        let input = call.input.clone();
        self.runtime.spawn(async move {
            let _ = sender.send(execute_code_mode_verb(&server, &actor, verb, input).await);
        });
        receiver
            .recv()
            .map_err(|_| AgentVerbRefusal {
                code: "engine_error".to_owned(),
                message: "the verb door stopped before answering".to_owned(),
            })?
            .map_err(|error| AgentVerbRefusal {
                code: error.kind.to_owned(),
                message: error.message,
            })
    }
}

async fn execute_code_mode_verb(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    verb: &str,
    input: Value,
) -> Result<Value, McpGatewayError> {
    let Some(McpEndpointTool::Verb(tool)) =
        registered_surface(McpSurfaceMode::ToolFirst).resolve(verb)
    else {
        return Err(McpGatewayError::new(
            -32601,
            "unknown_tool",
            format!("{verb} is not a verb in the SDK verb table"),
        ));
    };
    let arguments = mcp_agent_verb_arguments(tool.name, &input)?;
    arguments
        .validate(tool.name, tool)
        .map_err(mcp_tool_validation_error)?;
    mcp_admit_scoped_verb(server, tool, &arguments, actor)?;
    mcp_verb_gate(server, tool, &arguments, actor)?;
    let (output, ..) = execute_agent_verb_input(server, tool.name, input, actor).await?;
    Ok(output)
}
