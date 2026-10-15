//! Code mode's `self.memory.<verb>`: the SDK verb table through the tool door.
//!
//! A code-mode verb call is the `tools/call` of that verb by the same
//! connector credential. Its input projects onto the tool's arguments for the
//! same argument rules, scoped admission and credential gate, then takes the
//! one generated dispatcher every MCP door shares. Code mode holds no
//! authority a direct tool call lacks; only the paging envelope is left out,
//! since the guest receives the verb's whole output. Its writes carry the
//! run's host-owned origin, not a source the guest's input names.

use super::actor_dispatch::{mcp_execute_code_gate, mcp_tool_validation_error, mcp_verb_gate};
use super::admission::{mcp_admit_run_verb, mcp_admit_scoped_verb};
use super::tasks_response::{execute_agent_verb_input, mcp_agent_verb_arguments};
use super::{McpCallContext, McpGatewayError};
use crate::mcp::{McpEndpointTool, McpSurfaceMode, registered_surface};
use crate::server::SyncServer;
use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, RunCall, SelfAgentVerbCall, SelfEffect,
};
use oneiron::memory::HostWriteOrigin;
use oneiron::task_verb::sdk::RunVerb;
use serde_json::Value;
use std::sync::Arc;

/// The verb door one `execute_code` run binds, under that call's connector.
pub(crate) struct McpCodeModeVerbs {
    server: Arc<SyncServer>,
    actor: McpCallContext,
    runtime: tokio::runtime::Handle,
    /// The rows this run's verb calls listed as served during this call
    /// (DEC-0005); each answer carries its own into the run's record too.
    served: std::sync::Mutex<Vec<oneiron::EntityId>>,
}

impl McpCodeModeVerbs {
    /// Binds the door to the server runtime the `execute_code` call arrived on.
    pub(crate) fn new(server: &Arc<SyncServer>, actor: &McpCallContext) -> Self {
        Self {
            server: Arc::clone(server),
            actor: actor.clone(),
            runtime: tokio::runtime::Handle::current(),
            served: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// The rows this run's verb calls listed as served.
    pub(crate) fn served(&self) -> Vec<oneiron::EntityId> {
        self.served
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl AgentVerbDoor for McpCodeModeVerbs {
    fn call(
        &self,
        call: &SelfAgentVerbCall,
        origin: &HostWriteOrigin,
    ) -> Result<AgentVerbAnswer, AgentVerbRefusal> {
        // The run's worker thread drives its own reactor; the verb runs on the
        // server runtime, as a tool call would, and the worker waits for it.
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let server = Arc::clone(&self.server);
        let actor = self.actor.clone();
        let verb = call.verb.as_str();
        let input = call.input.clone();
        let origin = origin.clone();
        self.runtime.spawn(async move {
            let _ = sender.send(execute_code_mode_verb(&server, &actor, verb, input, origin).await);
        });
        let (output, listed) = receiver
            .recv()
            .map_err(|_| AgentVerbRefusal {
                code: "engine_error".to_owned(),
            })?
            .map_err(|error| AgentVerbRefusal {
                code: error.kind.to_owned(),
            })?;
        self.served
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(listed.iter().copied());
        Ok(AgentVerbAnswer {
            output,
            rows: Some(listed),
        })
    }

    /// A call the run serves itself meets this connector's door at each call
    /// too: a run row needs its own binding, and every call needs the
    /// credential `execute_code` was admitted on, still live. A search reads
    /// under that credential's grants, as `recall` does, from where its
    /// caller sits (DEC-0005).
    fn admit_run_call(
        &self,
        call: RunCall,
    ) -> Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        let refused = |error: McpGatewayError| AgentVerbRefusal {
            code: error.kind.to_owned(),
        };
        if let RunCall::Bridge(effect) = call
            && let Some(verb) = RunVerb::ALL.iter().find(|verb| verb.effect() == effect)
        {
            mcp_admit_run_verb(&self.actor, *verb).map_err(refused)?;
        }
        mcp_execute_code_gate(&self.server, &self.actor).map_err(refused)?;
        if call != RunCall::Bridge(SelfEffect::MemorySearch) {
            return Ok(None);
        }
        let unauthenticated = || AgentVerbRefusal {
            code: "mcp_auth_required".to_owned(),
        };
        let proof = self
            .actor
            .auth
            .as_ref()
            .and_then(crate::auth::CoreAuth::verified_slip)
            .ok_or_else(unauthenticated)?;
        // The one builder every door's credential key comes from.
        self.server
            .vault
            .credential_read_key(proof)
            .map_err(|_| AgentVerbRefusal {
                code: "engine_error".to_owned(),
            })?
            .map(|reader| Some(reader.at(self.actor.locality())))
            .ok_or_else(unauthenticated)
    }
}

async fn execute_code_mode_verb(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    verb: &str,
    input: Value,
    origin: HostWriteOrigin,
) -> Result<(Value, Vec<oneiron::EntityId>), McpGatewayError> {
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
    // A run's call is answered once and never continued.
    let mut served = Vec::new();
    let (output, ..) =
        execute_agent_verb_input(server, tool.name, input, actor, Some(origin), &mut served)
            .await?;
    Ok((output, served))
}
