//! The verb-hook boundary of an MCP row (ARCH-0080 §3), as the generated
//! dispatch crosses it: the row door's own admission first, then the pre
//! chain under the caller's read key, with a rewrite re-admitted as the
//! connector's own call would be. A connector's call whose hook asked names
//! the registration it came in by, so settlement runs it again here, under
//! its credential as it verified again then.

use std::sync::Arc;

use oneiron::claim::ScopedReadActorKey;
use oneiron::memory::{Memory, RewriteAdmit};
use oneiron::runtime_hooks::verb::{VerbAskCredential, VerbAskDoor};
use oneiron::runtime_hooks::{VerbCall, VerbHookPre};
use serde_json::Value;

use super::actor_dispatch::{mcp_tool_validation_error, mcp_verb_gate};
use super::admission::mcp_admit_scoped_verb;
use super::tasks_response::mcp_agent_verb_arguments;
use super::{McpCallContext, McpGatewayError, mcp_facade_error};
use crate::api::facade::RowHookResume;
use crate::mcp::{McpEndpointTool, McpResolvedActor, McpSurfaceMode, registered_surface};
use crate::server::SyncServer;

/// The pre chain of MCP row `tool` over its `input`, for `actor` calling
/// through `memory`. A host-door row, and whole-vault export, meet their
/// door's admission before any hook fires. The hooks read under the
/// memory's key, capped by their grant. A rewrite must pass the row's input
/// check, then the projection, scoped admission and credential gate the
/// connector's own call of the tool meets, for the same actor, at each
/// Rewrite. An ask saves the registration the call came in by, so
/// settlement runs it again here, its pre chain on the drain's permit. The
/// memory is read before the returned future first waits, so the future
/// holds none of it.
pub(crate) fn mcp_row_hooks_pre<'a>(
    server: &'a Arc<SyncServer>,
    tool: &'a str,
    actor: &'a McpCallContext,
    memory: &Memory<'_>,
    input: Value,
) -> impl Future<Output = Result<VerbHookPre, McpGatewayError>> + Send + use<'a> {
    let admitted = mcp_hooks_admitted(server, tool, actor, memory);
    let invocation = memory.invocation();
    let resume = RowHookResume {
        credential: mcp_verb_ask_credential(server, tool, actor, memory),
        drain: actor.drain.clone(),
    };
    async move {
        let (reader, check) = admitted?;
        crate::api::facade::row_hooks_pre_resumable(
            server,
            reader,
            check,
            actor.actor_ref,
            actor.actor_class,
            invocation,
            tool,
            input,
            resume,
        )
        .await
        .map_err(mcp_facade_error)
    }
}

/// The reference a verb hook's ask saves for a connector's call of `tool`:
/// the registration it came in by and the ceiling it was admitted at, when
/// a hook may run and its memory carries nothing the drain could not rebuild
/// (ARCH-0080 §3 Ask).
fn mcp_verb_ask_credential(
    server: &Arc<SyncServer>,
    tool: &str,
    actor: &McpCallContext,
    memory: &Memory<'_>,
) -> Option<VerbAskCredential> {
    if !VerbCall::may_run(&server.vault, tool) {
        return None;
    }
    let door = VerbAskDoor::Mcp {
        connection: actor.stream_connection.0.clone(),
        ceiling: mcp_adapter_ceiling(actor),
    };
    memory
        .clone()
        .with_credential_door(door)
        .verb_ask_credential()
}

/// BLAKE3 of the registration a connector call came in by: its actor, its
/// world and facet scope and its bound verbs. A call settlement runs again
/// must find the same (ARCH-0080 §3 Ask).
fn mcp_adapter_ceiling(actor: &McpResolvedActor) -> [u8; 32] {
    let ceiling = format!(
        "{:?}|{:?}|{:?}|{:?}",
        actor.actor_ref, actor.actor_class, actor.scope, actor.bound_verbs
    );
    *blake3::hash(ceiling.as_bytes()).as_bytes()
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

#[cfg(feature = "code-sandbox-wasmtime")]
impl McpCallContext {
    /// Runs a connector's call a verb hook's ask stopped again, once the ask
    /// settled proceed (ARCH-0080 §3 Ask), under `auth`, its credential as it
    /// verified again now. The registration is the one its saved
    /// `connection` names now, never a saved copy, and must carry the
    /// `ceiling` the call was admitted at. The saved args meet the admission
    /// the connector's own call of the tool meets, then run through the same
    /// door, the pre chain on the drain's permit.
    pub(crate) async fn resume_verb_ask(
        server: &Arc<SyncServer>,
        auth: crate::auth::CoreAuth,
        connection: &str,
        ceiling: &[u8; 32],
        call: oneiron::runtime_hooks::verb::VerbAskSavedCall,
        drain: oneiron::runtime_hooks::verb::VerbAskDrainPermit,
    ) -> Result<oneiron::memory::MemoryResult<Value>, oneiron::runtime_hooks::verb::VerbAskRefusal>
    {
        use oneiron::runtime_hooks::verb::VerbAskRefusal;
        // Only a generated tool-first row is a door a connector's call
        // comes back by.
        if !matches!(
            registered_surface(McpSurfaceMode::ToolFirst).resolve(&call.verb),
            Some(McpEndpointTool::Verb(_))
        ) {
            return Err(VerbAskRefusal::ContextUnavailable);
        }
        let now = server
            .vault
            .capability_slip_now()
            .map_err(|_| VerbAskRefusal::CredentialUnavailable)?;
        let registry = server.mcp_registry.lock().await;
        let resolved = registry.resolve_connection(connection, now, |class, actor| {
            server
                .vault
                .gate_actor_ceiling_exists(class, actor)
                .unwrap_or(false)
        });
        drop(registry);
        let mut actor = resolved.map_err(crate::credential_resume::adapter_refusal)?;
        if !crate::credential_resume::ceiling_holds(ceiling, &mcp_adapter_ceiling(&actor)) {
            return Err(VerbAskRefusal::ScopeRefused);
        }
        super::actor_dispatch::mcp_proof_admits(server, &actor, &auth)
            .map_err(|_| VerbAskRefusal::CredentialChanged)?;
        actor.auth = Some(auth);
        let landing = crate::api::write_facet::landing_facet(
            &server.vault,
            None,
            &actor.scope.facets,
            actor.scope.facet_ref,
        );
        let context = Self {
            actor,
            mode: McpSurfaceMode::ToolFirst,
            request_id: format!("verb-ask-{}", call.invocation.to_hex()),
            landing,
            invocation: Some(call.invocation),
            off_record_session: None,
            drain: Some(drain),
        };
        mcp_rewrite_admit(server, &call.verb, &context)(&call.verb, &call.args)
            .map_err(|_| VerbAskRefusal::ScopeRefused)?;
        let mut served = Vec::new();
        let ran = super::tasks_response::execute_agent_verb_input(
            server,
            &call.verb,
            call.args,
            &context,
            None,
            &mut served,
        )
        .await;
        Ok(ran.map(|(output, ..)| output).map_err(mcp_saved_error))
    }
}

/// A connector call's refusal as the error settlement saves for its retry:
/// its kind as the code and its hook stop kept; an internal failure is the
/// engine's own, which leaves the call for the next pass.
#[cfg(feature = "code-sandbox-wasmtime")]
fn mcp_saved_error(error: McpGatewayError) -> oneiron::MemoryError {
    let code = if error.code == -32603 {
        oneiron::memory::MEMORY_CODE_INTERNAL
    } else {
        error.kind
    };
    let mut saved = oneiron::MemoryError::new(code, error.message, &[]);
    saved.hook = error.hook;
    saved
}
