//! The verb-hook boundary of an MCP row (ARCH-0080 §3), as the generated
//! dispatch crosses it: the row door's own admission first, then the pre
//! chain under the caller's read key, with a rewrite re-admitted as the
//! connector's own call would be. A connector's call whose hook asked names
//! the registration it came in by, so settlement runs it again here, under
//! its credential as it verified again then. The managed vault's console
//! owner's call names his own stream instead (FIX 5204), and runs again here
//! while the vault records him as its live owner.

#[cfg(feature = "code-sandbox-wasmtime")]
mod ceiling;

use std::sync::Arc;

use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::vault_read::{VaultReadMethod, VaultReadRequest};
use oneiron::memory::{Memory, RewriteAdmit};
use oneiron::runtime_hooks::verb::{VerbAskCredential, VerbAskDoor, VerbAskMcpCeiling};
use oneiron::runtime_hooks::{VerbCall, VerbHookPre};
use serde_json::Value;

use super::actor_dispatch::{mcp_tool_validation_error, mcp_verb_gate};
use super::admission::mcp_admit_scoped_verb;
use super::tasks_response::mcp_agent_verb_arguments;
use super::{McpCallContext, McpGatewayError, mcp_facade_error};
use crate::api::facade::RowHookResume;
use crate::mcp::{
    McpEndpointTool, McpResolvedActor, McpSurfaceMode, McpVerbArguments, try_registered_surface,
};
use crate::server::SyncServer;

/// The pre chain of MCP row `tool` over its `input`, for `actor` calling
/// through `memory`. A host-door row, and whole-vault export, meet their
/// door's admission before any hook fires. The hooks read under the
/// memory's key, capped by their grant. A rewrite must pass the row's input
/// check, then the projection, scoped admission and credential gate the
/// connector's own call of the tool meets, for the same actor, at each
/// Rewrite. An ask saves the registration the call came in by, so
/// settlement runs it again here, its pre chain on the drain's permit. A
/// hook's ask runs on the task-work turn the memory's operation holds, if
/// any. A call that keeps no record keeps its hooks' records and ask pauses
/// for its live session only (FIX 4283), judged on the memory, with the hook
/// pause it resumes (`_meta.hook_ask`). The memory is read before the
/// returned future first waits, so the future holds none of it.
pub(crate) fn mcp_row_hooks_pre<'a>(
    server: &'a Arc<SyncServer>,
    tool: &'a str,
    actor: &'a McpCallContext,
    memory: &Memory<'_>,
    input: Value,
) -> impl Future<Output = Result<VerbHookPre, McpGatewayError>> + Send + use<'a> {
    let admitted = mcp_hooks_admitted(server, tool, actor, memory);
    let invocation = memory.invocation();
    let turn = memory.task_work_turn();
    let credential = mcp_verb_ask_credential(actor, memory);
    // FIX 4280: a call serving a room NOTE keeps its hooks' records for its
    // session; a close names the room hold this host keeps for the caller.
    let held = crate::api::call_receipt::room_notes::held_room_note(
        server,
        crate::api::call_receipt::mcp_session_principal(actor.auth.as_ref(), actor.actor_ref),
        Some(&input),
    );
    let session = oneiron::task_verb::verb_hook_boundary::hook_session_for_call(
        Some(memory),
        tool,
        &input,
        held.as_ref(),
    );
    async move {
        let (reader, check) = admitted?;
        let resume = RowHookResume {
            credential,
            drain: actor.drain.clone(),
            session: session.map_err(mcp_facade_error)?,
        };
        crate::api::facade::row_hooks_pre_with(
            server,
            reader,
            check,
            actor.actor_ref,
            actor.actor_class,
            invocation,
            tool,
            input,
            resume,
            turn,
        )
        .await
        .map_err(mcp_facade_error)
    }
}

/// The reference a verb hook's ask saves for a connector's call of `tool`:
/// the registration it came in by and the ceiling it was admitted at, when
/// its memory carries nothing the drain could not rebuild (ARCH-0080 §3
/// Ask). The managed vault's attested owner has no registration: his call
/// names his own STREAM connection (FIX 5204). Bound on every call, so a
/// retry of a call an ask parked meets its saved reference whether or not a
/// hook takes `tool` now.
fn mcp_verb_ask_credential(
    actor: &McpCallContext,
    memory: &Memory<'_>,
) -> Option<VerbAskCredential> {
    let door = actor
        .drain
        .as_ref()
        .filter(|drain| Some(drain.invocation()) == memory.invocation())
        .and_then(|drain| drain.credential_door())
        .cloned()
        .unwrap_or_else(|| {
            let owner = actor
                .auth
                .as_ref()
                .and_then(crate::api::scoped_auth::attested_owner_holder);
            match owner {
                Some(_) => VerbAskDoor::McpOwner {
                    connection: actor.stream_connection.0.clone(),
                },
                None => VerbAskDoor::Mcp {
                    connection: actor.stream_connection.0.clone(),
                    ceiling: mcp_adapter_ceiling(actor),
                },
            }
        });
    memory
        .clone()
        .with_credential_door(door)
        .verb_ask_credential()
}

/// The registration a connector call came in by, saved without a credential
/// so settlement can meet its live authority with this original ceiling.
pub(super) fn mcp_adapter_ceiling(actor: &McpResolvedActor) -> VerbAskMcpCeiling {
    VerbAskMcpCeiling {
        actor_ref: actor.actor_ref,
        actor_class: actor.actor_class,
        world: actor.scope.world_ref,
        facets: actor.scope.facets.clone(),
        write_facet: actor.scope.facet_ref,
        bound_verbs: actor
            .bound_verbs
            .as_ref()
            .map(|verbs| verbs.iter().map(|name| (*name).to_owned()).collect()),
    }
}

/// The door's admission of `tool` for `actor`, then what a hook reads, built
/// on every call so a binding installed meanwhile still finds it: the
/// memory's key and the rewrite admission.
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
    if actor.auth.is_none() && matches!(tool, "host.compact" | "host.wake" | "host.budget.hit") {
        return Err(McpGatewayError::new(
            -32020,
            "forbidden",
            "a host trigger requires the owner's verified credential",
        ));
    }
    // FIX 4794: a row whose handler takes the caller's credential refuses a
    // call with none here, before its pre hooks run, with that handler's error.
    if actor.auth.is_none() && crate::api::facade::needs_caller_credential(tool) {
        return Err(McpGatewayError::new(
            -32602,
            "tool_args_invalid",
            "invalid typed agent-verb argument",
        ));
    }
    let reader = VerbCall::reader_of(memory, tool).map_err(mcp_facade_error)?;
    Ok((reader, Some(mcp_rewrite_admit(server, tool, actor))))
}

/// The admission a connector's own call of `tool` meets, run on a hook's
/// rewritten args for the same actor. A row no generated tool carries
/// admits no rewrite. A native read's args are its native request: they
/// meet that method's own request validation first (FIX 1435).
fn mcp_rewrite_admit(server: &Arc<SyncServer>, tool: &str, actor: &McpCallContext) -> RewriteAdmit {
    let resolved = try_registered_surface(McpSurfaceMode::ToolFirst)
        .ok()
        .and_then(|surface| surface.resolve(tool));
    let generated = match resolved {
        Some(McpEndpointTool::Verb(generated)) => Some(generated),
        _ => None,
    };
    let (server, actor) = (Arc::clone(server), actor.clone());
    Arc::new(move |verb: &str, rewritten: &Value| {
        let refused = |error: McpGatewayError| format!("{}: {}", error.kind, error.message);
        let Some(tool) = generated else {
            return Err("no MCP tool carries this row to re-admit its args".to_owned());
        };
        let arguments = match tool.memory_method() {
            Some(method) => mcp_native_read_arguments(method, rewritten)?,
            None => mcp_agent_verb_arguments(tool.name, rewritten).map_err(refused)?,
        };
        arguments
            .validate(tool.name, tool)
            .map_err(|error| refused(mcp_tool_validation_error(error)))?;
        mcp_admit_scoped_verb(&server, tool, &arguments, &actor).map_err(refused)?;
        mcp_verb_gate(&server, tool, &arguments, &actor).map_err(refused)?;
        // A courtesy answer's rewritten reply_to meets its door's own check
        // here, so a bad one gives way to the caller's (FIX 5140).
        crate::owner::courtesy_delete::check_rewritten_reply_to(verb, rewritten)
    })
}

/// The `tools/call` arguments a native read's `request` projects onto, once
/// it passed `method`'s own request validation (FIX 1435).
fn mcp_native_read_arguments(
    method: VaultReadMethod,
    request: &Value,
) -> Result<McpVerbArguments, String> {
    VaultReadRequest::validate_body(method, request).map_err(|error| error.to_string())?;
    Ok(McpVerbArguments {
        request: Some(request.clone()),
        ..McpVerbArguments::default()
    })
}

#[cfg(feature = "code-sandbox-wasmtime")]
impl McpCallContext {
    /// Runs a connector's call a verb hook's ask stopped again, once the ask
    /// settled proceed (ARCH-0080 §3 Ask), under `auth`, its credential as it
    /// verified again now. The registration is the one its saved
    /// `connection` names now, never a saved copy, capped by the original
    /// `ceiling`. The saved args meet the admission
    /// the connector's own call of the tool meets, then run through the same
    /// door, the pre chain on the drain's permit.
    pub(crate) async fn resume_verb_ask(
        server: &Arc<SyncServer>,
        auth: crate::auth::CoreAuth,
        connection: &str,
        ceiling: &VerbAskMcpCeiling,
        call: oneiron::runtime_hooks::verb::VerbAskSavedCall,
        drain: oneiron::runtime_hooks::verb::VerbAskDrainPermit,
    ) -> Result<
        oneiron::runtime_hooks::verb::VerbAskResumed,
        oneiron::runtime_hooks::verb::VerbAskRefusal,
    > {
        use oneiron::runtime_hooks::verb::VerbAskRefusal;
        // Only a generated tool-first row is a door a connector's call
        // comes back by.
        if !matches!(
            try_registered_surface(McpSurfaceMode::ToolFirst)
                .ok()
                .and_then(|surface| surface.resolve(&call.verb)),
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
        super::actor_dispatch::mcp_proof_admits(server, &actor, &auth)
            .map_err(|_| VerbAskRefusal::CredentialChanged)?;
        ceiling::intersect_registration(server, &mut actor, ceiling)?;
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
            hook_ask: None,
            off_record_session: None,
            room_turn: None,
            drain: Some(drain),
            forwarded: None,
            client_surface: None,
            signing_request_transport: None,
        };
        rerun_saved_call(server, &context, call).await
    }

    /// Runs the managed vault's console owner's call a verb hook's ask
    /// stopped again, once the ask settled proceed (FIX 5204), under `auth`,
    /// the owner as [`crate::auth::CoreAuth::for_attested_owner`] rebuilt him
    /// now. His call came by his own STREAM `connection`, which must still be
    /// his; no connector registration, its ceiling or a holder proof stands
    /// behind it, and his live socket is not needed. The saved args meet the
    /// admission his own call of the tool meets, then run through the same
    /// door, the pre chain on the drain's permit.
    pub(crate) async fn resume_owner_verb_ask(
        server: &Arc<SyncServer>,
        auth: crate::auth::CoreAuth,
        connection: &str,
        call: oneiron::runtime_hooks::verb::VerbAskSavedCall,
        drain: oneiron::runtime_hooks::verb::VerbAskDrainPermit,
    ) -> Result<
        oneiron::runtime_hooks::verb::VerbAskResumed,
        oneiron::runtime_hooks::verb::VerbAskRefusal,
    > {
        use oneiron::runtime_hooks::verb::VerbAskRefusal;
        if !matches!(
            try_registered_surface(McpSurfaceMode::ToolFirst)
                .ok()
                .and_then(|surface| surface.resolve(&call.verb)),
            Some(McpEndpointTool::Verb(_))
        ) {
            return Err(VerbAskRefusal::ContextUnavailable);
        }
        let Some(owner) = auth.managed_owner() else {
            return Err(VerbAskRefusal::CredentialChanged);
        };
        let context = super::owner_call::owner_resume_context(
            server,
            auth,
            connection,
            call.invocation,
            drain,
        )
        .ok_or(VerbAskRefusal::CredentialChanged)?
        // His standing changed since it was read: as it reads now.
        .map_err(|_| {
            crate::code_consent_host::attested_owner_standing(server, owner)
                .err()
                .unwrap_or(VerbAskRefusal::CredentialUnavailable)
        })?;
        rerun_saved_call(server, &context, call).await
    }
}

/// The saved `call` run again in `context`, its door rebuilt: the saved args
/// meet the admission the caller's own call of the tool meets, then run
/// through the same dispatch. A native read runs again through its own
/// verb-hook boundary, on the saved request (FIX 1435). Either answer goes
/// beside the rows it was derived from, for the caller's retry to be
/// released by (FIX 1435, FIX 21054).
#[cfg(feature = "code-sandbox-wasmtime")]
async fn rerun_saved_call(
    server: &Arc<SyncServer>,
    context: &McpCallContext,
    call: oneiron::runtime_hooks::verb::VerbAskSavedCall,
) -> Result<
    oneiron::runtime_hooks::verb::VerbAskResumed,
    oneiron::runtime_hooks::verb::VerbAskRefusal,
> {
    use oneiron::runtime_hooks::verb::{VerbAskRefusal, VerbAskResumed};
    mcp_rewrite_admit(server, &call.verb, context)(&call.verb, &call.args)
        .map_err(|_| VerbAskRefusal::ScopeRefused)?;
    let mut served = super::McpServed::default();
    if let Some(McpEndpointTool::Verb(tool)) = try_registered_surface(McpSurfaceMode::ToolFirst)
        .ok()
        .and_then(|surface| surface.resolve(&call.verb))
        && let Some(method) = tool.memory_method()
    {
        // The native read's boundary, on the heap (FIX 12072).
        let ran = Box::pin(
            super::tasks_response::native_read::execute_native_read_input(
                server,
                tool,
                method,
                call.args,
                context,
                &mut served,
            ),
        )
        .await;
        return Ok(match (ran, served.into_rows()) {
            (Ok((output, _)), Some(producers)) => VerbAskResumed::RanWithProducers {
                result: Ok(output),
                producers,
            },
            (ran, _) => VerbAskResumed::Ran(ran.map(|(output, _)| output).map_err(mcp_saved_error)),
        });
    }
    let mut board_hooks = None;
    // The verb table's fan-out, on the heap (FIX 12072).
    let ran = Box::pin(super::tasks_response::execute_agent_verb_input(
        server,
        &call.verb,
        call.args,
        context,
        None,
        &mut served,
        &mut board_hooks,
    ))
    .await;
    match ran {
        Err(error) => Ok(VerbAskResumed::Ran(Err(mcp_saved_error(error)))),
        Ok((output, ..)) => {
            // A board read answers the settlement here: the receipt its hook
            // rows owe is recorded and their blocks spent as the answer
            // returns (OF-579).
            if let Some(mut hooks) = board_hooks {
                if let Err(error) = hooks.record_receipt(server).await {
                    return Ok(VerbAskResumed::Ran(Err(mcp_saved_error(error))));
                }
                hooks.spend(server);
            }
            Ok(
                match super::served_rows::saved_answer_rows(&call.verb, served) {
                    Some(producers) => VerbAskResumed::RanWithProducers {
                        result: Ok(output),
                        producers,
                    },
                    None => VerbAskResumed::Ran(Ok(output)),
                },
            )
        }
    }
}

/// A connector call's refusal as the error settlement saves for its retry:
/// its kind as the code and its hook stop kept; an internal failure is the
/// engine's own, which leaves the call for the next pass.
#[cfg(feature = "code-sandbox-wasmtime")]
fn mcp_saved_error(error: McpGatewayError) -> oneiron::MemoryError {
    let code = if error.legal_hold.is_some() {
        oneiron::memory::MEMORY_CODE_INVALID_STATE
    } else if error.code == -32603 {
        oneiron::memory::MEMORY_CODE_INTERNAL
    } else {
        error.kind
    };
    let mut saved = oneiron::MemoryError::new(code, error.message, &[]);
    saved.hook = error.hook;
    saved.legal_hold = error.legal_hold;
    saved.reason_codes = error.reason_codes;
    saved
}
