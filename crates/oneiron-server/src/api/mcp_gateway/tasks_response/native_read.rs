//! The native memory read arm of one generated verb tool call, through the
//! verb-hook boundary every generated row crosses (ARCH-0080 §3, FIX 1435).
//! `execute_mcp_native_read` and `execute_native_read_input` are its call
//! surface.

use super::{
    McpCallContext, McpCarrierPolicy, McpGatewayError, McpRowSurface, McpServed, mcp_facade_error,
    mcp_hook_stop_result,
};
use crate::mcp::{McpGeneratedVerbTool, McpVerbToolArgs};
use crate::server::SyncServer;
use oneiron::EntityId;
use oneiron::code_run::vault_read::VaultReadMethod;
use oneiron::context_board::CapabilityHit;
use oneiron::runtime_hooks::VerbHookStop;
use serde_json::Value;
use std::ops::ControlFlow;
use std::sync::Arc;

/// One native memory read tool call: one atomic native response, the rows
/// it served listed in `served`. Its request crosses the native read's
/// verb-hook boundary ([`execute_native_read_input`], FIX 1435). A verb
/// hook's stop is the tool result the client reads, not a refusal
/// (ARCH-0080 §3): it breaks out with that result, released by the rows
/// [`stop_release_rows`] names.
pub(super) async fn execute_mcp_native_read(
    server: &Arc<SyncServer>,
    args: &McpVerbToolArgs,
    actor: &McpCallContext,
    served: &mut McpServed,
) -> Result<
    ControlFlow<
        Value,
        (
            Value,
            crate::mcp::McpPageSource,
            McpCarrierPolicy,
            Option<u64>,
        ),
    >,
    McpGatewayError,
> {
    let Some(method) = args.tool.memory_method() else {
        return Err(super::super::mcp_verb_family_error(args));
    };
    let request = args.payload.arguments.request.clone().ok_or_else(|| {
        McpGatewayError::new(-32602, "tool_args_invalid", "native request is required")
            .with_field("arguments.request")
    })?;
    // The native read fan-out, on the heap (FIX 12072).
    let read = Box::pin(execute_native_read_input(
        server, args.tool, method, request, actor, served,
    ))
    .await;
    let (output, capabilities) = match read {
        Err(McpGatewayError {
            hook: Some(stop),
            hook_notice,
            ..
        }) => {
            let completed = matches!(*stop, VerbHookStop::Completed { .. });
            let rows = stop_release_rows(server, actor, &stop, served);
            // The drain read that answer, not this retry: its caller's
            // credential still reads every row it was derived from, and none
            // was erased since, or it gets only the word that the call ran,
            // as a claimed invocation's waiter does (FIX 1435).
            let lapsed = rows.zip(actor.auth.as_ref()).is_some_and(|(rows, auth)| {
                !crate::api::facade::rows_still_admitted(server.vault(), auth, rows)
            });
            if completed && lapsed {
                let ran = super::super::claimed_release::details_on_device_result();
                return Ok(ControlFlow::Break(ran));
            }
            let stopped = mcp_hook_stop_result(server, args, actor, *stop, rows, hook_notice)?;
            return Ok(ControlFlow::Break(stopped));
        }
        read => read?,
    };
    // One native response, with its own bounded query/batch
    // semantics. Do not invent an MCP cursor over nested DTOs.
    Ok(ControlFlow::Continue((
        output,
        crate::mcp::McpPageSource::complete(1),
        McpCarrierPolicy::DrainWithCapabilities(capabilities),
        None,
    )))
}

/// The rows a native read's hook `stop` is released by. A retry that gets
/// the answer an ask's settlement already ran restores into `served` the
/// rows that saved answer was derived from (FIX 1435). An answer saved with
/// none is released by no listed row, so off this device it is withheld as
/// a result whose rows are unknown is, never released as an empty set. Any
/// other stop is released by the rows `served` lists.
fn stop_release_rows<'s>(
    server: &SyncServer,
    actor: &McpCallContext,
    stop: &VerbHookStop,
    served: &'s mut McpServed,
) -> Option<&'s [EntityId]> {
    if !matches!(stop, VerbHookStop::Completed { .. }) {
        return served.rows();
    }
    let saved = actor.invocation.and_then(|invocation| {
        server
            .vault
            .verb_hook_saved_producers(invocation)
            .inspect_err(
                |error| tracing::warn!(%error, "a drained native read's rows did not read"),
            )
            .ok()
            .flatten()
    })?;
    served.extend(saved);
    served.rows()
}

/// The native read `method` of `tool` on `request` for `actor`, through its
/// verb-hook boundary (FIX 1435). The pre chain runs over the request under
/// the call's invocation, before any media is embedded or any row is read.
/// A rewrite meets the method's own request validation, then the admission
/// the caller's own call of the tool met. The read runs on the request the
/// chain left, and the post chain over the answer it served, after its
/// observations staged. A read that fails after the pre chain keeps a
/// session-only call's pre hook records and runs no post chain (FIX 5527).
/// A call an ask parked runs again here on its credential, its pre chain on
/// the drain's permit. A continuation restates a retained answer and never
/// reaches here, so no hook runs on it again. The rows the read served are
/// listed in `served`.
pub(crate) async fn execute_native_read_input(
    server: &Arc<SyncServer>,
    tool: McpGeneratedVerbTool,
    method: VaultReadMethod,
    request: Value,
    actor: &McpCallContext,
    served: &mut McpServed,
) -> Result<(Value, Vec<CapabilityHit>), McpGatewayError> {
    let producers = oneiron::memory::ProducerRows::default();
    let pre = {
        let memory = native_read_surface(actor).memory(server, actor, &producers);
        super::verb_hooks::mcp_row_hooks_pre(server, tool.name, actor, &memory, request)
    };
    let hooks = pre.await?;
    let read = Box::pin(super::memory_response::execute(
        server,
        method,
        hooks.args.clone(),
        actor,
    ))
    .await;
    served.extend(producers.take());
    let (output, capabilities, rows) = match read {
        Ok(read) => read,
        Err(error) => {
            crate::api::facade::row_hooks_abort(server, hooks).await;
            return Err(error);
        }
    };
    served.extend(rows);
    let output = crate::api::facade::row_hooks_post(server, hooks, output)
        .await
        .map_err(mcp_facade_error)?;
    Ok((output, capabilities))
}

/// The surface a native read's hooks read the call from: its credential, the
/// invocation it named or a fresh one, the hook pause it resumes and the
/// position a hook's ask is born at. A read holds no run and produces no
/// task work, so the surface holds neither.
fn native_read_surface(actor: &McpCallContext) -> McpRowSurface {
    let mut position = actor.scope.birth_position();
    if let Ok(Some(facet)) = actor.landing {
        position.facet = Some(facet);
    }
    McpRowSurface {
        position,
        invocation: actor
            .invocation
            .unwrap_or_else(oneiron::runtime_hooks::InvocationId::mint),
        run: None,
        task_work_turn: None,
    }
}
