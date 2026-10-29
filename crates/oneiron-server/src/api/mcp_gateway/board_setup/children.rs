//! The connector actor's own children on its board (FIX 1052): each child
//! that rides no TASK row is judged by the evidence it carries of where it
//! works, never by its parent actor alone.

use super::*;

/// Whether this connector reads its actor's children narrowed: a world or
/// facet narrowing, or a record scope that is not unrestricted.
pub(super) fn mcp_children_narrowed(actor: &McpCallContext) -> bool {
    actor.scope.is_narrow() || !actor.has_unrestricted_record_scope()
}

/// Whether a connector's board shows `child`, a live child of its actor that
/// rides none of the board's TASK rows, as a bare row.
///
/// A connector that is not narrowed judges it as before: a child on a TASK
/// under the caller's read and destination (FIX 9755), any other passed on
/// to its attempt row's own check. On a narrowed connector a child on a TASK
/// passes as that TASK's own row would, inside the connector's world/facet
/// ceiling too; a child on no TASK passes only when the scope its dispatch
/// froze sits inside that ceiling, on a world the caller's read reaches, for
/// a credential whose record scope is unrestricted. A child with no such
/// evidence, or whose evidence does not read, stays off the board, and the
/// board itself still answers.
pub(super) fn mcp_child_admitted(
    server: &SyncServer,
    actor: &McpCallContext,
    memory: &oneiron::memory::Memory<'_>,
    read: &oneiron::claim::ScopedRead<'_>,
    child: &oneiron::context_board::ChildState,
) -> Result<bool, McpGatewayError> {
    let task = child
        .task_ref
        .as_deref()
        .and_then(|task| oneiron::EntityId::from_hex(task).ok());
    if !mcp_children_narrowed(actor) {
        return match task {
            Some(task) => {
                oneiron::context_board::TasksSectionRows::task_admitted(memory, read, task)
                    .map_err(|error| mcp_engine_error("board children failed", error))
            }
            None => Ok(true),
        };
    }
    match narrowed_child_admitted(server, actor, memory, read, task, child) {
        Ok(admitted) => Ok(admitted),
        Err(error) => {
            tracing::debug!(
                kind = error.kind,
                "mcp board child omitted: its evidence did not read"
            );
            Ok(false)
        }
    }
}

/// [`mcp_child_admitted`] on a narrowed connector, by the child's TASK when
/// it names one, else by the scope its dispatch froze.
fn narrowed_child_admitted(
    server: &SyncServer,
    actor: &McpCallContext,
    memory: &oneiron::memory::Memory<'_>,
    read: &oneiron::claim::ScopedRead<'_>,
    task: Option<oneiron::EntityId>,
    child: &oneiron::context_board::ChildState,
) -> Result<bool, McpGatewayError> {
    if let Some(task) = task {
        let passes = oneiron::context_board::TasksSectionRows::task_admitted(memory, read, task)
            .map_err(|error| mcp_engine_error("board children failed", error))?;
        return Ok(passes && mcp_scope_admits_row(&server.vault, actor, read, &task.to_hex())?);
    }
    if !actor.has_unrestricted_record_scope() {
        return Ok(false);
    }
    let Some(scope) = child_dispatch_scope(&server.vault, &child.attempt)
        .map_err(|error| mcp_engine_error("board child scope failed", error))?
    else {
        return Ok(false);
    };
    if actor
        .scope
        .world_ref
        .is_some_and(|world| scope.world != Some(world))
    {
        return Ok(false);
    }
    let facet_inside = match scope.facet {
        Some(facet) => actor
            .scope
            .facets
            .contains(&oneiron::federation::ScopeId(facet)),
        None => matches!(actor.scope.facets, oneiron::federation::ScopeAxis::All),
    };
    if !facet_inside {
        return Ok(false);
    }
    match scope.world {
        Some(world) => read
            .is_entity_readable(&world)
            .map_err(|error| mcp_engine_error("board child world failed", error)),
        None => Ok(true),
    }
}

/// The branch scope a child's dispatch froze at spawn, read from its own
/// attempt row: `None` for an attempt no longer queued, one that is not an
/// agent dispatch, or a dispatch that froze no scope.
fn child_dispatch_scope(
    vault: &oneiron::Vault,
    attempt: &str,
) -> oneiron::Result<Option<oneiron::llm::Scope>> {
    let Ok(id) = oneiron::EntityId::from_hex(attempt) else {
        return Ok(None);
    };
    let id = oneiron::attempt_queue::AttemptId::from_bytes(id.as_bytes())?;
    let Some(record) = oneiron::AttemptQueue::new(vault).get(id)? else {
        return Ok(None);
    };
    let Ok(payload) = oneiron::dreamer_runner::decode_dreamer_attempt_payload(&record.payload)
    else {
        return Ok(None);
    };
    if payload.attempt_type != oneiron::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE {
        return Ok(None);
    }
    let input = oneiron::agent_dispatch::decode_agent_dispatch_input(&payload.input).ok();
    Ok(input.and_then(|input| input.scope))
}
