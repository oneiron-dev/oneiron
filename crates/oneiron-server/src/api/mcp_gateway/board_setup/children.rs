//! The connector actor's own children on its board (FIX 1052): each child
//! that rides no TASK row is judged by the evidence it carries of where it
//! works, never by its parent actor alone.

use super::*;

/// Whether a connector's board shows `child`, a live child of its actor that
/// rides none of the board's TASK rows, as a bare row.
///
/// A child on a TASK passes as that TASK's own row would: under the caller's
/// read and destination (FIX 9755) and inside the connector's world/facet
/// ceiling. A child on no TASK passes a connector that is not narrowed as its
/// attempt row always did. On a narrowed connector it passes only when the
/// scope its dispatch froze sits inside that ceiling, on a world the
/// caller's read reaches, for a credential whose record scope is
/// unrestricted; a child with no such evidence stays off the board.
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
    if let Some(task) = task {
        let passes = oneiron::context_board::TasksSectionRows::task_admitted(memory, read, task)
            .map_err(|error| mcp_engine_error("board children failed", error))?;
        return Ok(passes && mcp_scope_admits_row(&server.vault, actor, read, &task.to_hex())?);
    }
    let narrowed = actor.scope.is_narrow() || !actor.has_unrestricted_record_scope();
    if !narrowed {
        return mcp_scope_admits_row(&server.vault, actor, read, &child.attempt);
    }
    if !actor.has_unrestricted_record_scope() {
        return Ok(false);
    }
    let Some(scope) = child_dispatch_scope(&server.vault, &child.attempt)
        .map_err(|error| mcp_engine_error("board child scope failed", error))?
    else {
        return Ok(false);
    };
    if actor.scope.world_ref.is_some_and(|world| scope.world != Some(world)) {
        return Ok(false);
    }
    let facet_inside = match scope.facet {
        Some(facet) => actor.scope.facets.contains(&oneiron::federation::ScopeId(facet)),
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
