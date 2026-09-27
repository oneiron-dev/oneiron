//! Existing TASK intent and follow-up facts projected onto a room thread.
use super::{TaskAssignee, wire_decode::task_verb_body_in};
use crate::memory::{Memory, MemoryResult};
use crate::ports::EntityStoreRead;
use crate::workspace_roster::RoomThreadTask;
use crate::{EntityId, Error};
use std::collections::BTreeSet;

/// A read of existing TASK bodies only. `spec.thread_ref` is an optional
/// existing task-context pointer; consults also carry typed TURN references.
/// Neither field is inferred from label text or from room membership.
pub(crate) fn thread_tasks(
    memory: &Memory<'_>,
    roots: &BTreeSet<EntityId>,
    members: &BTreeSet<String>,
    now: u64,
) -> MemoryResult<Vec<RoomThreadTask>> {
    if roots.is_empty() {
        return Ok(Vec::new());
    }
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let mut candidates = Vec::new();
    for row in vault
        .store
        .port_entity_ids_by_type(&txn, crate::registry::ENTITY_TYPE_TASK, None)?
    {
        let id = row?;
        let Some(body) = task_verb_body_in(vault, &txn, id)? else {
            continue;
        };
        let from_spec = body.spec.as_map().and_then(|fields| {
            fields
                .iter()
                .find(|(key, _)| key.as_str() == Some("thread_ref"))
                .and_then(|(_, value)| value.as_str())
                .and_then(|value| EntityId::from_hex(value).ok())
        });
        let from_consult = body.consult.as_ref().and_then(|consult| {
            std::iter::once(consult.question_ref)
                .chain(consult.context_refs.iter().copied())
                .map(super::ConsultPayloadRef::entity_ref)
                .find(|id| roots.contains(id))
        });
        let Some(thread) = from_spec.or(from_consult).filter(|id| roots.contains(id)) else {
            continue;
        };
        let Some(authority) = vault.task_authority_state_in(&txn, id)? else {
            continue;
        };
        if !members.contains(&authority.owner_ref.to_hex()) {
            continue;
        }
        // Exhaust the shared TASK index for an exact room-local census.
        // No persisted thread→TASK index is added: this issue forbids new
        // stored state. The guard applies to relevant rows, not unrelated
        // TASKs belonging to other rooms in the vault.
        if candidates.len() == 100_000 {
            return Err(Error::IndexOverflow("room thread TASK matches").into());
        }
        candidates.push((id, thread, body, authority.cancelled));
    }
    drop(txn);
    let mut result = Vec::new();
    for (id, thread, body, cancelled) in candidates {
        // `Memory::get_entity` opens a reader of its own: finish the index
        // snapshot first or LMDB refuses recursive reuse of its reader slot.
        // Room membership alone never grants TASK visibility.
        let Some(view) = memory.get_entity(&id.to_hex())? else {
            continue;
        };
        let terminal = body.terminal();
        let open =
            terminal.is_none() && !cancelled && body.ttl.is_none_or(|ttl| ttl.deadline_at > now);
        let wait = if open {
            match body.assignee {
                Some(TaskAssignee::Human { actor_ref }) => {
                    let cursor = crate::human_task::human_followup_record(vault, id)?;
                    Some(crate::workspace_roster::RoomThreadWait {
                        task: id,
                        kind: crate::workspace_roster::RoomWaitKind::HumanTask,
                        who: actor_ref,
                        since: body.created_at,
                        next_nudge: cursor.and_then(|row| row.next_due_at),
                    })
                }
                Some(TaskAssignee::Peer { actor_ref } | TaskAssignee::Child { actor_ref })
                    if body.task_kind() == super::TaskKind::Consult
                        || matches!(
                            body.state,
                            Some(super::TaskExecutionState::Interrupted { .. })
                        ) =>
                {
                    Some(crate::workspace_roster::RoomThreadWait {
                        task: id,
                        kind: if matches!(
                            body.state,
                            Some(super::TaskExecutionState::Interrupted { .. })
                        ) {
                            crate::workspace_roster::RoomWaitKind::Hold
                        } else {
                            crate::workspace_roster::RoomWaitKind::Ask
                        },
                        who: actor_ref,
                        since: if matches!(
                            body.state,
                            Some(super::TaskExecutionState::Interrupted { .. })
                        ) {
                            view.occurred_start
                        } else {
                            body.created_at
                        },
                        // A peer has no native-human reminder cursor. Do not
                        // claim its TTL deadline is a scheduled nudge.
                        next_nudge: None,
                    })
                }
                _ => None,
            }
        } else {
            None
        };
        let delivered = terminal.and_then(|terminal| {
            (terminal.disposition == super::TaskTerminalDisposition::Completed)
                .then_some(
                    terminal
                        .result_ref
                        .map(|result| (result, terminal.finished_at)),
                )
                .flatten()
        });
        result.push(RoomThreadTask {
            task: id,
            thread,
            open,
            wait,
            delivered,
        });
    }
    Ok(result)
}
