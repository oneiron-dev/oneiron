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
        // Ask-group ladders live on the existing group row. A peer consult
        // without a group has no promised nudge; a governed ask supplies its
        // next notice or its absolute cutoff without a duplicate cursor.
        let ask_due = if body.task_kind() == super::TaskKind::Consult {
            super::ask_record::ask_notice_at_in(vault, &txn, id, 0)?
                .map(|(notice, cutoff)| notice.map_or(cutoff, |at| at.min(cutoff)))
        } else {
            None
        };
        candidates.push((id, thread, body, authority.cancelled, ask_due));
    }
    drop(txn);
    let mut result = Vec::new();
    for (id, thread, body, cancelled, ask_due) in candidates {
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
                        // Peer consults use the ask group's existing ladder;
                        // a bare consult has no follow-up promise.
                        next_nudge: ask_due,
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
        // A visible TASK does not grant a read of its result. The room row
        // and trunk header must not disclose a foreign result ref.
        let delivered = match delivered {
            Some((result, at)) if memory.get_entity(&result.to_hex())?.is_some() => {
                Some((result, at))
            }
            _ => None,
        };
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
