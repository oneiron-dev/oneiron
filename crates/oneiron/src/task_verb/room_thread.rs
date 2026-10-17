//! Existing TASK intent and follow-up facts projected onto a room thread.
use super::{TaskAssignee, wire_decode::task_verb_body_in};
use crate::memory::{Memory, MemoryResult};
use crate::workspace_roster::RoomThreadTask;
use crate::{EntityId, Error};
use std::collections::{BTreeMap, BTreeSet};

/// The turn a TASK spec's `thread_ref` names, when it names one.
fn spec_thread_ref(body: &super::consult_result::TaskVerbBody) -> Option<EntityId> {
    body.spec.as_map().and_then(|fields| {
        fields
            .iter()
            .find(|(key, _)| key.as_str() == Some("thread_ref"))
            .and_then(|(_, value)| value.as_str())
            .and_then(|value| EntityId::from_hex(value).ok())
    })
}

/// Every turn or claim a TASK body names as its place: its spec's
/// `thread_ref` and each typed consult ref, not only the first that lands
/// in a known thread (FIX 3124). The private-thread read walks them all.
/// An undecodable body names none.
pub(crate) fn context_refs(bytes: &[u8]) -> Vec<EntityId> {
    let Ok(body) = super::wire_decode::decode_task_verb_body(bytes) else {
        return Vec::new();
    };
    let mut refs: Vec<EntityId> = spec_thread_ref(&body).into_iter().collect();
    if let Some(consult) = &body.consult {
        refs.extend(
            std::iter::once(consult.question_ref)
                .chain(consult.context_refs.iter().copied())
                .map(super::ConsultPayloadRef::entity_ref),
        );
    }
    refs
}

fn thread_for_body(
    body: &super::consult_result::TaskVerbBody,
    roots: &BTreeMap<EntityId, EntityId>,
) -> Option<EntityId> {
    let from_spec = spec_thread_ref(body);
    let from_consult = body.consult.as_ref().and_then(|consult| {
        std::iter::once(consult.question_ref)
            .chain(consult.context_refs.iter().copied())
            .map(super::ConsultPayloadRef::entity_ref)
            .find(|id| roots.contains_key(id))
    });
    from_spec
        .and_then(|turn| roots.get(&turn).copied())
        .or_else(|| from_consult.and_then(|turn| roots.get(&turn).copied()))
}

/// All TASK identities carried by a thread, including replies and explicit
/// bindings. Conversion keeps these identities, so existing waits still resume.
pub(crate) fn task_ids_in(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    roots: &BTreeMap<EntityId, EntityId>,
    bindings: &BTreeMap<EntityId, EntityId>,
    members: &BTreeSet<String>,
) -> crate::Result<BTreeMap<EntityId, EntityId>> {
    let mut owned: BTreeSet<_> = bindings.keys().copied().collect();
    for member in members {
        owned.extend(super::owner_index::indexed_tasks_of_in(
            &vault.store,
            txn,
            &EntityId::from_hex(member)?,
        )?);
    }
    let mut tasks = BTreeMap::new();
    for task in owned {
        let Some(body) = task_verb_body_in(vault, txn, task)? else {
            continue;
        };
        let Some(authority) = vault.task_authority_state_in(txn, task)? else {
            continue;
        };
        if authority.owner_ref.to_hex() != body.owner_ref || !members.contains(&body.owner_ref) {
            continue;
        }
        if let Some(thread) = bindings
            .get(&task)
            .copied()
            .or_else(|| thread_for_body(&body, roots))
        {
            tasks.insert(task, thread);
        }
    }
    Ok(tasks)
}

/// Placement never grants task ownership or adds an executor to a roster.
/// Consult recipients keep the already-admitted ask route, including guests;
/// they do not acquire a seat by answering a project's question.
pub(crate) fn task_roster_in(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
    members: &BTreeSet<String>,
) -> crate::Result<()> {
    let body = task_verb_body_in(vault, txn, task)?.ok_or(Error::EntityNotFound)?;
    let authority = vault
        .task_authority_state_in(txn, task)?
        .ok_or(Error::EntityNotFound)?;
    if authority.owner_ref.to_hex() != body.owner_ref || !members.contains(&body.owner_ref) {
        return Err(crate::error::RecordError::InvalidTaskBody(
            "thread task owner is outside the project roster",
        )
        .into());
    }
    if let Some(assignee) = body.assignee {
        assignee.validate_in(vault, txn)?;
        if super::thread_task_is_open_in(vault, txn, task)?
            && body.task_kind() != super::TaskKind::Consult
            && assignee
                .entity_ref()
                .is_some_and(|id| !members.contains(&id.to_hex()))
        {
            return Err(crate::error::RecordError::InvalidTaskBody(
                "thread task assignee is outside the project roster",
            )
            .into());
        }
    }
    Ok(())
}

/// A read of existing TASK bodies only. `spec.thread_ref` is an optional
/// existing task-context pointer; consults also carry typed TURN references.
/// Neither field is inferred from label text or from room membership.
pub(crate) fn thread_tasks(
    memory: &Memory<'_>,
    roots: &BTreeMap<EntityId, EntityId>,
    bindings: &BTreeMap<EntityId, EntityId>,
    members: &BTreeSet<String>,
    now: u64,
) -> MemoryResult<Vec<RoomThreadTask>> {
    if roots.is_empty() && bindings.is_empty() {
        return Ok(Vec::new());
    }
    let vault = memory.vault();
    let audience = members
        .iter()
        .map(|id| EntityId::from_hex(id))
        .collect::<crate::Result<Vec<_>>>()?;
    vault.backfill_tasks_by_owner()?;
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    // Off this device a TASK a device-local world keeps is no match
    // (DEC-0005).
    let kept = crate::settings::device_local_worlds_at(vault, &txn, memory.locality())?;
    // Every member's task is read, however many (rule 5); past the threshold
    // row the census raises the owner's check, scoped to the reader.
    let mut count = crate::scan_check::ScanCount::start(
        &vault.store,
        &txn,
        crate::scan_check::EngineScan::RoomThreadTasks,
        memory.actor().as_bytes(),
    )?;
    // Only a TASK a room member owns can match, so the read walks the
    // members' tasks through the owner index, never every TASK in the vault
    // (F13); each one's live authority is rechecked below.
    let mut owned: BTreeSet<_> = bindings.keys().copied().collect();
    for member in &audience {
        owned.extend(super::owner_index::indexed_tasks_of_in(
            &vault.store,
            &txn,
            member,
        )?);
    }
    // Each thread's members: the room's, or a private thread's (FIX 2951)
    // audience among them, which its tasks read under.
    let mut audiences = BTreeMap::<EntityId, Vec<EntityId>>::new();
    let mut candidates = Vec::new();
    for id in owned {
        count.row();
        if crate::settings::device_local_keeps_among(&vault.store, &txn, &kept, &id)? {
            continue;
        }
        let Some(body) = task_verb_body_in(vault, &txn, id)? else {
            continue;
        };
        let Some(thread) = bindings
            .get(&id)
            .copied()
            .or_else(|| thread_for_body(&body, roots))
        else {
            continue;
        };
        let Some(authority) = vault.task_authority_state_in(&txn, id)? else {
            continue;
        };
        if authority.owner_ref.to_hex() != body.owner_ref || !members.contains(&body.owner_ref) {
            continue;
        }
        if !audiences.contains_key(&thread) {
            let narrowed =
                match crate::conversation_dag::conversation_of(&vault.store, &txn, &thread)
                    .and_then(|room| {
                        crate::workspace_roster::thread_members_in(
                            vault, &txn, room, thread, &audience,
                        )
                    }) {
                    Ok(narrowed) => narrowed,
                    // A thread whose root is gone names no audience of its own.
                    Err(
                        Error::EntityNotFound
                        | Error::Record(crate::error::RecordError::InvalidConversationDag(_)),
                    ) => audience.clone(),
                    Err(error) => return Err(error.into()),
                };
            audiences.insert(thread, narrowed);
        }
        // Exhaust the members' tasks for an exact room-local census.
        // Ask-group ladders live on the existing group row. A peer consult
        // without a group has no promised nudge; a governed ask supplies its
        // next notice or its absolute cutoff without a duplicate cursor.
        // Both come from the group's class, so from the TASK that gave it,
        // and so does a human member's follow-up cursor (DEC-0005). A group
        // whose class TASK is kept at the caller's locality, or was never
        // recorded, gives none of them.
        let ask_group = body.consult.as_ref().map(|payload| payload.correlation_ref);
        let group = match ask_group {
            Some(group_id) => {
                super::ask_record::read_group(vault, &txn, group_id)?.filter(|group| {
                    group
                        .members
                        .iter()
                        .any(|member| member.task == id.to_hex())
                })
            }
            None => None,
        };
        let mut withheld = group
            .as_ref()
            .is_some_and(super::ask_record::AskGroup::class_source_unrecorded);
        for task in group
            .iter()
            .flat_map(super::ask_record::AskGroup::class_tasks)
        {
            withheld |=
                crate::settings::device_local_keeps_among(&vault.store, &txn, &kept, &task)?;
        }
        let group = group.filter(|_| !withheld);
        let group_settled = match ask_group.filter(|_| group.is_some()) {
            Some(group_id) => super::ask_settlement::read_result(vault, &txn, group_id)?.is_some(),
            None => false,
        };
        let ask_due =
            if body.task_kind() == super::TaskKind::Consult && group.is_some() && !group_settled {
                super::ask_record::ask_notice_at_in(vault, &txn, id, 0)?
                    .map(|(notice, cutoff)| notice.map_or(cutoff, |at| at.min(cutoff)))
            } else {
                None
            };
        let class_tasks = group
            .map(|group| group.class_tasks().collect::<Vec<_>>())
            .unwrap_or_default();
        candidates.push((
            id,
            thread,
            body,
            authority.cancelled,
            ask_due,
            group_settled,
            class_tasks,
            withheld,
        ));
    }
    drop(txn);
    count.finish(vault);
    let mut lanes = BTreeMap::new();
    let mut result = Vec::new();
    for (id, thread, body, cancelled, ask_due, group_settled, class_tasks, withheld) in candidates {
        // `Memory::get_entity` opens a reader of its own: finish the index
        // snapshot first or LMDB refuses recursive reuse of its reader slot.
        // Room membership alone never grants TASK visibility: the caller's
        // own read lane, proof and access grants included, narrowed to its
        // thread's members.
        let scoped = match lanes.entry(thread) {
            std::collections::btree_map::Entry::Occupied(lane) => lane.into_mut(),
            std::collections::btree_map::Entry::Vacant(slot) => slot.insert(
                memory
                    .read_lane(crate::claim::ClaimReadStatus::Surfaceable)?
                    .for_audience(audiences.get(&thread).map_or(&audience[..], Vec::as_slice)),
            ),
        };
        if !scoped.is_entity_readable(&id)? {
            continue;
        }
        let Some(view) = memory.get_entity(&id.to_hex())?.value else {
            continue;
        };
        let terminal = body.terminal();
        let open = terminal.is_none()
            && !cancelled
            && !group_settled
            && body.ttl.is_none_or(|ttl| ttl.deadline_at > now);
        let wait = if open {
            match body.assignee.unwrap_or(TaskAssignee::Dreamer) {
                TaskAssignee::Human { actor_ref } => {
                    let cursor = crate::human_task::human_followup_record(vault, id)?;
                    Some(crate::workspace_roster::RoomThreadWait {
                        task: id,
                        kind: crate::workspace_roster::RoomWaitKind::HumanTask,
                        who: actor_ref,
                        since: body.created_at,
                        next_nudge: cursor
                            .filter(|row| row.assignee_ref == actor_ref)
                            .and_then(|row| row.next_due_at)
                            .filter(|at| {
                                !withheld && body.ttl.is_none_or(|ttl| *at <= ttl.deadline_at)
                            }),
                        until: body.ttl.map(|ttl| ttl.deadline_at),
                    })
                }
                assignee
                    if body.task_kind() == super::TaskKind::Consult
                        || matches!(
                            body.state,
                            Some(super::TaskExecutionState::Interrupted { .. })
                        ) =>
                {
                    // A local Dreamer task addresses the owning actor's
                    // executor; it needs no invented Dreamer PERSON row.
                    let actor_ref = assignee
                        .entity_ref()
                        .unwrap_or(EntityId::from_hex(&body.owner_ref)?);
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
                        until: body.ttl.map(|ttl| ttl.deadline_at),
                    })
                }
                _ => None,
            }
        } else {
            None
        };
        if let Some(wait) = &wait
            && !scoped.is_entity_readable(&wait.who)?
        {
            continue;
        }
        let completed_at = terminal
            .filter(|terminal| terminal.disposition == super::TaskTerminalDisposition::Completed)
            .map(|terminal| terminal.finished_at);
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
            Some((result, at)) if scoped.is_entity_readable(&result)? => Some((result, at)),
            _ => None,
        };
        // The thread's counts are derived from this TASK and its result, its
        // wait from the TASK its ask's class came from.
        memory.produced_from(
            std::iter::once(id)
                .chain(delivered.map(|(result, _)| result))
                .chain(class_tasks),
        );
        result.push(RoomThreadTask {
            task: id,
            thread,
            open,
            wait,
            delivered,
            completed_at,
        });
    }
    Ok(result)
}

/// What an open TASK waits on, read in `txn` by the rules [`thread_tasks`]
/// projects a wait with: a human assignee's follow-up cursor, an ask's
/// notice ladder, a held task's actor, each with the TASK's cutoff. `None`
/// for work that waits on no one.
fn open_task_wait(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    body: &super::consult_result::TaskVerbBody,
) -> crate::Result<Option<crate::workspace_roster::RoomThreadWait>> {
    use crate::workspace_roster::{RoomThreadWait, RoomWaitKind};
    let until = body.ttl.map(|ttl| ttl.deadline_at);
    let assignee = body.assignee.unwrap_or(TaskAssignee::Dreamer);
    if let TaskAssignee::Human { actor_ref } = assignee {
        let next_nudge = crate::human_task::human_followup_record_in_txn(vault, txn, id)?
            .filter(|row| row.assignee_ref == actor_ref)
            .and_then(|row| row.next_due_at)
            .filter(|at| until.is_none_or(|cutoff| *at <= cutoff));
        return Ok(Some(RoomThreadWait {
            task: id,
            kind: RoomWaitKind::HumanTask,
            who: actor_ref,
            since: body.created_at,
            next_nudge,
            until,
        }));
    }
    let ask = body.task_kind() == super::TaskKind::Consult;
    let held = matches!(
        body.state,
        Some(super::TaskExecutionState::Interrupted { .. })
    );
    if !ask && !held {
        return Ok(None);
    }
    // A held task waits from when it was held, as its entity row dates it.
    let since = if held {
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)?
            .ok_or(Error::EntityNotFound)?;
        crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("entity header"))?
            .occurred_start
    } else {
        body.created_at
    };
    let next_nudge = if ask {
        super::ask_record::ask_notice_at_in(vault, txn, id, 0)?
            .map(|(notice, cutoff)| notice.map_or(cutoff, |at| at.min(cutoff)))
    } else {
        None
    };
    Ok(Some(RoomThreadWait {
        task: id,
        kind: if held {
            RoomWaitKind::Hold
        } else {
            RoomWaitKind::Ask
        },
        who: assignee
            .entity_ref()
            .unwrap_or(EntityId::from_hex(&body.owner_ref)?),
        since,
        next_nudge,
        until,
    }))
}

/// The open TASKs bound to `roots`' threads, each with its thread root and
/// what it waits on ([`open_task_wait`]), for the engine's room upkeep: the
/// TASK facts [`thread_tasks`] folds, read in `txn` through no reader's lane.
/// Whether a reader may read each one, and the actor it waits on, is the
/// caller's to judge; `count` is the census the caller raises.
pub(crate) fn open_thread_tasks_in(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    roots: &BTreeMap<EntityId, EntityId>,
    bindings: &BTreeMap<EntityId, EntityId>,
    members: &[EntityId],
    now: u64,
    count: &mut crate::scan_check::ScanCount,
) -> crate::Result<
    Vec<(
        EntityId,
        EntityId,
        Option<crate::workspace_roster::RoomThreadWait>,
    )>,
> {
    let mut open = Vec::new();
    if roots.is_empty() && bindings.is_empty() {
        return Ok(open);
    }
    // Walk explicit bindings and members' tasks through the owner index,
    // never every TASK in the vault. Each one's live owner is checked below.
    let mut owned: BTreeSet<_> = bindings.keys().copied().collect();
    for member in members {
        owned.extend(super::owner_index::indexed_tasks_of_in(
            &vault.store,
            txn,
            member,
        )?);
    }
    for id in owned {
        count.row();
        let Some(body) = task_verb_body_in(vault, txn, id)? else {
            continue;
        };
        let Some(thread) = bindings
            .get(&id)
            .copied()
            .or_else(|| thread_for_body(&body, roots))
        else {
            continue;
        };
        let Some(authority) = vault.task_authority_state_in(txn, id)? else {
            continue;
        };
        if authority.owner_ref.to_hex() != body.owner_ref
            || !members.contains(&authority.owner_ref)
            || authority.cancelled
            || body.terminal().is_some()
            || body.ttl.as_ref().is_some_and(|ttl| ttl.deadline_at <= now)
        {
            continue;
        }
        // A consult whose ask group has settled is answered.
        if let Some(group) = body.consult.as_ref().map(|payload| payload.correlation_ref)
            && super::ask_record::read_group(vault, txn, group)?.is_some_and(|record| {
                record
                    .members
                    .iter()
                    .any(|member| member.task == id.to_hex())
            })
            && super::ask_settlement::read_result(vault, txn, group)?.is_some()
        {
            continue;
        }
        open.push((id, thread, open_task_wait(vault, txn, id, &body)?));
    }
    Ok(open)
}
