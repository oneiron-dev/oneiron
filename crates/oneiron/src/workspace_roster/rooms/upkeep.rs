//! What a room's upkeep reads (ONEIRON-ARCH-0067 §8: the engine performs
//! every room's mechanical upkeep, and a host does the speaking part).
//!
//! One pure read, scoped by the reader that asks: the turns a summary cites,
//! each thread's newest reply and its open TASKs, and the room's last
//! activity. Refs and times only, never a turn's words, and no judgment:
//! whether a room is due a summary or a nudge is a Coach recipe's on the
//! shared wake (ONEIRON-ARCH-0079), and its voice is the room's host. Nothing
//! here schedules, stores or speaks, and it grants nothing.
use super::*;
use crate::claim::ScopedRead;
use std::collections::BTreeMap;

/// One room as its upkeep reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomUpkeepInput {
    pub room: EntityId,
    /// Every turn the reader reads, oldest first: what a summary cites.
    pub source_refs: Vec<EntityId>,
    /// When the newest of them was spoken; `None` for a room with none.
    pub last_activity: Option<u64>,
    /// Each thread the reader reads, by its root turn.
    pub threads: Vec<RoomUpkeepThread>,
}

/// One thread's liveness facts, as the room's liveness fold reads them before
/// any policy ranks, caps or lanes them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomUpkeepThread {
    /// The thread's root turn.
    pub handle: EntityId,
    /// The trunk turn it hangs under.
    pub trunk: EntityId,
    /// Its root's time, or its newest reply's.
    pub last_message_at: u64,
    /// The open TASKs bound to it that the reader reads.
    pub open_tasks: Vec<EntityId>,
}

/// `room` as `read` reads it for upkeep, in one snapshot. A room `read`
/// cannot read is a missing room; a turn is kept only when it, its parent
/// and its anchor are readable, and an answer whose parent is not kept goes
/// with it, as a member's own read of the room drops it. Every turn and every
/// member's TASK is read, however many (rule 5): past the threshold row the
/// owner's check is raised for the room.
pub fn room_upkeep_input(read: &ScopedRead<'_>, room: EntityId) -> Result<RoomUpkeepInput> {
    let vault = read.vault();
    read.persist_grant_clock()?;
    vault.backfill_tasks_by_owner()?;
    let now = crate::unix_seconds_now();
    let txn = vault.store.env.read_txn()?;
    let policy = read.live_policy_manifest_in(&txn)?;
    let readable = |id: &str| -> Result<bool> {
        match EntityId::from_hex(id) {
            Ok(id) => read.is_ref_readable_with_policy_in(&txn, &policy, &id),
            Err(_) => Ok(false),
        }
    };
    if !read.is_ref_readable_with_policy_in(&txn, &policy, &room)? {
        return Err(Error::EntityNotFound);
    }
    let members = vault.room_audience_members_in_txn(&txn, room)?;
    let mut turn_rows = crate::scan_check::ScanCount::start(
        &vault.store,
        &txn,
        crate::scan_check::EngineScan::RoomHistoryRows,
        room.as_bytes(),
    )?;
    let mut turns = Vec::new();
    for row in HISTORY.iter_from(&vault.store, &txn, room.as_bytes())? {
        turn_rows.row();
        let (_, turn_id) = row?;
        let turn = turn_in(vault, &txn, turn_id)?;
        let mut kept = readable(turn.turn_id.as_str())?;
        for parent in turn.reply_to.iter().chain(&turn.thread_of) {
            kept = kept && readable(parent.as_str())?;
        }
        if kept {
            turns.push(turn);
        }
    }
    let turns = history::answer_closed(turns);
    let roots = liveness::thread_root_map(&turns)?;
    let bindings = liveness::thread_task_bindings(&turns, &roots)?;
    let mut census = crate::scan_check::ScanCount::start(
        &vault.store,
        &txn,
        crate::scan_check::EngineScan::RoomThreadTasks,
        room.as_bytes(),
    )?;
    let open = crate::task_verb::room_open_thread_tasks_in(
        vault,
        &txn,
        &roots,
        &bindings,
        &members,
        now,
        &mut census,
    )?;
    let mut threads = BTreeMap::new();
    for turn in turns.iter().filter(|turn| liveness::is_thread_root(turn)) {
        let handle = EntityId::from_hex(&turn.turn_id)?;
        let trunk = EntityId::from_hex(turn.thread_of.as_deref().ok_or_else(invalid)?)?;
        threads.insert(
            handle,
            RoomUpkeepThread {
                handle,
                trunk,
                last_message_at: turn.at,
                open_tasks: Vec::new(),
            },
        );
    }
    for turn in &turns {
        let id = EntityId::from_hex(&turn.turn_id)?;
        if let Some(root) = roots.get(&id)
            && let Some(thread) = threads.get_mut(root)
        {
            thread.last_message_at = thread.last_message_at.max(turn.at);
        }
    }
    for (task, thread) in open {
        if let Some(row) = threads.get_mut(&thread)
            && vault.thread_project_in_txn(&txn, room, thread)?.is_none()
            && read.is_ref_readable_with_policy_in(&txn, &policy, &task)?
        {
            row.open_tasks.push(task);
        }
    }
    let source_refs = turns
        .iter()
        .map(|turn| EntityId::from_hex(&turn.turn_id))
        .collect::<Result<Vec<_>>>()?;
    let last_activity = turns.iter().map(|turn| turn.at).max();
    drop(txn);
    turn_rows.finish(vault);
    census.finish(vault);
    Ok(RoomUpkeepInput {
        room,
        source_refs,
        last_activity,
        threads: threads.into_values().collect(),
    })
}

/// Every room in the vault, unread: a caller reads each through its own
/// scoped read ([`room_upkeep_input`]), which refuses a room it cannot read.
/// It lists ids only and grants nothing.
pub(crate) fn upkeep_rooms(vault: &Vault) -> Result<Vec<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    let mut rooms = Vec::new();
    for row in crate::ports::EntityStoreRead::port_entity_ids_by_type(
        &vault.store,
        &txn,
        crate::registry::ENTITY_TYPE_CONVERSATION,
        None,
    )? {
        let id = row?;
        if room_in(vault, &txn, id).is_ok() {
            rooms.push(id);
        }
    }
    Ok(rooms)
}

/// Who hosts `room` for its upkeep, which the engine resolves and a request
/// never names: the stored pin or handoff, else the present pool of the
/// session `turn` was spoken in, its live participants in arrival order. With
/// no such session live, no one is present and only a stored host holds.
/// Knowing the host grants nothing.
pub(crate) fn room_upkeep_host(
    vault: &Vault,
    room: EntityId,
    turn: Option<EntityId>,
) -> Result<Option<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    let session = match turn {
        Some(turn) => crate::compaction::turn_session_membership_in_txn(&vault.store, &txn, &turn)?,
        None => None,
    };
    let present = match session {
        Some(session) => vault
            .conversation_presence
            .lock()
            .map_err(|_| invalid())?
            .get(&session)
            .cloned()
            .unwrap_or_default(),
        None => Vec::new(),
    };
    Ok(room_host_in(vault, &txn, room, &present)?.host)
}
