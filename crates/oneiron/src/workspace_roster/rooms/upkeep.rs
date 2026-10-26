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
    /// Its root's time, or its newest reply's, of those the reader reads; 0
    /// when it reads none of them (FIX 5545).
    pub last_message_at: u64,
    /// The open TASKs bound to it that the reader reads.
    pub open_tasks: Vec<EntityId>,
    /// What those TASKs wait on, where the one waited on is a live PERSON
    /// the reader reads: a follow-up's next notice, an ask's due notice and
    /// the TASK's cutoff (OF-417).
    pub waits: Vec<RoomThreadWait>,
}

impl RoomUpkeepThread {
    /// Whether a person's own schedule still holds the thread at `now`
    /// (Unix seconds): some wait's next notice or cutoff is still ahead. A
    /// wait with neither time holds nothing.
    #[must_use]
    pub fn waiting_for_person(&self, now: u64) -> bool {
        self.waits.iter().any(|wait| {
            wait.next_nudge
                .into_iter()
                .chain(wait.until)
                .any(|at| now < at)
        })
    }
}

/// `room` as `read` reads it for upkeep, in one snapshot. A room `read`
/// cannot read is a missing room; a turn is kept only when it is readable
/// and its parent and anchor are readable or held back from `read` as places
/// (FIX 5545), and an answer whose parent is not kept goes with it, as a
/// member's own read of the room drops it. A held-back turn places its
/// thread and nothing else: no source ref, activity or TASK comes from it.
/// Every turn and every member's TASK is read, however many (rule 5): past
/// the threshold row the owner's check is raised for the room.
pub fn room_upkeep_input(read: &ScopedRead<'_>, room: EntityId) -> Result<RoomUpkeepInput> {
    let vault = read.vault();
    read.persist_grant_clock()?;
    vault.backfill_tasks_by_owner()?;
    let now = crate::unix_seconds_now();
    let txn = vault.store.env.read_txn()?;
    let fold = room_upkeep_fold_in_txn(read, &txn, room, now)?;
    drop(txn);
    Ok(fold.finish(vault).0)
}

/// [`room_upkeep_input`]'s read in the caller's snapshot, for a caller that
/// already holds one (OF-417: the room host's upkeep voice rechecks the
/// thread in the write it lands in). The caller persists `read`'s grant
/// clock and backfills the TASK owner index before taking `txn`, never in
/// it. Beside the input it keeps each thread's newest turn `read` reads.
pub(super) struct RoomUpkeepFold {
    input: RoomUpkeepInput,
    /// Each thread's newest turn the reader reads, by its root turn.
    newest: BTreeMap<EntityId, EntityId>,
    scans: [crate::scan_check::ScanCount; 2],
}

impl RoomUpkeepFold {
    /// The fold's input and newest turns, its scans' checks raised.
    pub(super) fn finish(self, vault: &Vault) -> (RoomUpkeepInput, BTreeMap<EntityId, EntityId>) {
        let [turn_rows, census] = self.scans;
        turn_rows.finish(vault);
        census.finish(vault);
        (self.input, self.newest)
    }
}

/// [`room_upkeep_input`] in `txn` at `now` (Unix seconds); see
/// [`RoomUpkeepFold`].
pub(super) fn room_upkeep_fold_in_txn(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    now: u64,
) -> Result<RoomUpkeepFold> {
    let vault = read.vault();
    let policy = read.live_policy_manifest_in(txn)?;
    let readable = |id: &str| -> Result<bool> {
        match EntityId::from_hex(id) {
            Ok(id) => read.is_ref_readable_with_policy_in(txn, &policy, &id),
            Err(_) => Ok(false),
        }
    };
    if !read.is_ref_readable_with_policy_in(txn, &policy, &room)? {
        return Err(Error::EntityNotFound);
    }
    let members = vault.room_audience_members_in_txn(txn, room)?;
    let mut turn_rows = crate::scan_check::ScanCount::start(
        &vault.store,
        txn,
        crate::scan_check::EngineScan::RoomHistoryRows,
        room.as_bytes(),
    )?;
    let mut folds = super::thread_reads::RootFolds::new();
    let mut held = |id: &str| -> Result<bool> {
        match EntityId::from_hex(id) {
            Ok(id) => super::thread_reads::turn_held_back_folded_for_in(read, txn, id, &mut folds),
            Err(_) => Ok(false),
        }
    };
    let mut reach = super::thread_reads::RoomReach::default();
    for row in HISTORY.iter_from(&vault.store, txn, room.as_bytes())? {
        turn_rows.row();
        let (_, turn_id) = row?;
        let turn = turn_in(vault, txn, turn_id)?;
        if !readable(turn.turn_id.as_str())? {
            if held(turn.turn_id.as_str())? {
                reach.push_held(&turn);
            }
            continue;
        }
        let mut kept = true;
        for parent in turn.reply_to.iter().chain(&turn.thread_of) {
            kept = kept && (readable(parent.as_str())? || held(parent.as_str())?);
        }
        if kept {
            reach.push_read(turn);
        }
    }
    let reach = reach.answer_closed();
    let turns = reach.placed();
    let roots = liveness::thread_root_map(turns)?;
    let bindings = liveness::thread_task_bindings(turns, &roots)?;
    let mut census = crate::scan_check::ScanCount::start(
        &vault.store,
        txn,
        crate::scan_check::EngineScan::RoomThreadTasks,
        room.as_bytes(),
    )?;
    let open = crate::task_verb::room_open_thread_tasks_in(
        vault,
        txn,
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
                waits: Vec::new(),
            },
        );
    }
    let mut newest: BTreeMap<EntityId, (u64, EntityId)> = BTreeMap::new();
    for turn in reach.read() {
        let id = EntityId::from_hex(&turn.turn_id)?;
        let Some(root) = roots.get(&id) else {
            continue;
        };
        if newest.get(root).is_none_or(|(at, _)| turn.at >= *at) {
            newest.insert(*root, (turn.at, id));
        }
        if let Some(thread) = threads.get_mut(root) {
            thread.last_message_at = thread.last_message_at.max(turn.at);
        }
    }
    for (task, thread, wait) in open {
        if let Some(row) = threads.get_mut(&thread)
            && vault.thread_project_in_txn(txn, room, thread)?.is_none()
            && read.is_ref_readable_with_policy_in(txn, &policy, &task)?
        {
            row.open_tasks.push(task);
            if let Some(wait) = wait
                && crate::consent::person_is_live_in_txn(vault, txn, &wait.who)?
                && read.is_ref_readable_with_policy_in(txn, &policy, &wait.who)?
            {
                row.waits.push(wait);
            }
        }
    }
    let source_refs = reach
        .read()
        .map(|turn| EntityId::from_hex(&turn.turn_id))
        .collect::<Result<Vec<_>>>()?;
    let last_activity = reach.read().map(|turn| turn.at).max();
    Ok(RoomUpkeepFold {
        input: RoomUpkeepInput {
            room,
            source_refs,
            last_activity,
            threads: threads.into_values().collect(),
        },
        newest: newest
            .into_iter()
            .map(|(root, (_, turn))| (root, turn))
            .collect(),
        scans: [turn_rows, census],
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
    room_upkeep_host_in_txn(vault, &txn, room, turn)
}

/// [`room_upkeep_host`] in the caller's snapshot. Presence is the process's
/// live list, read under its lock; only the pin and standing are `txn`'s.
pub(super) fn room_upkeep_host_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    turn: Option<EntityId>,
) -> Result<Option<EntityId>> {
    let session = match turn {
        Some(turn) => crate::compaction::turn_session_membership_in_txn(&vault.store, txn, &turn)?,
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
    Ok(room_host_in(vault, txn, room, &present)?.host)
}

/// The Dreamer's read under its relationship gate: the reach the Coach reads
/// rooms through and picks a nudge's host from (OF-417), and the one the
/// host's upkeep voice picks the host from as well (FIX 7399). Only refs and
/// turn times come out of it here, never a turn's words, and it grants
/// nothing.
pub(crate) fn room_upkeep_reach(vault: &Vault) -> Result<ScopedRead<'_>> {
    let dreamer = vault.dreamer_authority()?;
    let key = crate::claim::ScopedReadActorKey::with_actor_class(
        dreamer.entity_ref().to_hex(),
        dreamer.actor_class().gate_actor_class(),
    )
    .ok_or_else(|| Error::InvalidConfig("invalid Dreamer read key".into()))?
    .require_relationship_grants(Some(dreamer.entity_ref()));
    Ok(vault.scoped_read(key))
}

/// [`room_upkeep_reach`] for a door about to take its snapshot, its grant
/// clock persisted first; `None` when either fails, and the door selects the
/// host through its caller's own reach alone, as before.
pub(super) fn room_upkeep_reach_now(vault: &Vault) -> Option<ScopedRead<'_>> {
    let reach = room_upkeep_reach(vault).ok()?;
    reach.persist_grant_clock().ok()?;
    Some(reach)
}

/// Whether `caller` hosts `room` for its upkeep now, in `txn` at `now`: the
/// host the engine selects from `newest`, the newest turn the caller's own
/// reach reads there, as before, or the one it selects from the newest turn
/// `upkeep` reads, the Coach's reach ([`room_upkeep_reach`], FIX 7399). A
/// stored pin or handoff is the host either way; only a presence-chosen host
/// can differ, and either selection admits the caller. A room `upkeep` does
/// not read, or whose read fails, adds nothing.
pub(super) fn room_upkeep_hosts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    upkeep: Option<&ScopedRead<'_>>,
    (room, newest): (EntityId, Option<EntityId>),
    caller: EntityId,
    now: u64,
) -> Result<bool> {
    if room_upkeep_host_in_txn(vault, txn, room, newest)? == Some(caller) {
        return Ok(true);
    }
    let Some(upkeep) = upkeep else {
        return Ok(false);
    };
    let last = match room_upkeep_fold_in_txn(upkeep, txn, room, now) {
        Ok(fold) => fold.finish(vault).0.source_refs.last().copied(),
        Err(Error::EntityNotFound) => return Ok(false),
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "room upkeep did not read the Coach's reach");
            return Ok(false);
        }
    };
    Ok(last != newest && room_upkeep_host_in_txn(vault, txn, room, last)? == Some(caller))
}
