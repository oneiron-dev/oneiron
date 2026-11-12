//! A room turn's row, kept in the write that lands the turn (FIX 15647,
//! THREAD-TASK-ONE-SURFACE, THREAD-TASK-EVERY-ROOM): the witness's turn,
//! and every TURN the conversation DAG appends, in any room. Both put and
//! index the row, record the agents it addresses, and stage its wakes
//! through the one producer, `super::wake`.
use super::audience::{thread_audience_now_in, thread_binding};
use super::participation::{addressable_agent_in_txn, record_addressed_in_txn};
use super::*;
use crate::conversation_dag::{AppendRecord, AppendedRecord};
use crate::registry::ENTITY_TYPE_TURN;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use std::collections::BTreeMap;

/// Keeps `turn`'s row in this write: puts and indexes it, records the
/// writer `admitted` names (a door whose append recorded its writer already
/// passes `None`) and each agent `turn` addresses in its thread `branch`,
/// and, when this write mints the row, stages the turn's wakes for the
/// private `audience` that reads it now. A write that adds to a stored row
/// wakes no one again.
#[expect(
    clippy::too_many_arguments,
    reason = "the witness and the native turn writer hand over the row and the facts their writes proved"
)]
pub(super) fn record_room_turn_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    branch: Option<EntityId>,
    turn: &RoomTurn,
    admitted: Option<&Admitted>,
    minted: bool,
    audience: Option<&BTreeSet<EntityId>>,
    now: u64,
) -> Result<()> {
    let room = EntityId::from_hex(&turn.room_id)?;
    let turn_id = EntityId::from_hex(&turn.turn_id)?;
    put_room_turn_projection_in_txn(vault, txn, turn)?;
    if let Some(admitted) = admitted {
        admitted.record_in_txn(vault, txn, now)?;
    }
    record_addressed_in_txn(
        vault,
        txn,
        room,
        branch,
        turn_id,
        &turn.addressed_agents,
        now,
    )?;
    // FIX 15647: each agent the turn addresses, and each holder of its
    // thread's open TASK, is staged one wake in this write; whoever runs the
    // agent delivers it after the commit.
    if minted {
        super::wake::stage_room_wakes_in_txn(vault, txn, branch, turn, audience, now)?;
    }
    Ok(())
}

/// Puts `turn`'s room row and indexes it, and nothing else: no writer, no
/// address and no wake is recorded. Every room row is written here; the
/// open's backfill (`super::backfill`) writes nothing beside it.
pub(super) fn put_room_turn_projection_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    turn: &RoomTurn,
) -> Result<()> {
    let turn_id = EntityId::from_hex(&turn.turn_id)?;
    TURNS.put(&vault.store, txn, &turn_id, turn)?;
    super::history::index_turn(&vault.store, txn, turn)
}

/// Every TURN the conversation DAG appends keeps its room row and stages
/// its wakes in the append's own write, as a witness turn does, in any room
/// (THREAD-TASK-ONE-SURFACE, THREAD-TASK-EVERY-ROOM). `appended` is the
/// TURN the DAG's append wrote for `input` in `txn`; that append admitted
/// and recorded its writer. A TURN with no thread binding is a trunk turn:
/// its row answers no turn and names no thread. A thread's TURN answers its
/// DAG `Parent` inside the thread its binding names, so its `reply_to` is
/// that parent and its `thread_of` the thread's anchor. The row names each
/// recipient the witness lets a turn name there: one with a seat, or an
/// agent that speaks as a persona; any other recipient keeps its DAG
/// address and is named on no row. A thread TURN whose binding names no
/// anchor, or that has no parent, keeps no row; the append stands.
pub(crate) fn record_native_room_turn_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    input: &AppendRecord,
    appended: &AppendedRecord,
) -> Result<()> {
    let room = input.conversation;
    if appended.kind != ENTITY_TYPE_TURN || TURNS.contains(&vault.store, txn, &appended.id)? {
        return Ok(());
    }
    let LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_TURN,
        body,
    } = live_entity_row_in_txn(&vault.store, txn, &appended.id)?
    else {
        return Err(invalid());
    };
    // `(thread root, reply_to, thread_of)`: none of them for a trunk turn.
    let (branch, reply_to, thread_of) = match thread_binding(&body)? {
        None => (None, None, None),
        Some(binding) => {
            let (Some(parent), Some(anchor)) = (appended.parent, binding.anchor) else {
                return Ok(());
            };
            (Some(binding.root), Some(parent), Some(anchor))
        }
    };
    let now = vault.store.clock.now_recorded_at();
    let mut addressed = BTreeSet::new();
    if !input.recipients.is_empty() {
        let seats = room_access_in(vault, txn, room)?.member_ids;
        for recipient in &input.recipients {
            if seats.contains(&recipient.to_hex())
                || addressable_agent_in_txn(vault, txn, *recipient, now)?
            {
                addressed.insert(recipient.to_hex());
            }
        }
    }
    let turn = RoomTurn {
        turn_id: appended.id.to_hex(),
        room_id: room.to_hex(),
        actor: input.actor.entity_ref().to_hex(),
        addressed_agents: addressed,
        message_ids: Vec::new(),
        reply_to: reply_to.map(|id| id.to_hex()),
        thread_of: thread_of.map(|id| id.to_hex()),
        at: input.occurred.start,
        task_ids: Vec::new(),
        converted_project: None,
        quotes: BTreeMap::new(),
    };
    let audience = match branch {
        Some(root) => thread_audience_now_in(vault, txn, room, root)?,
        None => None,
    };
    record_room_turn_in_txn(
        vault,
        txn,
        branch,
        &turn,
        None,
        true,
        audience.as_ref(),
        now,
    )
}

/// A MESSAGE its writer adds to its own DAG TURN joins that TURN's room
/// row, when the TURN keeps one, as a witness's new message on a stored turn
/// does (FIX 2028): its id is listed once, and every other field of the row,
/// its quotes among them, stays as it was. The row's own write staged its
/// wakes; this one stages none.
pub(crate) fn record_room_message_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    turn: EntityId,
    message: EntityId,
) -> Result<()> {
    let Some(mut row) = TURNS.get(&vault.store, txn, &turn)? else {
        return Ok(());
    };
    let message = message.to_hex();
    if !row.message_ids.contains(&message) {
        row.message_ids.push(message);
        TURNS.put(&vault.store, txn, &turn, &row)?;
    }
    Ok(())
}
