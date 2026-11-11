//! A room turn's row, kept in the write that lands the turn (FIX 15647,
//! THREAD-TASK-ONE-SURFACE): the witness's turn, and a plain thread reply in
//! a project room. Both put and index the row, record the agents it
//! addresses, and stage its wakes through the one producer, `super::wake`.
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
    reason = "the witness and the thread reply door hand over the row and the facts their writes proved"
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
    TURNS.put(&vault.store, txn, &turn_id, turn)?;
    super::history::index_turn(&vault.store, txn, turn)?;
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

/// A plain thread reply in a project room keeps its room row and stages its
/// wakes in the reply's own write, as a witness turn does
/// (THREAD-TASK-ONE-SURFACE). `appended` is the TURN the conversation DAG's
/// thread door wrote for `input` in `txn`; its append admitted and recorded
/// its writer. The row answers the reply's DAG `Parent` inside the thread
/// its binding names, so its `reply_to` is that parent and its `thread_of`
/// the thread's anchor. It names each recipient the witness lets a turn
/// name there: one with a seat, or an agent that speaks as a persona; any
/// other recipient keeps its DAG address and is named on no row. A reply
/// whose parent is neither the anchor nor a turn of this thread that keeps a
/// row keeps no row and wakes no one, so a room walk never meets a gap; the
/// append stands. An ordinary room keeps no rows (THREAD-TASK-EVERY-ROOM).
pub(crate) fn record_thread_reply_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    input: &AppendRecord,
    appended: &AppendedRecord,
) -> Result<()> {
    let room = input.conversation;
    if appended.kind != ENTITY_TYPE_TURN
        || !super::super::project::ROOM_PROJECT.contains(&vault.store, txn, &room)?
        || TURNS.contains(&vault.store, txn, &appended.id)?
    {
        return Ok(());
    }
    let LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_TURN,
        body,
    } = live_entity_row_in_txn(&vault.store, txn, &appended.id)?
    else {
        return Err(invalid());
    };
    let (Some(binding), Some(parent)) = (thread_binding(&body)?, appended.parent) else {
        return Ok(());
    };
    let Some(anchor) = binding.anchor else {
        return Ok(());
    };
    if parent != anchor {
        let linked = TURNS.get(&vault.store, txn, &parent)?.is_some_and(|row| {
            row.room_id == room.to_hex() && row.thread_of == Some(anchor.to_hex())
        });
        if !linked {
            return Ok(());
        }
    }
    let now = vault.store.clock.now_recorded_at();
    let mut addressed = BTreeSet::new();
    if !input.recipients.is_empty() {
        let seats = room_in(vault, txn, room)?.member_ids;
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
        reply_to: Some(parent.to_hex()),
        thread_of: Some(anchor.to_hex()),
        at: input.occurred.start,
        task_ids: Vec::new(),
        converted_project: None,
        quotes: BTreeMap::new(),
    };
    let audience = thread_audience_now_in(vault, txn, room, binding.root)?;
    record_room_turn_in_txn(
        vault,
        txn,
        Some(binding.root),
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
