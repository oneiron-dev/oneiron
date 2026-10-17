//! OF-522: a room's turn rows on the owner's other machines. Each turn row,
//! with its thread-task bindings and conversion mark, rides the window its
//! TURN rides (`crate::sync::rooms`). A machine that takes one merges it here
//! as the witness door's append does, and indexes the room's history from it.
use super::*;

/// The turn row this vault holds for `id`, if any.
pub(crate) fn replicated_turn_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<RoomTurn>> {
    TURNS.get(&vault.store, txn, &id)
}

/// Why this vault refuses a carried turn row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TurnMergeRefusal {
    /// The row names ids that do not parse.
    InvalidIds,
    /// The row names fixed fields other than the row this vault holds.
    FixedFieldsConflict,
    /// This vault deleted the row's room; no room deletion is undone.
    RoomDeleted,
    /// This vault holds no record of the row's room.
    RoomMissing,
}

/// What merging a carried turn row did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TurnMerge {
    /// The row this vault holds changed, and its history is indexed.
    Written,
    /// This vault holds everything the row carries.
    Held,
    /// The row is left out, for the reason given.
    Refused(TurnMergeRefusal),
}

/// Merges a turn row another machine of this vault carried. A row this vault
/// lacks is written as carried. One it holds keeps its room, actor,
/// addressing, links, quote, time and conversion, and takes the carried
/// messages and bound tasks it lacks; a carried row that names other fixed
/// fields is refused. A row whose room this vault deleted, or holds no
/// record of, is refused before anything is written, so no turn or history
/// row dangles from a room that is gone (OF-522).
pub(crate) fn merge_replicated_turn_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    carried: RoomTurn,
) -> Result<TurnMerge> {
    let named = |hex: &str| EntityId::from_hex(hex).is_ok_and(|id| id.to_hex() == hex);
    if !named(&carried.turn_id)
        || !named(&carried.room_id)
        || !named(&carried.actor)
        || carried.reply_to.as_deref().is_some_and(|id| !named(id))
        || carried.thread_of.as_deref().is_some_and(|id| !named(id))
    {
        return Ok(TurnMerge::Refused(TurnMergeRefusal::InvalidIds));
    }
    let room = EntityId::from_hex(&carried.room_id)?;
    if crate::ports::removed_in_txn(&vault.store, txn, &room)? {
        return Ok(TurnMerge::Refused(TurnMergeRefusal::RoomDeleted));
    }
    if crate::ports::EntityStoreRead::port_entity_record(&vault.store, txn, &room)?.is_none() {
        return Ok(TurnMerge::Refused(TurnMergeRefusal::RoomMissing));
    }
    let id = EntityId::from_hex(&carried.turn_id)?;
    let merged = match TURNS.get(&vault.store, txn, &id)? {
        None => carried,
        Some(held) => {
            if held.room_id != carried.room_id
                || held.actor != carried.actor
                || held.addressed_agents != carried.addressed_agents
                || held.reply_to != carried.reply_to
                || held.thread_of != carried.thread_of
                || held.quote != carried.quote
            {
                return Ok(TurnMerge::Refused(TurnMergeRefusal::FixedFieldsConflict));
            }
            let mut merged = held.clone();
            for message in carried.message_ids {
                if !merged.message_ids.contains(&message) {
                    merged.message_ids.push(message);
                }
            }
            for task in carried.task_ids {
                if !merged.task_ids.contains(&task) {
                    merged.task_ids.push(task);
                }
            }
            if merged.converted_project.is_none() {
                merged.converted_project = carried.converted_project;
            }
            if merged == held {
                return Ok(TurnMerge::Held);
            }
            merged
        }
    };
    TURNS.put(&vault.store, txn, &id, &merged)?;
    history::index_turn(&vault.store, txn, &merged)?;
    Ok(TurnMerge::Written)
}
