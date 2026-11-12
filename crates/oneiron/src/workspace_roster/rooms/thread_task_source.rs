//! The thread a TASK made from a room message binds to
//! (`tasks.create.from_message`, THREAD-TASK-ONE-SURFACE).
//!
//! Entry: [`room_thread_source_in`].

use super::participation::turn_root_in_txn;
use super::replicated_turn_in;
use crate::edge::EdgeKind;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::{EntityId, Vault};

/// The project room and the thread root a MESSAGE or TURN `source` stands
/// in, for a TASK made from it: the root is where a bound TASK's holder
/// wakes and what a conversion reads. A MESSAGE is part of exactly one TURN
/// and belongs to that TURN's room alone. A source in a second thread under
/// the same trunk message names that thread's root, never the first one.
///
/// `None` when `source` is no MESSAGE or TURN, when its TURN keeps no room
/// row, or when that TURN is on the trunk: a trunk message binds no thread,
/// and the pane opens its thread first. The caller checks the room, the
/// thread's audience and the actor's read of `source`.
pub(crate) fn room_thread_source_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: EntityId,
) -> Result<Option<(EntityId, EntityId)>> {
    let turn = match vault.get_entity_type_in_txn(txn, &source)? {
        Some(ENTITY_TYPE_TURN) => source,
        Some(ENTITY_TYPE_MESSAGE) => {
            let turns = crate::conversation_dag::edge_ids(
                &vault.store,
                txn,
                &source,
                EdgeKind::PartOf,
                false,
                2,
            )?;
            let [turn] = turns.as_slice() else {
                return Ok(None);
            };
            *turn
        }
        _ => return Ok(None),
    };
    let Some(row) = replicated_turn_in(vault, txn, turn)? else {
        return Ok(None);
    };
    let room = EntityId::from_hex(&row.room_id)?;
    if source != turn {
        let owned = crate::conversation_dag::edge_ids(
            &vault.store,
            txn,
            &source,
            EdgeKind::BelongsTo,
            false,
            2,
        )?;
        if owned != [room] {
            return Ok(None);
        }
    }
    Ok(turn_root_in_txn(vault, txn, &row)?.map(|root| (room, root)))
}
