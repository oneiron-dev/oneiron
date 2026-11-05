//! A conversation's turn order within one SESSION (FIX 5029): the numbers a
//! chat window gives its turns, and the order its epochs count over.
//!
//! The SESSION keeps every turn witnessed into it, in its own order. A
//! conversation's turns are the ones of that order that belong to it; on a
//! DAG conversation, only the turns on the retained chain of the branch
//! read. Two conversations interleaved in one sitting each keep their own
//! contiguous order, so neither breaks the other's window or boundary. A
//! turn's number is its place in that whole order, never an ordinal reset
//! for one window. The mint reads the order again in its own transaction, so
//! a window lands only at the numbers it was sealed with.

use std::collections::BTreeSet;

use crate::EntityId;
use crate::compaction::driver::ConversationBinding;
use crate::compaction::{CompactionWindowMessage, SESSION_TURNS};
use crate::error::{Error, Result};
use crate::store::Store;

/// The turns of `binding`'s conversation witnessed into `session`, in that
/// SESSION's own order; on a DAG read, only the turns on the retained chain
/// of the branch read. A member that names another conversation, or none,
/// is skipped, even when that conversation was deleted or purged. `None`
/// when a branch's chain does not read here.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn conversation_turn_order_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    session: EntityId,
    binding: ConversationBinding,
) -> Result<Option<Vec<EntityId>>> {
    let chain: Option<BTreeSet<EntityId>> = match binding.branch {
        Some(head) => {
            match crate::conversation_dag::retained_chain(store, txn, &binding.conversation, head) {
                Ok(chain) => Some(chain.into_iter().collect()),
                Err(_) => return Ok(None),
            }
        }
        None => None,
    };
    let mut order = Vec::new();
    for (_, turn) in SESSION_TURNS.scan_keys(store, txn, session.as_bytes())? {
        match &chain {
            // Every record of the chain is its conversation's.
            Some(chain) => {
                if chain.contains(&turn) {
                    order.push(turn);
                }
            }
            // A turn is read by the conversation it names, live or not. A
            // turn that names another conversation, or none (its conversation
            // purged with its edge and no pin left), is not this one's and
            // never makes this order unreadable. A turn of this live
            // conversation always names it.
            None => {
                if crate::conversation_dag::named_room(store, txn, &turn)?
                    .is_ok_and(|room| room == binding.conversation)
                {
                    order.push(turn);
                }
            }
        }
    }
    Ok(Some(order))
}

/// In the mint's own transaction: each turn of a chat `window` stands at its
/// number in `binding`'s conversation order within `session`. A window whose
/// turns read another order now is refused, as a window off its boundary is.
///
/// # Errors
///
/// [`Error::InvariantViolation`] for an order that does not read or a turn
/// off its number, and storage errors.
pub(crate) fn validate_conversation_window_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    session: EntityId,
    binding: ConversationBinding,
    window: &[CompactionWindowMessage],
) -> Result<()> {
    let Some(order) = conversation_turn_order_in(store, txn, session, binding)? else {
        return Err(Error::InvariantViolation(
            "a conversation's turn order does not read in its session",
        ));
    };
    for message in window {
        let placed = usize::try_from(message.turn)
            .ok()
            .and_then(|at| order.get(at));
        if placed != Some(&message.turn_id) {
            return Err(Error::InvariantViolation(
                "a chat window's turn does not stand at its number in its conversation",
            ));
        }
    }
    Ok(())
}
