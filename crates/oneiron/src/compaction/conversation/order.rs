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
//!
//! A connector thread's own SESSION (OWN-VOICE-EPOCHS = C) is the one
//! exception to id order: its turns' ids derive from their exchange, not from
//! time, so it numbers them as its transcript orders them, by when they
//! occurred and then by id.

use std::collections::BTreeSet;

use crate::EntityId;
use crate::batch::EntityMetadataHeader;
use crate::compaction::driver::ConversationBinding;
use crate::compaction::{CompactionWindowMessage, SESSION_TURNS};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry::ENTITY_TYPE_TURN;
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
    if binding.branch.is_none()
        && session == crate::session_lifecycle::thread_session_id(binding.conversation)?
    {
        let mut keyed = Vec::with_capacity(order.len());
        for turn in order {
            let Some(key) = thread_turn_key_in(store, txn, &turn)? else {
                return Ok(None);
            };
            keyed.push(key);
        }
        keyed.sort_unstable();
        order = keyed.into_iter().map(|(_, turn)| turn).collect();
    }
    Ok(Some(order))
}

/// A turn's place in a connector thread's own SESSION: when it occurred,
/// then its id, as the thread's transcript orders it. `None` for a turn
/// whose row does not read.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn thread_turn_key_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<Option<((u64, [u8; 16]), EntityId)>> {
    let raw = store.port_entity_raw(txn, turn)?;
    Ok(raw
        .as_deref()
        .and_then(EntityMetadataHeader::parse)
        .map(|header| ((header.occurred_start, *turn.as_bytes()), *turn)))
}

/// Every TURN `conversation` holds, by its `ChildOf` edges, in no order.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn conversation_turns_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    conversation: &EntityId,
) -> Result<Vec<EntityId>> {
    let mut turns = Vec::new();
    for edge in store.port_edges(
        txn,
        conversation,
        EdgeDirection::In,
        Some(EdgeKind::ChildOf),
        None,
    )? {
        let turn = edge?.target;
        let raw = store.port_entity_raw(txn, &turn)?;
        if raw
            .as_deref()
            .and_then(EntityMetadataHeader::parse)
            .is_some_and(|header| header.entity_type == ENTITY_TYPE_TURN)
        {
            turns.push(turn);
        }
    }
    Ok(turns)
}

/// The last turn `conversation`'s landed epochs within `session` cover, by
/// its number there: where the conversation's lineage in that SESSION ends.
/// `None` when no epoch of it landed there.
///
/// # Errors
///
/// Storage errors, and a corrupted receipt index.
pub(crate) fn conversation_covered_end_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    session: EntityId,
    conversation: EntityId,
) -> Result<Option<EntityId>> {
    let mut end: Option<(u64, EntityId)> = None;
    for receipt in super::storage::conversation_receipts_in(store, txn, conversation)? {
        if receipt.session != session {
            continue;
        }
        let Some(last) = receipt
            .evidence()
            .and_then(|evidence| evidence.turns.last())
        else {
            continue;
        };
        if end.is_none_or(|(at, _)| receipt.turn_end > at) {
            end = Some((receipt.turn_end, last.turn));
        }
    }
    Ok(end.map(|(_, turn)| turn))
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

/// The connector thread `conversation`'s turns in its own SESSION, by their
/// numbers there; `None` when the order does not read. For the integration
/// tests' door (`test_doors::connector_thread_session`).
#[cfg(oneiron_test_support)]
pub(crate) fn thread_turn_order_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    conversation: EntityId,
) -> Result<Option<Vec<EntityId>>> {
    let session = crate::session_lifecycle::thread_session_id(conversation)?;
    conversation_turn_order_in(
        store,
        txn,
        session,
        ConversationBinding {
            conversation,
            branch: None,
        },
    )
}
