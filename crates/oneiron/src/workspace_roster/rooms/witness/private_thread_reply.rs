//! An ordinary room's witness refuses a new turn that replies into a private
//! thread (CHAT-ORDINARY-ROOM-REPLY-TO-TRUNK, CHAT-THREAD-REPLY-REFUSAL-SCOPE
//! = B). Entry: `refuse_trunk_reply_into_private_thread_in`.

use super::*;

/// The guard an ordinary room's witness runs on a turn it mints. Such a turn
/// lands on the trunk, so one whose message names a private thread's TURN as
/// its parent or anchor is refused, never shown to the whole room. A reply in
/// such a thread is a DAG reply (`reply_in_thread`). One aimed at a room-wide
/// thread still lands on the trunk, which every reader of that thread reads
/// anyway.
pub(super) fn refuse_trunk_reply_into_private_thread_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    input: &WitnessTurn,
) -> Result<()> {
    if names_private_thread_turn_in(vault, txn, input)? {
        return Err(Error::InvalidConfig(
            "an ordinary room's witness lands a new turn on its trunk: a reply in one of \
             its private threads goes through the conversation DAG's reply door"
                .into(),
        ));
    }
    Ok(())
}

/// Whether a message of `input` names, as its reply parent or its thread
/// anchor (`room_reply_to`, `room_thread_of`), a live TURN of a private
/// thread: its body carries a thread binding, and that thread has an
/// audience now (FIX 5545). A value that names no live TURN, a trunk TURN or
/// a turn of a room-wide thread names none.
fn names_private_thread_turn_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    input: &WitnessTurn,
) -> Result<bool> {
    let named = input
        .messages
        .iter()
        .filter_map(|message| message.metadata.as_ref())
        .flat_map(|metadata| {
            ["room_reply_to", "room_thread_of"]
                .into_iter()
                .filter_map(move |field| metadata.get(field)?.as_str())
        })
        .filter_map(|value| EntityId::from_hex(value).ok());
    for turn in named {
        if let LiveEntityRow::Live {
            entity_type: crate::registry::ENTITY_TYPE_TURN,
            body,
        } = live_entity_row_in_txn(&vault.store, txn, &turn)?
            && let Some(binding) = thread_binding(&body)?
            && thread_audience_now_in(vault, txn, binding.room, turn)?.is_some()
        {
            return Ok(true);
        }
    }
    Ok(false)
}
