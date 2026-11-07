//! `conversation_check_evidence` (FIX 4465 D): the Dreamer's read of the
//! span a conversation's self-written summary was cut from. Every declared
//! TURN and its children are read as the Dreamer, in one snapshot opened
//! after the grant clock is persisted, through the same collector a branch
//! reads by: its exact projected text, its children in stored order, in its
//! author's bucket. Each turn's fingerprint is compared with the pin its
//! landing declared. Nothing else is read: no raw body, no summary and no
//! home. A chat log reads the same span as its own reader, in its own
//! snapshot ([`conversation_span_text_in`]), before a summary stands in for
//! the turns it covers, and pins each raw turn it holds the same way
//! ([`scoped_turn_text_in`], FIX 5031).

use super::{TurnText, collect_in, dreamer_read, residency_deferred, snapshot};
use crate::claim::ScopedRead;
use crate::registry::ENTITY_TYPE_TURN;
use crate::{EntityId, Error, Result, Vault};

pub(crate) use crate::store::conversation_span::ConversationSpanRead;

/// Reads `turns`, each with the fingerprint its landing pinned, as the
/// Dreamer in one snapshot.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn conversation_span_text(
    vault: &Vault,
    turns: &[(EntityId, [u8; 32])],
) -> Result<ConversationSpanRead> {
    let read = dreamer_read(vault)?;
    let txn = snapshot(vault)?;
    conversation_span_text_in(&read, &txn, turns)
}

/// Reads `turns`, each with the fingerprint its landing pinned, as `read`
/// in the caller's `txn`: the TURN rows through `read`, their MESSAGE rows
/// as the same actor under the relationship gate.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn conversation_span_text_in(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    turns: &[(EntityId, [u8; 32])],
) -> Result<ConversationSpanRead> {
    let ids: Vec<EntityId> = turns.iter().map(|(turn, _)| *turn).collect();
    let rows = read.get_entities_parts_in_txn(txn, &ids)?;
    let mut texts = Vec::with_capacity(turns.len());
    for ((turn, pin), row) in turns.iter().zip(rows) {
        let Some((kind, _, body)) = row else {
            return Ok(ConversationSpanRead::Unreadable);
        };
        if kind != ENTITY_TYPE_TURN {
            return Ok(ConversationSpanRead::Unreadable);
        }
        let text = match collect_in(read, txn, turn, &body, &mut 0) {
            Ok(text) => text,
            Err(Error::InvalidClaimBody(reason)) if residency_deferred(reason) => {
                return Ok(ConversationSpanRead::Deferred);
            }
            Err(Error::InvalidClaimBody(_)) => return Ok(ConversationSpanRead::Unreadable),
            Err(error) => return Err(error),
        };
        if text.summary_fingerprint()? != *pin {
            return Ok(ConversationSpanRead::Drifted);
        }
        let Some(words) = text.text() else {
            return Ok(ConversationSpanRead::Unreadable);
        };
        texts.push(words.to_owned());
    }
    Ok(ConversationSpanRead::Ready(texts))
}

/// One stored TURN's projected text read as `read` in the caller's `txn`
/// (FIX 5031): the TURN row through `read`, its MESSAGE rows as the same
/// actor under the relationship gate. A chat log pins its raw turns this
/// way, so a room's held ceiling, a proof and a locality reach those pins
/// as they reach the log's evidence. `None` when `read` does not read the
/// row or it is no TURN.
///
/// # Errors
///
/// Storage errors, and a turn whose text does not project: a message the
/// reader may not read refuses the turn.
pub(crate) fn scoped_turn_text_in(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<Option<TurnText>> {
    let Some((kind, _, body)) = read
        .get_entities_parts_in_txn(txn, std::slice::from_ref(turn))?
        .pop()
        .flatten()
    else {
        return Ok(None);
    };
    if kind != ENTITY_TYPE_TURN {
        return Ok(None);
    }
    collect_in(read, txn, turn, &body, &mut 0).map(Some)
}
