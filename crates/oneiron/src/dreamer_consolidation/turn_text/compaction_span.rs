//! `conversation_check_evidence` (FIX 4465 D): the Dreamer's read of the
//! span a conversation's self-written summary was cut from. Every declared
//! TURN and its children are read as the Dreamer, in one snapshot opened
//! after the grant clock is persisted, through the same collector a branch
//! reads by: its exact projected text, its children in stored order, in its
//! author's bucket. Each turn's fingerprint is compared with the pin its
//! landing declared. Nothing else is read: no raw body, no summary and no
//! home.

use super::{collect_in, dreamer_read, residency_deferred, snapshot};
use crate::registry::ENTITY_TYPE_TURN;
use crate::{EntityId, Error, Result, Vault};

/// What the Dreamer's read of a declared span found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConversationSpanRead {
    /// Each declared turn's exact projected text, in the declared order.
    Ready(Vec<String>),
    /// A turn reads other words, rows, authors or stream generations than
    /// its pin.
    Drifted,
    /// A turn or a child it depends on is gone, has no text, or is not the
    /// Dreamer's to read.
    Unreadable,
    /// A turn's tagged MESSAGE is away from this replica for now: the read
    /// waits for it.
    Deferred,
}

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
    let ids: Vec<EntityId> = turns.iter().map(|(turn, _)| *turn).collect();
    let rows = read.get_entities_parts_in_txn(&txn, &ids)?;
    let mut texts = Vec::with_capacity(turns.len());
    for ((turn, pin), row) in turns.iter().zip(rows) {
        let Some((kind, _, body)) = row else {
            return Ok(ConversationSpanRead::Unreadable);
        };
        if kind != ENTITY_TYPE_TURN {
            return Ok(ConversationSpanRead::Unreadable);
        }
        let text = match collect_in(&read, &txn, turn, &body, &mut 0) {
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
