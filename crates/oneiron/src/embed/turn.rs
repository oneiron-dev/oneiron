//! The turn doors' half of embedding: a TURN whose text moved owes a vector
//! of its new text, marked with the write that moved it.
//!
//! A TURN's text lives in its MESSAGE children, so no write to the TURN row
//! itself tells the embedder anything. The doors that change a turn's text
//! mark it here, beside the tagger's mark for the same change: a witness that
//! mints or extends a turn, an off-record promotion, and a publication that
//! moves a MESSAGE's or TURN's text (an entity document, an idle revision).
//! An erased message marks its turns too, so they stop matching its words.
//! A streamed message reaches none of them until its stream ends, so a turn
//! embeds only finished text.

use crate::Vault;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{EdgeDirection, EntityStoreRead};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};

/// Marks `turn` for embedding at its current text, committed with the write
/// that changed it.
///
/// The marker commits to the turn's text and the embedding epoch, so a fill
/// for older text no longer matches it and is dropped as stale; the worker
/// then embeds the text marked here. A turn left with no text drops its
/// vector, which would otherwise keep matching words the turn no longer has.
/// A vault with no embedder marks nothing: attaching one queues every turn.
pub(crate) fn mark_turn_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    turn: EntityId,
) -> Result<()> {
    if vault.config.embedding_model.is_none() {
        return Ok(());
    }
    match super::turn_text_in_txn(vault, wtxn, &turn)? {
        Some(text) => {
            vault
                .store
                .mark_pending_embedding(wtxn, &turn, text.as_bytes())?;
            #[cfg(feature = "sync")]
            crate::sync::queue::push_embed_job_in_txn(
                &vault.store,
                wtxn,
                &turn,
                super::EMBED_PRIORITY_DEVICE,
            )?;
        }
        None => crate::vault::entity_revision::drop_vector_state(vault, wtxn, &turn)?,
    }
    Ok(())
}

/// The publication half: a write that moved the text of a TURN, or of a
/// MESSAGE inside one, marks that turn again in the same transaction.
pub(crate) fn mark_on_publication_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
    entity_type: u8,
) -> Result<()> {
    if vault.config.embedding_model.is_none() {
        return Ok(());
    }
    match entity_type {
        ENTITY_TYPE_TURN => mark_turn_in_txn(vault, wtxn, *entity),
        ENTITY_TYPE_MESSAGE => mark_turns_in_txn(vault, wtxn, turns_of(vault, wtxn, entity)?),
        _ => Ok(()),
    }
}

/// The turns `entity` is part of when it is a MESSAGE, read before an erase
/// takes the message and its edges; [`mark_turns_in_txn`] marks them after.
pub(crate) fn erased_message_turns_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
) -> Result<Vec<EntityId>> {
    let is_message = vault
        .store
        .port_entity_record(txn, entity)?
        .is_some_and(|row| row.entity_type == ENTITY_TYPE_MESSAGE);
    if vault.config.embedding_model.is_none() || !is_message {
        return Ok(Vec::new());
    }
    turns_of(vault, txn, entity)
}

/// Marks each of `turns` at its current text ([`mark_turn_in_txn`]).
pub(crate) fn mark_turns_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    turns: Vec<EntityId>,
) -> Result<()> {
    for turn in turns {
        mark_turn_in_txn(vault, wtxn, turn)?;
    }
    Ok(())
}

fn turns_of(vault: &Vault, txn: &heed::RoTxn<'_>, message: &EntityId) -> Result<Vec<EntityId>> {
    vault.filtered_edge_peers(
        txn,
        EdgeDirection::Out,
        message,
        EdgeKind::PartOf,
        Some(ENTITY_TYPE_TURN),
        "embedding frontier turns",
    )
}
