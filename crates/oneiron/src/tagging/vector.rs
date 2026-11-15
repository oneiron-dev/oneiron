//! The vector rung (ARCH-0024 signal 4): when the key, sound or role rungs
//! leave a person mention two or more candidates, the candidate whose stored
//! vector lies nearest the turn's stored vector goes first, when its cosine
//! reaches the vault's evidence floor for a person and leads the next one's
//! by at least [`LINKER_VECTOR_MARGIN`].
//!
//! The rung only reorders (Engine ruling 13 Nov 14:20). The mention keeps
//! every candidate, so it stays uncertain: the nightly re-check still asks
//! which one it is (IDENTITY_SETTLE), and the effect doors' guard still
//! refuses to act on it. A single candidate would read as settled, so the
//! rung never narrows the list. It reads vectors already stored and embeds
//! nothing. A vault with no embedding model, a turn not yet embedded, or a
//! candidate with no vector (a provisional entity has none) keeps the list
//! in the key's order. The tagger may save a turn before the embed worker
//! reaches it, so the re-check ranks the candidates again when it builds
//! the ask. No step writes a person's vector yet, so on a vault today the
//! rung keeps every list as it is (FIX [LINKER-PERSON-VECTOR-PRODUCER]).

use crate::error::Result;
use crate::learning_setting::{SettingSpec, setting_value_in_txn};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::{EntityId, Vault};

/// How far the nearest candidate's cosine must lead the next one's before
/// the vector rung puts it first: an owner-steered catalog row over a cosine
/// difference, 0 to 1.
pub const LINKER_VECTOR_MARGIN: SettingSpec = SettingSpec {
    key: "linker.vector.margin",
    min: 0.0,
    max: 1.0,
    seed: 0.05,
};

/// The stored vector of `turn`, the rung's query: `None` when the vault has
/// no embedding model or the turn has no vector yet.
pub(super) fn turn_vector_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<Option<Vec<f32>>> {
    if vault.config.embedding_model.is_none() {
        return Ok(None);
    }
    vault.vector_in_txn(&vault.store, txn, turn)
}

/// The person candidates `entities` with the one nearest `query` moved
/// first and the rest in their order, when the rung decides. `None` when
/// it does not: fewer than two candidates, one with no vector, a winner
/// under the floor, or a lead under the margin.
pub(super) fn ranked_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query: &[f32],
    entities: &[EntityId],
) -> Result<Option<Vec<EntityId>>> {
    if entities.len() < 2 {
        return Ok(None);
    }
    let mut scores = Vec::with_capacity(entities.len());
    for (index, id) in entities.iter().enumerate() {
        let Some(vector) = vault.vector_in_txn(&vault.store, txn, id)? else {
            return Ok(None);
        };
        scores.push((crate::distance::cosine_similarity(query, &vector), index));
    }
    // The highest cosine first; a tie keeps the key's order.
    scores.sort_by(|left, right| right.0.total_cmp(&left.0).then(left.1.cmp(&right.1)));
    let (best, winner) = scores[0];
    let (next, _) = scores[1];
    let floor = vault
        .no_match_floors()
        .resolve(vault.evidence_space(), Some(ENTITY_TYPE_PERSON))
        .floor;
    let margin = setting_value_in_txn(&vault.store, txn, &LINKER_VECTOR_MARGIN)?;
    // A NaN cosine fails both comparisons, so the rung keeps the order.
    let decides = best >= floor && f64::from(best - next) >= margin;
    if !decides {
        return Ok(None);
    }
    let mut ranked = Vec::with_capacity(entities.len());
    ranked.push(entities[winner]);
    ranked.extend(
        entities
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != winner)
            .map(|(_, id)| *id),
    );
    Ok(Some(ranked))
}

/// The person candidates of a mention in `turn`, ranked by the vector rung
/// as a save ranks them, for a re-check that runs outside a save: `None`
/// when the rung keeps their order.
pub(crate) fn ranked_for_turn_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    entities: &[EntityId],
) -> Result<Option<Vec<EntityId>>> {
    if entities.len() < 2 {
        return Ok(None);
    }
    match turn_vector_in_txn(vault, txn, turn)? {
        Some(query) => ranked_in_txn(vault, txn, &query, entities),
        None => Ok(None),
    }
}
