//! Base-apply vector arms: vectors, media vectors and phonetics.

use super::*;
use zeroize::Zeroizing;

#[allow(clippy::too_many_arguments)]
pub(super) fn apply_vector_arm(
    store: &Store,
    config: &crate::config::VaultConfig,
    wtxn: &mut RwTxn<'_>,
    state: &mut BatchApplyState,
    id: EntityId,
    vector: Vec<f32>,
    pending_embedding_token: Option<Vec<u8>>,
    provenance: Option<crate::embed::EmbeddingProvenance>,
) -> Result<()> {
    let vector = Zeroizing::new(vector);
    let pending_embedding_token = Zeroizing::new(pending_embedding_token);
    let same_batch_token = pending_embedding_token
        .as_deref()
        .or_else(|| state.pending_embedding_tokens_written.get(&id).map(Vec::as_slice));
    let plan = state.nsw_plans.get_mut(&id).and_then(VecDeque::pop_front);
    let applied = apply_vector(
        store,
        config,
        wtxn,
        id,
        &vector,
        provenance.as_ref(),
        same_batch_token,
    )?;
    if applied.wrote_vector {
        // A plan searched the committed graph; after an earlier
        // graph write in this batch it no longer describes it.
        crate::hnsw::hnsw_insert_planned(
            store,
            config,
            wtxn,
            (&id, vector.as_slice()),
            &mut state.pending_hnsw_rebuild,
            plan.as_ref().filter(|_| !state.had_vector_mutation),
        )?;
        state.had_vector_mutation = true;
    }
    if applied.cleared_pending_embedding {
        state.pending_embedding_tokens_written.remove(&id);
        #[cfg(feature = "sync")]
        state.pending_embedding_enqueue_priorities.remove(&id);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn apply_media_vector_arm(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    space: String,
    id: EntityId,
    kind: crate::embed::InputKind,
    text_hash: Option<[u8; crate::embed::TEXT_HASH_LEN]>,
    vector: Vec<f32>,
    provenance: Option<crate::embed::EmbeddingProvenance>,
) -> Result<()> {
    // OF-370: only promotion replays a room's media vector; it lands
    // when base's bindings still take it, else the backfill fills it.
    let vector = Zeroizing::new(vector);
    crate::embed::replay_media_vector_in_txn(
        store,
        wtxn,
        &space,
        &id,
        kind,
        text_hash,
        &vector,
        provenance.as_ref(),
    )?;
    Ok(())
}

pub(super) fn apply_phonetic_arm(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: EntityId,
    codes: Vec<String>,
) -> Result<()> {
    if !crate::vault::entity_revision::defer_phonetic(store, wtxn, &id, &codes)? {
        apply_phonetic(store, wtxn, id, &codes)?;
    }
    Ok(())
}
