use super::*;

use heed::RwTxn;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::{ManifestDbs, Store};

pub(super) struct AppliedVector {
    pub(super) wrote_vector: bool,
    pub(super) cleared_pending_embedding: bool,
}

pub(super) fn apply_vector(
    store: &Store,
    config: &crate::config::VaultConfig,
    wtxn: &mut RwTxn<'_>,
    id: EntityId,
    vector: &[f32],
    pending_embedding_token: Option<&[u8]>,
) -> Result<AppliedVector> {
    if stored_entity_is_lexical_query_hint_claim(store, wtxn, &id)? {
        return Err(Error::InvalidClaimBody(
            "lexical query hint ids are not vector-indexable",
        ));
    }
    if let Some(token) = pending_embedding_token
        && !store.pending_embedding_matches_in_txn(wtxn, &id, token)?
    {
        return Ok(AppliedVector {
            wrote_vector: false,
            cleared_pending_embedding: false,
        });
    }
    stage_vector_row(store, config, wtxn, &id, vector)?;
    let cleared_pending_embedding = match pending_embedding_token {
        Some(token) => store.clear_pending_embedding_if_token_matches(wtxn, &id, token)?,
        None => false,
    };
    Ok(AppliedVector {
        wrote_vector: true,
        cleared_pending_embedding,
    })
}

/// Validates one vector against the vault's embedding contract and stages its
/// row (ONE-1728 K11). Target-parameterized so a session witness stages the
/// identical bytes into the overlay: the `pe:` bookkeeping around it is
/// base-only (K6) and stays in [`apply_vector`].
pub(super) fn stage_vector_row(
    store: &impl ManifestDbs,
    config: &crate::config::VaultConfig,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    vector: &[f32],
) -> Result<()> {
    crate::store::ensure_model_id_for_vector_write(store, wtxn, config.embedding_model.as_deref())?;
    if vector.len() != config.dimensions {
        return Err(Error::DimensionMismatch {
            expected: config.dimensions,
            got: vector.len(),
        });
    }
    if let Some(error) = Error::invalid_vector_component(vector) {
        return Err(error);
    }

    let bytes = crate::store::encode_vector_row_v1(vector)?;
    store.vectors().put(wtxn, id.as_bytes(), &bytes)?;
    Ok(())
}
