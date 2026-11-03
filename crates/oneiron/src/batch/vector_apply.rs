use super::*;

use heed::RwTxn;

use crate::embed::EmbeddingProvenance;
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
    provenance: Option<&EmbeddingProvenance>,
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
    // Reject invalid vectors before staging too; deferral is not a validation bypass.
    validate_vector(store, config, wtxn, vector)?;
    if crate::vault::entity_revision::defer_index_inputs(
        store,
        wtxn,
        &id,
        None,
        Some((vector, provenance)),
        pending_embedding_token,
    )? {
        return Ok(AppliedVector {
            wrote_vector: false,
            cleared_pending_embedding: false,
        });
    }
    stage_vector_row(store, config, wtxn, &id, vector, provenance)?;
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
/// row (ONE-1728 K11), with who computed it. Target-parameterized so a session
/// witness stages the identical bytes into the overlay: the `pe:` bookkeeping
/// around it is base-only (K6) and stays in [`apply_vector`].
pub(super) fn stage_vector_row(
    store: &impl ManifestDbs,
    config: &crate::config::VaultConfig,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    vector: &[f32],
    provenance: Option<&EmbeddingProvenance>,
) -> Result<()> {
    validate_vector(store, config, wtxn, vector)?;

    let bytes = crate::store::encode_vector_row_v1(vector)?;
    store.vectors().put(wtxn, id.as_bytes(), &bytes)?;
    crate::embed::clear_embedding_locality_in_txn(store, wtxn, id)?;
    crate::embed::record_embedding_device_in_txn(store, wtxn, id, provenance)?;
    Ok(())
}

/// The outcome of taking a claim's carried cloud vector (FIX 7791) inside
/// its body put's transaction.
#[cfg(feature = "sync")]
pub(super) enum CarriedTake {
    /// The stored row, its provenance mark and its fill locality are
    /// staged; the caller still owes the decoded vector its HNSW insert.
    Staged(Vec<f32>),
    /// A revision door took the vector in under the put's pending token.
    Deferred,
    /// The carrier does not describe this vault's space, pin or dims; the
    /// body keeps the ordinary pending-embedding path.
    Mismatch,
}

/// The binding take of a carried claim vector (FIX 7791): sync judged the
/// sender route where the vault is; here, inside the put's own
/// transaction, the vault-local keys are re-verified against this
/// transaction's state, and the stored row is staged verbatim -- never
/// re-encoded -- with the sender's provenance mark and the locality its
/// fill declares. No mismatch is a hard error into the put: every one
/// leaves the pending-embedding path exactly as the put minted it.
#[cfg(feature = "sync")]
pub(super) fn take_carried_vector_row(
    store: &Store,
    config: &crate::config::VaultConfig,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    carried: &crate::sync::claim_vectors::CarriedVector,
    token: &[u8],
) -> Result<CarriedTake> {
    use crate::embed::EmbedderLocality;
    use crate::ports::{IndexMetaKey, RetrievalIndexInventory as _};
    use crate::sync::claim_vectors::{LOCALITY_OWNER_SERVER, LOCALITY_THIRD_PARTY};

    let locality = match carried.locality {
        LOCALITY_OWNER_SERVER => EmbedderLocality::OwnerServer,
        LOCALITY_THIRD_PARTY => EmbedderLocality::ThirdParty,
        _ => return Ok(CarriedTake::Mismatch),
    };
    let read_meta = |key: IndexMetaKey| -> Result<Option<String>> {
        store.port_index_meta_with_raw(&*wtxn, key, |bytes| {
            std::str::from_utf8(bytes)
                .map(str::to_owned)
                .map_err(|_| Error::CorruptedIndex("embedding space record"))
        })
    };
    // The space leg: the sender's space must be this vault's own (the
    // stored id wins over the config's, as at every vector write), and a
    // vault that declares no space takes no carried vector.
    let space = match read_meta(IndexMetaKey::ModelId)? {
        Some(stored) => Some(stored),
        None => config.embedding_model.clone(),
    };
    if space.as_deref() != Some(carried.model_id.as_str()) {
        return Ok(CarriedTake::Mismatch);
    }
    // A transform pin is a match key only where both sides pin one.
    let receiver_pin = match read_meta(IndexMetaKey::EmbeddingTransform)? {
        Some(stored) => Some(stored),
        None => config.embedding_transform.clone(),
    };
    if let (Some(sender_pin), Some(receiver_pin)) = (&carried.transform, &receiver_pin)
        && sender_pin != receiver_pin
    {
        return Ok(CarriedTake::Mismatch);
    }
    let Ok(vector) = crate::store::decode_vector_row(&carried.row, config.dimensions) else {
        return Ok(CarriedTake::Mismatch);
    };
    if validate_vector(store, config, wtxn, &vector).is_err() {
        return Ok(CarriedTake::Mismatch);
    }
    if crate::vault::entity_revision::defer_index_inputs(
        store,
        wtxn,
        id,
        None,
        Some((vector.as_slice(), Some(&carried.provenance))),
        Some(token),
    )? {
        return Ok(CarriedTake::Deferred);
    }
    store.vectors().put(wtxn, id.as_bytes(), &carried.row)?;
    crate::embed::record_embedding_device_in_txn(store, wtxn, id, Some(&carried.provenance))?;
    crate::embed::stamp_carried_embedding_locality_in_txn(store, wtxn, id, locality)?;
    Ok(CarriedTake::Staged(vector))
}

fn validate_vector(
    store: &impl ManifestDbs,
    config: &crate::config::VaultConfig,
    wtxn: &mut RwTxn<'_>,
    vector: &[f32],
) -> Result<()> {
    crate::store::ensure_model_id_for_vector_write(store, wtxn, config.embedding_model.as_deref())?;
    // The transform this handle was opened with, against the vault's pin as
    // this transaction sees it: another process may have migrated the vault
    // since. `None` declares nothing and is not checked.
    if let Some(transform) = config.embedding_transform.as_deref() {
        crate::store::admit_embedding_transform_in_txn(store, wtxn, transform)?;
    }
    if vector.len() != config.dimensions {
        return Err(Error::DimensionMismatch {
            expected: config.dimensions,
            got: vector.len(),
        });
    }
    if let Some(error) = Error::invalid_vector_component(vector) {
        return Err(error);
    }

    Ok(())
}
