//! FIX 7791: whether this vault takes a claim's carried cloud vector.
//!
//! The verdict is judged where the vault is (sync's receive path), before
//! the batch is built, because batch apply is Vault-free by design. It is
//! a pre-filter only: batch re-verifies the vault-local keys (body digest,
//! space, transform, dims) against the landed body inside the put's own
//! transaction, and that re-check is the binding one. Every mismatch here
//! is `Ok(false)` -- the body then takes the ordinary pending-embedding
//! path, never a quarantine.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{IndexMetaKey, RetrievalIndexInventory};
use crate::sync::claim_vectors::{LOCALITY_OWNER_SERVER, LOCALITY_THIRD_PARTY, claim_body_digest};

/// Whether `carried`, a well-formed window carrier for the claim whose
/// landed body is `body`, may stand as that claim's vector here: it embeds
/// this exact body, in this vault's space at this vault's dimensions,
/// under no conflicting transform pin, was filled off-device, and its
/// sender route is one the claim's `worlds` admit. An inheriting world
/// order admits every route; the space leg below still binds it. A
/// transform pin is a match key only where both sides pin one.
pub(crate) fn admit_carried_vector(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    body: &[u8],
    carried: &crate::sync::claim_vectors::CarriedVector,
    worlds: Vec<EntityId>,
) -> Result<bool> {
    if claim_body_digest(body) != carried.body_digest
        || !matches!(
            carried.locality,
            LOCALITY_OWNER_SERVER | LOCALITY_THIRD_PARTY
        )
        || usize::try_from(carried.dims) != Ok(vault.config.dimensions)
        || carried.route.is_empty()
    {
        return Ok(false);
    }
    // The space leg: the sender's space must be this vault's own, and a
    // vault that declares no space takes no carried vector.
    let effective_model = match read_meta_text(vault, txn, IndexMetaKey::ModelId)? {
        Some(stored) => Some(stored),
        None => vault.config.embedding_model.clone(),
    };
    if effective_model.as_deref() != Some(carried.model_id.as_str()) {
        return Ok(false);
    }
    let receiver_pin = match read_meta_text(vault, txn, IndexMetaKey::EmbeddingTransform)? {
        Some(stored) => Some(stored),
        None => vault.config.embedding_transform.clone(),
    };
    if let (Some(sender_pin), Some(receiver_pin)) = (&carried.transform, &receiver_pin)
        && sender_pin != receiver_pin
    {
        return Ok(false);
    }
    Ok(vault
        .world_model_routes_in_txn(txn, worlds)?
        .admits(&carried.route))
}

fn read_meta_text(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: IndexMetaKey,
) -> Result<Option<String>> {
    vault.store.port_index_meta_with_raw(txn, key, |bytes| {
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| Error::CorruptedIndex("embedding space record"))
    })
}
