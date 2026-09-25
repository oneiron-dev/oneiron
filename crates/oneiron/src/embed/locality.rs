//! Provenance of a filled vector, written atomically with the fill.
use super::EmbedderLocality;
use crate::{EntityId, Error, Result, Vault};

fn key(id: &EntityId) -> Vec<u8> {
    let mut key = b"embedding/locality/".to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}

pub(crate) fn clear_embedding_locality_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    store.vault_meta().delete(txn, &key(id))?;
    Ok(())
}

#[cfg(feature = "sync")]
pub(super) fn stamp_embedding_locality_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    locality: EmbedderLocality,
) -> Result<()> {
    let byte = match locality {
        EmbedderLocality::OnDevice => 0,
        EmbedderLocality::OwnerServer => 1,
        EmbedderLocality::ThirdParty => 2,
    };
    vault.store.vault_meta.put(txn, &key(id), &[byte])?;
    Ok(())
}

impl Vault {
    /// Where the current reconciled vector was actually filled. Client-supplied
    /// vectors and pending/stale fills carry no inferred locality.
    pub fn embedding_locality(&self, id: &EntityId) -> Result<Option<EmbedderLocality>> {
        let txn = self.store.env.read_txn()?;
        if self.store.vectors.get(&txn, id.as_bytes())?.is_none()
            || self.store.pending_embedding_token(&txn, id)?.is_some()
        {
            return Ok(None);
        }
        match self.store.vault_meta.get(&txn, &key(id))?.as_deref() {
            None => Ok(None),
            Some([0]) => Ok(Some(EmbedderLocality::OnDevice)),
            Some([1]) => Ok(Some(EmbedderLocality::OwnerServer)),
            Some([2]) => Ok(Some(EmbedderLocality::ThirdParty)),
            Some(_) => Err(Error::CorruptedIndex("embedding locality receipt")),
        }
    }
}
