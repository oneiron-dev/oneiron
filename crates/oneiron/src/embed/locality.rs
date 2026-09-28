//! Provenance of a filled vector, written atomically with the fill.
use super::EmbedderLocality;
use crate::side_table::{self, Raw, RawValue, SideTable};
use crate::{EntityId, Error, Result, Vault};

/// Where the current reconciled embedding vector was filled. Key: id16.
const EMBEDDING_LOCALITY: SideTable<EntityId, EmbedderLocality, Raw> =
    SideTable::new(&side_table::EMBEDDING_LOCALITY);

impl RawValue for EmbedderLocality {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, side_table::CodecError> {
        Ok(vec![match self {
            EmbedderLocality::OnDevice => 0,
            EmbedderLocality::OwnerServer => 1,
            EmbedderLocality::ThirdParty => 2,
        }])
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, side_table::CodecError> {
        match bytes {
            [0] => Ok(EmbedderLocality::OnDevice),
            [1] => Ok(EmbedderLocality::OwnerServer),
            [2] => Ok(EmbedderLocality::ThirdParty),
            _ => Err(Error::CorruptedIndex("embedding locality receipt").into()),
        }
    }
}

pub(crate) fn clear_embedding_locality_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    EMBEDDING_LOCALITY.delete(store, txn, id)?;
    Ok(())
}

#[cfg(feature = "sync")]
pub(super) fn stamp_embedding_locality_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    locality: EmbedderLocality,
) -> Result<()> {
    EMBEDDING_LOCALITY.put(&vault.store, txn, id, &locality)
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
        EMBEDDING_LOCALITY.get(&self.store, &txn, id)
    }
}
