//! First-provider backfill, distinct from embedding-space migration.
use super::EMBED_PRIORITY_BACKFILL;
#[cfg(feature = "sync")]
use super::pending_embedding_lease_key;
use crate::{EntityId, Error, Result};

/// Marker set atomically with the first model identity, consumed by cold attach.
pub(crate) const COLD_ATTACH_PENDING_KEY: &[u8] = b"cold_attach_pending";

impl crate::Vault {
    /// Requeues pre-embedder claims at priority 3 after the first model is attached.
    /// Open with the provider's pinned model identity first. This is idempotent,
    /// preserves hotter work, and never changes the model epoch or vector graph.
    pub fn cold_attach_embedder(&self) -> Result<usize> {
        if self.config.embedding_model.is_none() {
            return Err(Error::InvalidConfig(
                "cold attach requires an embedding model".into(),
            ));
        }
        self.with_write_txn(|wtxn| {
            if self
                .store
                .hnsw_meta
                .get(wtxn, COLD_ATTACH_PENDING_KEY)?
                .is_none()
            {
                return Ok(0);
            }
            let count = remark_claims_pending_in_txn(self, wtxn, EMBED_PRIORITY_BACKFILL, false)?;
            self.store.hnsw_meta.delete(wtxn, COLD_ATTACH_PENDING_KEY)?;
            Ok(count)
        })
    }
}

/// Re-marks every persisted claim after an embedding-space replacement.
/// Queue replacement deliberately deletes an old row first: queue insertion otherwise
/// preserves a hotter priority that belonged to the old model.
///
/// `priority` is consumed by the sync embed-queue re-push below; the signature
/// stays feature-independent because the base caller (`vault.rs`) supplies it
/// either way.
pub(crate) fn remark_all_claims_pending_in_txn(
    vault: &crate::Vault,
    wtxn: &mut heed::RwTxn<'_>,
    priority: u8,
) -> Result<usize> {
    remark_claims_pending_in_txn(vault, wtxn, priority, true)
}

fn remark_claims_pending_in_txn(
    vault: &crate::Vault,
    wtxn: &mut heed::RwTxn<'_>,
    priority: u8,
    replace_priority: bool,
) -> Result<usize> {
    #[cfg(not(feature = "sync"))]
    let _ = (priority, replace_priority);
    let mut claims = Vec::new();
    for row in vault.store.entities.iter(wtxn)? {
        let (key, raw) = row?;
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type == crate::registry::ENTITY_TYPE_CLAIM {
            let id = EntityId::from_bytes(
                key.as_ref()
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("entity id"))?,
            )
            .map_err(|_| Error::CorruptedIndex("entity id"))?;
            claims.push((id, raw[crate::batch::ENTITY_METADATA_HEADER_LEN..].to_vec()));
        }
    }
    for (id, body) in &claims {
        vault.store.mark_pending_embedding(wtxn, id, body)?;
        #[cfg(feature = "sync")]
        {
            if replace_priority {
                crate::sync::queue::delete_embed_job_in_txn(&vault.store, wtxn, id)?;
            }
            crate::sync::queue::push_embed_job_in_txn(&vault.store, wtxn, id, priority)?;
            vault
                .store
                .sync_state
                .delete(wtxn, pending_embedding_lease_key(id).as_str())?;
        }
    }
    Ok(claims.len())
}
