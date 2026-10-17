//! First-provider backfill, distinct from embedding-space migration.
use super::EMBED_PRIORITY_BACKFILL;
use crate::ports::{EntityStoreRead, IndexMetaKey, RetrievalIndexInventory};
use crate::{Error, Result};

/// Marker set atomically with the first model identity, consumed by cold attach.
pub(crate) const COLD_ATTACH_PENDING_KEY: &[u8] = b"cold_attach_pending";

impl crate::Vault {
    /// Requeues pre-embedder records at priority 3 after the first model is
    /// attached, or after a restore: each record still owed a vector, never
    /// one that holds its vector and is not pending. Open with the provider's
    /// pinned model identity first. This is idempotent, preserves hotter work,
    /// and never changes the model epoch or vector graph.
    pub fn cold_attach_embedder(&self) -> Result<usize> {
        if self.config.embedding_model.is_none() {
            return Err(Error::InvalidConfig(
                "cold attach requires an embedding model".into(),
            ));
        }
        self.with_write_txn_grouped(|wtxn| {
            if self
                .store
                .port_index_meta_with_raw(wtxn, IndexMetaKey::ColdAttachPending, |_| Ok(()))?
                .is_none()
            {
                return Ok(0);
            }
            let count = remark_pending_in_txn(self, wtxn, EMBED_PRIORITY_BACKFILL, false)?;
            // Featureless callers can mark pending rows but cannot populate
            // the sync worker queue. Preserve the marker for the serving build.
            #[cfg(feature = "sync")]
            self.store.hnsw_meta.delete(wtxn, COLD_ATTACH_PENDING_KEY)?;
            Ok(count)
        })
    }
}

/// Re-marks every embeddable record after an embedding-space replacement.
/// Queue replacement deliberately deletes an old row first: queue insertion otherwise
/// preserves a hotter priority that belonged to the old model.
///
/// `priority` is consumed by the sync embed-queue re-push below; the signature
/// stays feature-independent because the base caller (`vault.rs`) supplies it
/// either way.
pub(crate) fn remark_all_embeddable_pending_in_txn(
    vault: &crate::Vault,
    wtxn: &mut heed::RwTxn<'_>,
    priority: u8,
) -> Result<usize> {
    remark_pending_in_txn(vault, wtxn, priority, true)
}

/// Queues every record the worker embeds ([`super::embeddable_payload_in_txn`]):
/// the same rule the worker leases by, so nothing queued here is work it can
/// only fail on, and nothing it can embed is left out. A TURN is marked at its
/// messages' text, as the turn doors mark it.
///
/// A replacement (`replace_priority`) also drops what a record the rule does
/// not embed still carries — a marker, a job, a lease — so none of it is left
/// for a worker in the new space to trip over. An attach leaves out a record
/// that already holds its vector and is not pending.
fn remark_pending_in_txn(
    vault: &crate::Vault,
    wtxn: &mut heed::RwTxn<'_>,
    priority: u8,
    replace_priority: bool,
) -> Result<usize> {
    #[cfg(not(feature = "sync"))]
    let _ = priority;
    let mut embeddable = Vec::new();
    let mut retired = Vec::new();
    for row in vault.store.port_entity_records(wtxn)? {
        let (id, row) = row?;
        // A stale record's words are withdrawn (an erased source's, an
        // epoch summary's): never queued again until it is written anew.
        if crate::ports::stale_in_txn(&vault.store, wtxn, &id)? {
            retired.push(id);
        } else if row.entity_type == crate::registry::ENTITY_TYPE_TURN {
            match super::turn_text_in_txn(vault, wtxn, &id)? {
                Some(text) => embeddable.push((id, text.into_bytes())),
                None => retired.push(id),
            }
        } else if super::embeddable_payload(row.entity_type, &row.body).is_some() {
            embeddable.push((id, row.body));
        } else if row.entity_type == crate::registry::ENTITY_TYPE_CLAIM
            || row.entity_type == crate::registry::ENTITY_TYPE_SUMMARY
        {
            retired.push(id);
        }
    }
    if !replace_priority {
        // An attach queues only what is still owed a vector. A record that
        // holds one and is not pending was embedded in this space already,
        // e.g. a restored record the worker filled before this attach.
        let mut owed = Vec::with_capacity(embeddable.len());
        for (id, body) in embeddable {
            if vault
                .store
                .port_vector_with_raw(wtxn, &id, |_| Ok(()))?
                .is_none()
                || vault
                    .store
                    .has_current_pending_embedding_in_txn(wtxn, &id)?
            {
                owed.push((id, body));
            }
        }
        embeddable = owed;
    }
    if replace_priority {
        for id in &retired {
            vault.store.clear_pending_embedding(wtxn, id)?;
            #[cfg(feature = "sync")]
            {
                crate::sync::queue::delete_embed_job_in_txn(&vault.store, wtxn, id)?;
                super::clear_pending_embedding_lease_if_any(vault, wtxn, id)?;
            }
        }
    }
    for (id, body) in &embeddable {
        vault.store.mark_pending_embedding(wtxn, id, body)?;
        #[cfg(feature = "sync")]
        {
            if replace_priority {
                crate::sync::queue::delete_embed_job_in_txn(&vault.store, wtxn, id)?;
            }
            crate::sync::queue::push_embed_job_in_txn(&vault.store, wtxn, id, priority)?;
            super::clear_pending_embedding_lease_if_any(vault, wtxn, id)?;
        }
    }
    Ok(embeddable.len())
}
