//! First-provider backfill, distinct from embedding-space migration.
use super::EMBED_PRIORITY_BACKFILL;
#[cfg(feature = "sync")]
use super::pending_embedding_lease_key;
use crate::ports::EntityStoreRead;
use crate::{Error, Result};

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
            // Featureless callers can mark pending rows but cannot populate
            // the sync worker queue. Preserve the marker for the serving build.
            #[cfg(feature = "sync")]
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
    for row in vault.store.port_entity_records(wtxn)? {
        let (id, row) = row?;
        if row.entity_type == crate::registry::ENTITY_TYPE_CLAIM {
            claims.push((id, row.body));
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

#[cfg(test)]
mod tests {
    use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
    use crate::{ClaimCandidate, EdgeActorClass, WriteActor, WriteEnvelope, WriteProvenance};
    use crate::{EntityId, TimeRange, Vault, VaultConfig};

    #[test]
    fn cold_attach_consumes_marker_only_when_queue_work_is_available() -> crate::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.dimensions = 4;
        config.map_size = 64 * 1024 * 1024;
        config.embedding_model = None;
        let vault = Vault::open(dir.path(), config.clone())?;
        // First open seeds the bootstrap skills, whose claims predate the embedder too.
        let seeded_claims = vault
            .entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?
            .len();
        let subject = EntityId::now();
        vault.put_entity(
            &subject,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&serde_json::json!({"name":"fixture"})).unwrap(),
        )?;
        let id = EntityId::now();
        let candidate = ClaimCandidate::new(
            "test.fact",
            ClaimSubject::Entity(subject),
            "a fact".into(),
            1.0,
        );
        let envelope = WriteEnvelope::new(
            WriteActor::new(subject, EdgeActorClass::Human),
            ClaimSource::UserStated,
            WriteProvenance::new(rmpv::Value::Map(vec![(
                "fixture".into(),
                "cold-attach".into(),
            )]))?,
            ClaimApprovalStatus::Auto,
        );
        vault
            .batch()
            .claim_candidate(&id, candidate, &envelope, TimeRange { start: 1, end: 1 }, 1)
            .commit()?;
        drop(vault);
        config.embedding_model = Some("fixture/embedder@v1".into());
        let vault = Vault::open(dir.path(), config.clone())?;
        assert_eq!(vault.cold_attach_embedder()?, seeded_claims + 1);
        drop(vault);
        let vault = Vault::open(dir.path(), config)?;
        // A serving build queued the work. A featureless build must leave the
        // one-time pass available so a later serving build can populate it.
        assert_eq!(
            vault.cold_attach_embedder()?,
            if cfg!(feature = "sync") {
                0
            } else {
                seeded_claims + 1
            }
        );
        Ok(())
    }
}
