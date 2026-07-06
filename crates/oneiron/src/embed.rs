use crate::error::{Error, Result};
use crate::types::EntityId;

/// Highest priority: a pending claim surfaced in user-visible retrieval.
pub const EMBED_PRIORITY_SURFACED_HOT: u8 = 0;
/// Server-originated sync materialization.
pub const EMBED_PRIORITY_SERVER: u8 = 1;
/// Local device write.
pub const EMBED_PRIORITY_DEVICE: u8 = 2;
/// Cold attach-embedder or model backfill.
pub const EMBED_PRIORITY_BACKFILL: u8 = 3;

/// Default pending-embedding lease duration.
#[cfg(feature = "sync")]
pub const DEFAULT_PENDING_EMBEDDING_LEASE_MS: u64 = 30_000;

/// Where an embedder runs relative to the vault owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EmbedderLocality {
    /// Runs on the same device as the vault.
    OnDevice,
    /// Runs on infrastructure controlled by the vault owner.
    OwnerServer,
    /// Runs on a third-party service.
    ThirdParty,
}

/// One pending claim body supplied to a host-injected embedder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEmbeddingInput {
    pub entity_id: EntityId,
    pub claim_body: Vec<u8>,
    pub pending_embedding_token: Vec<u8>,
}

/// Host-injected retrieval embedder.
///
/// The engine owns queueing, leases, and vector storage. Implementations own
/// model execution and any locality-specific policy before returning vectors.
pub trait Embedder: Send + Sync {
    fn model_id(&self) -> &str;
    fn dimensions(&self) -> usize;
    fn locality(&self) -> EmbedderLocality;
    fn embed(&self, inputs: &[PendingEmbeddingInput]) -> Result<Vec<Vec<f32>>>;
}

#[cfg(feature = "sync")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingEmbeddingLease {
    expires_at_ms: u64,
    token: Vec<u8>,
}

#[cfg(feature = "sync")]
#[derive(Debug, Clone)]
struct LeasedPendingEmbedding {
    input: PendingEmbeddingInput,
    lease_value: Vec<u8>,
}

#[cfg(feature = "sync")]
#[derive(Debug, Default, Clone)]
struct LeaseBatch {
    work: Vec<LeasedPendingEmbedding>,
    active_leases: usize,
    stale_jobs: usize,
}

/// Summary from one reconciler pass.
#[cfg(feature = "sync")]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PendingEmbeddingReconcileReport {
    pub leased: usize,
    pub active_leases: usize,
    pub stale_jobs: usize,
    pub embedded: usize,
    pub filled: usize,
    pub stale_fills: usize,
}

/// Per-vault pending-embedding reconciler.
#[cfg(feature = "sync")]
pub struct PendingEmbeddingReconciler {
    vault: std::sync::Arc<crate::Vault>,
    embedder: std::sync::Arc<dyn Embedder>,
    batch_size: usize,
    lease_duration_ms: u64,
}

#[cfg(feature = "sync")]
impl PendingEmbeddingReconciler {
    #[must_use]
    pub fn new(
        vault: std::sync::Arc<crate::Vault>,
        embedder: std::sync::Arc<dyn Embedder>,
    ) -> Self {
        Self {
            vault,
            embedder,
            batch_size: 32,
            lease_duration_ms: DEFAULT_PENDING_EMBEDDING_LEASE_MS,
        }
    }

    #[must_use]
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size.max(1);
        self
    }

    #[must_use]
    pub fn with_lease_duration_ms(mut self, lease_duration_ms: u64) -> Self {
        self.lease_duration_ms = lease_duration_ms.max(1);
        self
    }

    pub fn reconcile_once(&self) -> Result<PendingEmbeddingReconcileReport> {
        self.reconcile_once_at(unix_millis_now())
    }

    fn reconcile_once_at(&self, now_ms: u64) -> Result<PendingEmbeddingReconcileReport> {
        self.validate_embedder_for_vault()?;
        let batch = self.lease_due_jobs(now_ms)?;
        let mut report = PendingEmbeddingReconcileReport {
            leased: batch.work.len(),
            active_leases: batch.active_leases,
            stale_jobs: batch.stale_jobs,
            ..PendingEmbeddingReconcileReport::default()
        };
        if batch.work.is_empty() {
            return Ok(report);
        }

        let inputs: Vec<PendingEmbeddingInput> =
            batch.work.iter().map(|work| work.input.clone()).collect();
        let vectors = self.embedder.embed(&inputs)?;
        if vectors.len() != batch.work.len() {
            return Err(Error::InvariantViolation(
                "embedder returned mismatched vector count",
            ));
        }
        report.embedded = vectors.len();

        for (work, vector) in batch.work.iter().zip(vectors.iter()) {
            if self.complete_leased_work(work, vector)? {
                report.filled += 1;
            } else {
                report.stale_fills += 1;
            }
        }

        Ok(report)
    }

    fn validate_embedder_for_vault(&self) -> Result<()> {
        if self.embedder.dimensions() != self.vault.config.dimensions {
            return Err(Error::DimensionMismatch {
                expected: self.vault.config.dimensions,
                got: self.embedder.dimensions(),
            });
        }
        let Some(config_model) = self.vault.config.embedding_model.as_deref() else {
            return Err(Error::InvalidConfig(
                "embedding model is required before embedding reconciliation".to_owned(),
            ));
        };
        if config_model != self.embedder.model_id() {
            return Err(Error::EmbeddingModelChanged {
                stored: config_model.to_owned(),
                requested: self.embedder.model_id().to_owned(),
            });
        }
        Ok(())
    }

    fn lease_due_jobs(&self, now_ms: u64) -> Result<LeaseBatch> {
        let queue = crate::sync::SyncQueue::new(std::sync::Arc::clone(&self.vault))?;
        let jobs = queue.drain_embed_jobs()?;
        let mut batch = LeaseBatch::default();
        if jobs.is_empty() {
            return Ok(batch);
        }

        self.vault.with_write_txn(|wtxn| {
            for job in jobs {
                if batch.work.len() >= self.batch_size {
                    break;
                }
                let Some(input) = pending_input_in_txn(&self.vault, wtxn, &job.entity_id)? else {
                    crate::sync::queue::delete_embed_job_in_txn(
                        &self.vault.store,
                        wtxn,
                        &job.entity_id,
                    )?;
                    clear_pending_embedding_lease_if_any(&self.vault, wtxn, &job.entity_id)?;
                    batch.stale_jobs += 1;
                    continue;
                };

                let key = pending_embedding_lease_key(&job.entity_id);
                if let Some(existing) = self.vault.store.sync_state.get(wtxn, key.as_str())?
                    && let Some(lease) = decode_pending_embedding_lease(existing)
                    && lease.token == input.pending_embedding_token
                    && lease.expires_at_ms > now_ms
                {
                    batch.active_leases += 1;
                    continue;
                }

                let expires_at_ms = now_ms.saturating_add(self.lease_duration_ms);
                let lease_value =
                    encode_pending_embedding_lease(expires_at_ms, &input.pending_embedding_token);
                self.vault
                    .store
                    .sync_state
                    .put(wtxn, key.as_str(), lease_value.as_slice())?;
                batch
                    .work
                    .push(LeasedPendingEmbedding { input, lease_value });
            }
            Ok(())
        })?;

        Ok(batch)
    }

    fn complete_leased_work(&self, work: &LeasedPendingEmbedding, vector: &[f32]) -> Result<bool> {
        let mut filled_current = false;
        self.vault.with_write_txn(|wtxn| {
            let current_before = self
                .vault
                .store
                .pending_embedding_token_in_txn(wtxn, &work.input.entity_id)?;
            crate::batch::apply_ops(
                &self.vault.store,
                &self.vault.config,
                &self.vault.analyzer,
                wtxn,
                vec![crate::batch::BatchOp::Vector {
                    id: work.input.entity_id,
                    vector: vector.to_vec(),
                    pending_embedding_token: Some(work.input.pending_embedding_token.clone()),
                }],
                self.vault
                    .text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
                false,
                true,
            )?;
            let current_after = self
                .vault
                .store
                .pending_embedding_token_in_txn(wtxn, &work.input.entity_id)?;

            clear_pending_embedding_lease_if_matches(
                &self.vault,
                wtxn,
                &work.input.entity_id,
                &work.lease_value,
            )?;

            let token_was_current =
                current_before.as_deref() == Some(work.input.pending_embedding_token.as_slice());
            if current_after.is_none() {
                crate::sync::queue::delete_embed_job_in_txn(
                    &self.vault.store,
                    wtxn,
                    &work.input.entity_id,
                )?;
            }
            filled_current = token_was_current && current_after.is_none();
            Ok(())
        })?;
        Ok(filled_current)
    }
}

#[cfg(feature = "sync")]
pub(crate) fn enqueue_pending_embedding_jobs(
    vault: &crate::Vault,
    ids: &[EntityId],
    priority: u8,
) -> Result<()> {
    if ids.is_empty() {
        return Ok(());
    }
    vault.with_write_txn(|wtxn| {
        for id in ids {
            if vault
                .store
                .pending_embedding_token_in_txn(wtxn, id)?
                .is_some()
            {
                crate::sync::queue::push_embed_job_in_txn(&vault.store, wtxn, id, priority)?;
            }
        }
        Ok(())
    })
}

#[cfg(feature = "sync")]
fn pending_input_in_txn(
    vault: &crate::Vault,
    wtxn: &heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<Option<PendingEmbeddingInput>> {
    let Some(token) = vault.store.pending_embedding_token_in_txn(wtxn, id)? else {
        return Ok(None);
    };
    let Some(raw) = vault.store.entities.get(wtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = crate::batch::EntityMetadataHeader::parse(raw)
        .ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != crate::types::ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    Ok(Some(PendingEmbeddingInput {
        entity_id: *id,
        claim_body: raw[crate::batch::ENTITY_METADATA_HEADER_LEN..].to_vec(),
        pending_embedding_token: token,
    }))
}

#[cfg(feature = "sync")]
fn pending_embedding_lease_key(id: &EntityId) -> String {
    format!("pelease:{}", id.to_hex())
}

#[cfg(feature = "sync")]
fn encode_pending_embedding_lease(expires_at_ms: u64, token: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(1 + 8 + token.len());
    value.push(1);
    value.extend_from_slice(&expires_at_ms.to_be_bytes());
    value.extend_from_slice(token);
    value
}

#[cfg(feature = "sync")]
fn decode_pending_embedding_lease(value: &[u8]) -> Option<PendingEmbeddingLease> {
    if value.len() < 9 || value[0] != 1 {
        return None;
    }
    let expires_at_ms = u64::from_be_bytes(value[1..9].try_into().ok()?);
    Some(PendingEmbeddingLease {
        expires_at_ms,
        token: value[9..].to_vec(),
    })
}

#[cfg(feature = "sync")]
fn clear_pending_embedding_lease_if_any(
    vault: &crate::Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let key = pending_embedding_lease_key(id);
    Ok(vault.store.sync_state.delete(wtxn, key.as_str())?)
}

#[cfg(feature = "sync")]
fn clear_pending_embedding_lease_if_matches(
    vault: &crate::Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    expected: &[u8],
) -> Result<bool> {
    let key = pending_embedding_lease_key(id);
    let Some(current) = vault.store.sync_state.get(wtxn, key.as_str())? else {
        return Ok(false);
    };
    if current != expected {
        return Ok(false);
    }
    Ok(vault.store.sync_state.delete(wtxn, key.as_str())?)
}

#[cfg(feature = "sync")]
fn unix_millis_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[cfg(all(test, feature = "sync"))]
mod tests {
    use std::sync::{Arc, Mutex};

    use rmpv::Value;

    use super::*;
    use crate::Vault;
    use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
    use crate::sync::SyncQueue;
    use crate::types::{ENTITY_TYPE_CLAIM, EntityId, TimeRange, VaultConfig};

    #[derive(Debug)]
    struct RecordingEmbedder {
        model_id: String,
        dimensions: usize,
        seen: Mutex<Vec<EntityId>>,
    }

    impl RecordingEmbedder {
        fn new(model_id: &str, dimensions: usize) -> Self {
            Self {
                model_id: model_id.to_owned(),
                dimensions,
                seen: Mutex::new(Vec::new()),
            }
        }

        fn seen(&self) -> Vec<EntityId> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl Embedder for RecordingEmbedder {
        fn model_id(&self) -> &str {
            &self.model_id
        }

        fn dimensions(&self) -> usize {
            self.dimensions
        }

        fn locality(&self) -> EmbedderLocality {
            EmbedderLocality::OnDevice
        }

        fn embed(&self, inputs: &[PendingEmbeddingInput]) -> Result<Vec<Vec<f32>>> {
            self.seen
                .lock()
                .unwrap()
                .extend(inputs.iter().map(|input| input.entity_id));
            Ok(inputs
                .iter()
                .enumerate()
                .map(|(index, _)| {
                    let mut vector = vec![0.0; self.dimensions];
                    vector[index % self.dimensions] = 1.0;
                    vector
                })
                .collect())
        }
    }

    fn test_vault() -> (tempfile::TempDir, Arc<Vault>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = VaultConfig::device();
        config.dimensions = 4;
        config.embedding_model = Some("test/embedder@v1".to_owned());
        let vault = Vault::open(dir.path(), config).expect("open vault");
        clear_default_policy_manifest_for_test(&vault);
        (dir, Arc::new(vault))
    }

    fn clear_default_policy_manifest_for_test(vault: &Vault) {
        let id = crate::gate::default_policy_manifest_id().expect("default policy manifest id");
        vault
            .with_write_txn(|wtxn| {
                crate::batch::deindex_entity_for_test(&vault.store, wtxn, &id)?;
                Ok(())
            })
            .expect("clear default policy manifest");
    }

    fn entity_id(byte: u8) -> EntityId {
        let mut bytes = [byte; 16];
        bytes[0] = 0x7e;
        EntityId::from_bytes(bytes).expect("valid entity id")
    }

    fn claim_body_bytes(value: &str) -> Vec<u8> {
        let body = ClaimBody::new(
            "test.status",
            ClaimSubject::Entity(entity_id(0xC1)),
            Value::from(value),
            0.9,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        crate::claim::encode_claim_body(&body).expect("encode claim body")
    }

    fn put_claim(vault: &Vault, id: EntityId, value: &str) -> Result<()> {
        vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_CLAIM,
                TimeRange { start: 1, end: 1 },
                1,
                &claim_body_bytes(value),
            )
            .commit()
    }

    fn put_claim_with_text(vault: &Vault, id: EntityId, value: &str, text: &str) -> Result<()> {
        vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_CLAIM,
                TimeRange { start: 1, end: 1 },
                1,
                &claim_body_bytes(value),
            )
            .text(&id, &[("body", text)])
            .commit()
    }

    fn pending_token(vault: &Vault, id: &EntityId) -> Result<Option<Vec<u8>>> {
        let rtxn = vault.store.env.read_txn()?;
        vault.store.pending_embedding_token(&rtxn, id)
    }

    #[test]
    fn apply_put_enqueues_device_priority_embed_job() -> Result<()> {
        let (_dir, vault) = test_vault();
        let id = entity_id(0x11);

        put_claim(&vault, id, "queued")?;

        let queue = SyncQueue::new(Arc::clone(&vault))?;
        let jobs = queue.drain_embed_jobs()?;
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].entity_id, id);
        assert_eq!(jobs[0].priority, EMBED_PRIORITY_DEVICE);
        Ok(())
    }

    #[test]
    fn run_with_pending_vectors_hot_bumps_embed_job() -> Result<()> {
        let (_dir, vault) = test_vault();
        let id = entity_id(0x12);

        put_claim_with_text(&vault, id, "queued", "hotneedle")?;
        let pending = vault
            .query()
            .search_text("hotneedle", 10)
            .run_with_pending_vectors()?;

        assert_eq!(pending.pending_vector_ids, vec![id]);
        let queue = SyncQueue::new(Arc::clone(&vault))?;
        let jobs = queue.drain_embed_jobs()?;
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].entity_id, id);
        assert_eq!(jobs[0].priority, EMBED_PRIORITY_SURFACED_HOT);
        Ok(())
    }

    #[test]
    fn reconciler_processes_jobs_by_priority() -> Result<()> {
        let (_dir, vault) = test_vault();
        let hot = entity_id(0x20);
        let server = entity_id(0x21);
        let device = entity_id(0x22);
        put_claim(&vault, hot, "hot")?;
        put_claim(&vault, server, "server")?;
        put_claim(&vault, device, "device")?;

        let queue = SyncQueue::new(Arc::clone(&vault))?;
        queue.push_embed_job(&hot, EMBED_PRIORITY_SURFACED_HOT)?;
        queue.push_embed_job(&server, EMBED_PRIORITY_SERVER)?;

        let embedder = Arc::new(RecordingEmbedder::new("test/embedder@v1", 4));
        let reconciler = PendingEmbeddingReconciler::new(
            Arc::clone(&vault),
            embedder.clone() as Arc<dyn Embedder>,
        )
        .with_batch_size(3);
        let report = reconciler.reconcile_once_at(10)?;

        assert_eq!(report.filled, 3);
        assert_eq!(embedder.seen(), vec![hot, server, device]);
        Ok(())
    }

    #[test]
    fn expired_lease_redrains_without_double_fill() -> Result<()> {
        let (_dir, vault) = test_vault();
        let id = entity_id(0x30);
        put_claim(&vault, id, "lease")?;

        let embedder = Arc::new(RecordingEmbedder::new("test/embedder@v1", 4));
        let reconciler = PendingEmbeddingReconciler::new(
            Arc::clone(&vault),
            embedder.clone() as Arc<dyn Embedder>,
        )
        .with_lease_duration_ms(10);

        let leased = reconciler.lease_due_jobs(1)?;
        assert_eq!(leased.work.len(), 1);

        let active = reconciler.reconcile_once_at(5)?;
        assert_eq!(active.leased, 0);
        assert_eq!(active.active_leases, 1);
        assert!(embedder.seen().is_empty());

        let expired = reconciler.reconcile_once_at(12)?;
        assert_eq!(expired.leased, 1);
        assert_eq!(expired.filled, 1);
        assert_eq!(embedder.seen(), vec![id]);
        assert!(pending_token(&vault, &id)?.is_none());

        let empty = reconciler.reconcile_once_at(30)?;
        assert_eq!(empty.leased, 0);
        assert_eq!(embedder.seen(), vec![id]);
        Ok(())
    }

    #[test]
    fn stale_completion_preserves_newer_pending_job() -> Result<()> {
        let (_dir, vault) = test_vault();
        let id = entity_id(0x40);
        put_claim(&vault, id, "old")?;

        let embedder = Arc::new(RecordingEmbedder::new("test/embedder@v1", 4));
        let reconciler = PendingEmbeddingReconciler::new(
            Arc::clone(&vault),
            embedder.clone() as Arc<dyn Embedder>,
        );

        let leased = reconciler.lease_due_jobs(1)?;
        assert_eq!(leased.work.len(), 1);
        put_claim(&vault, id, "new")?;

        let filled = reconciler.complete_leased_work(&leased.work[0], &[1.0, 0.0, 0.0, 0.0])?;
        assert!(!filled, "old-token fill must be stale");
        assert!(
            pending_token(&vault, &id)?.is_some(),
            "new pending marker must survive stale completion"
        );

        let report = reconciler.reconcile_once_at(2)?;
        assert_eq!(report.filled, 1);
        assert_eq!(embedder.seen(), vec![id]);
        assert!(pending_token(&vault, &id)?.is_none());
        Ok(())
    }
}
