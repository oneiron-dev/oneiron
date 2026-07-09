use std::sync::{Arc, Mutex};

use rmpv::Value;

use super::*;
use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::entity_id::EntityId;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::sync::SyncQueue;
use crate::types::{TimeRange, VaultConfig};

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
    let reconciler =
        PendingEmbeddingReconciler::new(Arc::clone(&vault), embedder.clone() as Arc<dyn Embedder>)
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
    let reconciler =
        PendingEmbeddingReconciler::new(Arc::clone(&vault), embedder.clone() as Arc<dyn Embedder>)
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
    let reconciler =
        PendingEmbeddingReconciler::new(Arc::clone(&vault), embedder.clone() as Arc<dyn Embedder>);

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
