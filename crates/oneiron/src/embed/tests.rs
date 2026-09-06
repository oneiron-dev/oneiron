// cfg(all(test, ...)) modules are not recognized by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use rmpv::Value;

use super::*;
use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::config::VaultConfig;
use crate::entity_id::EntityId;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::sync::SyncQueue;
use crate::temporal::TimeRange;

#[path = "warn_capture.rs"]
mod warn_capture;
use warn_capture::WarnCapture;

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

#[derive(Debug)]
struct RemoteFixtureEmbedder {
    model_id: String,
    dimensions: usize,
    locality: EmbedderLocality,
    fail: bool,
    seen: Mutex<Vec<EntityId>>,
}

impl RemoteFixtureEmbedder {
    fn new(model_id: &str, dimensions: usize, locality: EmbedderLocality) -> Self {
        Self {
            model_id: model_id.to_owned(),
            dimensions,
            locality,
            fail: false,
            seen: Mutex::new(Vec::new()),
        }
    }

    fn failing(mut self) -> Self {
        self.fail = true;
        self
    }

    fn seen(&self) -> Vec<EntityId> {
        self.seen.lock().unwrap().clone()
    }

    /// Two-hot fixture direction, deliberately not collinear with
    /// [`RecordingEmbedder`]'s one-hot vectors so a search can tell which
    /// embedder produced the stored row.
    fn fixture_vector(index: usize, dimensions: usize) -> Vec<f32> {
        let mut vector = vec![0.0; dimensions];
        vector[index % dimensions] = 0.6;
        vector[(index + 1) % dimensions] = 0.8;
        vector
    }
}

impl Embedder for RemoteFixtureEmbedder {
    fn model_id(&self) -> &str {
        &self.model_id
    }

    fn dimensions(&self) -> usize {
        self.dimensions
    }

    fn locality(&self) -> EmbedderLocality {
        self.locality
    }

    fn embed(&self, inputs: &[PendingEmbeddingInput]) -> Result<Vec<Vec<f32>>> {
        if self.fail {
            return Err(Error::InvalidConfig("remote embedder offline".to_owned()));
        }
        self.seen
            .lock()
            .unwrap()
            .extend(inputs.iter().map(|input| input.entity_id));
        Ok(inputs
            .iter()
            .enumerate()
            .map(|(index, _)| Self::fixture_vector(index, self.dimensions))
            .collect())
    }
}

/// Rung-2 transport double: quantizes fixture vectors to int8+scale on the
/// "wire" and dequantizes on receipt, as a host int8-transport impl would.
#[derive(Debug)]
struct Int8TransportEmbedder {
    model_id: String,
    originals: Vec<Vec<f32>>,
    seen: Mutex<Vec<EntityId>>,
}

impl Int8TransportEmbedder {
    fn new(model_id: &str, originals: Vec<Vec<f32>>) -> Self {
        Self {
            model_id: model_id.to_owned(),
            originals,
            seen: Mutex::new(Vec::new()),
        }
    }

    fn seen(&self) -> Vec<EntityId> {
        self.seen.lock().unwrap().clone()
    }
}

impl Embedder for Int8TransportEmbedder {
    fn model_id(&self) -> &str {
        &self.model_id
    }

    fn dimensions(&self) -> usize {
        self.originals[0].len()
    }

    fn locality(&self) -> EmbedderLocality {
        EmbedderLocality::ThirdParty
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
                let original = &self.originals[index % self.originals.len()];
                let max_abs = original.iter().fold(0.0f32, |acc, v| acc.max(v.abs()));
                let scale = max_abs / 127.0;
                let codes: Vec<i8> = original
                    .iter()
                    .map(|v| (v / scale).round().clamp(-127.0, 127.0) as i8)
                    .collect();
                dequantize_int8_embedding(&codes, scale)
            })
            .collect())
    }
}

#[derive(Debug)]
struct FixedDecision(EgressDecision);

impl EgressPredicate for FixedDecision {
    fn decide(&self, _input: &PendingEmbeddingInput) -> EgressDecision {
        self.0
    }
}

#[derive(Debug)]
struct AllowOnly(EntityId);

impl EgressPredicate for AllowOnly {
    fn decide(&self, input: &PendingEmbeddingInput) -> EgressDecision {
        if input.entity_id == self.0 {
            EgressDecision::Allow
        } else {
            EgressDecision::NoVerdict
        }
    }
}

fn routed_reconciler(
    vault: &Arc<Vault>,
    local: &Arc<RecordingEmbedder>,
    remote: Arc<dyn Embedder>,
    decision: EgressDecision,
) -> Result<PendingEmbeddingReconciler> {
    PendingEmbeddingReconciler::new(Arc::clone(vault), Arc::clone(local) as Arc<dyn Embedder>)
        .with_batch_size(8)
        .with_remote_rung(RemoteRung::new(remote, Arc::new(FixedDecision(decision))))
}

#[test]
fn no_verdict_routes_local_and_drains() -> Result<()> {
    let (_dir, vault) = test_vault();
    let ids = [entity_id(0x50), entity_id(0x51), entity_id(0x52)];
    for (index, id) in ids.iter().enumerate() {
        put_claim(&vault, *id, &format!("nv-{index}"))?;
    }

    let local = Arc::new(RecordingEmbedder::new("test/embedder@v1", 4));
    let remote = Arc::new(RemoteFixtureEmbedder::new(
        "test/embedder@v1",
        4,
        EmbedderLocality::OwnerServer,
    ));
    let reconciler = routed_reconciler(
        &vault,
        &local,
        remote.clone() as Arc<dyn Embedder>,
        EgressDecision::NoVerdict,
    )?;

    let report = reconciler.reconcile_once_at(10)?;
    assert_eq!(report.filled, 3);
    assert_eq!(report.egress_no_verdict, 3);
    assert_eq!(report.egress_denied, 0);
    assert_eq!(report.routed_remote, 0);
    assert_eq!(report.remote_failed_fallback_local, 0);
    assert!(remote.seen().is_empty(), "no bytes may leave the device");
    assert_eq!(local.seen().len(), 3);
    for id in &ids {
        assert!(pending_token(&vault, id)?.is_none());
    }

    let drained = reconciler.reconcile_once_at(20)?;
    assert_eq!(drained.leased, 0);
    assert_eq!(drained.active_leases, 0);
    Ok(())
}

#[test]
fn deny_routes_local() -> Result<()> {
    let (_dir, vault) = test_vault();
    let ids = [entity_id(0x54), entity_id(0x55)];
    for (index, id) in ids.iter().enumerate() {
        put_claim(&vault, *id, &format!("deny-{index}"))?;
    }

    let local = Arc::new(RecordingEmbedder::new("test/embedder@v1", 4));
    let remote = Arc::new(RemoteFixtureEmbedder::new(
        "test/embedder@v1",
        4,
        EmbedderLocality::OwnerServer,
    ));
    let reconciler = routed_reconciler(
        &vault,
        &local,
        remote.clone() as Arc<dyn Embedder>,
        EgressDecision::Deny,
    )?;

    let report = reconciler.reconcile_once_at(10)?;
    assert_eq!(report.filled, 2);
    assert_eq!(report.egress_denied, 2);
    assert_eq!(report.egress_no_verdict, 0);
    assert_eq!(report.routed_remote, 0);
    assert!(remote.seen().is_empty());
    assert_eq!(local.seen().len(), 2);
    Ok(())
}

#[test]
fn allow_routes_remote_filled_and_searchable() -> Result<()> {
    let (_dir, vault) = test_vault();
    let ids = [entity_id(0x56), entity_id(0x57)];
    for (index, id) in ids.iter().enumerate() {
        put_claim(&vault, *id, &format!("allow-{index}"))?;
    }

    let local = Arc::new(RecordingEmbedder::new("test/embedder@v1", 4));
    let remote = Arc::new(RemoteFixtureEmbedder::new(
        "test/embedder@v1",
        4,
        EmbedderLocality::OwnerServer,
    ));
    let reconciler = routed_reconciler(
        &vault,
        &local,
        remote.clone() as Arc<dyn Embedder>,
        EgressDecision::Allow,
    )?;

    let report = reconciler.reconcile_once_at(10)?;
    assert_eq!(report.filled, 2);
    assert_eq!(report.routed_remote, 2);
    assert_eq!(report.egress_denied, 0);
    assert_eq!(report.egress_no_verdict, 0);
    assert_eq!(report.remote_failed_fallback_local, 0);
    assert!(local.seen().is_empty(), "primary must not see allowed work");
    assert_eq!(remote.seen().len(), 2);

    for (index, id) in remote.seen().iter().enumerate() {
        let query = RemoteFixtureEmbedder::fixture_vector(index, 4);
        let results = vault.search_vector(&query, 2)?;
        let hit = results
            .iter()
            .find(|scored| scored.id == *id)
            .expect("remote-filled vector must be searchable");
        assert!(
            hit.score > 0.999,
            "stored vector must be the remote fixture, got score {}",
            hit.score
        );
    }
    Ok(())
}

#[test]
fn remote_failure_falls_back_local_and_warns() -> Result<()> {
    let (_dir, vault) = test_vault();
    let ids = [entity_id(0x58), entity_id(0x59)];
    for (index, id) in ids.iter().enumerate() {
        put_claim(&vault, *id, &format!("fail-{index}"))?;
    }

    let local = Arc::new(RecordingEmbedder::new("test/embedder@v1", 4));
    let remote = Arc::new(
        RemoteFixtureEmbedder::new("test/embedder@v1", 4, EmbedderLocality::ThirdParty).failing(),
    );
    let reconciler = routed_reconciler(
        &vault,
        &local,
        remote as Arc<dyn Embedder>,
        EgressDecision::Allow,
    )?;

    let capture = WarnCapture::default();
    let report = capture.with_default(|| reconciler.reconcile_once_at(10))?;

    assert_eq!(report.filled, 2);
    assert_eq!(report.remote_failed_fallback_local, 2);
    assert_eq!(report.routed_remote, 0);
    assert_eq!(local.seen().len(), 2, "fallback must embed locally");
    assert!(
        capture
            .messages()
            .iter()
            .any(|message| message.contains("remote embed failed")),
        "fallback must log a warning, got {:?}",
        capture.messages()
    );
    for id in &ids {
        assert!(pending_token(&vault, id)?.is_none());
    }
    Ok(())
}

#[test]
fn int8_round_trip_through_remote_rung() -> Result<()> {
    let (_dir, vault) = test_vault();
    let ids = [entity_id(0x5A), entity_id(0x5B)];
    for (index, id) in ids.iter().enumerate() {
        put_claim(&vault, *id, &format!("int8-{index}"))?;
    }

    let originals = vec![
        vec![0.83, -0.41, 0.29, 0.57],
        vec![-0.12, 0.94, -0.33, 0.08],
    ];
    let local = Arc::new(RecordingEmbedder::new("test/embedder@v1", 4));
    let remote = Arc::new(Int8TransportEmbedder::new(
        "test/embedder@v1",
        originals.clone(),
    ));
    let reconciler = routed_reconciler(
        &vault,
        &local,
        remote.clone() as Arc<dyn Embedder>,
        EgressDecision::Allow,
    )?;

    let report = reconciler.reconcile_once_at(10)?;
    assert_eq!(report.filled, 2);
    assert_eq!(report.routed_remote, 2);

    for (index, id) in remote.seen().iter().enumerate() {
        let original = &originals[index % originals.len()];
        let results = vault.search_vector(original, 2)?;
        let hit = results
            .iter()
            .find(|scored| scored.id == *id)
            .expect("round-tripped vector must be searchable");
        assert!(
            hit.score >= 0.999,
            "int8 round-trip cosine must be >= 0.999, got {}",
            hit.score
        );
    }
    Ok(())
}

#[test]
fn dequantize_int8_embedding_scales_codes() {
    assert_eq!(
        dequantize_int8_embedding(&[-127, 0, 64], 0.5),
        vec![-63.5, 0.0, 32.0]
    );
}

#[test]
fn with_remote_rung_validates_configuration() -> Result<()> {
    let (_dir, vault) = test_vault();
    let allow = || Arc::new(FixedDecision(EgressDecision::Allow)) as Arc<dyn EgressPredicate>;

    let local = Arc::new(RecordingEmbedder::new("test/embedder@v1", 4));
    let on_device_remote = Arc::new(RemoteFixtureEmbedder::new(
        "test/embedder@v1",
        4,
        EmbedderLocality::OnDevice,
    ));
    let Err(err) = PendingEmbeddingReconciler::new(
        Arc::clone(&vault),
        Arc::clone(&local) as Arc<dyn Embedder>,
    )
    .with_remote_rung(RemoteRung::new(
        on_device_remote as Arc<dyn Embedder>,
        allow(),
    )) else {
        panic!("OnDevice remote rung must be rejected");
    };
    assert!(
        matches!(err, Error::InvalidConfig(ref msg) if msg == "remote rung embedder must not be OnDevice")
    );

    let remote_primary = Arc::new(RemoteFixtureEmbedder::new(
        "test/embedder@v1",
        4,
        EmbedderLocality::OwnerServer,
    ));
    let remote = || {
        Arc::new(RemoteFixtureEmbedder::new(
            "test/embedder@v1",
            4,
            EmbedderLocality::ThirdParty,
        )) as Arc<dyn Embedder>
    };
    let Err(err) =
        PendingEmbeddingReconciler::new(Arc::clone(&vault), remote_primary as Arc<dyn Embedder>)
            .with_remote_rung(RemoteRung::new(remote(), allow()))
    else {
        panic!("non-OnDevice primary must be rejected");
    };
    assert!(
        matches!(err, Error::InvalidConfig(ref msg) if msg == "remote rung requires an OnDevice primary embedder")
    );

    let Err(err) = PendingEmbeddingReconciler::new(
        Arc::clone(&vault),
        Arc::clone(&local) as Arc<dyn Embedder>,
    )
    .with_remote_rung(RemoteRung::new(remote(), allow()))?
    .with_remote_rung(RemoteRung::new(remote(), allow())) else {
        panic!("duplicate remote rung must be rejected");
    };
    assert!(
        matches!(err, Error::InvalidConfig(ref msg) if msg == "a remote rung is already configured")
    );
    Ok(())
}

#[test]
fn remote_rung_dims_and_model_gates() -> Result<()> {
    let (_dir, vault) = test_vault();
    put_claim(&vault, entity_id(0x5C), "gated")?;
    let allow = || Arc::new(FixedDecision(EgressDecision::Allow)) as Arc<dyn EgressPredicate>;

    let local = Arc::new(RecordingEmbedder::new("test/embedder@v1", 4));
    let wrong_dims = Arc::new(RemoteFixtureEmbedder::new(
        "test/embedder@v1",
        8,
        EmbedderLocality::OwnerServer,
    ));
    let reconciler = PendingEmbeddingReconciler::new(
        Arc::clone(&vault),
        Arc::clone(&local) as Arc<dyn Embedder>,
    )
    .with_remote_rung(RemoteRung::new(
        wrong_dims.clone() as Arc<dyn Embedder>,
        allow(),
    ))?;
    let err = reconciler.reconcile_once_at(10).unwrap_err();
    assert!(matches!(
        err,
        Error::DimensionMismatch {
            expected: 4,
            got: 8
        }
    ));
    assert!(wrong_dims.seen().is_empty());
    assert!(local.seen().is_empty(), "gates fire before any embed call");

    let wrong_model = Arc::new(RemoteFixtureEmbedder::new(
        "other/embedder@v2",
        4,
        EmbedderLocality::OwnerServer,
    ));
    let reconciler = PendingEmbeddingReconciler::new(
        Arc::clone(&vault),
        Arc::clone(&local) as Arc<dyn Embedder>,
    )
    .with_remote_rung(RemoteRung::new(
        wrong_model.clone() as Arc<dyn Embedder>,
        allow(),
    ))?;
    let err = reconciler.reconcile_once_at(10).unwrap_err();
    assert!(matches!(
        err,
        Error::EmbeddingModelChanged { ref stored, ref requested }
            if stored == "test/embedder@v1" && requested == "other/embedder@v2"
    ));
    assert!(wrong_model.seen().is_empty());
    assert!(local.seen().is_empty());
    Ok(())
}

#[test]
fn remote_lease_window_uses_rung_duration() -> Result<()> {
    let (_dir, vault) = test_vault();
    let allowed = entity_id(0x5D);
    let held_back = entity_id(0x5E);
    put_claim(&vault, allowed, "remote-lease")?;
    put_claim(&vault, held_back, "local-lease")?;

    let local = Arc::new(RecordingEmbedder::new("test/embedder@v1", 4));
    let remote = Arc::new(RemoteFixtureEmbedder::new(
        "test/embedder@v1",
        4,
        EmbedderLocality::OwnerServer,
    ));
    let reconciler = PendingEmbeddingReconciler::new(
        Arc::clone(&vault),
        Arc::clone(&local) as Arc<dyn Embedder>,
    )
    .with_batch_size(8)
    .with_remote_rung(RemoteRung::new(
        remote as Arc<dyn Embedder>,
        Arc::new(AllowOnly(allowed)),
    ))?;

    let batch = reconciler.lease_due_jobs(1)?;
    assert_eq!(batch.work.len(), 2);
    assert_eq!(batch.egress_no_verdict, 1);

    let rtxn = vault.store.env.read_txn()?;
    let remote_raw = vault
        .store
        .sync_state
        .get(&rtxn, pending_embedding_lease_key(&allowed).as_str())?
        .expect("remote lease row");
    let remote_lease = decode_pending_embedding_lease(&remote_raw).expect("decode remote lease");
    assert_eq!(
        remote_lease.expires_at_ms,
        1 + DEFAULT_REMOTE_PENDING_EMBEDDING_LEASE_MS
    );

    let local_raw = vault
        .store
        .sync_state
        .get(&rtxn, pending_embedding_lease_key(&held_back).as_str())?
        .expect("local lease row");
    let local_lease = decode_pending_embedding_lease(&local_raw).expect("decode local lease");
    assert_eq!(
        local_lease.expires_at_ms,
        1 + DEFAULT_PENDING_EMBEDDING_LEASE_MS
    );
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

/// OnDevice primary that always fails `embed`, for the partition-order
/// stall regression below.
#[derive(Debug)]
struct FailingLocalEmbedder {
    model_id: String,
    dimensions: usize,
}

impl Embedder for FailingLocalEmbedder {
    fn model_id(&self) -> &str {
        &self.model_id
    }

    fn dimensions(&self) -> usize {
        self.dimensions
    }

    fn locality(&self) -> EmbedderLocality {
        EmbedderLocality::OnDevice
    }

    fn embed(&self, _inputs: &[PendingEmbeddingInput]) -> Result<Vec<Vec<f32>>> {
        Err(Error::InvalidConfig("primary embedder offline".to_owned()))
    }
}

/// Codex F1 regression (ONE-1338 respin): the remote batch runs BEFORE the
/// local batch, so a primary failure — which aborts the pass, as it always
/// has — cannot strand never-attempted remote-routed rows behind their
/// long 120s leases. The remote claim must be attempted and filled even
/// though the pass itself errors on the local batch.
#[test]
fn local_failure_does_not_strand_remote_work() -> Result<()> {
    let (_dir, vault) = test_vault();
    let remote_routed = entity_id(0x5F);
    let local_routed = entity_id(0x60);
    put_claim(&vault, remote_routed, "remote-first")?;
    put_claim(&vault, local_routed, "local-after")?;

    let failing_primary = Arc::new(FailingLocalEmbedder {
        model_id: "test/embedder@v1".to_owned(),
        dimensions: 4,
    });
    let remote = Arc::new(RemoteFixtureEmbedder::new(
        "test/embedder@v1",
        4,
        EmbedderLocality::OwnerServer,
    ));
    let reconciler =
        PendingEmbeddingReconciler::new(Arc::clone(&vault), failing_primary as Arc<dyn Embedder>)
            .with_batch_size(8)
            .with_remote_rung(RemoteRung::new(
                remote.clone() as Arc<dyn Embedder>,
                Arc::new(AllowOnly(remote_routed)),
            ))?;

    let err = reconciler.reconcile_once_at(10).unwrap_err();
    assert!(
        matches!(err, Error::InvalidConfig(ref msg) if msg == "primary embedder offline"),
        "the local-batch primary failure still propagates (pinned behavior)"
    );

    assert_eq!(
        remote.seen(),
        vec![remote_routed],
        "the remote batch must have been attempted before the local failure"
    );
    assert!(
        pending_token(&vault, &remote_routed)?.is_none(),
        "the remote-routed claim must be filled despite the aborted pass"
    );
    assert!(
        pending_token(&vault, &local_routed)?.is_some(),
        "the local claim stays pending behind its short lease"
    );
    Ok(())
}

/// Qodo #466-F2: a 0ms remote lease is born expired — every pass would
/// re-lease and re-embed the same rows. Rejected at attach time alongside
/// the other rung validations.
#[test]
fn zero_remote_lease_duration_is_rejected() {
    let (_dir, vault) = test_vault();
    let local = Arc::new(RecordingEmbedder::new("test/embedder@v1", 4));
    let remote = Arc::new(RemoteFixtureEmbedder::new(
        "test/embedder@v1",
        4,
        EmbedderLocality::OwnerServer,
    ));
    let mut rung = RemoteRung::new(
        remote as Arc<dyn Embedder>,
        Arc::new(FixedDecision(EgressDecision::Allow)),
    );
    rung.lease_duration_ms = 0;

    let Err(err) = PendingEmbeddingReconciler::new(
        Arc::clone(&vault),
        Arc::clone(&local) as Arc<dyn Embedder>,
    )
    .with_remote_rung(rung) else {
        panic!("a 0ms remote lease must be rejected");
    };
    assert!(
        matches!(err, Error::InvalidConfig(ref msg) if msg == "remote rung lease duration must be greater than zero")
    );
}

/// Qodo #466-F1: when the remote batch completed but the local batch then
/// fails the pass, the completed remote counters must surface via a warn
/// (the report itself is dropped with the error — pinned propagation). A
/// PURE-local failure stays silent, as EMB-1 always propagated it.
#[test]
fn partial_remote_completion_is_logged_when_local_batch_fails() -> Result<()> {
    let (_dir, vault) = test_vault();
    let remote_routed = entity_id(0x62);
    let local_routed = entity_id(0x63);
    put_claim(&vault, remote_routed, "partial-remote")?;
    put_claim(&vault, local_routed, "partial-local")?;

    let failing_primary = Arc::new(FailingLocalEmbedder {
        model_id: "test/embedder@v1".to_owned(),
        dimensions: 4,
    });
    let remote = Arc::new(RemoteFixtureEmbedder::new(
        "test/embedder@v1",
        4,
        EmbedderLocality::OwnerServer,
    ));
    let reconciler = PendingEmbeddingReconciler::new(
        Arc::clone(&vault),
        Arc::clone(&failing_primary) as Arc<dyn Embedder>,
    )
    .with_batch_size(8)
    .with_remote_rung(RemoteRung::new(
        remote as Arc<dyn Embedder>,
        Arc::new(AllowOnly(remote_routed)),
    ))?;

    let capture = WarnCapture::default();
    let result = capture.with_default(|| reconciler.reconcile_once_at(10));
    assert!(result.is_err(), "the local failure still fails the pass");
    assert!(
        capture
            .messages()
            .iter()
            .any(|message| message.contains("local batch failed after remote work completed")),
        "completed remote work must surface in a warning, got {:?}",
        capture.messages()
    );

    // Pure-local failure (no remote work attempted): silent propagation.
    let (_dir2, vault2) = test_vault();
    put_claim(&vault2, entity_id(0x64), "pure-local")?;
    let reconciler = PendingEmbeddingReconciler::new(
        Arc::clone(&vault2),
        Arc::new(FailingLocalEmbedder {
            model_id: "test/embedder@v1".to_owned(),
            dimensions: 4,
        }) as Arc<dyn Embedder>,
    );
    let capture = WarnCapture::default();
    let result = capture.with_default(|| reconciler.reconcile_once_at(10));
    assert!(result.is_err());
    assert!(
        capture
            .messages()
            .iter()
            .all(|message| !message.contains("local batch failed after remote work completed")),
        "a pure-local failure must not claim remote work completed"
    );
    Ok(())
}
