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
use crate::error::StoreError;

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
    let vault = Vault::open_unseeded_for_test(dir.path(), config).expect("open vault");
    (dir, Arc::new(vault))
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
    )
    .unwrap();
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

fn pending_token(vault: &Vault, id: &EntityId) -> Result<Option<Vec<u8>>> {
    let rtxn = vault.store.env.read_txn()?;
    vault.store.pending_embedding_token(&rtxn, id)
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
    assert!(matches!(err, Error::InvalidConfig(_)));

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
    assert!(matches!(err, Error::InvalidConfig(_)));

    let Err(err) = PendingEmbeddingReconciler::new(
        Arc::clone(&vault),
        Arc::clone(&local) as Arc<dyn Embedder>,
    )
    .with_remote_rung(RemoteRung::new(remote(), allow()))?
    .with_remote_rung(RemoteRung::new(remote(), allow())) else {
        panic!("duplicate remote rung must be rejected");
    };
    assert!(matches!(err, Error::InvalidConfig(_)));
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
        Error::Store(StoreError::EmbeddingModelChanged { ref stored, ref requested })
            if stored == "test/embedder@v1" && requested == "other/embedder@v2"
    ));
    assert!(wrong_model.seen().is_empty());
    assert!(local.seen().is_empty());
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

    let filled = reconciler.complete_leased_work(
        &leased.work[0],
        &[1.0, 0.0, 0.0, 0.0],
        EmbedderLocality::OnDevice,
    )?;
    assert!(!filled, "old-token fill must be stale");
    assert!(
        pending_token(&vault, &id)?.is_some(),
        "new pending marker must survive stale completion"
    );

    let report = reconciler.reconcile_once_at(2)?;
    assert_eq!(
        report.filled, 0,
        "edits are published by idle, not per operation"
    );
    assert!(embedder.seen().is_empty());
    assert!(pending_token(&vault, &id)?.is_some());
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
        matches!(err, Error::InvalidConfig(_)),
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
    assert!(matches!(err, Error::InvalidConfig(_)));
}

mod payload;
