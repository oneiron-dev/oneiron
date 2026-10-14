//! DEC-0005: a device-local world's rows never reach a model off this
//! device, whatever the host's egress list allows. They embed on device, or
//! stay pending and unsent.

use super::*;

fn put_world(vault: &Vault, world: EntityId) -> Result<()> {
    vault.put_entity(
        &world,
        crate::registry::ENTITY_TYPE_WORLD,
        TimeRange { start: 1, end: 1 },
        1,
        b"world",
    )
}

fn put_world_claim(vault: &Vault, id: EntityId, world: EntityId) -> Result<()> {
    let mut body = ClaimBody::new(
        "test.status",
        ClaimSubject::Entity(entity_id(0xC1)),
        Value::from("kept"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.world = Some(world);
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &crate::claim::encode_claim_body(&body)?,
        )
        .commit()
}

#[test]
fn a_device_local_claim_never_reaches_a_remote_the_host_allows() -> Result<()> {
    let (_dir, vault) = test_vault();
    let world = entity_id(0x90);
    put_world(&vault, world)?;
    let (kept, open) = (entity_id(0x91), entity_id(0x92));
    put_world_claim(&vault, kept, world)?;
    put_claim(&vault, open, "open")?;
    vault.keep_world_on_this_machine_for_test(world, true)?;
    let local = Arc::new(RecordingEmbedder::new("test/embedder@v1", 4));
    let remote = Arc::new(RemoteFixtureEmbedder::new(
        "test/embedder@v1",
        4,
        EmbedderLocality::ThirdParty,
    ));
    let reconciler = routed_reconciler(
        &vault,
        &local,
        remote.clone() as Arc<dyn Embedder>,
        EgressDecision::Allow,
    )?;

    let report = reconciler.reconcile_once_at(10)?;
    assert_eq!(remote.seen(), vec![open]);
    assert_eq!(local.seen(), vec![kept]);
    assert_eq!(report.device_local, 1);
    assert_eq!(report.filled, 2);
    assert!(pending_token(&vault, &kept)?.is_none());
    Ok(())
}

/// A remote whose rows' world turns device-only after they were leased to
/// it, as it is about to send them.
struct FlaggedBeforeSend {
    inner: RemoteFixtureEmbedder,
    vault: Arc<Vault>,
    world: EntityId,
}

impl Embedder for FlaggedBeforeSend {
    fn model_id(&self) -> &str {
        self.inner.model_id()
    }

    fn dimensions(&self) -> usize {
        self.inner.dimensions()
    }

    fn locality(&self) -> EmbedderLocality {
        self.inner.locality()
    }

    fn embed(&self, inputs: &[PendingEmbeddingInput]) -> Result<Vec<Vec<f32>>> {
        self.vault
            .keep_world_on_this_machine_for_test(self.world, true)?;
        self.inner.embed(inputs)
    }

    fn embed_released(
        &self,
        inputs: &[PendingEmbeddingInput],
        release: &dyn Fn(&[EntityId]) -> Result<()>,
    ) -> Result<Vec<(Vec<f32>, crate::embed::EmbeddingProvenance)>> {
        self.vault
            .keep_world_on_this_machine_for_test(self.world, true)?;
        let rows: Vec<EntityId> = inputs.iter().map(|input| input.entity_id).collect();
        release(&rows)?;
        self.inner.embed_marked(inputs)
    }
}

#[test]
fn a_world_flagged_after_the_lease_keeps_its_rows_from_the_remote() -> Result<()> {
    let (_dir, vault) = test_vault();
    let world = entity_id(0x93);
    put_world(&vault, world)?;
    let kept = entity_id(0x94);
    put_world_claim(&vault, kept, world)?;
    let local = Arc::new(RecordingEmbedder::new("test/embedder@v1", 4));
    let remote = Arc::new(FlaggedBeforeSend {
        inner: RemoteFixtureEmbedder::new("test/embedder@v1", 4, EmbedderLocality::OwnerServer),
        vault: Arc::clone(&vault),
        world,
    });
    let reconciler = routed_reconciler(
        &vault,
        &local,
        remote.clone() as Arc<dyn Embedder>,
        EgressDecision::Allow,
    )?;

    let report = reconciler.reconcile_once_at(10)?;
    assert!(
        remote.inner.seen().is_empty(),
        "nothing may leave the device"
    );
    assert_eq!(report.remote_failed_fallback_local, 1);
    assert_eq!(local.seen(), vec![kept]);
    assert!(pending_token(&vault, &kept)?.is_none());
    Ok(())
}

#[test]
fn with_no_embedder_on_this_device_a_device_local_row_stays_pending_unsent() -> Result<()> {
    let (_dir, vault) = test_vault();
    let world = entity_id(0x95);
    put_world(&vault, world)?;
    let kept = entity_id(0x96);
    put_world_claim(&vault, kept, world)?;
    vault.keep_world_on_this_machine_for_test(world, true)?;
    let primary = Arc::new(RemoteFixtureEmbedder::new(
        "test/embedder@v1",
        4,
        EmbedderLocality::OwnerServer,
    ));
    let reconciler =
        PendingEmbeddingReconciler::new(Arc::clone(&vault), primary.clone() as Arc<dyn Embedder>);

    let report = reconciler.reconcile_once_at(10)?;
    assert_eq!((report.leased, report.device_local), (0, 1));
    assert!(primary.seen().is_empty(), "nothing may leave the device");
    assert!(pending_token(&vault, &kept)?.is_some());

    vault.keep_world_on_this_machine_for_test(world, false)?;
    let report = reconciler.reconcile_once_at(20)?;
    assert_eq!(report.filled, 1);
    assert_eq!(primary.seen(), vec![kept]);
    Ok(())
}
