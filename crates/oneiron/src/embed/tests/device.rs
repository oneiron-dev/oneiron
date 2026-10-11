//! Each stored vector names the device and runtime that computed it (ARCH-0036,
//! owner 2026-10-11): one model is one space on every device, and one device's
//! vectors can be selected for a patch.

use super::*;

const TEXT: &str = "The spare key to the boathouse hangs behind the tide clock.";

fn cpu() -> EmbeddingProvenance {
    EmbeddingProvenance::new(EmbeddingDevice::Cpu, "candle 0.11.0 q8_0 x86_64")
}

fn cuda() -> EmbeddingProvenance {
    EmbeddingProvenance::new(EmbeddingDevice::Cuda, "candle 0.11.0 q8_0")
}

fn metal() -> EmbeddingProvenance {
    EmbeddingProvenance::new(EmbeddingDevice::Metal, "candle 0.11.0 q8_0")
}

/// The vault's model on one device: a text's vector depends on the text alone.
struct DeviceEmbedder(EmbeddingProvenance);

impl Embedder for DeviceEmbedder {
    fn model_id(&self) -> &str {
        "test/embedder@v1"
    }

    fn dimensions(&self) -> usize {
        4
    }

    fn locality(&self) -> EmbedderLocality {
        EmbedderLocality::OnDevice
    }

    fn embed(&self, inputs: &[PendingEmbeddingInput]) -> Result<Vec<Vec<f32>>> {
        inputs
            .iter()
            .map(|input| Ok(text_vector(&payload_text(&input.payload)?)))
            .collect()
    }

    fn provenance(&self) -> EmbeddingProvenance {
        self.0.clone()
    }
}

fn text_vector(text: &str) -> Vec<f32> {
    let sum = text.bytes().map(u32::from).sum::<u32>();
    vec![1.0, (sum % 13) as f32, (text.len() % 7) as f32, 0.5]
}

/// Embeds every pending record with `device`, as a worker on that device would.
fn fill_on(vault: &Arc<Vault>, device: EmbeddingProvenance) -> usize {
    let reconciler =
        PendingEmbeddingReconciler::new(Arc::clone(vault), Arc::new(DeviceEmbedder(device)));
    reconciler.reconcile_once().unwrap().filled
}

fn count(device: EmbeddingProvenance, vectors: u64) -> EmbeddingProvenanceCount {
    EmbeddingProvenanceCount {
        device: device.device,
        runtime: device.runtime,
        vectors,
    }
}

/// The owner's ruling: the same text by the same model, once on a CPU and once
/// on CUDA, lands in one space and ranks the same; the selection read returns
/// exactly the vectors one device computed.
#[test]
fn the_same_text_on_cpu_and_cuda_shares_one_space_and_each_device_is_selectable() {
    let (_dir, vault) = test_vault();
    let (on_cpu, on_cuda, other) = (entity_id(0xA1), entity_id(0xA2), entity_id(0xA3));
    put_claim(&vault, on_cpu, TEXT).unwrap();
    assert_eq!(fill_on(&vault, cpu()), 1);
    put_claim(&vault, on_cuda, TEXT).unwrap();
    assert_eq!(fill_on(&vault, cuda()), 1);
    put_claim(
        &vault,
        other,
        "Lunch moved to the noodle place on Thursday.",
    )
    .unwrap();
    assert_eq!(fill_on(&vault, cpu()), 1);

    assert_eq!(
        vault.doctor().unwrap().embedding_model_id.as_deref(),
        Some("test/embedder@v1"),
        "a device move keeps the space"
    );
    let query = vault.get_vector(&on_cpu).unwrap().expect("cpu vector");
    assert_eq!(vault.get_vector(&on_cuda).unwrap(), Some(query.clone()));
    let hits = vault.search_vector(&query, 3).unwrap();
    let mut top: Vec<EntityId> = hits[..2].iter().map(|hit| hit.id).collect();
    top.sort();
    assert_eq!(top, vec![on_cpu, on_cuda], "{hits:?}");
    assert_eq!(hits[0].score, hits[1].score, "{hits:?}");
    assert!(hits[2].score < hits[1].score, "{hits:?}");

    assert_eq!(vault.embedding_provenance(&on_cpu).unwrap(), Some(cpu()));
    assert_eq!(vault.embedding_provenance(&on_cuda).unwrap(), Some(cuda()));
    assert_eq!(
        vault
            .vectors_by_provenance(EmbeddingDevice::Cuda, None)
            .unwrap(),
        vec![on_cuda]
    );
    assert_eq!(
        vault
            .vectors_by_provenance(EmbeddingDevice::Cpu, Some(&cpu().runtime))
            .unwrap(),
        vec![on_cpu, other]
    );
    assert!(
        vault
            .vectors_by_provenance(EmbeddingDevice::Cpu, Some("candle 0.10.0 q8_0 x86_64"))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        vault.embedding_provenance_counts().unwrap(),
        vec![count(cpu(), 2), count(cuda(), 1)]
    );
}

/// A vector's mark lasts as long as the vector: through a restart and a graph
/// rebuild. A caller's own vector replaces it and reads as unknown, and a
/// deleted record leaves no count behind.
#[test]
fn a_mark_lasts_as_long_as_its_vector() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.embedding_model = Some("test/embedder@v1".to_owned());
    let open = || Arc::new(Vault::open_unseeded_for_test(dir.path(), config.clone()).unwrap());
    let (marked, replaced, deleted) = (entity_id(0xB1), entity_id(0xB2), entity_id(0xB3));
    let vault = open();
    for (id, text) in [
        (marked, TEXT),
        (replaced, "second line"),
        (deleted, "third"),
    ] {
        put_claim(&vault, id, text).unwrap();
    }
    assert_eq!(fill_on(&vault, metal()), 3);
    drop(vault);

    let vault = open();
    assert_eq!(vault.embedding_provenance(&marked).unwrap(), Some(metal()));
    vault.maintain().rebuild_hnsw().run().unwrap();
    assert_eq!(vault.embedding_provenance(&marked).unwrap(), Some(metal()));
    vault.put_vector(&replaced, &[0.0, 1.0, 0.0, 0.0]).unwrap();
    assert_eq!(
        vault.embedding_provenance(&replaced).unwrap(),
        Some(EmbeddingProvenance::unknown())
    );
    vault.batch().delete(&deleted).commit().unwrap();
    assert_eq!(vault.embedding_provenance(&deleted).unwrap(), None);
    assert_eq!(
        vault.embedding_provenance_counts().unwrap(),
        vec![count(metal(), 1), count(EmbeddingProvenance::unknown(), 1)]
    );
}

/// Replica apply: vectors never ride sync, so a replica embeds a replicated
/// record itself and marks it with its own device, and the origin keeps its
/// mark. Replaying the same record never drops the replica's.
#[test]
fn a_replica_marks_the_vectors_it_computes_and_a_replay_keeps_them() {
    let (_origin_dir, origin) = test_vault();
    let (_replica_dir, replica) = test_vault();
    let id = entity_id(0xC5);
    put_claim(&origin, id, TEXT).unwrap();
    assert_eq!(fill_on(&origin, cpu()), 1);

    let replicate = || {
        replica
            .batch()
            .put_replicated(
                &id,
                ENTITY_TYPE_CLAIM,
                TimeRange { start: 1, end: 1 },
                1,
                &claim_body_bytes(TEXT),
            )
            .commit()
            .unwrap();
    };
    replicate();
    assert_eq!(fill_on(&replica, cuda()), 1);
    replicate();
    assert_eq!(
        fill_on(&replica, metal()),
        0,
        "an unchanged record stays filled"
    );
    assert_eq!(replica.embedding_provenance(&id).unwrap(), Some(cuda()));
    assert_eq!(origin.embedding_provenance(&id).unwrap(), Some(cpu()));
    assert_eq!(
        replica.get_vector(&id).unwrap(),
        origin.get_vector(&id).unwrap()
    );
}

/// Export and restore: a checkpoint holds no vectors, so a restore carries no
/// mark for a vector it did not restore, and queues the worker to embed them
/// again (bug repro: it only marked them, and the worker leases queued jobs
/// only, so a restored vault never got its vectors back). The restoring
/// worker's device marks what it computes, and a new space drops every mark
/// with the vectors.
#[test]
fn a_restore_marks_only_the_vectors_it_embeds_again() {
    let dir = tempfile::tempdir().unwrap();
    let config = crate::test_util::embedding_test_config();
    let source = Arc::new(Vault::open(dir.path().join("source"), config.clone()).unwrap());
    let id = entity_id(0xD1);
    put_claim(&source, id, TEXT).unwrap();
    drain_on(&source, cpu());
    assert_eq!(source.embedding_provenance(&id).unwrap(), Some(cpu()));
    let checkpoint = dir.path().join("checkpoint");
    source.snapshot_checkpoint(&checkpoint, 100).unwrap();
    drop(source);

    let (restored, _) = Vault::restore_checkpoint(
        &checkpoint,
        &dir.path().join("restored"),
        config,
        crate::recovery::checkpoint::RestoreReason::Restore,
        101,
    )
    .unwrap();
    assert_eq!(restored.embedding_provenance(&id).unwrap(), None);
    assert!(restored.embedding_provenance_counts().unwrap().is_empty());
    let mut restored = Arc::new(restored);
    drain_on(&restored, metal());
    assert_eq!(restored.embedding_provenance(&id).unwrap(), Some(metal()));
    let counts = restored.embedding_provenance_counts().unwrap();
    assert!(
        counts
            .iter()
            .all(|count| count.device == EmbeddingDevice::Metal),
        "{counts:?}"
    );

    let restored = Arc::get_mut(&mut restored).expect("one handle");
    restored.refill_embedding_space().unwrap();
    assert!(restored.embedding_provenance_counts().unwrap().is_empty());
}

/// Runs a worker on `device` until it leases nothing, for a vault on the
/// test config's model, whose seeding writes claims of its own.
fn drain_on(vault: &Arc<Vault>, device: EmbeddingProvenance) {
    let reconciler = PendingEmbeddingReconciler::new(
        Arc::clone(vault),
        Arc::new(ModelEmbedder("test/model@v1", device)),
    );
    for _ in 0..32 {
        if reconciler.reconcile_once().unwrap().leased == 0 {
            return;
        }
    }
    panic!("the worker never drained");
}

/// [`DeviceEmbedder`] for a vault on another model.
struct ModelEmbedder(&'static str, EmbeddingProvenance);

impl Embedder for ModelEmbedder {
    fn model_id(&self) -> &str {
        self.0
    }

    fn dimensions(&self) -> usize {
        4
    }

    fn locality(&self) -> EmbedderLocality {
        EmbedderLocality::OnDevice
    }

    fn embed(&self, inputs: &[PendingEmbeddingInput]) -> Result<Vec<Vec<f32>>> {
        DeviceEmbedder(self.1.clone()).embed(inputs)
    }

    fn provenance(&self) -> EmbeddingProvenance {
        self.1.clone()
    }
}
