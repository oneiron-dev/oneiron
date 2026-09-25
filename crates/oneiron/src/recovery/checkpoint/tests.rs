use super::*;
use crate::{EntityId, temporal::TimeRange};
#[test]
fn canonical_snapshot_rebuilds_indexes_excludes_runtime_and_mints_epoch() {
    let root = tempfile::tempdir().unwrap();
    let source = Vault::open(root.path().join("source"), VaultConfig::device()).unwrap();
    let id = EntityId::now();
    source
        .batch()
        .put(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 10, end: 20 },
            30,
            b"canonical person",
        )
        .text(&id, &[("body", "restore searchable")])
        .phonetic(&id, &["RSTR"])
        .commit()
        .unwrap();
    source
        .with_write_txn(|txn| {
            source
                .store
                .vault_meta
                .put(txn, b"dreamer:budget:test", b"spent")?;
            source
                .store
                .vault_meta
                .put(txn, b"retr_run:test", b"runtime")?;
            source.store.ppr_cache.put(txn, b"derived", b"cache")?;
            Ok(())
        })
        .unwrap();
    let observations = [crate::self_heal::DiagnosticObservation {
        source_ref: id,
        kind: crate::consent::CONSENT_REASON_DENIED,
        payload_digest: [1; 32],
        observed_at: 50,
    }];
    let diagnostics = crate::self_heal::run_deterministic_detectors(
        &source,
        &crate::self_heal::DiagnosticWorkingSet {
            scope_ref: "restore-diagnostic",
            observations: &observations,
        },
        &[&crate::self_heal::ConsentDeniedDetector],
    )
    .unwrap();
    assert_eq!(diagnostics.len(), 1);
    let path = root.path().join("checkpoint");
    let checkpoint_id = source.snapshot_checkpoint(&path, 100).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
            0
        );
    }
    let after = EntityId::now();
    source
        .put_entity(
            &after,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange {
                start: 101,
                end: 101,
            },
            101,
            b"after checkpoint",
        )
        .unwrap();
    for (index, reason) in [
        RestoreReason::Restore,
        RestoreReason::Wake,
        RestoreReason::Migrate,
    ]
    .into_iter()
    .enumerate()
    {
        let (restored, report) = Vault::restore_checkpoint(
            &path,
            &root.path().join(format!("restored-{index}")),
            VaultConfig::device(),
            reason,
            200,
        )
        .unwrap();
        assert_eq!(
            restored.get(&id).unwrap(),
            Some(b"canonical person".to_vec())
        );
        assert_eq!(restored.get(&after).unwrap(), None);
        assert!(
            restored
                .entities_by_type(crate::registry::ENTITY_TYPE_PERSON)
                .unwrap()
                .contains(&id)
        );
        assert_eq!(report.rebuilt_text_documents, 1);
        let txn = restored.store.env.read_txn().unwrap();
        assert!(
            restored
                .store
                .vault_meta
                .get(&txn, b"dreamer:budget:test")
                .unwrap()
                .is_none()
        );
        assert!(
            restored
                .store
                .vault_meta
                .get(&txn, b"retr_run:test")
                .unwrap()
                .is_none()
        );
        assert!(restored.store.ppr_cache.is_empty(&txn).unwrap());
        assert!(!restored.store.phonetic_index.is_empty(&txn).unwrap());
        assert!(!restored.store.text_postings.is_empty(&txn).unwrap());
        drop(txn);
        assert!(
            restored
                .entities_by_type(crate::registry::ENTITY_TYPE_DIAGNOSTIC)
                .unwrap()
                .is_empty()
        );
        let epochs = restored.restore_epochs().unwrap();
        assert_eq!(epochs.len(), 1);
        assert_eq!(epochs[0].checkpoint_id, checkpoint_id);
        assert_eq!(epochs[0].restored_at, 200);
        assert_eq!(epochs[0].reason, reason);
    }
}
#[test]
fn corrupt_checkpoint_and_existing_destination_are_refused_without_overwrite() {
    let root = tempfile::tempdir().unwrap();
    let vault = Vault::open(root.path().join("source"), VaultConfig::device()).unwrap();
    let image = root.path().join("checkpoint");
    vault.snapshot_checkpoint(&image, 1).unwrap();
    let destination = root.path().join("existing");
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(destination.join("owned"), b"keep").unwrap();
    assert!(
        Vault::restore_checkpoint(
            &image,
            &destination,
            VaultConfig::device(),
            RestoreReason::Restore,
            2
        )
        .is_err()
    );
    assert_eq!(std::fs::read(destination.join("owned")).unwrap(), b"keep");
    let mut bytes = std::fs::read(&image).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    std::fs::write(&image, bytes).unwrap();
    assert!(
        Vault::restore_checkpoint(
            &image,
            &root.path().join("fresh"),
            VaultConfig::device(),
            RestoreReason::Restore,
            2
        )
        .is_err()
    );
    assert!(!root.path().join("fresh").exists());
}

#[test]
fn restore_rebuilds_pending_consent_indexes_and_preserves_insertion_order() {
    let root = tempfile::tempdir().unwrap();
    let source = Vault::open(root.path().join("source"), VaultConfig::device()).unwrap();
    let mut expected = Vec::new();
    for _ in 0..2 {
        let record = crate::store::PendingGateConsentRecord {
            version: crate::store::PENDING_GATE_CONSENT_VERSION,
            claim_id: *EntityId::now().as_bytes(),
            decision_id: crate::store::GateDecisionId::now(),
            created_at: 100,
            diff_handle: vec![1],
            read_frontier_hash: [2; 32],
            reason_codes: vec!["gate.pending.test".into()],
            dreamer_run_id: Some("pending-run".into()),
        };
        source
            .with_write_txn(|txn| source.store.put_pending_gate_consent_in_txn(txn, &record))
            .unwrap();
        expected.push(record);
    }
    // Damage only rebuildable sidecars, including an orphan. The primary
    // pending records, original index-state witness and sequence are intact.
    source
        .with_write_txn(|txn| {
            for prefix in [
                b"gate_pending:run_index:v1:".as_slice(),
                b"gate_pending:group_index:v1:",
                b"gate_pending:hash_index:v1:",
                b"gate_pending:sequence_index:v1:",
                b"gate_pending:critical_confirm_by_id:v1:",
            ] {
                let keys = source
                    .store
                    .vault_meta
                    .prefix_iter(&*txn, prefix)?
                    .map(|r| r.map(|(k, _)| k.to_vec()))
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                for key in keys {
                    source.store.vault_meta.delete(txn, &key)?;
                }
                source
                    .store
                    .vault_meta
                    .put(txn, &[prefix, b"orphan"].concat(), b"corrupt")?;
            }
            Ok(())
        })
        .unwrap();
    let image = root.path().join("checkpoint");
    source.snapshot_checkpoint(&image, 110).unwrap();
    let (restored, _) = Vault::restore_checkpoint(
        &image,
        &root.path().join("restored"),
        VaultConfig::device(),
        RestoreReason::Restore,
        120,
    )
    .unwrap();
    assert_eq!(
        restored
            .store
            .pending_gate_consents_for_run("pending-run")
            .unwrap(),
        expected
    );
    assert_eq!(
        restored
            .store
            .pending_gate_consents_for_group_key("pending-run")
            .unwrap(),
        expected
    );
    let txn = restored.store.env.read_txn().unwrap();
    let page = restored
        .store
        .pending_gate_consents_page_in_txn(&txn, None, None, 10)
        .unwrap();
    assert_eq!(
        page.iter().map(|(_, r)| r.clone()).collect::<Vec<_>>(),
        expected
    );
    assert_eq!(page.iter().map(|(s, _)| *s).collect::<Vec<_>>(), vec![1, 2]);
    drop(txn);
    // Rebuilt deletion witnesses still support normal lifecycle operations.
    restored
        .with_write_txn(|txn| {
            restored.store.delete_pending_gate_consent_in_txn(
                txn,
                &EntityId::from_bytes(expected[0].claim_id).unwrap(),
            )
        })
        .unwrap();
    assert_eq!(
        restored
            .store
            .pending_gate_consents_for_run("pending-run")
            .unwrap(),
        expected[1..]
    );
}

#[test]
fn checkpoint_omits_ingest_counters_but_preserves_quota_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let source = Vault::open(dir.path().join("source"), VaultConfig::device()).unwrap();
    let baseline = dir.path().join("baseline");
    source.snapshot_checkpoint(&baseline, 100).unwrap();
    let mut config = Vec::new();
    config.extend_from_slice(&4_u32.to_le_bytes());
    config.extend_from_slice(&60_u64.to_le_bytes());
    source
        .with_write_txn(|txn| {
            source
                .store
                .sync_queue
                .put(txn, b"m:maintenance_ingest_quota_config:v1", &config)?;
            Ok(())
        })
        .unwrap();
    let configured = dir.path().join("configured");
    source.snapshot_checkpoint(&configured, 100).unwrap();
    assert_ne!(
        std::fs::read(&baseline).unwrap(),
        std::fs::read(&configured).unwrap()
    );
    let mut key = b"m:maintenance_ingest_quota:v1:".to_vec();
    key.extend_from_slice(&[7; 32]);
    let mut count = Vec::new();
    count.extend_from_slice(&60_u64.to_le_bytes());
    count.extend_from_slice(&4_u32.to_le_bytes());
    source
        .with_write_txn(|txn| {
            source.store.sync_queue.put(txn, &key, &count)?;
            Ok(())
        })
        .unwrap();
    let counted = dir.path().join("counted");
    source.snapshot_checkpoint(&counted, 100).unwrap();
    assert_eq!(
        std::fs::read(&configured).unwrap(),
        std::fs::read(&counted).unwrap()
    );
}

#[test]
fn checkpoint_refuses_unreconstructable_explicit_vectors_before_creating_image() {
    for (entity_type, body) in [
        (crate::registry::ENTITY_TYPE_PERSON, b"person".as_slice()),
        (crate::registry::ENTITY_TYPE_SUMMARY, b"".as_slice()),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut config = VaultConfig::device();
        config.dimensions = 4;
        config.embedding_model = Some("test/model@v1".into());
        let source = Vault::open(dir.path().join("source"), config).unwrap();
        let id = EntityId::now();
        source
            .put_entity(&id, entity_type, TimeRange { start: 1, end: 1 }, 1, body)
            .unwrap();
        let vector = vec![1.0, 0.0, 0.0, 0.0];
        source.put_vector(&id, &vector).unwrap();
        let checkpoint = dir.path().join("checkpoint");
        assert!(matches!(
            source.snapshot_checkpoint(&checkpoint, 100),
            Err(Error::InvalidConfig(_))
        ));
        assert!(!checkpoint.exists());
        assert_eq!(source.get_vector(&id).unwrap(), Some(vector));
    }
}

#[test]
fn checkpoint_requeues_nonempty_summary_vectors_for_embedding() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".into());
    let source = Vault::open(dir.path().join("source"), config.clone()).unwrap();
    // The bootstrap skills' seeded claims are embedding sources as well.
    let seeded_claims = source
        .entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)
        .unwrap()
        .len();
    let id = EntityId::now();
    source
        .put_entity(
            &id,
            crate::registry::ENTITY_TYPE_SUMMARY,
            TimeRange { start: 1, end: 1 },
            1,
            b"summary rebuild source",
        )
        .unwrap();
    source.put_vector(&id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
    let checkpoint = dir.path().join("checkpoint");
    source.snapshot_checkpoint(&checkpoint, 100).unwrap();
    let (restored, report) = Vault::restore_checkpoint(
        &checkpoint,
        &dir.path().join("restored"),
        config,
        RestoreReason::Restore,
        101,
    )
    .unwrap();
    assert_eq!(
        restored.get(&id).unwrap(),
        Some(b"summary rebuild source".to_vec())
    );
    assert_eq!(report.pending_embeddings, seeded_claims + 1);
    assert!(restored.get_vector(&id).unwrap().is_none());
}
