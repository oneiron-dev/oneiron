//! Embedding-model identity gates, HNSW compat records, embedding-space migration.

use super::*;
use crate::error::StoreError;

#[test]
fn opens_empty_vault_without_embedding_model() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let mut cfg = test_config();
    cfg.embedding_model = None;
    let vault = Vault::open(temp_dir.path(), cfg)?;
    assert_eq!(read_model_id(&vault)?, None);

    Ok(())
}

#[test]
fn stamps_embedding_model_on_empty_vault_open() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let mut cfg = test_config();
    cfg.embedding_model = Some("test/model-a@v1".to_owned());
    let vault = Vault::open(temp_dir.path(), cfg)?;
    assert_eq!(read_model_id(&vault)?, Some("test/model-a@v1".to_owned()));

    Ok(())
}

#[test]
fn opens_populated_vault_with_matching_embedding_model() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let mut cfg = test_config();
    cfg.embedding_model = Some("test/model-a@v1".to_owned());
    let vault = Vault::open(temp_dir.path(), cfg.clone())?;
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;
    drop(vault);

    let reopened = Vault::open(temp_dir.path(), cfg)?;
    let restored = reopened.get_vector(&id)?.expect("stored vector");
    for (actual, expected) in restored.iter().zip([0.1, 0.2, 0.3, 0.4]) {
        assert!(
            (actual - expected).abs() <= 0.000_2,
            "f16 round trip: {actual} != {expected}"
        );
    }

    Ok(())
}

#[test]
fn rejects_populated_vault_missing_embedding_model_identity() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();
    let mut cfg = test_config();
    cfg.embedding_model = Some("test/model-a@v1".to_owned());
    let vault = Vault::open(path, cfg.clone())?;
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;

    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.hnsw_meta.delete(&mut wtxn, MODEL_ID_KEY)?;
        wtxn.commit()?;
    }
    drop(vault);

    let Err(err) = Vault::open(path, cfg) else {
        panic!("expected missing embedding model identity rejection");
    };
    assert_matches!(err, Error::InvalidConfig(_));

    Ok(())
}

#[test]
fn rejects_vault_missing_model_identity_when_hnsw_meta_marks_population() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();
    let mut cfg = test_config();
    cfg.embedding_model = Some("test/model-a@v1".to_owned());
    let vault = Vault::open(path, cfg.clone())?;

    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.hnsw_meta.delete(&mut wtxn, MODEL_ID_KEY)?;
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, COUNT_KEY, &1_u64.to_le_bytes())?;
        wtxn.commit()?;
    }
    drop(vault);

    let Err(err) = Vault::open(path, cfg) else {
        panic!("expected missing embedding model identity rejection");
    };
    assert_matches!(err, Error::InvalidConfig(_));

    Ok(())
}

#[test]
fn rejects_populated_vault_open_without_requested_embedding_model() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();
    let mut cfg = test_config();
    cfg.embedding_model = Some("test/model-a@v1".to_owned());
    let vault = Vault::open(path, cfg)?;
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;
    drop(vault);

    let mut cfg = test_config();
    cfg.embedding_model = None;
    let Err(err) = Vault::open(path, cfg) else {
        panic!("expected missing requested embedding model rejection");
    };
    assert_matches!(err, Error::InvalidConfig(_));

    Ok(())
}

#[test]
fn detects_embedding_model_mismatch_on_populated_open() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let mut cfg = test_config();
    cfg.embedding_model = Some("test/model-a@v1".to_owned());
    let vault = Vault::open(temp_dir.path(), cfg)?;
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;
    drop(vault);

    let mut cfg = test_config();
    cfg.embedding_model = Some("test/model-b@v1".to_owned());
    let Err(err) = Vault::open(temp_dir.path(), cfg) else {
        panic!("expected mismatch");
    };
    assert_matches!(err, Error::Store(StoreError::EmbeddingModelChanged {
            ref stored,
            ref requested
        }) if stored == "test/model-a@v1" && requested == "test/model-b@v1");

    Ok(())
}

#[test]
fn rejects_vector_write_without_embedding_model_identity() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let mut cfg = test_config();
    cfg.embedding_model = None;
    let vault = Vault::open(temp_dir.path(), cfg)?;
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;

    let Err(err) = vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4]) else {
        panic!("expected missing embedding model rejection");
    };
    assert_matches!(err, Error::InvalidConfig(_));
    assert_eq!(vault.get_vector(&id)?, None);

    Ok(())
}

#[test]
fn persists_hnsw_metric_and_structure_tags() -> Result<()> {
    let (temp_dir, vault) = open_test_vault();
    let raw = read_hnsw_config_record(&vault)?;
    assert_eq!(raw.len(), EXPECTED_HNSW_COMPATIBILITY_LEN);
    assert_eq!(raw[0], EXPECTED_HNSW_COMPATIBILITY_VERSION);
    assert_eq!(raw[25], EXPECTED_HNSW_DISTANCE_METRIC_COSINE);
    assert_eq!(raw[26], EXPECTED_HNSW_INDEX_STRUCTURE_FLAT_NSW);
    drop(vault);

    let reopened = Vault::open(temp_dir.path(), test_config())?;
    let raw = read_hnsw_config_record(&reopened)?;
    assert_eq!(raw.len(), EXPECTED_HNSW_COMPATIBILITY_LEN);
    assert_eq!(raw[0], EXPECTED_HNSW_COMPATIBILITY_VERSION);
    assert_eq!(raw[25], EXPECTED_HNSW_DISTANCE_METRIC_COSINE);
    assert_eq!(raw[26], EXPECTED_HNSW_INDEX_STRUCTURE_FLAT_NSW);
    Ok(())
}

#[test]
fn upgrades_empty_vault_with_legacy_hnsw_compatibility_record() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();
    let cfg = test_config();
    let vault = Vault::open(path, cfg.clone())?;
    let legacy = legacy_hnsw_compatibility_record(&cfg);
    write_hnsw_config_record(&vault, &legacy)?;
    drop(vault);

    let reopened = Vault::open(path, cfg)?;
    let raw = read_hnsw_config_record(&reopened)?;
    assert_eq!(raw.len(), EXPECTED_HNSW_COMPATIBILITY_LEN);
    assert_eq!(raw[0], EXPECTED_HNSW_COMPATIBILITY_VERSION);
    assert_eq!(raw[25], EXPECTED_HNSW_DISTANCE_METRIC_COSINE);
    assert_eq!(raw[26], EXPECTED_HNSW_INDEX_STRUCTURE_FLAT_NSW);
    Ok(())
}

#[test]
fn rejects_populated_vault_with_legacy_hnsw_compatibility_record() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();
    let cfg = test_config();
    let vault = Vault::open(path, cfg.clone())?;
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;
    let legacy = legacy_hnsw_compatibility_record(&cfg);
    write_hnsw_config_record(&vault, &legacy)?;
    drop(vault);

    let Err(err) = Vault::open(path, cfg) else {
        panic!("expected legacy hnsw compatibility rejection");
    };
    assert_matches!(err, Error::Store(StoreError::HnswConfigChanged { .. }));
    Ok(())
}

#[test]
fn detects_hnsw_metric_and_structure_mismatch_on_open() -> Result<()> {
    let (temp_dir, vault) = open_test_vault();
    let mut raw = read_hnsw_config_record(&vault)?;
    assert_eq!(raw.len(), EXPECTED_HNSW_COMPATIBILITY_LEN);
    raw[25] = 2;
    raw[26] = 2;
    write_hnsw_config_record(&vault, &raw)?;
    drop(vault);

    let Err(err) = Vault::open(temp_dir.path(), test_config()) else {
        panic!("expected hnsw metric/structure mismatch");
    };
    assert_matches!(err, Error::Store(StoreError::HnswConfigChanged { .. }));
    Ok(())
}

/// Consolidated from two single-knob clones (ONE-1145): each case flips one
/// knob of the persisted HNSW config identity and pins the EXACT
/// stored/requested literal strings of the typed gate error.
#[test]
fn detects_hnsw_config_and_dimension_mismatch_on_open() {
    type Reconfigure = fn(&mut VaultConfig);
    let cases: &[(&str, Reconfigure, &str)] = &[
        (
            "ef_construction_flip",
            |cfg: &mut VaultConfig| cfg.hnsw.ef_construction += 1,
            "dimensions=4,m_max_0=64,ef_construction=201,distance_metric=cosine,index_structure=flat_nsw,fast_dims=none",
        ),
        (
            "dimensions_flip",
            |cfg: &mut VaultConfig| cfg.dimensions = 8,
            "dimensions=8,m_max_0=64,ef_construction=200,distance_metric=cosine,index_structure=flat_nsw,fast_dims=none",
        ),
    ];

    for (case_name, reconfigure, requested_literal) in cases {
        let (temp_dir, vault) = open_test_vault();
        drop(vault);

        let mut cfg = test_config();
        reconfigure(&mut cfg);
        let Err(err) = Vault::open(temp_dir.path(), cfg) else {
            panic!("case {case_name}: expected hnsw config mismatch");
        };
        match err {
            Error::Store(StoreError::HnswConfigChanged { stored, requested }) => {
                assert_eq!(
                    stored,
                    "dimensions=4,m_max_0=64,ef_construction=200,distance_metric=cosine,index_structure=flat_nsw,fast_dims=none",
                    "case {case_name}: stored literal"
                );
                assert_eq!(
                    requested, *requested_literal,
                    "case {case_name}: requested literal"
                );
            }
            other => panic!("case {case_name}: expected HnswConfigChanged, got {other:?}"),
        }
    }
}

#[test]
fn allows_ef_search_retuning_on_open() -> Result<()> {
    let (temp_dir, vault) = open_test_vault();
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;
    drop(vault);

    let mut cfg = test_config();
    cfg.hnsw.ef_search = 512;
    let reopened = Vault::open(temp_dir.path(), cfg)?;
    drop(reopened);
    Ok(())
}

#[test]
fn rejects_populated_vault_missing_hnsw_compatibility_metadata() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();
    let vault = Vault::open(path, test_config())?;
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;

    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.hnsw_meta.delete(&mut wtxn, HNSW_CONFIG_KEY)?;
        wtxn.commit()?;
    }
    drop(vault);

    let Err(err) = Vault::open(path, test_config()) else {
        panic!("expected missing compatibility metadata rejection");
    };
    assert_matches!(err, Error::InvalidConfig(_));
    Ok(())
}

#[test]
fn embedding_model_id_rejects_invalid_shape_at_every_write_door() -> Result<()> {
    for invalid in [
        "model",
        "org/name",
        "org/name@",
        "org//name@v1",
        "org/name@v1@next",
        "org@name/revision",
        "org/name/extra@v1",
        "org/name @v1",
        "org/name@v 1",
    ] {
        let temp_dir = tempfile::tempdir()?;
        let mut open_cfg = test_config();
        open_cfg.embedding_model = Some(invalid.to_owned());
        match Vault::open(temp_dir.path(), open_cfg) {
            Err(Error::InvalidConfig(_)) => {}
            Err(other) => panic!("wrong open error for {invalid}: {other:?}"),
            Ok(_) => panic!("accepted invalid model shape {invalid}"),
        }

        let mut cfg = test_config();
        cfg.embedding_model = None;
        let mut vault = Vault::open(temp_dir.path(), cfg)?;
        let id = EntityId::now();
        vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
        vault.config.embedding_model = Some(invalid.to_owned());
        assert_matches!(
            vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4]),
            Err(Error::InvalidConfig(_))
        );
        assert_eq!(read_model_id(&vault)?, None, "write door stamped {invalid}");
        assert_eq!(vault.get_vector(&id)?, None, "write door stored {invalid}");

        assert_matches!(
            vault.begin_embedding_migration(invalid),
            Err(Error::InvalidConfig(_))
        );
        assert_eq!(read_model_id(&vault)?, None, "migration stamped {invalid}");
        assert_eq!(vault.get_vector(&id)?, None, "migration stored {invalid}");
    }
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn embedding_migration_invalidates_inflight_async_fill_token() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let mut cfg = test_config();
    cfg.embedding_model = Some("test/old@v1".to_owned());
    let mut vault = Vault::open_unseeded_for_test(temp_dir.path(), cfg)?;
    let id = EntityId::now();
    let policy_id = crate::gate::default_policy_manifest_id()?;
    vault.with_write_txn(|wtxn| {
        crate::batch::deindex_entity_for_test(&vault.store, wtxn, &policy_id)
    })?;
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_CLAIM,
            test_time_range(1, 1),
            1,
            &crate::claim::encode_claim_body(&public_stamped(crate::claim::ClaimBody::new(
                "test.inflight",
                crate::claim::ClaimSubject::Entity(seeded_entity_id(0xC1A1)),
                rmpv::Value::from("needle"),
                0.9,
                crate::claim::ClaimApprovalStatus::Auto,
                crate::claim::ClaimLifecycleStatus::Active,
            )?))?,
        )
        .commit()?;
    let token = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .pending_embedding_token(&rtxn, &id)?
            .expect("pending token")
    };
    vault.begin_embedding_migration("test/new@v2")?;
    vault
        .batch()
        .vector_for_pending_embedding(&id, &[1.0, 0.0, 0.0, 0.0], &token)
        .commit()?;
    assert_eq!(vault.get_vector(&id)?, None);
    let replacement = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .pending_embedding_token(&rtxn, &id)?
            .expect("replacement token")
    };
    assert_ne!(replacement, token);
    let vault = Arc::new(vault);
    let queue = SyncQueue::new(Arc::clone(&vault))?;
    assert!(
        queue
            .drain_embed_jobs()?
            .iter()
            .any(|job| job.entity_id == id)
    );
    let embedder = Arc::new(MigrationEmbedder {
        model_id: "test/new@v2".to_owned(),
    });
    let report = PendingEmbeddingReconciler::new(Arc::clone(&vault), embedder).reconcile_once()?;
    assert_eq!(report.filled, 1);
    assert_eq!(vault.get_vector(&id)?, Some(vec![0.0, 1.0, 0.0, 0.0]));
    Ok(())
}

#[test]
fn legacy_v1_marker_cannot_fill_after_embedding_epoch_change() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let mut cfg = test_config();
    cfg.embedding_model = Some("test/old@v1".to_owned());
    let mut vault = Vault::open(temp_dir.path(), cfg)?;
    let id = EntityId::now();
    let policy_id = crate::gate::default_policy_manifest_id()?;
    vault.with_write_txn(|wtxn| {
        crate::batch::deindex_entity_for_test(&vault.store, wtxn, &policy_id)
    })?;
    let body = crate::claim::encode_claim_body(&public_stamped(crate::claim::ClaimBody::new(
        "test.legacy_marker",
        crate::claim::ClaimSubject::Entity(seeded_entity_id(0xC1A1)),
        rmpv::Value::from("legacy marker body"),
        0.9,
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
    )?))?;
    vault
        .batch()
        .put(
            &id,
            crate::registry::ENTITY_TYPE_CLAIM,
            test_time_range(1, 1),
            1,
            &body,
        )
        .commit()?;

    let mut legacy_marker = [0_u8; 33];
    legacy_marker[0] = 1;
    legacy_marker[1..].copy_from_slice(&Sha256::digest(&body));
    let marker_key = crate::store::Store::pending_embedding_marker_key(&id);
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .sync_state
            .put(wtxn, marker_key.as_str(), &legacy_marker)?;
        Ok(())
    })?;
    vault.begin_embedding_migration("test/new@v2")?;
    let current_marker = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .pending_embedding_token(&rtxn, &id)?
            .expect("migration re-marked the claim")
    };
    assert_eq!(current_marker[0], 2);
    assert_ne!(current_marker, legacy_marker);

    // A v1 row cannot prove which epoch produced its vector. Put the old row
    // back after the flip to exercise the validator, not just the migration's
    // replacement of it with an epoch-bound v2 token.
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .sync_state
            .put(wtxn, marker_key.as_str(), &legacy_marker)?;
        Ok(())
    })?;
    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(vault.store.pending_embedding_token(&rtxn, &id)?, None);
    drop(rtxn);
    assert!(!vault.with_write_txn(|wtxn| {
        vault
            .store
            .pending_embedding_matches_in_txn(wtxn, &id, &legacy_marker)
    })?);
    vault
        .batch()
        .vector_for_pending_embedding(&id, &[1.0, 0.0, 0.0, 0.0], &legacy_marker)
        .commit()?;
    assert_eq!(vault.get_vector(&id)?, None, "old-model fill is a no-op");
    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        vault
            .store
            .sync_state
            .get(&rtxn, marker_key.as_str())?
            .as_deref(),
        Some(legacy_marker.as_slice()),
        "rejected fill must not clear the marker"
    );
    drop(rtxn);

    // Fresh epoch-bound work still fills normally after the rejected attempt.
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .sync_state
            .put(wtxn, marker_key.as_str(), &current_marker)?;
        Ok(())
    })?;
    vault
        .batch()
        .vector_for_pending_embedding(&id, &[0.0, 1.0, 0.0, 0.0], &current_marker)
        .commit()?;
    assert_eq!(vault.get_vector(&id)?, Some(vec![0.0, 1.0, 0.0, 0.0]));
    Ok(())
}
#[cfg(feature = "sync")]
#[test]
fn embedding_migration_degrades_to_lexical_then_refills_without_mixing() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let mut cfg = test_config();
    cfg.embedding_model = Some("test/old@v1".to_owned());
    let mut vault = Vault::open_unseeded_for_test(temp_dir.path(), cfg)?;
    let id = EntityId::now();
    let policy_id = crate::gate::default_policy_manifest_id()?;
    vault.with_write_txn(|wtxn| {
        crate::batch::deindex_entity_for_test(&vault.store, wtxn, &policy_id)?;
        Ok(())
    })?;
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_CLAIM,
            test_time_range(1, 1),
            1,
            &crate::claim::encode_claim_body(&public_stamped(crate::claim::ClaimBody::new(
                "test.migration",
                crate::claim::ClaimSubject::Entity(seeded_entity_id(0xC1A1)),
                rmpv::Value::from("needle"),
                0.9,
                crate::claim::ClaimApprovalStatus::Auto,
                crate::claim::ClaimLifecycleStatus::Active,
            )?))?,
        )
        .text(&id, &[("body", "migration lexical needle")])
        .commit()?;
    vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;
    assert_eq!(vault.search_vector(&[1.0, 0.0, 0.0, 0.0], 10)?.len(), 1);

    // Prove same-model preserves populated space before destructive migration.
    {
        let data_path = temp_dir.path().join("data.mdb");
        let bytes_before_populated = std::fs::read(&data_path)?;
        let ver_before_pop = read_hnsw_meta_u64(&vault, VECTOR_VERSION_KEY)?;
        let epoch_before_pop = read_hnsw_meta_u64(&vault, EMBEDDING_MODEL_EPOCH_KEY)?;
        vault.begin_embedding_migration("test/old@v1")?;
        assert_eq!(std::fs::read(&data_path)?, bytes_before_populated);
        assert_eq!(
            read_hnsw_meta_u64(&vault, VECTOR_VERSION_KEY)?,
            ver_before_pop
        );
        assert_eq!(
            read_hnsw_meta_u64(&vault, EMBEDDING_MODEL_EPOCH_KEY)?,
            epoch_before_pop
        );
        assert_eq!(read_model_id(&vault)?, Some("test/old@v1".to_owned()));
    }
    vault.begin_embedding_migration("test/new@v2")?;
    assert_eq!(read_model_id(&vault)?, Some("test/new@v2".to_owned()));
    assert_eq!(vault.get_vector(&id)?, None);
    assert!(vault.search_vector(&[1.0, 0.0, 0.0, 0.0], 10)?.is_empty());
    assert_eq!(vault.search_text("lexical needle", 10)?.len(), 1);
    let vault = Arc::new(vault);
    let queue = SyncQueue::new(Arc::clone(&vault))?;
    let jobs = queue.drain_embed_jobs()?;
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].priority, crate::embed::EMBED_PRIORITY_BACKFILL);
    queue.push_embed_job(&id, crate::embed::EMBED_PRIORITY_BACKFILL)?;

    let old = Arc::new(MigrationEmbedder {
        model_id: "test/old@v1".to_owned(),
    });
    let old_reconciler = PendingEmbeddingReconciler::new(Arc::clone(&vault), old);
    assert_matches!(
        old_reconciler.reconcile_once(),
        Err(Error::Store(StoreError::EmbeddingModelChanged { .. }))
    );
    let new = Arc::new(MigrationEmbedder {
        model_id: "test/new@v2".to_owned(),
    });
    let report = PendingEmbeddingReconciler::new(Arc::clone(&vault), new).reconcile_once()?;
    assert_eq!(report.filled, 1);
    assert_eq!(vault.get_vector(&id)?, Some(vec![0.0, 1.0, 0.0, 0.0]));
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn embedding_migration_proves_atomic_space_replacement_contract() -> Result<()> {
    fn put_claim(vault: &Vault, id: &EntityId, body: &str) -> Result<()> {
        vault
            .batch()
            .put(
                id,
                ENTITY_TYPE_CLAIM,
                test_time_range(1, 1),
                1,
                &crate::claim::encode_claim_body(&public_stamped(crate::claim::ClaimBody::new(
                    "test.migration_proof",
                    crate::claim::ClaimSubject::Entity(seeded_entity_id(0xC1A1)),
                    rmpv::Value::from(body),
                    0.9,
                    crate::claim::ClaimApprovalStatus::Auto,
                    crate::claim::ClaimLifecycleStatus::Active,
                )?))?,
            )
            .text(id, &[("body", body)])
            .commit()
    }

    let temp_dir = tempfile::tempdir()?;
    let mut cfg = test_config();
    cfg.embedding_model = Some("test/old@v1".to_owned());
    let vault = Vault::open_unseeded_for_test(temp_dir.path(), cfg.clone())?;
    let policy_id = crate::gate::default_policy_manifest_id()?;
    vault.with_write_txn(|wtxn| {
        crate::batch::deindex_entity_for_test(&vault.store, wtxn, &policy_id)?;
        Ok(())
    })?;
    let first = EntityId::now();
    let second = EntityId::now();
    put_claim(&vault, &first, "migration proof first")?;
    put_claim(&vault, &second, "migration proof second")?;
    // second claim intentionally has NO vector: proves re-mark of no-vector claims per DONE-means.
    vault.put_vector(&first, &[1.0, 0.0, 0.0, 0.0])?;

    let config_before = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .hnsw_meta
            .get(&rtxn, HNSW_CONFIG_KEY)?
            .unwrap()
            .to_vec()
    };
    assert!(
        vault
            .store
            .hnsw_neighbors
            .len(&vault.store.env.read_txn()?)?
            > 0
    );
    let version_before = read_hnsw_meta_u64(&vault, VECTOR_VERSION_KEY)?;
    // Pre-migration: COUNT and entry_point must be present; seed a valid ow1 exception.
    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .hnsw_meta
                .get(&rtxn, crate::hnsw::COUNT_KEY)?
                .is_some()
        );
        assert!(vault.store.hnsw_meta.get(&rtxn, b"entry_point")?.is_some());
    }
    let ow1_key = {
        let id = EntityId::now();
        let mut k = Vec::with_capacity(4 + 16);
        k.extend_from_slice(b"ow1:");
        k.extend_from_slice(id.as_bytes());
        k
    };
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .hnsw_meta
            .put(wtxn, &ow1_key, first.as_bytes())?;
        Ok(())
    })?;

    // A hotter job and an in-flight lease belong to the retired model. Migration
    // must replace (not preserve) both when it re-marks the claim.
    let vault = Arc::new(vault);
    SyncQueue::new(Arc::clone(&vault))?.push_embed_job(&first, 0)?;
    let vault = Arc::try_unwrap(vault).unwrap_or_else(|_| panic!("sole queue owner"));
    vault.with_write_txn(|wtxn| {
        vault.store.sync_state.put(
            wtxn,
            format!("pelease:{}", first.to_hex()).as_str(),
            b"old-model-lease",
        )?;
        Ok(())
    })?;
    let mut vault = vault;

    // Prove same-model preserves populated space before destructive migration.
    {
        let data_path = temp_dir.path().join("data.mdb");
        let bytes_before_populated = std::fs::read(&data_path)?;
        let ver_before_pop = read_hnsw_meta_u64(&vault, VECTOR_VERSION_KEY)?;
        vault.begin_embedding_migration("test/old@v1")?;
        assert_eq!(std::fs::read(&data_path)?, bytes_before_populated);
        assert_eq!(
            read_hnsw_meta_u64(&vault, VECTOR_VERSION_KEY)?,
            ver_before_pop
        );
        assert_eq!(read_model_id(&vault)?, Some("test/old@v1".to_owned()));
    }
    vault.begin_embedding_migration("test/new@v2")?;
    assert_eq!(read_model_id(&vault)?, Some("test/new@v2".to_owned()));
    assert_eq!(
        read_hnsw_meta_u64(&vault, VECTOR_VERSION_KEY)?,
        version_before + 1
    );
    assert_eq!(vault.get_vector(&first)?, None);
    assert_eq!(vault.get_vector(&second)?, None);
    assert_eq!(
        vault
            .store
            .hnsw_neighbors
            .len(&vault.store.env.read_txn()?)?,
        0
    );
    assert!(
        vault
            .store
            .hnsw_meta
            .get(&vault.store.env.read_txn()?, crate::hnsw::COUNT_KEY)?
            .is_none()
    );
    assert!(
        vault
            .store
            .hnsw_meta
            .get(&vault.store.env.read_txn()?, b"entry_point")?
            .is_none()
    );
    assert!(
        vault
            .store
            .hnsw_meta
            .get(&vault.store.env.read_txn()?, &ow1_key)?
            .is_none()
    );
    let config_after = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .hnsw_meta
            .get(&rtxn, HNSW_CONFIG_KEY)?
            .unwrap()
            .to_vec()
    };
    assert_eq!(
        config_after, config_before,
        "compatibility metadata survives graph clear"
    );
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .pending_embedding_token(&rtxn, &first)?
            .is_some()
    );
    assert!(
        vault
            .store
            .pending_embedding_token(&rtxn, &second)?
            .is_some()
    );
    assert!(
        vault
            .store
            .sync_state
            .get(&rtxn, format!("pelease:{}", first.to_hex()).as_str())?
            .is_none()
    );
    drop(rtxn);
    let vault = Arc::new(vault);
    let jobs = SyncQueue::new(Arc::clone(&vault))?.drain_embed_jobs()?;
    assert_eq!(jobs.len(), 2);
    assert!(
        jobs.iter()
            .all(|job| job.priority == crate::embed::EMBED_PRIORITY_BACKFILL)
    );
    let vault = Arc::try_unwrap(vault).unwrap_or_else(|_| panic!("sole queue owner"));
    drop(vault);

    // A same-model migration takes the false branch and must not dirty LMDB bytes.
    // Snapshot is taken after reopen: Vault::open itself may seed system agents /
    // rebuild indexes on 7f1050ee (ONE-1869), so only the begin_* call must be byte-noop.
    let mut reopened = Vault::open_unseeded_for_test(
        temp_dir.path(),
        VaultConfig {
            embedding_model: Some("test/new@v2".to_owned()),
            ..cfg.clone()
        },
    )?;
    let data_path = temp_dir.path().join("data.mdb");
    let bytes_before_noop = std::fs::read(&data_path)?;
    reopened.begin_embedding_migration("test/new@v2")?;
    assert_eq!(std::fs::read(&data_path)?, bytes_before_noop);
    drop(reopened);
    assert!(matches!(
        Vault::open_unseeded_for_test(temp_dir.path(), cfg),
        Err(Error::Store(StoreError::EmbeddingModelChanged { .. }))
    ));
    assert!(
        Vault::open_unseeded_for_test(
            temp_dir.path(),
            VaultConfig {
                embedding_model: Some("test/new@v2".to_owned()),
                ..test_config()
            }
        )
        .is_ok()
    );

    // A malformed entity makes re-marking fail after model/graph/version writes
    // were staged; the transaction must leave every committed byte unchanged.
    let rollback_dir = tempfile::tempdir()?;
    let mut old_cfg = test_config();
    old_cfg.embedding_model = Some("test/old@v1".to_owned());
    let mut rollback = Vault::open_unseeded_for_test(rollback_dir.path(), old_cfg)?;
    let policy_id = crate::gate::default_policy_manifest_id()?;
    rollback.with_write_txn(|wtxn| {
        crate::batch::deindex_entity_for_test(&rollback.store, wtxn, &policy_id)
    })?;
    let id = EntityId::now();
    rollback.put_entity(&id, 1, test_time_range(1, 1), 1, b"rollback node")?;
    rollback.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;
    let pending_id = EntityId::now();
    let pending_body =
        crate::claim::encode_claim_body(&public_stamped(crate::claim::ClaimBody::new(
            "test.rollback_pending",
            crate::claim::ClaimSubject::Entity(seeded_entity_id(0xC1A1)),
            rmpv::Value::from("old marker remains current"),
            0.9,
            crate::claim::ClaimApprovalStatus::Auto,
            crate::claim::ClaimLifecycleStatus::Active,
        )?))?;
    rollback
        .batch()
        .put(
            &pending_id,
            ENTITY_TYPE_CLAIM,
            test_time_range(1, 1),
            1,
            &pending_body,
        )
        .commit()?;
    let pending_token = {
        let rtxn = rollback.store.env.read_txn()?;
        rollback
            .store
            .pending_embedding_token(&rtxn, &pending_id)?
            .expect("pending claim marker")
    };
    rollback.with_write_txn(|wtxn| {
        rollback
            .store
            .entities
            .put(wtxn, EntityId::now().as_bytes(), b"bad")?;
        Ok(())
    })?;
    let rollback_data = std::fs::read(rollback_dir.path().join("data.mdb"))?;
    let rollback_version = read_hnsw_meta_u64(&rollback, VECTOR_VERSION_KEY)?;
    let rollback_epoch = read_hnsw_meta_u64(&rollback, EMBEDDING_MODEL_EPOCH_KEY)?;
    assert_matches!(
        rollback.begin_embedding_migration("test/new@v2"),
        Err(Error::CorruptedIndex("entity header"))
    );
    assert_eq!(
        std::fs::read(rollback_dir.path().join("data.mdb"))?,
        rollback_data
    );
    assert_eq!(read_model_id(&rollback)?, Some("test/old@v1".to_owned()));
    assert_eq!(
        read_hnsw_meta_u64(&rollback, VECTOR_VERSION_KEY)?,
        rollback_version
    );
    assert_eq!(
        read_hnsw_meta_u64(&rollback, EMBEDDING_MODEL_EPOCH_KEY)?,
        rollback_epoch
    );
    let pending_after_rollback = {
        let rtxn = rollback.store.env.read_txn()?;
        rollback
            .store
            .pending_embedding_token(&rtxn, &pending_id)?
            .expect("rollback preserved pending marker")
    };
    assert_eq!(pending_after_rollback, pending_token);
    assert_eq!(rollback.get_vector(&id)?, Some(vec![1.0, 0.0, 0.0, 0.0]));
    Ok(())
}

#[test]
fn embedding_model_first_write_is_atomic() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let mut cfg = test_config();
    cfg.embedding_model = Some("test/model-x@v1".to_owned());

    let vault = Vault::open(temp_dir.path(), cfg.clone())?;
    drop(vault);

    let vault = Vault::open(temp_dir.path(), cfg)?;
    drop(vault);

    let mut cfg2 = test_config();
    cfg2.embedding_model = Some("test/model-y@v1".to_owned());
    let Err(err) = Vault::open(temp_dir.path(), cfg2) else {
        panic!("expected embedding model change rejection");
    };
    assert_matches!(err, Error::Store(StoreError::EmbeddingModelChanged { .. }));

    Ok(())
}

/// Drains `vault` with the new model until nothing is leased. Every pass must
/// succeed: a job the worker can only fail on would surface here.
#[cfg(feature = "sync")]
fn drain_with_new_model(vault: &Arc<Vault>) -> Result<()> {
    let reconciler = PendingEmbeddingReconciler::new(
        Arc::clone(vault),
        Arc::new(MigrationEmbedder {
            model_id: "test/new@v2".to_owned(),
        }),
    )
    .with_batch_size(256);
    for _ in 0..64 {
        if reconciler.reconcile_once()?.leased == 0 {
            break;
        }
    }
    Ok(())
}

/// An epoch SUMMARY is embedded like a claim, so a migration that drops its
/// vector must queue it again: the new model fills it on the next drain.
#[cfg(feature = "sync")]
#[test]
fn embedding_migration_requeues_epoch_summaries() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let mut cfg = test_config();
    cfg.embedding_model = Some("test/old@v1".to_owned());
    let mut vault = Vault::open_unseeded_for_test(temp_dir.path(), cfg)?;
    let summary = EntityId::now();
    let body =
        crate::compaction::encode_epoch_summary_body(&crate::compaction::EpochSummaryBody {
            v: crate::compaction::EPOCH_SUMMARY_BODY_VERSION,
            session: seeded_entity_id(0x5E55).to_hex(),
            epoch: 1,
            turn_start: 1,
            turn_end: 3,
            level: crate::compaction::EPOCH_SUMMARY_LEVEL,
            text: "the epoch prose".to_owned(),
            actor: seeded_entity_id(0xAC70).to_hex(),
        })?;
    vault
        .batch()
        .put(
            &summary,
            crate::registry::ENTITY_TYPE_SUMMARY,
            test_time_range(1, 1),
            1,
            &body,
        )
        .commit()?;
    // Filled under the old model: a vector, no marker, no job.
    vault.put_vector(&summary, &[1.0, 0.0, 0.0, 0.0])?;

    vault.begin_embedding_migration("test/new@v2")?;
    assert_eq!(vault.get_vector(&summary)?, None);
    let vault = Arc::new(vault);
    drain_with_new_model(&vault)?;
    assert_eq!(vault.get_vector(&summary)?, Some(vec![0.0, 1.0, 0.0, 0.0]));
    Ok(())
}

/// Lexical query hints are lexical-only claims. A migration queues none of
/// them, and drops the marker and job one still carries, so the drain finishes
/// with every real claim refilled and no job left behind.
#[cfg(feature = "sync")]
#[test]
fn embedding_migration_leaves_no_work_for_lexical_hint_claims() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let mut cfg = test_config();
    cfg.embedding_model = Some("test/old@v1".to_owned());
    let mut vault = Vault::open(temp_dir.path(), cfg)?;
    let actor = EntityId::now();
    let subject = EntityId::now();
    for id in [&actor, &subject] {
        vault.put_entity(id, ENTITY_TYPE_PERSON, test_time_range(1, 1), 1, b"person")?;
    }
    let claim = EntityId::now();
    vault
        .batch()
        .claim_candidate_with_lexical_hints(
            &claim,
            crate::ClaimCandidate::new(
                "profile.preference",
                crate::claim::ClaimSubject::Entity(subject),
                rmpv::Value::from("sencha"),
                0.9,
            ),
            &crate::WriteEnvelope::new(
                crate::WriteActor::new(actor, crate::EdgeActorClass::Human),
                crate::claim::ClaimSource::UserStated,
                crate::WriteProvenance::new(rmpv::Value::from("fixture"))?,
                crate::claim::ClaimApprovalStatus::Approved,
            ),
            test_time_range(10, 10),
            11,
            &["which tea", "favourite drink"],
        )
        .commit()?;
    let hints: Vec<EntityId> = vault
        .entities_by_type(ENTITY_TYPE_CLAIM)?
        .into_iter()
        .filter(|id| {
            vault
                .get_raw(id)
                .ok()
                .flatten()
                .and_then(|raw| {
                    crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true).ok()
                })
                .is_some_and(|body| body.predicate == crate::claim::PREDICATE_LEXICAL_QUERY_HINT)
        })
        .collect();
    assert!(!hints.is_empty(), "the write produced hint claims");
    // Work an earlier sweep left on the hints: a marker and a queued job each.
    vault.with_write_txn(|wtxn| {
        for hint in &hints {
            let raw = vault
                .store
                .entities
                .get(&*wtxn, hint.as_bytes())?
                .map(|raw| raw.to_vec())
                .expect("hint row");
            vault
                .store
                .mark_pending_embedding(wtxn, hint, &raw[ENTITY_METADATA_HEADER_LEN..])?;
            crate::sync::queue::push_embed_job_in_txn(
                &vault.store,
                wtxn,
                hint,
                crate::embed::EMBED_PRIORITY_BACKFILL,
            )?;
        }
        Ok(())
    })?;

    vault.begin_embedding_migration("test/new@v2")?;
    let vault = Arc::new(vault);
    drain_with_new_model(&vault)?;
    assert!(
        vault.get_vector(&claim)?.is_some(),
        "the real claim refills"
    );
    for hint in &hints {
        assert_eq!(vault.get_vector(hint)?, None);
        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(vault.store.pending_embedding_token(&rtxn, hint)?, None);
    }
    assert!(
        SyncQueue::new(Arc::clone(&vault))?
            .drain_embed_jobs()?
            .is_empty(),
        "no job is left behind"
    );
    Ok(())
}

/// The refill runs the migration's swap under the pin the vault already
/// holds: every vector dropped, every record queued and filled again.
#[cfg(feature = "sync")]
#[test]
fn refilling_the_embedding_space_keeps_the_pin_and_refills_every_record() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let mut cfg = test_config();
    cfg.embedding_model = Some("test/new@v2".to_owned());
    let mut vault = Vault::open_unseeded_for_test(temp_dir.path(), cfg)?;
    let id = EntityId::now();
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_CLAIM,
            test_time_range(1, 1),
            1,
            &crate::claim::encode_claim_body(&public_stamped(crate::claim::ClaimBody::new(
                "test.refill",
                crate::claim::ClaimSubject::Entity(seeded_entity_id(0xC1A1)),
                rmpv::Value::from("needle"),
                0.9,
                crate::claim::ClaimApprovalStatus::Auto,
                crate::claim::ClaimLifecycleStatus::Active,
            )?))?,
        )
        .commit()?;
    vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;
    let epoch = read_hnsw_meta_u64(&vault, EMBEDDING_MODEL_EPOCH_KEY)?;

    vault.refill_embedding_space()?;
    assert_eq!(read_model_id(&vault)?, Some("test/new@v2".to_owned()));
    assert!(read_hnsw_meta_u64(&vault, EMBEDDING_MODEL_EPOCH_KEY)? > epoch);
    assert_eq!(vault.get_vector(&id)?, None);
    let vault = Arc::new(vault);
    drain_with_new_model(&vault)?;
    assert_eq!(vault.get_vector(&id)?, Some(vec![0.0, 1.0, 0.0, 0.0]));
    Ok(())
}

const TRANSFORM_A: &str = "attn=bidirectional;pool=mean;dims=4";
const TRANSFORM_B: &str = "attn=causal;pool=mean;dims=4";

fn stored_transform(vault: &Vault) -> Result<Option<String>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .hnsw_meta
        .get(&rtxn, crate::store::EMBEDDING_TRANSFORM_KEY)?
        .map(|raw| String::from_utf8_lossy(&raw).into_owned()))
}

fn transform_config(transform: Option<&str>) -> VaultConfig {
    let mut cfg = test_config();
    cfg.embedding_transform = transform.map(str::to_owned);
    cfg
}

/// The transform is pinned beside the model on first open. Another one is a
/// typed refusal that writes nothing, so it refuses again after a restart; a
/// host that declares none is not checked.
#[test]
fn an_embedding_transform_is_pinned_and_another_is_refused() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), transform_config(Some(TRANSFORM_A)))?;
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;
    assert_eq!(stored_transform(&vault)?.as_deref(), Some(TRANSFORM_A));
    drop(vault);

    for _restart in 0..2 {
        assert_matches!(
            Vault::open(temp_dir.path(), transform_config(Some(TRANSFORM_B))).err(),
            Some(Error::Store(StoreError::EmbeddingTransformChanged { .. }))
        );
    }
    let vault = Vault::open(temp_dir.path(), transform_config(None))?;
    assert_eq!(stored_transform(&vault)?.as_deref(), Some(TRANSFORM_A));
    drop(vault);
    Vault::open(temp_dir.path(), transform_config(Some(TRANSFORM_A)))?;
    Ok(())
}

/// A vault filled before the pin existed has none, and adopts the first one
/// it is opened with, populated or not.
#[test]
fn a_vault_without_a_pinned_transform_adopts_the_first_one_declared() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), transform_config(None))?;
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;
    assert_eq!(stored_transform(&vault)?, None);
    drop(vault);

    let vault = Vault::open(temp_dir.path(), transform_config(Some(TRANSFORM_A)))?;
    assert_eq!(stored_transform(&vault)?.as_deref(), Some(TRANSFORM_A));
    assert!(
        vault.get_vector(&id)?.is_some(),
        "adopting keeps the vectors"
    );
    drop(vault);
    assert_matches!(
        Vault::open(temp_dir.path(), transform_config(Some(TRANSFORM_B))).err(),
        Some(Error::Store(StoreError::EmbeddingTransformChanged { .. }))
    );
    Ok(())
}

/// A transform declared only after open — a model whose files arrived later —
/// is adopted where none is pinned and refused where another is.
#[test]
fn a_transform_learned_after_open_is_adopted_or_refused() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), transform_config(None))?;
    vault.adopt_embedding_transform(TRANSFORM_A)?;
    vault.adopt_embedding_transform(TRANSFORM_A)?;
    assert_eq!(stored_transform(&vault)?.as_deref(), Some(TRANSFORM_A));
    assert_matches!(
        vault.adopt_embedding_transform(TRANSFORM_B),
        Err(Error::Store(StoreError::EmbeddingTransformChanged { .. }))
    );
    assert_eq!(stored_transform(&vault)?.as_deref(), Some(TRANSFORM_A));
    Ok(())
}

/// A transform change under the same model is a migration: the vectors go,
/// both pins move in one transaction, and the new transform opens.
#[test]
fn a_transform_change_under_the_same_model_migrates_the_space() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let mut vault = Vault::open(temp_dir.path(), transform_config(Some(TRANSFORM_A)))?;
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;
    let version = read_hnsw_meta_u64(&vault, VECTOR_VERSION_KEY)?;

    vault.migrate_embedding_space("test/model@v1", TRANSFORM_A)?;
    assert!(
        vault.get_vector(&id)?.is_some(),
        "the same pins are left alone"
    );
    vault.migrate_embedding_space("test/model@v1", TRANSFORM_B)?;
    assert_eq!(vault.get_vector(&id)?, None);
    assert!(read_hnsw_meta_u64(&vault, VECTOR_VERSION_KEY)? > version);
    assert_eq!(read_model_id(&vault)?.as_deref(), Some("test/model@v1"));
    assert_eq!(stored_transform(&vault)?.as_deref(), Some(TRANSFORM_B));
    drop(vault);
    Vault::open(temp_dir.path(), transform_config(Some(TRANSFORM_B)))?;
    assert_matches!(
        Vault::open(temp_dir.path(), transform_config(Some(TRANSFORM_A))).err(),
        Some(Error::Store(StoreError::EmbeddingTransformChanged { .. }))
    );

    // A move to another model without a declared transform drops the old one.
    let mut vault = Vault::open(temp_dir.path(), transform_config(None))?;
    vault.begin_embedding_migration("test/other@v2")?;
    assert_eq!(stored_transform(&vault)?, None);
    Ok(())
}

/// A write checks the transform its handle declares against the vault's pin
/// as the write's own transaction sees it, beside the model. A handle another
/// process migrated past is stale, and its vectors are refused — written or
/// staged — rather than filed under the other transform. A handle that
/// declares none is not checked.
#[test]
fn a_vector_write_rechecks_the_declared_transform() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), transform_config(Some(TRANSFORM_A)))?;
    let clean = EntityId::now();
    vault.put_entity(&clean, 1, test_time_range(1, 1), 1, b"node")?;
    vault.put_vector(&clean, &[1.0, 0.0, 0.0, 0.0])?;
    let text = |content: &str| rmp_serde::to_vec_named(&serde_json::json!({ "content": content }));
    let edited = EntityId::now();
    for content in ["first", "second"] {
        vault
            .batch()
            .put(
                &edited,
                crate::registry::ENTITY_TYPE_ASSET_TEXT,
                test_time_range(1, 1),
                1,
                &text(content).expect("body"),
            )
            .commit()?;
    }

    // What another process's migration to transform B leaves in the vault.
    vault.with_write_txn(|wtxn| {
        vault.store.hnsw_meta.put(
            wtxn,
            crate::store::EMBEDDING_TRANSFORM_KEY,
            TRANSFORM_B.as_bytes(),
        )?;
        Ok(())
    })?;
    assert_matches!(
        vault.put_vector(&clean, &[0.0, 1.0, 0.0, 0.0]),
        Err(Error::Store(StoreError::EmbeddingTransformChanged { .. }))
    );
    assert_matches!(
        vault.put_vector(&edited, &[0.0, 1.0, 0.0, 0.0]),
        Err(Error::Store(StoreError::EmbeddingTransformChanged { .. })),
        "a vector staged for an unpublished revision is checked too"
    );
    assert_eq!(vault.get_vector(&clean)?, Some(vec![1.0, 0.0, 0.0, 0.0]));
    drop(vault);

    let vault = Vault::open(temp_dir.path(), transform_config(None))?;
    vault.put_vector(&clean, &[0.0, 1.0, 0.0, 0.0])?;
    Ok(())
}

/// A migration to the pins the vault already holds succeeds without a swap,
/// and leaves the handle that asked on those pins: a handle another process
/// migrated past writes again, with no vector dropped and no epoch advanced
/// for it. Asking for the same model with no transform keeps the stored one.
#[test]
fn a_migration_already_done_brings_a_stale_handle_up_to_the_vault() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let mut vault = Vault::open(temp_dir.path(), transform_config(Some(TRANSFORM_A)))?;
    let model = read_model_id(&vault)?.expect("a pinned model");
    let epoch_key = crate::store::EMBEDDING_MODEL_EPOCH_KEY;
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
    vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;
    let restamp = |vault: &Vault, transform: &str| {
        // What another process's migration to `transform` leaves in the vault.
        vault.with_write_txn(|wtxn| {
            vault.store.hnsw_meta.put(
                wtxn,
                crate::store::EMBEDDING_TRANSFORM_KEY,
                transform.as_bytes(),
            )?;
            Ok(())
        })
    };

    restamp(&vault, TRANSFORM_B)?;
    let epoch = read_hnsw_meta_u64(&vault, epoch_key)?;
    vault.migrate_embedding_space(&model, TRANSFORM_B)?;
    assert_eq!(read_hnsw_meta_u64(&vault, epoch_key)?, epoch);
    assert_eq!(vault.get_vector(&id)?, Some(vec![1.0, 0.0, 0.0, 0.0]));
    vault.put_vector(&id, &[0.0, 1.0, 0.0, 0.0])?;

    restamp(&vault, TRANSFORM_A)?;
    vault.begin_embedding_migration(&model)?;
    assert_eq!(read_hnsw_meta_u64(&vault, epoch_key)?, epoch);
    assert_eq!(stored_transform(&vault)?.as_deref(), Some(TRANSFORM_A));
    vault.put_vector(&id, &[0.0, 0.0, 1.0, 0.0])?;
    assert_eq!(vault.get_vector(&id)?, Some(vec![0.0, 0.0, 1.0, 0.0]));
    Ok(())
}

/// A migration in a build without the sync queue marks every claim but can
/// queue none, so it leaves the deferred-backfill marker set, and the first
/// serving open queues them from it (cold attach). A serving build queues
/// them in the swap itself and needs no marker.
#[test]
fn a_migration_that_cannot_queue_leaves_the_backfill_to_the_next_serving_open() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let mut cfg = test_config();
    cfg.embedding_model = Some("test/old@v1".to_owned());
    let mut vault = Vault::open_unseeded_for_test(temp_dir.path(), cfg.clone())?;
    let claim = EntityId::now();
    vault
        .batch()
        .put(
            &claim,
            crate::registry::ENTITY_TYPE_CLAIM,
            test_time_range(1, 1),
            1,
            &crate::claim::encode_claim_body(&public_stamped(crate::claim::ClaimBody::new(
                "test.backfill",
                crate::claim::ClaimSubject::Entity(seeded_entity_id(0xBAC1)),
                rmpv::Value::from("needle"),
                0.9,
                crate::claim::ClaimApprovalStatus::Auto,
                crate::claim::ClaimLifecycleStatus::Active,
            )?))?,
        )
        .commit()?;
    vault.put_vector(&claim, &[1.0, 0.0, 0.0, 0.0])?;

    vault.begin_embedding_migration("test/new@v2")?;
    let marked = |vault: &Vault| -> Result<bool> {
        let rtxn = vault.store.env.read_txn()?;
        Ok(vault
            .store
            .hnsw_meta
            .get(&rtxn, crate::embed::COLD_ATTACH_PENDING_KEY)?
            .is_some())
    };
    assert_eq!(marked(&vault)?, !cfg!(feature = "sync"));
    cfg.embedding_model = Some("test/new@v2".to_owned());

    #[cfg(not(feature = "sync"))]
    {
        drop(vault);
        let vault = Vault::open_unseeded_for_test(temp_dir.path(), cfg)?;
        assert!(
            vault.cold_attach_embedder()? >= 1,
            "the claim is marked again"
        );
        assert!(marked(&vault)?, "and the marker waits for a serving open");
    }
    #[cfg(feature = "sync")]
    {
        // What the same swap leaves in a build without the queue: the claim
        // marked, no job, the marker set.
        vault.with_write_txn(|wtxn| {
            crate::sync::queue::delete_embed_job_in_txn(&vault.store, wtxn, &claim)?;
            vault
                .store
                .hnsw_meta
                .put(wtxn, crate::embed::COLD_ATTACH_PENDING_KEY, b"1")?;
            Ok(())
        })?;
        drop(vault);
        let vault = Arc::new(Vault::open_unseeded_for_test(temp_dir.path(), cfg)?);
        assert!(vault.cold_attach_embedder()? >= 1);
        assert!(!marked(&vault)?, "the serving open consumed it");
        drain_with_new_model(&vault)?;
        assert_eq!(vault.get_vector(&claim)?, Some(vec![0.0, 1.0, 0.0, 0.0]));
    }
    Ok(())
}
