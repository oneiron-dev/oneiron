//! Embedding-model identity gates, HNSW compat records, embedding-space migration.

use super::*;

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
    assert_matches!(err, Error::InvalidConfig(ref message)
            if message.contains("missing embedding model identity"));

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
    assert_matches!(err, Error::InvalidConfig(ref message)
            if message.contains("missing embedding model identity"));

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
    assert_matches!(err, Error::InvalidConfig(ref message)
            if message.contains("embedding model is required to open"));

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
    assert_matches!(err, Error::EmbeddingModelChanged {
            ref stored,
            ref requested
        } if stored == "test/model-a@v1" && requested == "test/model-b@v1");

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
    assert_matches!(err, Error::InvalidConfig(ref message)
            if message.contains("embedding model is required before writing vectors"));
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
    assert_matches!(err, Error::HnswConfigChanged {
            ref stored,
            ref requested
        } if stored == "dimensions=4,m_max_0=64,ef_construction=200,distance_metric=missing,index_structure=missing,fast_dims=none"
            && requested == "dimensions=4,m_max_0=64,ef_construction=200,distance_metric=cosine,index_structure=flat_nsw,fast_dims=none");
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
    assert_matches!(err, Error::HnswConfigChanged {
            ref stored,
            ref requested
        } if stored == "dimensions=4,m_max_0=64,ef_construction=200,distance_metric=unknown(2),index_structure=unknown(2),fast_dims=none"
            && requested == "dimensions=4,m_max_0=64,ef_construction=200,distance_metric=cosine,index_structure=flat_nsw,fast_dims=none");
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
            Error::HnswConfigChanged { stored, requested } => {
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
    assert_matches!(err, Error::InvalidConfig(ref message)
            if message.contains("missing complete vector/hnsw compatibility metadata"));
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
    let mut vault = Vault::open(temp_dir.path(), cfg)?;
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
            )))?,
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

#[cfg(feature = "sync")]
#[test]
fn legacy_v1_marker_accepted_until_migration_then_rejected() -> Result<()> {
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
    )))?;
    vault
        .batch()
        .put(&id, ENTITY_TYPE_CLAIM, test_time_range(1, 1), 1, &body)
        .commit()?;

    let mut legacy_marker = [0_u8; 33];
    legacy_marker[0] = 1;
    legacy_marker[1..].copy_from_slice(&Sha256::digest(&body));
    let marker_key = format!("pe:{}", id.to_hex());
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .sync_state
            .put(wtxn, marker_key.as_str(), &legacy_marker)?;
        Ok(())
    })?;
    let accepted_legacy_marker = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .pending_embedding_token(&rtxn, &id)?
            .expect("v1 marker remains accepted before migration")
    };
    assert_eq!(accepted_legacy_marker, legacy_marker);
    assert!(vault.with_write_txn(|wtxn| {
        vault
            .store
            .pending_embedding_matches_in_txn(wtxn, &id, &legacy_marker)
    })?);
    vault
        .batch()
        .vector_for_pending_embedding(&id, &[1.0, 0.0, 0.0, 0.0], &legacy_marker)
        .commit()?;
    assert_eq!(vault.get_vector(&id)?, Some(vec![1.0, 0.0, 0.0, 0.0]));
    let cleared = {
        let rtxn = vault.store.env.read_txn()?;
        vault.store.pending_embedding_token(&rtxn, &id)?
    };
    assert_eq!(cleared, None, "accepted legacy fill clears its marker");

    // Restore the legacy value after proving acceptance so migration itself must replace it.
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .sync_state
            .put(wtxn, marker_key.as_str(), &legacy_marker)?;
        Ok(())
    })?;

    vault.begin_embedding_migration("test/new@v2")?;
    let v2_marker = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .sync_state
            .get(&rtxn, marker_key.as_str())?
            .expect("migration re-marked claim")
            .to_vec()
    };
    assert_eq!(v2_marker.len(), legacy_marker.len());
    assert_eq!(v2_marker[0], 2, "migration stores a v2 marker");
    assert_ne!(v2_marker, legacy_marker);

    vault
        .batch()
        .vector_for_pending_embedding(&id, &[1.0, 0.0, 0.0, 0.0], &legacy_marker)
        .commit()?;
    assert_eq!(vault.get_vector(&id)?, None, "old v1 fill is a no-op");
    let v2_marker_after_old_fill = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .sync_state
            .get(&rtxn, marker_key.as_str())?
            .expect("v2 marker survives rejected v1 fill")
            .to_vec()
    };
    assert_eq!(v2_marker_after_old_fill, v2_marker);

    let vault = Arc::new(vault);
    let jobs = SyncQueue::new(Arc::clone(&vault))?.drain_embed_jobs()?;
    assert!(jobs.iter().any(|job| {
        job.entity_id == id && job.priority == crate::embed::EMBED_PRIORITY_BACKFILL
    }));
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn embedding_migration_degrades_to_lexical_then_refills_without_mixing() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let mut cfg = test_config();
    cfg.embedding_model = Some("test/old@v1".to_owned());
    let mut vault = Vault::open(temp_dir.path(), cfg)?;
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
            )))?,
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
        Err(Error::EmbeddingModelChanged { .. })
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
                )))?,
            )
            .text(id, &[("body", body)])
            .commit()
    }

    let temp_dir = tempfile::tempdir()?;
    let mut cfg = test_config();
    cfg.embedding_model = Some("test/old@v1".to_owned());
    let vault = Vault::open(temp_dir.path(), cfg.clone())?;
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
    let mut reopened = Vault::open(
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
        Vault::open(temp_dir.path(), cfg),
        Err(Error::EmbeddingModelChanged { .. })
    ));
    assert!(
        Vault::open(
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
    let mut rollback = Vault::open(rollback_dir.path(), old_cfg)?;
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
        )))?;
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
    assert_matches!(err, Error::EmbeddingModelChanged { .. });

    Ok(())
}
