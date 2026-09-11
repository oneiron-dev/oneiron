//! Vector writes, HNSW search/recall, validation and sync-protocol error taxonomy.

use super::*;
#[cfg(feature = "sync")]
use crate::error::SyncError;

#[test]
fn put_get_vectors_and_validate_dimensions() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let vector = [0.1_f32, 0.2, 0.3, 0.4];

    vault.put_vector(&id, &vector)?;
    let got = vault.get_vector(&id)?.ok_or(Error::EntityNotFound)?;
    // Persisted vector rows are the canonical EMB-3 `VECTOR_ROW_FORMAT_F16_V1`
    // two-byte-per-component format, so a round-trip is f16-quantized by
    // design and exact f32 equality is not the writer's promise. Assert the
    // componentwise error bound instead; it is far tighter than f16's ~1e-3
    // resolution at this magnitude while still catching any real corruption,
    // reordering, or truncation.
    assert_eq!(got.len(), vector.len(), "round-trip must preserve arity");
    for (index, (&got, &want)) in got.iter().zip(vector.iter()).enumerate() {
        assert!(
            (got - want).abs() <= 0.001,
            "component {index} outside the f16 round-trip bound: got {got}, want {want}"
        );
    }

    let bad = [1.0_f32, 2.0, 3.0];
    let err = vault
        .put_vector(&EntityId::now(), &bad)
        .expect_err("expected dimension mismatch");
    assert_matches!(
        err,
        Error::DimensionMismatch {
            expected: 4,
            got: 3
        }
    );

    Ok(())
}

#[test]
fn put_vector_routes_through_hnsw_insert() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let vector = [0.1_f32, 0.2, 0.3, 0.4];

    vault.put_vector(&id, &vector)?;

    let rtxn = vault.store.env.read_txn()?;
    let count_raw = vault
        .store
        .hnsw_meta
        .get(&rtxn, b"count")?
        .ok_or(Error::EntityNotFound)?;
    let count = u64::from_le_bytes(
        count_raw
            .as_ref()
            .try_into()
            .map_err(|_| Error::InvalidKey)?,
    );
    assert_eq!(count, 1);

    let entry_point = vault
        .store
        .hnsw_meta
        .get(&rtxn, b"entry_point")?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(entry_point.as_ref(), id.as_bytes());

    assert!(
        vault
            .store
            .hnsw_neighbors
            .get(&rtxn, id.as_bytes())?
            .is_some()
    );
    Ok(())
}

#[test]
fn vector_version_bumps_once_per_batch_commit() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let a = EntityId::now();
    let b = EntityId::now();

    assert_eq!(read_hnsw_meta_u64(&vault, VECTOR_VERSION_KEY)?, 0);

    vault
        .batch()
        .vector(&a, &[0.1_f32, 0.2, 0.3, 0.4])
        .vector(&b, &[0.4_f32, 0.3, 0.2, 0.1])
        .commit()?;
    assert_eq!(read_hnsw_meta_u64(&vault, VECTOR_VERSION_KEY)?, 1);

    vault.batch().delete(&a).delete(&b).commit()?;
    assert_eq!(read_hnsw_meta_u64(&vault, VECTOR_VERSION_KEY)?, 2);
    Ok(())
}

#[test]
fn search_vector_empty_graph_and_dimension_validation() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let empty = vault.search_vector(&[0.1_f32, 0.2, 0.3, 0.4], 10)?;
    assert!(empty.is_empty());

    let err = vault
        .search_vector(&[1.0_f32, 2.0, 3.0], 5)
        .expect_err("expected dimension mismatch");
    assert_matches!(
        err,
        Error::DimensionMismatch {
            expected: 4,
            got: 3
        }
    );
    Ok(())
}

#[test]
fn search_vector_skips_deleted_nodes() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let entry = EntityId::now();
    let deleted = EntityId::now();
    let live = EntityId::now();

    for id in [entry, deleted, live] {
        vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"vector-node")?;
    }

    vault.put_vector(&entry, &[1.0_f32, 0.0, 0.0, 0.0])?;
    vault.put_vector(&deleted, &[0.98_f32, 0.05, 0.0, 0.0])?;
    vault.put_vector(&live, &[0.0_f32, 1.0, 0.0, 0.0])?;

    assert!(vault.delete_entity(&deleted)?);

    let results = vault.search_vector(&[0.98_f32, 0.05, 0.0, 0.0], 3)?;
    assert!(!results.iter().any(|item| item.id == deleted));
    assert!(results.iter().any(|item| item.id == entry));
    Ok(())
}

#[test]
fn search_vector_ignores_reserved_sentinel_neighbors() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let entry = EntityId::now();
    let live = EntityId::now();

    vault.put_entity(&entry, 1, test_time_range(1, 1), 1, b"entry")?;
    vault.put_entity(&live, 1, test_time_range(1, 1), 1, b"live")?;
    vault.put_vector(&entry, &[1.0_f32, 0.0, 0.0, 0.0])?;
    vault.put_vector(&live, &[0.0_f32, 1.0, 0.0, 0.0])?;

    let mut corrupted = Vec::with_capacity(ENTITY_ID_LEN * 2);
    corrupted.extend_from_slice(&[0x00; ENTITY_ID_LEN]);
    corrupted.extend_from_slice(live.as_bytes());

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .hnsw_neighbors
        .put(&mut wtxn, entry.as_bytes(), &corrupted)?;
    wtxn.commit()?;

    let results = vault.search_vector(&[0.0_f32, 1.0, 0.0, 0.0], 5)?;
    assert!(results.iter().any(|item| item.id == live));
    Ok(())
}

#[test]
fn search_after_entry_point_deleted() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let entry = EntityId::now();
    let survivor = EntityId::now();

    vault.put_entity(&entry, 1, test_time_range(1, 1), 1, b"entry")?;
    vault.put_entity(&survivor, 1, test_time_range(1, 1), 1, b"survivor")?;
    vault.put_vector(&entry, &[1.0_f32, 0.0, 0.0, 0.0])?;
    vault.put_vector(&survivor, &[0.0_f32, 1.0, 0.0, 0.0])?;

    assert_eq!(vault.search_vector(&[1.0_f32, 0.0, 0.0, 0.0], 5)?.len(), 2);
    assert!(vault.delete_entity(&entry)?);

    let results = vault.search_vector(&[0.0_f32, 1.0, 0.0, 0.0], 5)?;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, survivor);

    Ok(())
}

#[test]
fn validates_non_finite_vector_and_edge_weights() {
    let (_dir, vault) = open_test_vault();

    let vector_err = vault
        .put_vector(&EntityId::now(), &[1.0_f32, f32::NAN, 2.0, 3.0])
        .expect_err("expected invalid vector");
    let Error::InvalidVector { index, value } = vector_err else {
        panic!("expected invalid vector, got {vector_err:?}");
    };
    assert_eq!(index, 1);
    assert!(value.is_nan());

    let inf_err = vault
        .put_vector(&EntityId::now(), &[1.0_f32, f32::INFINITY, 2.0, 3.0])
        .expect_err("expected invalid vector");
    assert_matches!(
        inf_err,
        Error::InvalidVector { index: 1, value }
            if value.is_infinite() && value.is_sign_positive()
    );

    let edge_err = vault
        .put_edge(
            &EntityId::now(),
            EdgeKind::Supports,
            &EntityId::now(),
            f32::INFINITY,
        )
        .expect_err("expected invalid edge weight");
    let Error::InvalidEdgeWeight { value } = edge_err else {
        panic!("expected invalid edge weight, got {edge_err:?}");
    };
    assert!(value.is_infinite());
}

#[test]
fn error_kind_and_retryable_classify_validation_errors() {
    let vector = Error::InvalidVector {
        index: 0,
        value: f32::NAN,
    };
    assert_eq!(vector.kind(), ErrorKind::InvalidVector);
    assert!(!vector.is_retryable());

    let concurrent = Error::ConcurrentWrite("retry maintenance");
    assert_eq!(concurrent.kind(), ErrorKind::ConcurrentWrite);
    assert!(concurrent.is_retryable());

    let timeout = Error::Io(std::io::Error::from(std::io::ErrorKind::TimedOut));
    assert_eq!(timeout.kind(), ErrorKind::Io);
    assert!(timeout.is_retryable());
}

#[cfg(feature = "sync")]
#[test]
fn sync_protocol_errors_carry_typed_context_and_engine_source() {
    let protocol = Error::sync_protocol(SyncProtocolValidation::Selector {
        reason: SyncSelectorValidation::ForeignWorldId,
    });
    assert_eq!(protocol.kind(), ErrorKind::SyncProtocolError);
    assert_matches!(
        protocol,
        Error::Sync(SyncError::SyncProtocolError {
            context: SyncProtocolValidation::Selector {
                reason: SyncSelectorValidation::ForeignWorldId
            }
        })
    );

    let source = std::io::Error::from(std::io::ErrorKind::TimedOut);
    let engine = Error::sync_engine(SyncEngineContext::LoroExportUpdates, source);
    assert_eq!(engine.kind(), ErrorKind::SyncEngineError);
    assert_matches!(
        &engine,
        Error::Sync(SyncError::SyncEngineError {
            context: SyncEngineContext::LoroExportUpdates,
            source
        }) if source.downcast_ref::<std::io::Error>().is_some()
    );

    let operation_source = std::io::Error::from(std::io::ErrorKind::TimedOut);
    let rollback_source = std::io::Error::other("root revert failed");
    let operation_kind = operation_source.kind();
    let rollback_kind = rollback_source.kind();
    assert_ne!(operation_kind, rollback_kind);
    let rollback = Error::sync_engine_rollback(
        SyncEngineContext::LoroRevert,
        operation_source,
        rollback_source,
    );
    assert_eq!(rollback.kind(), ErrorKind::SyncEngineError);
    let Error::Sync(SyncError::SyncEngineError {
        context: SyncEngineContext::LoroRevert,
        source,
    }) = &rollback
    else {
        panic!("expected revert engine error, got {rollback:?}");
    };
    let rollback = source
        .downcast_ref::<SyncRollbackError>()
        .expect("sync rollback source should preserve both errors");
    let operation = rollback
        .operation()
        .downcast_ref::<std::io::Error>()
        .expect("operation source should preserve its error type");
    let rollback = rollback
        .rollback()
        .downcast_ref::<std::io::Error>()
        .expect("rollback source should preserve its error type");
    assert_eq!(operation.kind(), operation_kind);
    assert_eq!(rollback.kind(), rollback_kind);
}

#[test]
fn hnsw_recall_at_10_vs_bruteforce() -> Result<()> {
    const DIMENSIONS: usize = 128;
    const NODE_COUNT: usize = 1_000;
    const LIMIT: usize = 10;
    const QUERY_COUNT: usize = 25;

    let temp_dir = tempfile::tempdir()?;
    let mut config = test_config();
    config.dimensions = DIMENSIONS;
    config.map_size = 128 * 1024 * 1024;
    config.hnsw.m_max_0 = 64;
    config.hnsw.ef_construction = 256;
    config.hnsw.ef_search = 256;

    let vault = Vault::open(temp_dir.path(), config)?;
    let mut rng = StdRng::seed_from_u64(42);
    let mut corpus = Vec::with_capacity(NODE_COUNT);

    let insert_started = Instant::now();
    for _ in 0..NODE_COUNT {
        let id = EntityId::now();
        let vector: Vec<f32> = (0..DIMENSIONS)
            .map(|_| rng.gen_range(-1.0_f32..1.0_f32))
            .collect();

        vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"recall-node")?;
        vault.put_vector(&id, &vector)?;
        corpus.push((id, vector));
    }
    let insert_elapsed = insert_started.elapsed();

    let search_started = Instant::now();
    let mut recall_sum = 0.0_f32;
    for query_idx in 0..QUERY_COUNT {
        let stride = NODE_COUNT / QUERY_COUNT;
        let query_vector = &corpus[query_idx * stride].1;

        let ann = vault.search_vector(query_vector, LIMIT)?;
        let ann_ids: HashSet<EntityId> = ann.iter().map(|item| item.id).collect();

        let mut brute_force: Vec<(EntityId, f32)> = corpus
            .iter()
            .map(|(id, vector)| (*id, crate::distance::cosine_distance(query_vector, vector)))
            .collect();
        brute_force.sort_by(|left, right| {
            left.1
                .total_cmp(&right.1)
                .then_with(|| left.0.as_bytes().cmp(right.0.as_bytes()))
        });

        let brute_ids: HashSet<EntityId> =
            brute_force.iter().take(LIMIT).map(|(id, _)| *id).collect();
        let hits = brute_ids.intersection(&ann_ids).count();
        recall_sum += hits as f32 / LIMIT as f32;
    }
    let search_elapsed = search_started.elapsed();

    let recall_at_10 = recall_sum / QUERY_COUNT as f32;
    eprintln!(
        "hnsw recall@10={recall_at_10:.4}, insert_ms={}, search_ms={}",
        insert_elapsed.as_millis(),
        search_elapsed.as_millis()
    );

    assert!(
        recall_at_10 > 0.95,
        "expected recall@10 > 0.95, got {recall_at_10:.4}"
    );

    Ok(())
}

/// ONE-324 AC9: recall under refresh churn. Re-puts ≥ 10% of the vault's
/// vectors with new values through the localized symmetric refresh path,
/// then requires recall@10 vs brute force on the UPDATED corpus to stay
/// above the same 0.95 gate as the build-time recall test.
#[test]
fn hnsw_recall_at_10_after_refresh_churn() -> Result<()> {
    const DIMENSIONS: usize = 128;
    const NODE_COUNT: usize = 1_000;
    const CHURN_COUNT: usize = 100; // 10% of the vault
    const LIMIT: usize = 10;
    const QUERY_COUNT: usize = 25;

    let temp_dir = tempfile::tempdir()?;
    let mut config = test_config();
    config.dimensions = DIMENSIONS;
    config.map_size = 128 * 1024 * 1024;
    config.hnsw.m_max_0 = 64;
    config.hnsw.ef_construction = 256;
    config.hnsw.ef_search = 256;

    let vault = Vault::open(temp_dir.path(), config)?;
    let mut rng = StdRng::seed_from_u64(43);
    let mut corpus = Vec::with_capacity(NODE_COUNT);

    for _ in 0..NODE_COUNT {
        let id = EntityId::now();
        let vector: Vec<f32> = (0..DIMENSIONS)
            .map(|_| rng.gen_range(-1.0_f32..1.0_f32))
            .collect();

        vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"churn-node")?;
        vault.put_vector(&id, &vector)?;
        corpus.push((id, vector));
    }

    let refresh_started = Instant::now();
    let stride = NODE_COUNT / CHURN_COUNT;
    for churn_idx in 0..CHURN_COUNT {
        let corpus_idx = churn_idx * stride;
        let new_vector: Vec<f32> = (0..DIMENSIONS)
            .map(|_| rng.gen_range(-1.0_f32..1.0_f32))
            .collect();
        let id = corpus[corpus_idx].0;
        vault.put_vector(&id, &new_vector)?;
        corpus[corpus_idx].1 = new_vector;
    }
    let refresh_elapsed = refresh_started.elapsed();

    // The vault is API-built, so every re-put must take the localized
    // refresh path — count stays exact and no node may be lost.
    {
        let rtxn = vault.store.env.read_txn()?;
        let count_raw = vault
            .store
            .hnsw_meta
            .get(&rtxn, b"count")?
            .ok_or(Error::EntityNotFound)?;
        let count = u64::from_le_bytes(
            count_raw
                .as_ref()
                .try_into()
                .map_err(|_| Error::InvalidKey)?,
        );
        assert_eq!(count, NODE_COUNT as u64);
    }

    let mut recall_sum = 0.0_f32;
    for query_idx in 0..QUERY_COUNT {
        let stride = NODE_COUNT / QUERY_COUNT;
        let query_vector = &corpus[query_idx * stride].1;

        let ann = vault.search_vector(query_vector, LIMIT)?;
        let ann_ids: HashSet<EntityId> = ann.iter().map(|item| item.id).collect();

        let mut brute_force: Vec<(EntityId, f32)> = corpus
            .iter()
            .map(|(id, vector)| (*id, crate::distance::cosine_distance(query_vector, vector)))
            .collect();
        brute_force.sort_by(|left, right| {
            left.1
                .total_cmp(&right.1)
                .then_with(|| left.0.as_bytes().cmp(right.0.as_bytes()))
        });

        let brute_ids: HashSet<EntityId> =
            brute_force.iter().take(LIMIT).map(|(id, _)| *id).collect();
        let hits = brute_ids.intersection(&ann_ids).count();
        recall_sum += hits as f32 / LIMIT as f32;
    }

    let recall_at_10 = recall_sum / QUERY_COUNT as f32;
    eprintln!(
        "refresh-churn recall@10={recall_at_10:.4}, churn={CHURN_COUNT}/{NODE_COUNT}, refresh_ms={}",
        refresh_elapsed.as_millis()
    );

    assert!(
        recall_at_10 > 0.95,
        "expected refresh-churn recall@10 > 0.95, got {recall_at_10:.4}"
    );

    Ok(())
}
