//! Batch write path, temporal/long-interval indexes and their open-time migration.

use super::*;

#[test]
fn put_query_and_delete_edges() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let src = EntityId::now();
    let tgt = EntityId::now();
    let kind = EdgeKind::Supports;
    let weight = 0.75_f32;

    vault.put_edge(&src, kind, &tgt, weight)?;

    let out = vault.edges_out(&src)?;
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].kind, kind);
    assert_eq!(out[0].target, tgt);
    assert!((out[0].weight - weight).abs() < f32::EPSILON);

    let inbound = vault.edges_in(&tgt)?;
    assert_eq!(inbound.len(), 1);
    assert_eq!(inbound[0].kind, kind);
    assert_eq!(inbound[0].target, src);
    assert!((inbound[0].weight - weight).abs() < f32::EPSILON);

    assert!(vault.delete_edge(&src, kind, &tgt)?);
    assert!(vault.edges_out(&src)?.is_empty());
    assert!(vault.edges_in(&tgt)?.is_empty());
    assert!(!vault.delete_edge(&src, kind, &tgt)?);

    Ok(())
}

#[test]
fn delete_edge_cleans_inbound_orphans() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let src = EntityId::now();
    let tgt = EntityId::now();
    let kind = EdgeKind::Supports;

    vault.put_edge(&src, kind, &tgt, 0.5)?;

    let key_out = Store::encode_edge_key(&src, kind, &tgt);
    let key_in = Store::encode_edge_key(&tgt, kind, &src);
    let mut wtxn = vault.store.env.write_txn()?;
    assert!(vault.store.edges_out.delete(&mut wtxn, &key_out)?);
    wtxn.commit()?;

    assert!(!vault.delete_edge(&src, kind, &tgt)?);

    let rtxn = vault.store.env.read_txn()?;
    assert!(vault.store.edges_in.get(&rtxn, &key_in)?.is_none());
    Ok(())
}

#[test]
fn batch_put_multiple_entities_atomically() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id_a = EntityId::now();
    let id_b = EntityId::now();
    let id_c = EntityId::now();

    vault
        .batch()
        .put(&id_a, 1, test_time_range(100, 100), 101, b"a")
        .put(&id_b, 1, test_time_range(200, 201), 202, b"b")
        .put(&id_c, 6, test_time_range(300, 400), 401, b"c")
        .commit()?;

    assert_eq!(vault.get(&id_a)?.ok_or(Error::EntityNotFound)?, b"a");
    assert_eq!(vault.get(&id_b)?.ok_or(Error::EntityNotFound)?, b"b");
    assert_eq!(vault.get(&id_c)?.ok_or(Error::EntityNotFound)?, b"c");
    Ok(())
}

#[test]
fn batch_put_writes_type_index() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let entity_type = 1_u8;

    vault
        .batch()
        .put(&id, entity_type, test_time_range(10, 20), 30, b"type-index")
        .commit()?;

    let key = Store::encode_type_key(entity_type, &id);
    let rtxn = vault.store.env.read_txn()?;
    assert!(vault.store.type_index.get(&rtxn, &key)?.is_some());

    let mut hits = 0_usize;
    for entry in vault.store.type_index.prefix_iter(&rtxn, &[entity_type])? {
        let (found_key, _) = entry?;
        if *found_key == key {
            hits += 1;
        }
    }
    assert_eq!(hits, 1);
    Ok(())
}

#[test]
fn batch_put_writes_temporal_indexes() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault
        .batch()
        .put(&id, 6, test_time_range(1_000, 2_000), 3_000, b"range")
        .commit()?;

    {
        let rtxn = vault.store.env.read_txn()?;
        let start_key = Store::encode_temporal_key(1_000, &id);
        let end_key = Store::encode_temporal_key(2_000, &id);
        let learned_key = Store::encode_temporal_key(3_000, &id);
        assert!(
            vault
                .store
                .temporal_occurred_start
                .get(&rtxn, &start_key)?
                .is_some()
        );
        assert!(
            vault
                .store
                .temporal_occurred_end
                .get(&rtxn, &end_key)?
                .is_some()
        );
        assert!(
            vault
                .store
                .temporal_learned
                .get(&rtxn, &learned_key)?
                .is_some()
        );
    }

    let point_id = EntityId::now();
    vault
        .batch()
        .put(
            &point_id,
            6,
            test_time_range(7_777, 7_777),
            8_888,
            b"point-event",
        )
        .commit()?;
    let point_end_key = Store::encode_temporal_key(7_777, &point_id);
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &point_end_key)?
            .is_none()
    );

    Ok(())
}

#[test]
fn entities_in_learned_range_rejects_corrupted_temporal_key() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let mut key = [0_u8; 24];
    key[..8].copy_from_slice(&50_u64.to_be_bytes());
    key[8..].fill(0xFF);

    vault.with_write_txn(|wtxn| {
        vault.store.temporal_learned.put(wtxn, &key, &[])?;
        Ok(())
    })?;

    let result = vault.entities_in_learned_range(40, 60);
    assert!(
        matches!(result, Err(Error::CorruptedIndex(_))),
        "expected index corruption, got {result:?}",
    );

    Ok(())
}

#[test]
fn batch_put_writes_long_interval_index_by_end_time() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let end = 1_000 + crate::batch::LONG_INTERVAL_THRESHOLD_SECS + 1;

    vault
        .batch()
        .put(&id, 6, test_time_range(1_000, end), 3_000, b"long-range")
        .commit()?;

    let key = Store::encode_temporal_key(end, &id);
    let rtxn = vault.store.env.read_txn()?;
    let value = vault
        .store
        .temporal_long_intervals
        .get(&rtxn, &key)?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(
        u64::from_be_bytes(value.as_ref().try_into().map_err(|_| Error::InvalidKey)?),
        1_000
    );
    Ok(())
}

#[test]
fn batch_put_and_deindex_pin_temporal_boundary_comparisons() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let exact_id = seeded_entity_id(0xB0A0);
    let over_id = seeded_entity_id(0xB0A1);
    let start = 1_000_u64;
    let exact_end = start + LONG_INTERVAL_THRESHOLD_SECS;
    let over_end = exact_end + 1;

    vault
        .batch()
        .put(
            &exact_id,
            6,
            test_time_range(start, exact_end),
            3_000,
            b"exact-threshold",
        )
        .put(
            &over_id,
            6,
            test_time_range(start, over_end),
            3_001,
            b"over-threshold",
        )
        .commit()?;

    let exact_long_key = Store::encode_temporal_key(exact_end, &exact_id);
    let over_long_key = Store::encode_temporal_key(over_end, &over_id);
    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .temporal_long_intervals
                .get(&rtxn, &exact_long_key)?
                .is_none(),
            "span == LONG_INTERVAL_THRESHOLD_SECS is not a long interval"
        );
        assert_eq!(
            vault
                .store
                .temporal_long_intervals
                .get(&rtxn, &over_long_key)?
                .as_deref(),
            Some(&start.to_be_bytes()[..]),
            "span > LONG_INTERVAL_THRESHOLD_SECS must be indexed"
        );
    }

    let exact_sentinel = [0xA5_u8; 8];
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .temporal_long_intervals
            .put(&mut wtxn, &exact_long_key, &exact_sentinel)?;
        wtxn.commit()?;
    }
    vault.put_entity(
        &exact_id,
        6,
        test_time_range(start, exact_end),
        3_010,
        b"exact-threshold-updated",
    )?;
    {
        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            vault
                .store
                .temporal_long_intervals
                .get(&rtxn, &exact_long_key)?
                .as_deref(),
            Some(&exact_sentinel[..]),
            "exact-threshold re-put must not run the old/new long-interval branches"
        );
    }

    assert!(vault.delete_entity(&over_id)?);
    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .temporal_long_intervals
                .get(&rtxn, &over_long_key)?
                .is_none(),
            "deindex_entity must remove real over-threshold long intervals"
        );
    }

    assert!(vault.delete_entity(&exact_id)?);
    {
        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            vault
                .store
                .temporal_long_intervals
                .get(&rtxn, &exact_long_key)?
                .as_deref(),
            Some(&exact_sentinel[..]),
            "deindex_entity must not treat an exact-threshold span as long"
        );
    }

    let point_id = seeded_entity_id(0xB0A2);
    let point_ts = 7_000_u64;
    vault.put_entity(
        &point_id,
        6,
        test_time_range(point_ts, point_ts),
        8_000,
        b"point",
    )?;
    let point_end_key = Store::encode_temporal_key(point_ts, &point_id);
    let point_sentinel = [0xC3_u8; 4];
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .temporal_occurred_end
            .put(&mut wtxn, &point_end_key, &point_sentinel)?;
        wtxn.commit()?;
    }
    vault.put_entity(
        &point_id,
        6,
        test_time_range(point_ts, point_ts),
        8_001,
        b"point-updated",
    )?;
    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &point_end_key)?
            .as_deref(),
        Some(&point_sentinel[..]),
        "point re-put must not run the old range-end delete branch"
    );
    Ok(())
}

#[test]
fn open_migrates_legacy_long_interval_rows() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();
    let id = EntityId::now();
    let end = 1_000 + crate::batch::LONG_INTERVAL_THRESHOLD_SECS + 10;

    let vault = Vault::open(path, test_config())?;
    vault
        .batch()
        .put(
            &id,
            6,
            test_time_range(1_000, end),
            3_000,
            b"legacy-long-range",
        )
        .commit()?;

    let new_key = Store::encode_temporal_key(end, &id);
    let mut legacy_value = [0_u8; 16];
    legacy_value[..8].copy_from_slice(&1_000_u64.to_be_bytes());
    legacy_value[8..].copy_from_slice(&end.to_be_bytes());

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .temporal_long_intervals
        .delete(&mut wtxn, &new_key)?;
    vault
        .store
        .temporal_long_intervals
        .put(&mut wtxn, id.as_bytes(), &legacy_value)?;
    vault
        .store
        .hnsw_meta
        .delete(&mut wtxn, TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY)?;
    wtxn.commit()?;
    drop(vault);

    let reopened = Vault::open(path, test_config())?;
    let rtxn = reopened.store.env.read_txn()?;
    assert!(
        reopened
            .store
            .temporal_long_intervals
            .get(&rtxn, id.as_bytes())?
            .is_none()
    );
    let value = reopened
        .store
        .temporal_long_intervals
        .get(&rtxn, &new_key)?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(
        u64::from_be_bytes(value.as_ref().try_into().map_err(|_| Error::InvalidKey)?),
        1_000
    );
    Ok(())
}

#[test]
fn open_rejects_newer_long_interval_schema_version() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();

    let vault = Vault::open(path, test_config())?;
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.hnsw_meta.put(
        &mut wtxn,
        TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY,
        &[3_u8],
    )?;
    wtxn.commit()?;
    drop(vault);

    let Err(err) = Vault::open(path, test_config()) else {
        panic!("expected invalid key");
    };
    assert_matches!(err, Error::InvalidKey);
    Ok(())
}

#[test]
fn open_checks_model_id_before_migrating_long_interval_schema() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();
    let id = EntityId::now();
    let end = 1_000 + crate::batch::LONG_INTERVAL_THRESHOLD_SECS + 10;

    let mut cfg = test_config();
    cfg.embedding_model = Some("test/model-a@v1".to_owned());
    let vault = Vault::open(path, cfg)?;
    vault
        .batch()
        .put(
            &id,
            6,
            test_time_range(1_000, end),
            3_000,
            b"legacy-long-range",
        )
        .commit()?;

    let new_key = Store::encode_temporal_key(end, &id);
    let mut legacy_value = [0_u8; 16];
    legacy_value[..8].copy_from_slice(&1_000_u64.to_be_bytes());
    legacy_value[8..].copy_from_slice(&end.to_be_bytes());

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .temporal_long_intervals
        .delete(&mut wtxn, &new_key)?;
    vault
        .store
        .temporal_long_intervals
        .put(&mut wtxn, id.as_bytes(), &legacy_value)?;
    vault
        .store
        .hnsw_meta
        .delete(&mut wtxn, TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY)?;
    wtxn.commit()?;
    drop(vault);

    let mut mismatch_cfg = test_config();
    mismatch_cfg.embedding_model = Some("test/model-b@v1".to_owned());
    let Err(err) = Vault::open(path, mismatch_cfg) else {
        panic!("expected embedding model change rejection");
    };
    assert_matches!(err, Error::EmbeddingModelChanged { .. });

    let cfg = test_config();
    let _guard = lmdb_database_open_guard()?;
    // SAFETY: test-only reopen of the same LMDB path. The prior Vault has
    // been dropped; single-Env-per-path invariant holds inside the test
    // scope. tmp path is local (not NFS), and map_size matches the
    // original open above.
    let env = unsafe {
        heed::EnvOpenOptions::new()
            .map_size(cfg.map_size)
            .max_readers(cfg.max_readers)
            .max_dbs(32)
            .open(path)?
    };
    let rtxn = env.read_txn()?;
    let hnsw_meta = env
        .open_database::<Bytes, Bytes>(&rtxn, Some("hnsw_meta"))?
        .ok_or(Error::EntityNotFound)?;
    let temporal_long_intervals = env
        .open_database::<Bytes, Bytes>(&rtxn, Some("temporal_long_intervals"))?
        .ok_or(Error::EntityNotFound)?;

    assert!(temporal_long_intervals.get(&rtxn, id.as_bytes())?.is_some());
    assert!(temporal_long_intervals.get(&rtxn, &new_key)?.is_none());
    assert!(
        hnsw_meta
            .get(&rtxn, TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY)?
            .is_none()
    );
    Ok(())
}

#[test]
fn batch_with_edges_and_entities() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let src = EntityId::now();
    let tgt = EntityId::now();
    let vector = [0.9_f32, 0.8, 0.7, 0.6];

    vault
        .batch()
        .put(&src, 1, test_time_range(1, 2), 3, b"src")
        .put(&tgt, 4, test_time_range(4, 5), 6, b"tgt")
        .vector(&src, &vector)
        .edge(&src, EdgeKind::BelongsTo, &tgt, 0.5)
        .commit()?;

    assert_eq!(vault.get(&src)?.ok_or(Error::EntityNotFound)?, b"src");
    assert_eq!(vault.get(&tgt)?.ok_or(Error::EntityNotFound)?, b"tgt");
    // Same EMB-3 f16 row contract as `put_get_vectors_and_validate_dimensions`:
    // the batch path stores two bytes per component, so compare within the
    // quantization bound rather than demanding exact f32 equality.
    let got_vector = vault.get_vector(&src)?.ok_or(Error::EntityNotFound)?;
    assert_eq!(
        got_vector.len(),
        vector.len(),
        "round-trip must preserve arity"
    );
    for (index, (&got, &want)) in got_vector.iter().zip(vector.iter()).enumerate() {
        assert!(
            (got - want).abs() <= 0.001,
            "component {index} outside the f16 round-trip bound: got {got}, want {want}"
        );
    }

    let out = vault.edges_out(&src)?;
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].kind, EdgeKind::BelongsTo);
    assert_eq!(out[0].target, tgt);
    Ok(())
}

#[test]
fn edges_out_returns_all_edges_for_same_source() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let src = EntityId::now();
    let tgt_a = EntityId::now();
    let tgt_b = EntityId::now();
    let tgt_c = EntityId::now();
    let expected = [
        (EdgeKind::BelongsTo, tgt_a, 1.0_f32),
        (EdgeKind::Mentions, tgt_b, 0.6_f32),
        (EdgeKind::Supports, tgt_c, 0.9_f32),
    ];

    vault.put_edge(&src, expected[0].0, &expected[0].1, expected[0].2)?;
    vault.put_edge(&src, expected[1].0, &expected[1].1, expected[1].2)?;
    vault.put_edge(&src, expected[2].0, &expected[2].1, expected[2].2)?;

    let out = vault.edges_out(&src)?;
    assert_eq!(out.len(), expected.len());
    for (kind, target, weight) in expected {
        assert!(
            out.iter().any(|e| {
                e.kind == kind && e.target == target && (e.weight - weight).abs() < f32::EPSILON
            }),
            "missing edge ({kind:?}, {target:?}, {weight})"
        );
    }

    Ok(())
}

#[test]
fn with_write_txn_and_batch_in() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp.path(), test_config()).unwrap();
    let id = EntityId::now();

    vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"atomic")
                .apply(wtxn)?;
            Ok(())
        })
        .unwrap();

    assert_eq!(vault.get(&id).unwrap().unwrap(), b"atomic");
}

#[test]
fn batch_edge_with_created_at() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp.path(), test_config()).unwrap();
    let src = EntityId::now();
    let tgt = EntityId::now();

    vault
        .batch()
        .put(&src, 1, TimeRange { start: 1, end: 1 }, 1, b"src")
        .put(&tgt, 1, TimeRange { start: 1, end: 1 }, 1, b"tgt")
        .edge_with_created_at(&src, EdgeKind::Mentions, &tgt, 0.8, 99999)
        .commit()
        .unwrap();

    let edges = vault.edges_out(&src).unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].created_at, 99999);
    assert!((edges[0].weight - 0.8).abs() < f32::EPSILON);
}
