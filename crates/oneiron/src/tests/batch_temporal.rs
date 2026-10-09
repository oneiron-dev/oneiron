//! Batch write path, temporal/long-interval indexes and their open-time migration.

use super::*;
use crate::error::StoreError;

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
            crate::registry::ENTITY_TYPE_EVENT,
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
            crate::registry::ENTITY_TYPE_EVENT,
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
    assert_matches!(err, Error::Store(StoreError::EmbeddingModelChanged { .. }));

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
