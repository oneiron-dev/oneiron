use core::assert_matches;
use tempfile::tempdir;

use super::*;
use crate::Vault;
use crate::config::VaultConfig;
use crate::store::Store;
use crate::temporal::TimeRange;

fn test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.embedding_model = Some("test-model-v1".to_owned());
    config.map_size = 64 * 1024 * 1024;
    config.hnsw.m_max_0 = 1;
    config.hnsw.ef_construction = 8;
    config.hnsw.ef_search = 8;
    config
}

fn point(start: u64, end: u64) -> TimeRange {
    TimeRange { start, end }
}

fn vector_bytes(vector: &[f32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(vector.len() * 4);
    for value in vector {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

#[test]
fn visited_capacity_hint_caps_by_graph_size() {
    assert_eq!(visited_capacity_hint(8, 3), 3);
    assert_eq!(visited_capacity_hint(2, 16), 4);
    assert_eq!(visited_capacity_hint(1, 0), 1);
}

fn put_vector_raw(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    vector: &[f32],
) -> Result<()> {
    let bytes = vector_bytes(vector);
    store.vectors.put(wtxn, id.as_bytes(), &bytes)?;
    Ok(())
}

#[test]
fn hnsw_deindex_scrubs_backlinks() -> Result<()> {
    let temp_dir = tempdir()?;
    let store = Store::open(temp_dir.path(), &test_config())?;
    let mut wtxn = store.env.write_txn()?;
    let a = EntityId::now();
    let b = EntityId::now();
    let c = EntityId::now();

    write_neighbors(&store, &mut wtxn, &a, &[b, c])?;
    write_neighbors(&store, &mut wtxn, &b, &[a])?;
    write_neighbors(&store, &mut wtxn, &c, &[a])?;
    store
        .hnsw_meta
        .put(&mut wtxn, ENTRY_POINT_KEY, a.as_bytes())?;
    store
        .hnsw_meta
        .put(&mut wtxn, COUNT_KEY, &3_u64.to_le_bytes())?;

    hnsw_deindex(&store, &mut wtxn, &a)?;

    assert!(store.hnsw_neighbors.get(&wtxn, a.as_bytes())?.is_none());
    assert_eq!(load_neighbors(&store, &wtxn, &b)?, Vec::<EntityId>::new());
    assert_eq!(load_neighbors(&store, &wtxn, &c)?, Vec::<EntityId>::new());
    assert_eq!(read_count(&store, &wtxn)?, 2);
    assert_eq!(
        read_entry_point(&store, &wtxn)?.expect("replacement entry point"),
        b
    );
    Ok(())
}

#[test]
fn hnsw_deindex_non_entry_preserves_entry_point() -> Result<()> {
    let temp_dir = tempdir()?;
    let store = Store::open(temp_dir.path(), &test_config())?;
    let mut wtxn = store.env.write_txn()?;
    let a = EntityId::now();
    let b = EntityId::now();
    let c = EntityId::now();

    write_neighbors(&store, &mut wtxn, &a, &[b, c])?;
    write_neighbors(&store, &mut wtxn, &b, &[a, c])?;
    write_neighbors(&store, &mut wtxn, &c, &[a, b])?;
    store
        .hnsw_meta
        .put(&mut wtxn, ENTRY_POINT_KEY, a.as_bytes())?;
    store
        .hnsw_meta
        .put(&mut wtxn, COUNT_KEY, &3_u64.to_le_bytes())?;

    hnsw_deindex(&store, &mut wtxn, &c)?;

    assert!(store.hnsw_neighbors.get(&wtxn, c.as_bytes())?.is_none());
    assert_eq!(load_neighbors(&store, &wtxn, &a)?, vec![b]);
    assert_eq!(load_neighbors(&store, &wtxn, &b)?, vec![a]);
    assert_eq!(read_count(&store, &wtxn)?, 2);
    assert_eq!(read_entry_point(&store, &wtxn)?.expect("entry point"), a);
    Ok(())
}

#[test]
fn hnsw_insert_existing_node_updates_neighbors_and_count() -> Result<()> {
    let temp_dir = tempdir()?;
    let store = Store::open(temp_dir.path(), &test_config())?;
    let mut wtxn = store.env.write_txn()?;
    let a = EntityId::now();
    let b = EntityId::now();
    let c = EntityId::now();

    put_vector_raw(&store, &mut wtxn, &a, &[1.0, 0.0, 0.0, 0.0])?;
    put_vector_raw(&store, &mut wtxn, &b, &[0.8, 0.6, 0.0, 0.0])?;
    put_vector_raw(&store, &mut wtxn, &c, &[0.0, 1.0, 0.0, 0.0])?;

    write_neighbors(&store, &mut wtxn, &a, &[b])?;
    write_neighbors(&store, &mut wtxn, &b, &[a, c])?;
    write_neighbors(&store, &mut wtxn, &c, &[b])?;
    store
        .hnsw_meta
        .put(&mut wtxn, ENTRY_POINT_KEY, b.as_bytes())?;
    store
        .hnsw_meta
        .put(&mut wtxn, COUNT_KEY, &3_u64.to_le_bytes())?;

    put_vector_raw(&store, &mut wtxn, &a, &[0.0, 1.0, 0.0, 0.0])?;
    hnsw_insert(&store, &test_config(), &mut wtxn, &a, &[0.0, 1.0, 0.0, 0.0])?;

    assert_eq!(read_count(&store, &wtxn)?, 3);
    assert_eq!(load_neighbors(&store, &wtxn, &a)?, vec![c]);
    assert_eq!(load_neighbors(&store, &wtxn, &b)?, vec![a]);
    assert_eq!(load_neighbors(&store, &wtxn, &c)?, vec![a]);
    Ok(())
}

#[test]
fn hnsw_refresh_prunes_stale_neighbors_without_new_ids() -> Result<()> {
    let temp_dir = tempdir()?;
    let store = Store::open(temp_dir.path(), &test_config())?;
    let mut wtxn = store.env.write_txn()?;
    let a = EntityId::now();
    let b = EntityId::now();
    let c = EntityId::now();

    put_vector_raw(&store, &mut wtxn, &a, &[0.0, 1.0, 0.0, 0.0])?;
    put_vector_raw(&store, &mut wtxn, &b, &[1.0, 0.0, 0.0, 0.0])?;
    put_vector_raw(&store, &mut wtxn, &c, &[0.0, 1.0, 0.0, 0.0])?;

    write_neighbors(&store, &mut wtxn, &a, &[b, c])?;
    write_neighbors(&store, &mut wtxn, &b, &[a])?;
    write_neighbors(&store, &mut wtxn, &c, &[a])?;
    store
        .hnsw_meta
        .put(&mut wtxn, ENTRY_POINT_KEY, b.as_bytes())?;
    store
        .hnsw_meta
        .put(&mut wtxn, COUNT_KEY, &3_u64.to_le_bytes())?;

    hnsw_insert(&store, &test_config(), &mut wtxn, &a, &[0.0, 1.0, 0.0, 0.0])?;

    assert_eq!(load_neighbors(&store, &wtxn, &a)?, vec![c]);
    assert_eq!(load_neighbors(&store, &wtxn, &b)?, vec![a]);
    assert_eq!(load_neighbors(&store, &wtxn, &c)?, vec![a]);
    assert_eq!(
        read_entry_point(&store, &wtxn)?.expect("rebuilt entry point"),
        b
    );
    Ok(())
}

#[test]
fn put_vector_refresh_preserves_search_connectivity() -> Result<()> {
    let temp_dir = tempdir()?;
    let mut config = test_config();
    config.hnsw.m_max_0 = 2;
    let vault = Vault::open(temp_dir.path(), config)?;
    let a = EntityId::now();
    let b = EntityId::now();
    let c = EntityId::now();

    for id in [a, b, c] {
        vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
    }

    let mut wtxn = vault.store.env.write_txn()?;
    put_vector_raw(&vault.store, &mut wtxn, &a, &[0.8, 0.2, 0.0, 0.0])?;
    put_vector_raw(&vault.store, &mut wtxn, &b, &[1.0, 0.0, 0.0, 0.0])?;
    put_vector_raw(&vault.store, &mut wtxn, &c, &[0.0, 1.0, 0.0, 0.0])?;
    write_neighbors(&vault.store, &mut wtxn, &c, &[a])?;
    write_neighbors(&vault.store, &mut wtxn, &a, &[b])?;
    write_neighbors(&vault.store, &mut wtxn, &b, &[a])?;
    vault
        .store
        .hnsw_meta
        .put(&mut wtxn, ENTRY_POINT_KEY, c.as_bytes())?;
    vault
        .store
        .hnsw_meta
        .put(&mut wtxn, COUNT_KEY, &3_u64.to_le_bytes())?;
    wtxn.commit()?;

    let query = [1.0_f32, 0.0, 0.0, 0.0];
    let before = vault.search_vector(&query, 3)?;
    assert!(
        before.iter().any(|entry| entry.id == b),
        "expected B to be reachable before refresh, got {before:?}"
    );

    vault.put_vector(&a, &[0.0, 1.0, 0.0, 0.0])?;

    let after = vault.search_vector(&query, 3)?;
    assert!(
        after.iter().any(|entry| entry.id == b),
        "expected B to remain reachable after refresh, got {after:?}"
    );
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        load_neighbors(&vault.store, &rtxn, &a)?.contains(&c),
        "expected refreshed node to pick up a new outgoing link toward its new region"
    );
    Ok(())
}

#[test]
fn put_vector_refresh_repairs_entry_point_reachability() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let a = EntityId::now();
    let b = EntityId::now();
    let c = EntityId::now();

    for id in [a, b, c] {
        vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
    }

    let mut wtxn = vault.store.env.write_txn()?;
    put_vector_raw(&vault.store, &mut wtxn, &a, &[1.0, 0.0, 0.0, 0.0])?;
    put_vector_raw(&vault.store, &mut wtxn, &b, &[0.9, 0.1, 0.0, 0.0])?;
    put_vector_raw(&vault.store, &mut wtxn, &c, &[0.0, 1.0, 0.0, 0.0])?;
    write_neighbors(&vault.store, &mut wtxn, &a, &[b])?;
    write_neighbors(&vault.store, &mut wtxn, &b, &[a])?;
    write_neighbors(&vault.store, &mut wtxn, &c, &[a])?;
    vault
        .store
        .hnsw_meta
        .put(&mut wtxn, ENTRY_POINT_KEY, a.as_bytes())?;
    vault
        .store
        .hnsw_meta
        .put(&mut wtxn, COUNT_KEY, &3_u64.to_le_bytes())?;
    wtxn.commit()?;

    vault.put_vector(&a, &[0.0, 1.0, 0.0, 0.0])?;

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        read_entry_point(&vault.store, &rtxn)?.expect("reachable entry point"),
        b
    );
    assert_eq!(load_neighbors(&vault.store, &rtxn, &a)?, vec![c]);
    assert!(
        load_neighbors(&vault.store, &rtxn, &b)?.contains(&a),
        "expected the rebuilt graph to stay searchable from the refreshed entry region"
    );
    drop(rtxn);

    let results = vault.search_vector(&[1.0, 0.0, 0.0, 0.0], 3)?;
    assert!(
        results.iter().any(|entry| entry.id == b),
        "expected old-region node to remain reachable after entry-point refresh, got {results:?}"
    );
    Ok(())
}

#[test]
fn put_vector_refresh_rewrites_stale_incoming_only_links() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let a = EntityId::now();
    let b = EntityId::now();
    let c = EntityId::now();

    for id in [a, b, c] {
        vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
    }

    let mut wtxn = vault.store.env.write_txn()?;
    put_vector_raw(&vault.store, &mut wtxn, &a, &[1.0, 0.0, 0.0, 0.0])?;
    put_vector_raw(&vault.store, &mut wtxn, &b, &[1.0, 0.0, 0.0, 0.0])?;
    put_vector_raw(&vault.store, &mut wtxn, &c, &[1.0, 0.0, 0.0, 0.0])?;
    write_neighbors(&vault.store, &mut wtxn, &a, &[c])?;
    write_neighbors(&vault.store, &mut wtxn, &b, &[a])?;
    write_neighbors(&vault.store, &mut wtxn, &c, &[a])?;
    vault
        .store
        .hnsw_meta
        .put(&mut wtxn, ENTRY_POINT_KEY, a.as_bytes())?;
    vault
        .store
        .hnsw_meta
        .put(&mut wtxn, COUNT_KEY, &3_u64.to_le_bytes())?;
    wtxn.commit()?;

    vault.put_vector(&a, &[0.0, 1.0, 0.0, 0.0])?;

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(load_neighbors(&vault.store, &rtxn, &a)?, vec![b]);
    assert_eq!(load_neighbors(&vault.store, &rtxn, &b)?, vec![c]);
    assert_eq!(load_neighbors(&vault.store, &rtxn, &c)?, vec![b]);
    Ok(())
}

/// Each variant corrupts HNSW state in a different way then asserts the
/// targeted API path propagates the expected `CorruptedIndex` message
/// rather than silently returning bad neighbors or vectors.
///
/// Search-side variants (use `vault.search_vector`):
/// - `search/corrupted_neighbor_bytes`: neighbor row with a non-multiple
///   of `ENTITY_ID_LEN` payload.
/// - `search/corrupted_vector_bytes`: vector row truncated to 3 bytes.
/// - `search/corrupted_entry_point_bytes`: `ENTRY_POINT_KEY` rewritten
///   to 3 bytes instead of `ENTITY_ID_LEN`.
/// - `search/missing_entry_point_when_count_is_nonzero`:
///   `ENTRY_POINT_KEY` deleted while count > 0.
/// - `search/missing_entry_point_vector_when_count_is_nonzero`: vector
///   row for the entry point deleted.
/// - `search/non_empty_graph_when_count_is_zero`: count forced to 0 while
///   the graph still has nodes.
///
/// Insert-side variants (call `hnsw_insert` directly):
/// - `insert/corrupted_count_bytes`: `COUNT_KEY` rewritten to 3 bytes.
/// - `insert/non_empty_graph_when_count_is_zero`: graph already has
///   neighbors/entry-point but `COUNT_KEY` is missing (read as 0).
/// - `insert/missing_entry_point_vector`: entry point row present but
///   its vector row is missing.
///
/// Version-side variant:
/// - `read_vector_version/corrupted_bytes`: `VECTOR_VERSION_KEY`
///   rewritten to 3 bytes.
#[test]
fn hnsw_corruption_variants_fail_closed() -> Result<()> {
    // Each variant runs in its own temp vault/store and reports the
    // observed error and the API path's expected message.
    type Variant = fn() -> Result<(Error, &'static str)>;

    fn search_corrupted_neighbor_bytes() -> Result<(Error, &'static str)> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
        vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .hnsw_neighbors
            .put(&mut wtxn, id.as_bytes(), &[1, 2, 3])?;
        wtxn.commit()?;

        let err = vault
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
            .expect_err("expected corrupted neighbor list");
        Ok((err, ERR_NEIGHBOR_VALUE_BYTES))
    }

    fn search_corrupted_vector_bytes() -> Result<(Error, &'static str)> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
        vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .vectors
            .put(&mut wtxn, id.as_bytes(), &[1, 2, 3])?;
        wtxn.commit()?;

        let err = vault
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
            .expect_err("expected corrupted vector bytes");
        Ok((err, ERR_VECTOR_BYTES))
    }

    fn search_corrupted_entry_point_bytes() -> Result<(Error, &'static str)> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
        vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, ENTRY_POINT_KEY, &[1, 2, 3])?;
        wtxn.commit()?;

        let err = vault
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
            .expect_err("expected corrupted entry point bytes");
        Ok((err, ERR_ENTRY_POINT_BYTES))
    }

    fn search_missing_entry_point_when_count_is_nonzero() -> Result<(Error, &'static str)> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
        vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;

        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.hnsw_meta.delete(&mut wtxn, ENTRY_POINT_KEY)?;
        wtxn.commit()?;

        let err = vault
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
            .expect_err("expected missing entry point corruption");
        Ok((err, ERR_ENTRY_POINT_MISSING))
    }

    fn search_missing_entry_point_vector_when_count_is_nonzero() -> Result<(Error, &'static str)> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
        vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;

        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vectors.delete(&mut wtxn, id.as_bytes())?;
        wtxn.commit()?;

        let err = vault
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
            .expect_err("expected missing entry point vector corruption");
        Ok((err, ERR_ENTRY_POINT_VECTOR_MISSING))
    }

    fn search_non_empty_graph_when_count_is_zero() -> Result<(Error, &'static str)> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
        vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, COUNT_KEY, &0_u64.to_le_bytes())?;
        wtxn.commit()?;

        let err = vault
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
            .expect_err("expected zero-count graph corruption");
        Ok((err, ERR_ZERO_COUNT_GRAPH_NOT_EMPTY))
    }

    fn insert_corrupted_count_bytes() -> Result<(Error, &'static str)> {
        let temp_dir = tempdir()?;
        let store = Store::open(temp_dir.path(), &test_config())?;
        let mut wtxn = store.env.write_txn()?;
        let existing = EntityId::now();
        let new_id = EntityId::now();

        put_vector_raw(&store, &mut wtxn, &existing, &[1.0, 0.0, 0.0, 0.0])?;
        put_vector_raw(&store, &mut wtxn, &new_id, &[0.0, 1.0, 0.0, 0.0])?;
        write_neighbors(&store, &mut wtxn, &existing, &[])?;
        store
            .hnsw_meta
            .put(&mut wtxn, ENTRY_POINT_KEY, existing.as_bytes())?;
        store.hnsw_meta.put(&mut wtxn, COUNT_KEY, &[1, 2, 3])?;

        let err = hnsw_insert(
            &store,
            &test_config(),
            &mut wtxn,
            &new_id,
            &[0.0, 1.0, 0.0, 0.0],
        )
        .expect_err("expected corrupted count bytes");
        Ok((err, ERR_COUNT_BYTES))
    }

    fn insert_non_empty_graph_when_count_is_zero() -> Result<(Error, &'static str)> {
        let temp_dir = tempdir()?;
        let store = Store::open(temp_dir.path(), &test_config())?;
        let mut wtxn = store.env.write_txn()?;
        let existing = EntityId::now();
        let new_id = EntityId::now();

        write_neighbors(&store, &mut wtxn, &existing, &[])?;
        store
            .hnsw_meta
            .put(&mut wtxn, ENTRY_POINT_KEY, existing.as_bytes())?;
        put_vector_raw(&store, &mut wtxn, &new_id, &[0.0, 1.0, 0.0, 0.0])?;

        let err = hnsw_insert(
            &store,
            &test_config(),
            &mut wtxn,
            &new_id,
            &[0.0, 1.0, 0.0, 0.0],
        )
        .expect_err("expected non-empty graph corruption");
        Ok((err, ERR_ZERO_COUNT_GRAPH_NOT_EMPTY))
    }

    fn insert_missing_entry_point_vector() -> Result<(Error, &'static str)> {
        let temp_dir = tempdir()?;
        let store = Store::open(temp_dir.path(), &test_config())?;
        let mut wtxn = store.env.write_txn()?;
        let existing = EntityId::now();
        let new_id = EntityId::now();

        write_neighbors(&store, &mut wtxn, &existing, &[])?;
        store
            .hnsw_meta
            .put(&mut wtxn, ENTRY_POINT_KEY, existing.as_bytes())?;
        store
            .hnsw_meta
            .put(&mut wtxn, COUNT_KEY, &1_u64.to_le_bytes())?;
        put_vector_raw(&store, &mut wtxn, &new_id, &[0.0, 1.0, 0.0, 0.0])?;

        let err = hnsw_insert(
            &store,
            &test_config(),
            &mut wtxn,
            &new_id,
            &[0.0, 1.0, 0.0, 0.0],
        )
        .expect_err("expected missing entry point vector corruption");
        Ok((err, ERR_ENTRY_POINT_VECTOR_MISSING))
    }

    fn read_vector_version_corrupted_bytes() -> Result<(Error, &'static str)> {
        let temp_dir = tempdir()?;
        let store = Store::open(temp_dir.path(), &test_config())?;
        let mut wtxn = store.env.write_txn()?;
        store
            .hnsw_meta
            .put(&mut wtxn, VECTOR_VERSION_KEY, &[1, 2, 3])?;

        let err = read_vector_version(&store, &wtxn).expect_err("expected corrupted version bytes");
        Ok((err, ERR_VECTOR_VERSION_BYTES))
    }

    let variants: Vec<(&str, Variant)> = vec![
        (
            "search/corrupted_neighbor_bytes",
            search_corrupted_neighbor_bytes,
        ),
        (
            "search/corrupted_vector_bytes",
            search_corrupted_vector_bytes,
        ),
        (
            "search/corrupted_entry_point_bytes",
            search_corrupted_entry_point_bytes,
        ),
        (
            "search/missing_entry_point_when_count_is_nonzero",
            search_missing_entry_point_when_count_is_nonzero,
        ),
        (
            "search/missing_entry_point_vector_when_count_is_nonzero",
            search_missing_entry_point_vector_when_count_is_nonzero,
        ),
        (
            "search/non_empty_graph_when_count_is_zero",
            search_non_empty_graph_when_count_is_zero,
        ),
        ("insert/corrupted_count_bytes", insert_corrupted_count_bytes),
        (
            "insert/non_empty_graph_when_count_is_zero",
            insert_non_empty_graph_when_count_is_zero,
        ),
        (
            "insert/missing_entry_point_vector",
            insert_missing_entry_point_vector,
        ),
        (
            "read_vector_version/corrupted_bytes",
            read_vector_version_corrupted_bytes,
        ),
    ];

    for (case_name, variant) in variants {
        let (err, expected_msg) = variant()?;
        assert!(
            matches!(&err, Error::CorruptedIndex(message) if *message == expected_msg),
            "case {case_name}: expected CorruptedIndex({expected_msg:?}), got {err:?}"
        );
    }
    Ok(())
}

#[test]
fn hnsw_insert_rejects_corrupted_neighbor_lists() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let a = EntityId::now();
    let b = EntityId::now();

    vault.put_entity(&a, 1, point(1, 1), 1, b"a")?;
    vault.put_entity(&b, 1, point(1, 1), 1, b"b")?;
    vault.put_vector(&a, &[1.0, 0.0, 0.0, 0.0])?;

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .hnsw_neighbors
        .put(&mut wtxn, a.as_bytes(), &[0; ENTITY_ID_LEN])?;
    wtxn.commit()?;

    let err = vault
        .put_vector(&b, &[0.9, 0.1, 0.0, 0.0])
        .expect_err("expected corrupted write-side neighbors to fail");
    assert_matches!(err, Error::CorruptedIndex(message) if message == ERR_NEIGHBOR_VALUE_BYTES);
    Ok(())
}

#[test]
fn beam_search_strict_rejects_corrupted_neighbor_rows() -> Result<()> {
    let temp_dir = tempdir()?;
    let store = Store::open(temp_dir.path(), &test_config())?;
    let a = EntityId::now();
    let b = EntityId::now();

    let mut wtxn = store.env.write_txn()?;
    store
        .entities
        .put(&mut wtxn, a.as_bytes(), &[0, 0, 0, 0, 0, 0, 0, 0])?;
    store
        .entities
        .put(&mut wtxn, b.as_bytes(), &[0, 0, 0, 0, 0, 0, 0, 0])?;
    store.vectors.put(
        &mut wtxn,
        a.as_bytes(),
        &vector_bytes(&[1.0, 0.0, 0.0, 0.0]),
    )?;
    store.vectors.put(
        &mut wtxn,
        b.as_bytes(),
        &vector_bytes(&[0.9, 0.1, 0.0, 0.0]),
    )?;
    store
        .hnsw_neighbors
        .put(&mut wtxn, a.as_bytes(), b.as_bytes())?;
    store
        .hnsw_neighbors
        .put(&mut wtxn, b.as_bytes(), &[0; ENTITY_ID_LEN])?;
    wtxn.commit()?;

    let rtxn = store.env.read_txn()?;
    let err = beam_search(
        &store,
        &rtxn,
        &[1.0, 0.0, 0.0, 0.0],
        a,
        BeamOptions {
            ef: 2,
            lenient_neighbors: false,
            check_existence: false,
            score_dims: 4,
        },
        &mut 0,
    )
    .expect_err("strict beam search should reject corrupted neighbors");
    assert_matches!(err, Error::CorruptedIndex(message) if message == ERR_NEIGHBOR_VALUE_BYTES);
    Ok(())
}

// Original 9 corruption tests folded into `hnsw_corruption_variants_fail_closed` above.

#[test]
fn select_best_entry_point_prefers_full_reachability() {
    let a = EntityId::now();
    let b = EntityId::now();
    let c = EntityId::now();
    let neighbors = HashMap::from([(a, vec![c]), (b, vec![a]), (c, vec![a])]);

    assert_eq!(select_best_entry_point(&neighbors, Some(a)), Some(b));
    assert_eq!(reachable_from_entry(&neighbors, b).len(), neighbors.len());
}

#[test]
fn select_best_entry_point_tie_breaks_by_entity_id() {
    let low = EntityId::from_bytes([0x10; ENTITY_ID_LEN]).expect("test id should be valid");
    let mid = EntityId::from_bytes([0x20; ENTITY_ID_LEN]).expect("test id should be valid");
    let high = EntityId::from_bytes([0x30; ENTITY_ID_LEN]).expect("test id should be valid");
    let neighbors = HashMap::from([
        (high, Vec::<EntityId>::new()),
        (mid, Vec::<EntityId>::new()),
        (low, Vec::<EntityId>::new()),
    ]);

    assert_eq!(reachable_from_entry(&neighbors, low).len(), 1);
    assert_eq!(reachable_from_entry(&neighbors, mid).len(), 1);
    assert_eq!(reachable_from_entry(&neighbors, high).len(), 1);
    assert!(reachable_from_entry(&neighbors, low).len() < neighbors.len());
    assert_eq!(select_best_entry_point(&neighbors, Some(high)), Some(low));
}

// ─── ONE-325 / ONE-324: symmetric links + localized delete/refresh ───

/// Builds a distinct, lexicographically ordered test id: `value` (>= 1,
/// big-endian) in the first 8 bytes, zero padding after. Ordering by
/// `as_bytes()` equals numeric ordering of `value`.
fn id_from_u64(value: u64) -> EntityId {
    assert!(value >= 1, "zero would collide with the reserved zero id");
    let mut bytes = [0_u8; ENTITY_ID_LEN];
    bytes[..8].copy_from_slice(&value.to_be_bytes());
    EntityId::from_bytes(bytes).expect("nonzero counter ids avoid reserved sentinels")
}

/// SplitMix64 — deterministic test PRNG, no external dependency.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn pseudo_vector(state: &mut u64, dim: usize) -> Vec<f32> {
    (0..dim)
        .map(|_| ((splitmix64(state) >> 40) as f32 / (1 << 24) as f32) * 2.0 - 1.0)
        .collect()
}

fn small_graph_config(dim: usize, m_max_0: usize, ef: usize) -> VaultConfig {
    let mut config = VaultConfig::device();
    config.dimensions = dim;
    config.embedding_model = Some("test-model-v1".to_owned());
    config.map_size = 64 * 1024 * 1024;
    config.hnsw.m_max_0 = m_max_0;
    config.hnsw.ef_construction = ef;
    config.hnsw.ef_search = ef;
    config
}

/// Builds a vault with `n` deterministic vectors through the public API
/// (so the symmetric-link path is exercised end to end). Returns the ids
/// in insertion order.
fn build_symmetric_vault(
    vault: &crate::Vault,
    n: u64,
    dim: usize,
    seed: u64,
) -> Result<Vec<EntityId>> {
    let mut state = seed;
    let mut ids = Vec::with_capacity(n as usize);
    let mut batch = vault.batch();
    for value in 1..=n {
        let id = id_from_u64(value);
        batch = batch.vector(&id, &pseudo_vector(&mut state, dim));
        ids.push(id);
    }
    batch.commit()?;
    Ok(ids)
}

/// Asserts the symmetric-link invariant over the entire neighbors DB:
/// every stored link has its reverse, except the orphan-protection case
/// where a node's single remaining link may be one-way. Every referenced
/// neighbor must have a row (no dangling ids).
fn assert_symmetric_links(store: &Store, txn: &RoTxn<'_>) -> Result<()> {
    for entry in store.hnsw_neighbors.iter(txn)? {
        let (key, raw) = entry?;
        let node = parse_entity_id(key, ERR_NEIGHBOR_KEY_BYTES)?;
        let list = decode_neighbors(raw, false)?;
        for neighbor in &list {
            let back_raw = store.hnsw_neighbors.get(txn, neighbor.as_bytes())?;
            let back_raw = back_raw.unwrap_or_else(|| {
                panic!("dangling link {node:?} -> {neighbor:?}: neighbor row missing")
            });
            let back = decode_neighbors(back_raw, false)?;
            if back.contains(&node) {
                continue;
            }
            // A one-way link is legitimate ONLY when the orphan-protection
            // exception is tracked: `node` must be recorded as a holder
            // under target `neighbor`. An UNTRACKED one-way link is exactly
            // the stale-delete hazard ONE-325 forbids — deleting `neighbor`
            // derives its backlinks from its own forward list, never sees
            // `node`, and would strand the deleted id in `node`'s row. The
            // pre-fix `|| list.len() == 1` clause blessed precisely that
            // hole; require the exception record instead.
            let holders = read_one_way_exception_holders(store, txn, neighbor)?;
            assert!(
                holders.contains(&node),
                "untracked one-way link {node:?} -> {neighbor:?} (own degree {}): \
                     no exception record under {neighbor:?}; a delete of {neighbor:?} \
                     would orphan this backlink",
                list.len()
            );
        }
    }
    Ok(())
}

#[test]
fn fresh_vault_sets_symmetric_marker_and_keeps_links_symmetric() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), small_graph_config(8, 2, 16))?;
    build_symmetric_vault(&vault, 24, 8, 7)?;

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        vault.store.hnsw_meta.get(&rtxn, SYMMETRIC_LINKS_KEY)?,
        Some([SYMMETRIC_LINKS_ENABLED].as_slice()),
        "fresh graphs must carry the symmetric-links marker"
    );
    assert_symmetric_links(&vault.store, &rtxn)?;
    assert_eq!(read_count(&vault.store, &rtxn)?, 24);
    Ok(())
}

/// ONE-325 regression: orphan protection keeps a victim's last link
/// (`victim -> from`) one-way, but the symmetric delete of `from` derives
/// its backlinks from `from`'s OWN forward list — which never contains the
/// victim. The tracked exception record is what lets the delete still
/// scrub `from` out of the victim's row; without it the deleted id lingers
/// there forever, violating the active-index purge contract while queries
/// silently tolerate the dangling id.
#[test]
fn delete_purges_orphan_protected_one_way_backlink() -> Result<()> {
    // m_max_0 = 1 forces every prune cascade down to the single-link case
    // that trips orphan protection.
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), small_graph_config(4, 1, 8))?;
    let from = id_from_u64(1); // deletion target
    let victim = id_from_u64(2); // keeps a one-way link `victim -> from`
    let near = id_from_u64(3); // closer to `from`, claims its single slot

    // Entity records back the vectors so the search existence check resolves
    // live nodes (graph shape is driven entirely by the vector inserts).
    for id in [from, victim, near] {
        vault.put_entity(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"node")?;
    }

    vault.put_vector(&from, &[1.0, 0.0, 0.0, 0.0])?;
    vault.put_vector(&victim, &[0.8, 0.6, 0.0, 0.0])?;
    // `near` is closer to `from` than `victim` is, so inserting it prunes
    // `victim` out of `from`'s one neighbor slot; orphan protection then
    // keeps the reverse `victim -> from` one-way.
    vault.put_vector(&near, &[0.99, 0.14, 0.0, 0.0])?;

    // Pre-delete: the one-way link exists and is TRACKED.
    {
        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(load_neighbors(&vault.store, &rtxn, &victim)?, vec![from]);
        assert!(
            !load_neighbors(&vault.store, &rtxn, &from)?.contains(&victim),
            "scenario invalid: `from` still points back at `victim`"
        );
        assert_eq!(
            read_one_way_exception_holders(&vault.store, &rtxn, &from)?,
            vec![victim],
            "orphan-protected one-way link must be recorded as an exception"
        );
        // The strengthened invariant accepts the link *because* it is tracked.
        assert_symmetric_links(&vault.store, &rtxn)?;
    }

    let mut wtxn = vault.store.env.write_txn()?;
    hnsw_deindex(&vault.store, &mut wtxn, &from)?;
    wtxn.commit()?;

    let rtxn = vault.store.env.read_txn()?;
    // 1. The victim's row no longer carries the deleted id.
    assert!(
        !load_neighbors(&vault.store, &rtxn, &victim)?.contains(&from),
        "deleted id left stranded in the orphan-protected victim's row"
    );
    // 2. No surviving row references the deleted node anywhere.
    for entry in vault.store.hnsw_neighbors.iter(&rtxn)? {
        let (k, raw) = entry?;
        assert!(
            !neighbor_bytes_contain(raw, &from)?,
            "stale backlink to deleted node left in row {k:?}"
        );
    }
    // 3. The exception record is cleared.
    assert!(
        read_one_way_exception_holders(&vault.store, &rtxn, &from)?.is_empty(),
        "exception record must be cleared once its target is deleted"
    );
    // 4. The graph still upholds the exception-checked invariant; count drops.
    assert_symmetric_links(&vault.store, &rtxn)?;
    assert_eq!(read_count(&vault.store, &rtxn)?, 2);
    // 5. A query at the deleted node's position never returns it and the
    //    search over the victim's region still resolves to a live node.
    let hits = hnsw_search(
        &vault.store,
        &vault.config,
        &rtxn,
        &[1.0, 0.0, 0.0, 0.0],
        5,
        false,
    )?;
    assert!(
        hits.iter().all(|hit| hit.id != from),
        "search must not return the deleted node"
    );
    assert!(!hits.is_empty(), "search must still reach a live node");
    Ok(())
}

#[test]
fn symmetric_marker_corruption_fails_closed() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), small_graph_config(4, 2, 8))?;
    let a = id_from_u64(1);
    let b = id_from_u64(2);
    vault.put_vector(&a, &[1.0, 0.0, 0.0, 0.0])?;
    vault.put_vector(&b, &[0.0, 1.0, 0.0, 0.0])?;

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .hnsw_meta
        .put(&mut wtxn, SYMMETRIC_LINKS_KEY, &[9])?;
    wtxn.commit()?;

    let insert_err = vault
        .put_vector(&id_from_u64(3), &[0.5, 0.5, 0.0, 0.0])
        .expect_err("insert must reject a malformed symmetric marker");
    assert_matches!(insert_err, Error::CorruptedIndex(message) if message == ERR_SYMMETRIC_MARKER_BYTES);

    let mut wtxn = vault.store.env.write_txn()?;
    let deindex_err = hnsw_deindex(&vault.store, &mut wtxn, &a)
        .expect_err("deindex must reject a malformed symmetric marker");
    assert_matches!(deindex_err, Error::CorruptedIndex(message) if message == ERR_SYMMETRIC_MARKER_BYTES);
    Ok(())
}

#[test]
fn refresh_fallback_counter_corruption_fails_closed() -> Result<()> {
    let temp_dir = tempdir()?;
    let store = Store::open(temp_dir.path(), &test_config())?;
    let mut wtxn = store.env.write_txn()?;
    store
        .hnsw_meta
        .put(&mut wtxn, REFRESH_FALLBACK_REBUILDS_KEY, &[1, 2, 3])?;

    let err = read_refresh_fallback_rebuilds(&store, &wtxn)
        .expect_err("expected corrupted fallback counter bytes");
    assert_matches!(err, Error::CorruptedIndex(message) if message == ERR_FALLBACK_COUNTER_BYTES);

    store
        .hnsw_meta
        .put(&mut wtxn, LEGACY_REBUILDS_KEY, &[4, 5])?;
    let err = read_legacy_snapshot_rebuilds(&store, &wtxn)
        .expect_err("expected corrupted legacy rebuild counter bytes");
    assert_matches!(err, Error::CorruptedIndex(message) if message == ERR_LEGACY_REBUILDS_BYTES);
    Ok(())
}

/// ONE-325 AC1: on a symmetric graph, deletes scrub backlinks through the
/// node's own neighbor list and never iterate the full `hnsw_neighbors`
/// DB. The fixture (256 nodes) is far larger than any node's
/// neighborhood (m_max_0 = 4); a full-scan implementation costs ≥ 256
/// probed ops and fails the literal bound. Removing the marker from the
/// very same vault demonstrates the bound bites: the legacy scan path
/// exceeds the node count.
#[test]
fn hnsw_deindex_symmetric_op_count_is_local() -> Result<()> {
    for n in [128_u64, 256] {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), small_graph_config(8, 4, 16))?;
        let ids = build_symmetric_vault(&vault, n, 8, 11)?;

        let victim = ids[(n / 2) as usize];
        let mut wtxn = vault.store.env.write_txn()?;
        let mut ops = 0_u64;
        hnsw_deindex_probed(&vault.store, &mut wtxn, &victim, &mut ops)?;
        wtxn.commit()?;

        // Measured: 10 ops at n=128, 12 ops at n=256 (deterministic
        // fixture). A full-scan implementation costs ≥ n - 1.
        eprintln!("symmetric deindex n={n}: {ops} probed ops");
        assert!(
            ops <= 32,
            "symmetric deindex on n={n} should be neighborhood-local, took {ops} ops"
        );

        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(read_count(&vault.store, &rtxn)?, n - 1);
        assert!(
            vault
                .store
                .hnsw_neighbors
                .get(&rtxn, victim.as_bytes())?
                .is_none()
        );
        // No surviving row may still reference the deleted node.
        for entry in vault.store.hnsw_neighbors.iter(&rtxn)? {
            let (key, raw) = entry?;
            assert!(
                !neighbor_bytes_contain(raw, &victim)?,
                "stale backlink to deleted node left in row {key:?}"
            );
        }
        drop(rtxn);

        // Contrast: the same vault downgraded to legacy (marker removed)
        // pays a full scan — the op count the symmetric path must beat.
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .hnsw_meta
            .delete(&mut wtxn, SYMMETRIC_LINKS_KEY)?;
        let mut legacy_ops = 0_u64;
        let second_victim = ids[(n / 2 + 1) as usize];
        hnsw_deindex_probed(&vault.store, &mut wtxn, &second_victim, &mut legacy_ops)?;
        wtxn.commit()?;
        assert!(
            legacy_ops >= n - 1,
            "legacy deindex must visit every row (n={n}), took {legacy_ops} ops"
        );
    }
    Ok(())
}

/// ONE-324 AC5: refreshing an existing node is a localized update — no
/// full iteration over `vectors` or `hnsw_neighbors`. A snapshot-rebuild
/// implementation costs ≥ n beam searches (thousands of probed ops); the
/// literal bound pins the localized class across two fixture sizes.
#[test]
fn hnsw_refresh_symmetric_op_count_is_local() -> Result<()> {
    for n in [128_u64, 256] {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), small_graph_config(8, 4, 16))?;
        let ids = build_symmetric_vault(&vault, n, 8, 13)?;

        let target = ids[(n / 2) as usize];
        let mut state = 0xDEAD_BEEF_u64 ^ n;
        let new_vector = pseudo_vector(&mut state, 8);

        let mut wtxn = vault.store.env.write_txn()?;
        let mut ops = 0_u64;
        hnsw_insert_probed(
            &vault.store,
            &vault.config,
            &mut wtxn,
            &target,
            &new_vector,
            &mut ops,
        )?;
        wtxn.commit()?;

        // Measured: 78 ops at n=128, 100 ops at n=256 (deterministic
        // fixture). A snapshot rebuild costs ≥ n row reads before it
        // even starts searching.
        eprintln!("symmetric refresh n={n}: {ops} probed ops");
        assert!(
            ops <= 300,
            "symmetric refresh on n={n} should be neighborhood-local, took {ops} ops"
        );

        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(read_count(&vault.store, &rtxn)?, n);
        assert!(
            !load_neighbors(&vault.store, &rtxn, &target)?.is_empty(),
            "refreshed node must be re-linked"
        );
        assert_symmetric_links(&vault.store, &rtxn)?;
        assert_eq!(
            read_refresh_fallback_rebuilds(&vault.store, &rtxn)?,
            0,
            "localized refresh must not fall back to a rebuild"
        );
        assert_eq!(
            read_legacy_snapshot_rebuilds(&vault.store, &rtxn)?,
            0,
            "symmetric refresh must never run a legacy snapshot rebuild"
        );
    }
    Ok(())
}

/// ONE-324 AC7: a refresh that empties an old neighbor's list re-links
/// that neighbor (repair pass) instead of leaving it dangling.
#[test]
fn symmetric_refresh_repairs_orphaned_old_neighbors() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), small_graph_config(4, 1, 8))?;
    let a = id_from_u64(1);
    let b = id_from_u64(2);
    let c = id_from_u64(3);

    vault.put_vector(&a, &[1.0, 0.0, 0.0, 0.0])?;
    vault.put_vector(&b, &[0.9, 0.1, 0.0, 0.0])?;
    vault.put_vector(&c, &[0.89, 0.11, 0.0, 0.0])?;

    {
        // Sanity: with m_max_0 = 1 the API-built graph concentrates links
        // around the closest pairs; C holds B's only strong link.
        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(load_neighbors(&vault.store, &rtxn, &b)?, vec![c]);
    }

    // Move B to the far side of the sphere: C's list would empty.
    vault.put_vector(&b, &[0.0, 0.0, 1.0, 0.0])?;

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(read_count(&vault.store, &rtxn)?, 3);
    for id in [a, b, c] {
        assert!(
            !load_neighbors(&vault.store, &rtxn, &id)?.is_empty(),
            "node {id:?} left orphaned after refresh"
        );
    }
    // Every referenced neighbor still has a row (nothing dangles).
    for entry in vault.store.hnsw_neighbors.iter(&rtxn)? {
        let (_, raw) = entry?;
        for neighbor in decode_neighbors(raw, false)? {
            assert!(
                vault
                    .store
                    .hnsw_neighbors
                    .get(&rtxn, neighbor.as_bytes())?
                    .is_some()
            );
        }
    }
    Ok(())
}

/// ONE-324 AC10 machinery: the fallback rebuild is symmetric, keeps the
/// marker, and bumps the persistent measurement counter.
#[test]
fn symmetric_fallback_rebuild_is_measured_and_symmetric() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), small_graph_config(8, 2, 16))?;
    build_symmetric_vault(&vault, 12, 8, 17)?;

    let mut wtxn = vault.store.env.write_txn()?;
    hnsw_symmetric_fallback_rebuild(&vault.store, &vault.config, &mut wtxn)?;
    wtxn.commit()?;

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(read_refresh_fallback_rebuilds(&vault.store, &rtxn)?, 1);
    assert_eq!(
        vault.store.hnsw_meta.get(&rtxn, SYMMETRIC_LINKS_KEY)?,
        Some([SYMMETRIC_LINKS_ENABLED].as_slice())
    );
    assert_eq!(read_count(&vault.store, &rtxn)?, 12);
    assert_symmetric_links(&vault.store, &rtxn)?;
    Ok(())
}

/// ONE-324 AC11: batched vector refreshes on a legacy (unmigrated) graph
/// coalesce into exactly one snapshot rebuild per transaction; symmetric
/// graphs never rebuild at all.
#[test]
fn batched_vector_refreshes_coalesce_rebuilds() -> Result<()> {
    // Legacy vault: hand-built asymmetric graph without the marker.
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let a = id_from_u64(1);
    let b = id_from_u64(2);
    let c = id_from_u64(3);

    let mut wtxn = vault.store.env.write_txn()?;
    put_vector_raw(&vault.store, &mut wtxn, &a, &[1.0, 0.0, 0.0, 0.0])?;
    put_vector_raw(&vault.store, &mut wtxn, &b, &[0.0, 1.0, 0.0, 0.0])?;
    put_vector_raw(&vault.store, &mut wtxn, &c, &[0.0, 0.0, 1.0, 0.0])?;
    write_neighbors(&vault.store, &mut wtxn, &a, &[b])?;
    write_neighbors(&vault.store, &mut wtxn, &b, &[a, c])?;
    write_neighbors(&vault.store, &mut wtxn, &c, &[a])?;
    vault
        .store
        .hnsw_meta
        .put(&mut wtxn, ENTRY_POINT_KEY, a.as_bytes())?;
    vault
        .store
        .hnsw_meta
        .put(&mut wtxn, COUNT_KEY, &3_u64.to_le_bytes())?;
    wtxn.commit()?;

    vault
        .batch()
        .vector(&a, &[0.5, 0.5, 0.0, 0.0])
        .vector(&b, &[0.0, 0.5, 0.5, 0.0])
        .vector(&c, &[0.5, 0.0, 0.5, 0.0])
        .vector(&id_from_u64(4), &[0.5, 0.0, 0.0, 0.5])
        .commit()?;
    {
        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            read_legacy_snapshot_rebuilds(&vault.store, &rtxn)?,
            1,
            "a batch of legacy refreshes must trigger exactly one snapshot rebuild"
        );
        assert_eq!(read_count(&vault.store, &rtxn)?, 4);
        assert!(
            vault
                .store
                .hnsw_meta
                .get(&rtxn, SYMMETRIC_LINKS_KEY)?
                .is_none(),
            "legacy snapshot rebuild must not stamp the symmetric marker"
        );
    }

    // Symmetric vault: batched refreshes stay localized — zero rebuilds.
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), small_graph_config(4, 2, 8))?;
    build_symmetric_vault(&vault, 8, 4, 19)?;
    vault
        .batch()
        .vector(&id_from_u64(2), &[0.7, 0.1, 0.1, 0.1])
        .vector(&id_from_u64(5), &[0.1, 0.7, 0.1, 0.1])
        .vector(&id_from_u64(7), &[0.1, 0.1, 0.7, 0.1])
        .commit()?;
    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        read_legacy_snapshot_rebuilds(&vault.store, &rtxn)?,
        0,
        "symmetric refreshes must not trigger snapshot rebuilds"
    );
    Ok(())
}

/// ONE-325 AC3: `maintain().rebuild_hnsw()` is the one-time migration —
/// it rewrites a legacy asymmetric graph symmetrically and stamps the
/// marker, after which refreshes take the localized path.
#[test]
fn maintain_rebuild_migrates_legacy_vault_to_symmetric() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let a = id_from_u64(1);
    let b = id_from_u64(2);
    let c = id_from_u64(3);

    let mut wtxn = vault.store.env.write_txn()?;
    put_vector_raw(&vault.store, &mut wtxn, &a, &[1.0, 0.0, 0.0, 0.0])?;
    put_vector_raw(&vault.store, &mut wtxn, &b, &[0.0, 1.0, 0.0, 0.0])?;
    put_vector_raw(&vault.store, &mut wtxn, &c, &[0.0, 0.9, 0.1, 0.0])?;
    // Asymmetric on purpose: b -> a has no reverse link.
    write_neighbors(&vault.store, &mut wtxn, &a, &[c])?;
    write_neighbors(&vault.store, &mut wtxn, &b, &[a])?;
    write_neighbors(&vault.store, &mut wtxn, &c, &[a])?;
    vault
        .store
        .hnsw_meta
        .put(&mut wtxn, ENTRY_POINT_KEY, a.as_bytes())?;
    vault
        .store
        .hnsw_meta
        .put(&mut wtxn, COUNT_KEY, &3_u64.to_le_bytes())?;
    wtxn.commit()?;

    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .hnsw_meta
                .get(&rtxn, SYMMETRIC_LINKS_KEY)?
                .is_none()
        );
    }

    vault.maintain().rebuild_hnsw().run()?;

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        vault.store.hnsw_meta.get(&rtxn, SYMMETRIC_LINKS_KEY)?,
        Some([SYMMETRIC_LINKS_ENABLED].as_slice()),
        "maintenance rebuild must stamp the symmetric marker"
    );
    assert_eq!(read_count(&vault.store, &rtxn)?, 3);
    assert_symmetric_links(&vault.store, &rtxn)?;
    drop(rtxn);

    // Post-migration refreshes are localized: no snapshot rebuild runs.
    vault.put_vector(&b, &[0.0, 0.0, 1.0, 0.0])?;

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        read_legacy_snapshot_rebuilds(&vault.store, &rtxn)?,
        0,
        "post-migration refresh must stay localized"
    );
    assert_symmetric_links(&vault.store, &rtxn)?;
    Ok(())
}

/// Legacy vaults keep legacy semantics until migrated: a refresh on an
/// unmarked graph runs the historical snapshot rebuild and does NOT
/// stamp the marker.
#[test]
fn legacy_refresh_keeps_marker_unset() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let a = id_from_u64(1);
    let b = id_from_u64(2);

    let mut wtxn = vault.store.env.write_txn()?;
    put_vector_raw(&vault.store, &mut wtxn, &a, &[1.0, 0.0, 0.0, 0.0])?;
    put_vector_raw(&vault.store, &mut wtxn, &b, &[0.0, 1.0, 0.0, 0.0])?;
    write_neighbors(&vault.store, &mut wtxn, &a, &[b])?;
    write_neighbors(&vault.store, &mut wtxn, &b, &[a])?;
    vault
        .store
        .hnsw_meta
        .put(&mut wtxn, ENTRY_POINT_KEY, a.as_bytes())?;
    vault
        .store
        .hnsw_meta
        .put(&mut wtxn, COUNT_KEY, &2_u64.to_le_bytes())?;
    wtxn.commit()?;

    vault.put_vector(&a, &[0.0, 0.0, 1.0, 0.0])?;

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        read_legacy_snapshot_rebuilds(&vault.store, &rtxn)?,
        1,
        "legacy refresh must run the snapshot rebuild"
    );
    assert!(
        vault
            .store
            .hnsw_meta
            .get(&rtxn, SYMMETRIC_LINKS_KEY)?
            .is_none(),
        "legacy rebuild must not stamp the symmetric marker"
    );
    Ok(())
}

/// The pre-SCC selector — one full directed BFS per candidate node,
/// `O(V·(V+E))` — kept verbatim as the exhaustive reference that the
/// linear implementation must match: maximal directed reach, ties broken
/// by lowest entity id.
fn reference_select_best_entry_point(
    neighbors_by_id: &HashMap<EntityId, Vec<EntityId>>,
    suggested: Option<EntityId>,
) -> Option<EntityId> {
    let mut best = suggested.or_else(|| neighbors_by_id.keys().copied().next())?;
    let mut best_reach = reachable_from_entry(neighbors_by_id, best).len();
    if best_reach == neighbors_by_id.len() {
        return Some(best);
    }

    for candidate in neighbors_by_id.keys().copied() {
        if candidate == best {
            continue;
        }
        let reach = reachable_from_entry(neighbors_by_id, candidate).len();
        if reach > best_reach || (reach == best_reach && candidate.as_bytes() < best.as_bytes()) {
            best = candidate;
            best_reach = reach;
            if best_reach == neighbors_by_id.len() {
                break;
            }
        }
    }

    Some(best)
}

/// Directed reach decides the entry point, not SCC size and not weak
/// (undirected) components: a 6-node chain's head (forward closure 6)
/// beats a 5-node cycle (the largest SCC, closure 5). The chain head is
/// deliberately NOT the lowest id of its own component, so a
/// "lowest id in the biggest component" implementation also fails here.
#[test]
fn select_best_entry_point_prefers_long_chain_over_larger_scc() {
    let cycle: Vec<EntityId> = (1..=5_u64).map(id_from_u64).collect();
    let chain_head = id_from_u64(60);
    let chain_rest: Vec<EntityId> = (10..=14_u64).map(id_from_u64).collect();

    let mut neighbors = HashMap::new();
    for (i, id) in cycle.iter().enumerate() {
        neighbors.insert(*id, vec![cycle[(i + 1) % cycle.len()]]);
    }
    neighbors.insert(chain_head, vec![chain_rest[0]]);
    for [left, right] in chain_rest.array_windows::<2>() {
        neighbors.insert(*left, vec![*right]);
    }
    neighbors.insert(
        *chain_rest.last().expect("test chain has a tail"),
        Vec::new(),
    );

    assert_eq!(
        select_best_entry_point(&neighbors, Some(cycle[0])),
        Some(chain_head)
    );
}

/// On closure ties the winner is the lowest entity id over ALL member
/// nodes of the tied source SCCs — not the suggested node and not an
/// SCC-root artifact. Two disconnected 2-cycles tie at closure 2; the
/// 0x10 member of the {0x10, 0x40} cycle must win.
#[test]
fn select_best_entry_point_tie_breaks_by_lowest_member_id_across_sccs() {
    let m1 = EntityId::from_bytes([0x10; ENTITY_ID_LEN]).expect("test id should be valid");
    let m2 = EntityId::from_bytes([0x40; ENTITY_ID_LEN]).expect("test id should be valid");
    let n1 = EntityId::from_bytes([0x20; ENTITY_ID_LEN]).expect("test id should be valid");
    let n2 = EntityId::from_bytes([0x30; ENTITY_ID_LEN]).expect("test id should be valid");
    let neighbors = HashMap::from([
        (m1, vec![m2]),
        (m2, vec![m1]),
        (n1, vec![n2]),
        (n2, vec![n1]),
    ]);

    assert_eq!(select_best_entry_point(&neighbors, Some(n1)), Some(m1));
}

/// AC: on randomized disconnected fixtures the SCC-based entry reaches at
/// least as many nodes as the per-candidate-BFS reference's choice. The
/// fixtures are disconnected (>= 2 disjoint components), so no node is
/// fully reaching, the reference is deterministic (max reach, lowest-id
/// tie-break), and the result must match it exactly.
#[test]
fn select_best_entry_point_matches_exhaustive_reference_on_disconnected_fixtures() {
    for seed in 0..60_u64 {
        let mut state = seed;
        let component_count = 2 + (splitmix64(&mut state) % 4) as usize;
        let mut neighbors = HashMap::new();
        let mut all_ids = Vec::new();
        let mut next_id = 1_u64;

        for _ in 0..component_count {
            let size = 2 + (splitmix64(&mut state) % 9) as usize;
            let ids: Vec<EntityId> = (0..size)
                .map(|_| {
                    let id = id_from_u64(next_id);
                    next_id += 1;
                    id
                })
                .collect();
            for (i, id) in ids.iter().enumerate() {
                let out_degree = (splitmix64(&mut state) % 4) as usize;
                let mut outs: Vec<EntityId> = Vec::new();
                for _ in 0..out_degree {
                    let target = (splitmix64(&mut state) % size as u64) as usize;
                    if target != i && !outs.contains(&ids[target]) {
                        outs.push(ids[target]);
                    }
                }
                neighbors.insert(*id, outs);
            }
            all_ids.extend(ids);
        }

        let suggested = all_ids[(splitmix64(&mut state) as usize) % all_ids.len()];
        let expected = reference_select_best_entry_point(&neighbors, Some(suggested))
            .expect("non-empty fixture");
        let actual =
            select_best_entry_point(&neighbors, Some(suggested)).expect("non-empty fixture");

        let expected_reach = reachable_from_entry(&neighbors, expected).len();
        let actual_reach = reachable_from_entry(&neighbors, actual).len();
        assert!(
            actual_reach >= expected_reach,
            "seed {seed}: SCC entry reaches {actual_reach} < reference {expected_reach}"
        );
        assert!(
            expected_reach < neighbors.len(),
            "seed {seed}: disconnected fixture must not be fully reachable"
        );
        assert_eq!(
            actual, expected,
            "seed {seed}: deterministic (max reach, lowest id) winner must match"
        );
    }
}

/// AC: complexity stays `O(V+E)`-class on a multi-component fixture —
/// verified by op-count probe. 10 disjoint 100-node chains: V = 1000,
/// E = 990. The SCC path touches each node and edge a small constant
/// number of times (measured ~3.6·(V+E)); budget 8·(V+E). A
/// per-candidate full-BFS selector pays Σ reach(v) =
/// 10 · (100·101/2) ≈ 50,500 node visits alone and cannot fit the
/// budget.
#[test]
fn select_best_entry_point_op_count_is_linear_on_multi_component_fixture() {
    const CHAINS: usize = 10;
    const CHAIN_LEN: usize = 100;

    let mut neighbors = HashMap::new();
    let mut heads = Vec::new();
    let mut next_id = 1_u64;
    for _ in 0..CHAINS {
        let ids: Vec<EntityId> = (0..CHAIN_LEN)
            .map(|_| {
                let id = id_from_u64(next_id);
                next_id += 1;
                id
            })
            .collect();
        heads.push(ids[0]);
        for [left, right] in ids.array_windows::<2>() {
            neighbors.insert(*left, vec![*right]);
        }
        neighbors.insert(*ids.last().expect("test chain has a tail"), Vec::new());
    }

    let v = CHAINS * CHAIN_LEN;
    let e = CHAINS * (CHAIN_LEN - 1);
    let mut ops = 0_u64;
    // Suggested is NOT the winning head: every chain head reaches
    // CHAIN_LEN nodes, ties break to the lowest id (heads[0]).
    let entry = select_best_entry_point_probed(&neighbors, Some(heads[3]), &mut ops)
        .expect("non-empty fixture");

    assert_eq!(entry, heads[0]);
    let budget = 8 * (v + e) as u64;
    assert!(
        ops <= budget,
        "ops {ops} exceeded linear budget {budget} (V={v}, E={e})"
    );
}

/// AC: complexity stays `O(V+E)`-class even when many source SCCs feed a
/// SHARED reachable suffix — the shape a per-source closure walk degrades
/// to `Θ(sources · suffix)` on. K single-node sources all point at the head
/// of one shared K-node chain: V = 2K, E = 2K-1, and every source's forward
/// closure is the same K+1 nodes. The reverse-topological DP computes the
/// chain's reach once and reuses it for every source, relaxing each
/// condensation edge a single time, so ops stay linear. The previous
/// per-source closure walk re-traversed the whole shared chain once per
/// source: with K=100 it spends ~2·K² ≈ 20k closure ops and blows this
/// budget (8·(V+E) = 3192) — pre-fix the assert below fails; post-fix it
/// passes well under budget.
#[test]
fn select_best_entry_point_op_count_is_linear_on_shared_suffix_fixture() {
    const K: usize = 100;
    let sources: Vec<EntityId> = (1..=K as u64).map(id_from_u64).collect();
    let chain: Vec<EntityId> = ((K as u64 + 1)..=(2 * K as u64)).map(id_from_u64).collect();

    let mut neighbors = HashMap::new();
    for source in &sources {
        neighbors.insert(*source, vec![chain[0]]);
    }
    for [left, right] in chain.array_windows::<2>() {
        neighbors.insert(*left, vec![*right]);
    }
    neighbors.insert(*chain.last().expect("test chain has a tail"), Vec::new());

    let v = 2 * K; // K sources + K chain nodes
    let e = K + (K - 1); // source->head edges + chain edges
    let mut ops = 0_u64;
    // Suggested is NOT the winner: every source reaches K+1 nodes (itself
    // plus the shared chain), so they tie and the lowest id (sources[0])
    // wins. The suggested source reaches only K+1 < 2K nodes, so the cheap
    // fully-reachable early-exit does not fire and the SCC path runs.
    let entry = select_best_entry_point_probed(&neighbors, Some(sources[3]), &mut ops)
        .expect("non-empty fixture");

    assert_eq!(entry, sources[0]);
    let budget = 8 * (v + e) as u64;
    assert!(
        ops <= budget,
        "ops {ops} exceeded linear budget {budget} (V={v}, E={e})"
    );
}

/// AC: fully reachable graphs keep the cheap early-exit — a single BFS,
/// no SCC pass (which alone would at least double the op count), and the
/// suggested entry point is kept verbatim even though it is not the
/// lowest id.
#[test]
fn select_best_entry_point_keeps_suggested_on_fully_reachable_graph_with_single_bfs() {
    const N: usize = 200;
    let ids: Vec<EntityId> = (1..=N as u64).map(id_from_u64).collect();
    let mut neighbors = HashMap::new();
    for (i, id) in ids.iter().enumerate() {
        neighbors.insert(*id, vec![ids[(i + 1) % N]]);
    }
    let suggested = ids[N / 2];

    let mut ops = 0_u64;
    let entry = select_best_entry_point_probed(&neighbors, Some(suggested), &mut ops)
        .expect("non-empty fixture");

    assert_eq!(entry, suggested);
    // Single BFS budget: one op per node + one per edge, nothing else.
    let single_bfs_budget = (N + N) as u64;
    assert!(
        ops <= single_bfs_budget,
        "expected single-BFS early-exit, got {ops} ops > {single_bfs_budget}"
    );
}

// ===== EMB-2 (ONE-1334) MRL funnel =====

fn funnel_config(dims: usize, fast_dims: Option<u16>, ef: usize) -> VaultConfig {
    let mut config = VaultConfig::device();
    config.dimensions = dims;
    config.fast_dims = fast_dims;
    config.embedding_model = Some("test-model-v1".to_owned());
    config.map_size = 64 * 1024 * 1024;
    config.hnsw.m_max_0 = 16;
    config.hnsw.ef_construction = ef;
    config.hnsw.ef_search = ef;
    config
}

/// Inserts entities + vectors through the public write path so construction
/// exercises the real (prefix-scored) insert code. Ids ascend with index.
fn build_funnel_vault(vault: &Vault, vectors: &[Vec<f32>]) -> Result<Vec<EntityId>> {
    let mut ids = Vec::with_capacity(vectors.len());
    for index in 0..vectors.len() {
        let id = id_from_u64(index as u64 + 1);
        vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
        ids.push(id);
    }
    let mut batch = vault.batch();
    for (id, vector) in ids.iter().zip(vectors) {
        batch = batch.vector(id, vector);
    }
    batch.commit()?;
    Ok(ids)
}

/// Exact top-k by cosine distance over the first `dims` components, ties by
/// id bytes ascending (the pinned funnel tiebreak).
fn brute_force_top_k(
    ids: &[EntityId],
    vectors: &[Vec<f32>],
    query: &[f32],
    dims: usize,
    k: usize,
) -> Vec<EntityId> {
    let mut scored: Vec<HeapEntry> = ids
        .iter()
        .zip(vectors)
        .map(|(id, vector)| HeapEntry {
            id: *id,
            distance: cosine_distance(
                &query[..dims.min(query.len())],
                &vector[..dims.min(vector.len())],
            ),
        })
        .collect();
    scored.sort_unstable();
    scored.truncate(k);
    scored.into_iter().map(|entry| entry.id).collect()
}

#[test]
fn funnel_rescore_matches_brute_force_full_dim_top10() -> Result<()> {
    const N: usize = 96;
    const DIMS: usize = 8;
    // ef_search >= fixture count: the beam holds every reachable node, so
    // recall@10 == 1.0 is structural, not flaky (AC1).
    let temp_dir = tempdir()?;
    let vault = Vault::open(
        temp_dir.path(),
        funnel_config(DIMS, Some((DIMS / 2) as u16), N.max(128)),
    )?;
    let mut state = 0x1334;
    let vectors: Vec<Vec<f32>> = (0..N).map(|_| pseudo_vector(&mut state, DIMS)).collect();
    let ids = build_funnel_vault(&vault, &vectors)?;

    let mut query_state = 0xBEEF;
    for _ in 0..6 {
        let query = pseudo_vector(&mut query_state, DIMS);
        let got: Vec<EntityId> = vault
            .search_vector(&query, 10)?
            .into_iter()
            .map(|scored| scored.id)
            .collect();
        let expected = brute_force_top_k(&ids, &vectors, &query, DIMS, 10);
        assert_eq!(
            got, expected,
            "funnel rescore must equal exact full-dim top-10 (same ids, same order)"
        );
    }
    Ok(())
}

#[test]
fn funnel_prefix_length_query_returns_prefix_ranking() -> Result<()> {
    const N: usize = 64;
    const DIMS: usize = 8;
    const FAST: usize = DIMS / 2;
    let temp_dir = tempdir()?;
    let vault = Vault::open(
        temp_dir.path(),
        funnel_config(DIMS, Some(FAST as u16), N.max(128)),
    )?;
    let mut state = 0x1334_0002;
    let vectors: Vec<Vec<f32>> = (0..N).map(|_| pseudo_vector(&mut state, DIMS)).collect();
    let ids = build_funnel_vault(&vault, &vectors)?;

    let full_query = pseudo_vector(&mut state, DIMS);
    let prefix_query = &full_query[..FAST];
    let got: Vec<EntityId> = vault
        .search_vector(prefix_query, 10)?
        .into_iter()
        .map(|scored| scored.id)
        .collect();
    let expected = brute_force_top_k(&ids, &vectors, prefix_query, FAST, 10);
    assert_eq!(
        got, expected,
        "a fast_dims-length query must rank by prefix similarity"
    );
    Ok(())
}

/// Three vectors whose prefix ranking and full-dim ranking provably differ:
/// v1/v2 share a prefix with opposite tails, v3 is prefix-close to neither.
fn skip_rescore_fixture() -> Vec<Vec<f32>> {
    vec![
        vec![1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0],
        vec![1.0, 0.0, 0.0, 0.0, -1.0, 0.0, 0.0, 0.0],
        vec![0.9, 0.1, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0],
    ]
}

#[test]
fn funnel_skip_rescore_flag_controls_ranking_space() -> Result<()> {
    const DIMS: usize = 8;
    const FAST: usize = 4;
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), funnel_config(DIMS, Some(FAST as u16), 128))?;
    let vectors = skip_rescore_fixture();
    let ids = build_funnel_vault(&vault, &vectors)?;
    let query = &vectors[0];

    // Prefix space: v1 and v2 tie exactly (identical prefixes) -> id asc,
    // then v3. Full space: v1, then v3, then v2 (opposite tail).
    let prefix_order = vec![ids[0], ids[1], ids[2]];
    let full_order = vec![ids[0], ids[2], ids[1]];

    // Direct vault path exposes raw channel order: full-length queries
    // always rescore (no flag on this path).
    let vault_path: Vec<EntityId> = vault
        .search_vector(query, 10)?
        .into_iter()
        .map(|scored| scored.id)
        .collect();
    assert_eq!(vault_path, full_order, "vault path must rescore");
    let vault_prefix_path: Vec<EntityId> = vault
        .search_vector(&query[..FAST], 10)?
        .into_iter()
        .map(|scored| scored.id)
        .collect();
    assert_eq!(
        vault_prefix_path, prefix_order,
        "a fast_dims-length query is inherently prefix-only"
    );

    // Pipeline final ordering is the 1186-D3 blend, not raw channel order,
    // so the flag is asserted via channel-limit MEMBERSHIP: with a
    // channel limit of 2, prefix ranking admits {v1, v2} while the rescored
    // ranking admits {v1, v3}.
    let members = |scores: Vec<ScoredEntity>| -> HashSet<EntityId> {
        scores.into_iter().map(|scored| scored.id).collect()
    };
    let rescored = members(vault.query().search_vector(query, 2).limit(10).run()?);
    assert_eq!(
        rescored,
        HashSet::from([ids[0], ids[2]]),
        "default (skip=false) must admit the full-dim top-2"
    );

    let hot_lane = members(
        vault
            .query()
            .search_vector(query, 2)
            .skip_vector_rescore(true)
            .limit(10)
            .run()?,
    );
    assert_eq!(
        hot_lane,
        HashSet::from([ids[0], ids[1]]),
        "skip_vector_rescore(true) must admit the prefix top-2"
    );

    let prefix_query_members = members(
        vault
            .query()
            .search_vector(&query[..FAST], 2)
            .limit(10)
            .run()?,
    );
    assert_eq!(
        hot_lane, prefix_query_members,
        "hot lane must match the fast_dims-length-query channel behavior"
    );
    Ok(())
}

#[test]
fn funnel_dim_mismatch_rejected_on_vault_and_pipeline() -> Result<()> {
    const DIMS: usize = 8;
    const FAST: usize = 4;
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), funnel_config(DIMS, Some(FAST as u16), 128))?;
    build_funnel_vault(&vault, &skip_rescore_fixture())?;

    for bad_len in [3, 5, 7, 9] {
        let bad_query = vec![1.0_f32; bad_len];
        let err = vault.search_vector(&bad_query, 10).unwrap_err();
        assert_matches!(
            err,
            Error::DimensionMismatch { expected: DIMS, got } if got == bad_len
        );
        let err = vault
            .query()
            .search_vector(&bad_query, 10)
            .run()
            .unwrap_err();
        assert_matches!(
            err,
            Error::DimensionMismatch { expected: DIMS, got } if got == bad_len
        );
    }

    // No phantom acceptance: with fast_dims None, a prefix-length query
    // still errors on both paths.
    let temp_dir_plain = tempdir()?;
    let plain = Vault::open(temp_dir_plain.path(), funnel_config(DIMS, None, 128))?;
    build_funnel_vault(&plain, &skip_rescore_fixture())?;
    let prefix_query = vec![1.0_f32; FAST];
    let err = plain.search_vector(&prefix_query, 10).unwrap_err();
    assert_matches!(
        err,
        Error::DimensionMismatch { expected: DIMS, got: FAST }
    );
    let err = plain
        .query()
        .search_vector(&prefix_query, 10)
        .run()
        .unwrap_err();
    assert_matches!(
        err,
        Error::DimensionMismatch { expected: DIMS, got: FAST }
    );
    Ok(())
}

/// Prefix-identical / full-dim-opposite pairs: under prefix construction the
/// paired nodes are mutual nearest neighbors; under full-dim construction
/// they repel. Proves construction actually slices (AC6) while the funnel
/// rescore still restores the exact full-dim top-k.
fn adversarial_vectors(pairs: usize, dims: usize, fast: usize, state: &mut u64) -> Vec<Vec<f32>> {
    let mut vectors = Vec::with_capacity(pairs * 2);
    for _ in 0..pairs {
        let prefix = pseudo_vector(state, fast);
        let tail = pseudo_vector(state, dims - fast);
        let mut aligned = prefix.clone();
        aligned.extend(tail.iter().copied());
        let mut opposed = prefix;
        opposed.extend(tail.iter().map(|value| -value));
        vectors.push(aligned);
        vectors.push(opposed);
    }
    vectors
}

#[test]
fn funnel_construction_slices_prefix_and_rescore_restores_exactness() -> Result<()> {
    const DIMS: usize = 8;
    const FAST: usize = 4;
    const PAIRS: usize = 24;
    let mut state = 0x1334_0006;
    let vectors = adversarial_vectors(PAIRS, DIMS, FAST, &mut state);

    let funnel_dir = tempdir()?;
    let funnel_vault = Vault::open(
        funnel_dir.path(),
        funnel_config(DIMS, Some(FAST as u16), 128),
    )?;
    let ids = build_funnel_vault(&funnel_vault, &vectors)?;

    let full_dir = tempdir()?;
    let full_vault = Vault::open(full_dir.path(), funnel_config(DIMS, None, 128))?;
    build_funnel_vault(&full_vault, &vectors)?;

    let funnel_rtxn = funnel_vault.store.env.read_txn()?;
    let full_rtxn = full_vault.store.env.read_txn()?;
    let mut any_difference = false;
    for id in &ids {
        let funnel_neighbors: HashSet<EntityId> =
            load_neighbors(&funnel_vault.store, &funnel_rtxn, id)?
                .into_iter()
                .collect();
        let full_neighbors: HashSet<EntityId> = load_neighbors(&full_vault.store, &full_rtxn, id)?
            .into_iter()
            .collect();
        if funnel_neighbors != full_neighbors {
            any_difference = true;
            break;
        }
    }
    assert!(
        any_difference,
        "prefix construction must produce a different graph shape than full-dim construction"
    );
    drop(funnel_rtxn);
    drop(full_rtxn);

    let mut query_state = 0x1334_0007;
    for _ in 0..5 {
        let query = pseudo_vector(&mut query_state, DIMS);
        let got: Vec<EntityId> = funnel_vault
            .search_vector(&query, 10)?
            .into_iter()
            .map(|scored| scored.id)
            .collect();
        let expected = brute_force_top_k(&ids, &vectors, &query, DIMS, 10);
        assert_eq!(
            got, expected,
            "funnel rescore must restore exact full-dim top-k on the adversarial fixture"
        );
    }
    Ok(())
}
