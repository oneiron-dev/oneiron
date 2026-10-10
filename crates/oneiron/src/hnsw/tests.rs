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
    config.embedding_model = Some("test/model@v1".to_owned());
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

/// Each variant corrupts HNSW state in a different way then asserts the
/// targeted API path propagates `CorruptedIndex` rather than silently
/// returning bad neighbors or vectors.
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
/// Version-side variants:
/// - `read_vector_version/corrupted_bytes`: `VECTOR_VERSION_KEY`
///   rewritten to 3 bytes.
/// - `read_embedding_model_epoch/corrupted_bytes`:
///   `EMBEDDING_MODEL_EPOCH_KEY` rewritten to 3 bytes.
#[test]
fn hnsw_corruption_variants_fail_closed() -> Result<()> {
    // Each variant runs in its own temp vault/store.
    type Variant = fn() -> Result<Error>;

    fn search_corrupted_neighbor_bytes() -> Result<Error> {
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
        Ok(err)
    }

    fn search_corrupted_vector_bytes() -> Result<Error> {
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
        Ok(err)
    }

    fn search_corrupted_entry_point_bytes() -> Result<Error> {
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
        Ok(err)
    }

    fn search_missing_entry_point_when_count_is_nonzero() -> Result<Error> {
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
        Ok(err)
    }

    fn search_missing_entry_point_vector_when_count_is_nonzero() -> Result<Error> {
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
        Ok(err)
    }

    fn search_non_empty_graph_when_count_is_zero() -> Result<Error> {
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
        Ok(err)
    }

    fn insert_corrupted_count_bytes() -> Result<Error> {
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
        Ok(err)
    }

    fn insert_non_empty_graph_when_count_is_zero() -> Result<Error> {
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
        Ok(err)
    }

    fn insert_missing_entry_point_vector() -> Result<Error> {
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
        Ok(err)
    }

    fn read_vector_version_corrupted_bytes() -> Result<Error> {
        let temp_dir = tempdir()?;
        let store = Store::open(temp_dir.path(), &test_config())?;
        let mut wtxn = store.env.write_txn()?;
        store
            .hnsw_meta
            .put(&mut wtxn, VECTOR_VERSION_KEY, &[1, 2, 3])?;

        let err = read_vector_version(&store, &wtxn).expect_err("expected corrupted version bytes");
        Ok(err)
    }

    fn read_embedding_model_epoch_corrupted_bytes() -> Result<Error> {
        let temp_dir = tempdir()?;
        let store = Store::open(temp_dir.path(), &test_config())?;
        let mut wtxn = store.env.write_txn()?;
        store
            .hnsw_meta
            .put(&mut wtxn, EMBEDDING_MODEL_EPOCH_KEY, &[1, 2, 3])?;

        let err = read_embedding_model_epoch(&store, &wtxn)
            .expect_err("expected corrupted embedding model epoch bytes");
        Ok(err)
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
        (
            "read_embedding_model_epoch/corrupted_bytes",
            read_embedding_model_epoch_corrupted_bytes,
        ),
    ];

    for (case_name, variant) in variants {
        let err = variant()?;
        assert!(
            matches!(err, Error::CorruptedIndex(_)),
            "case {case_name}: expected CorruptedIndex, got {err:?}",
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
    assert_matches!(err, Error::CorruptedIndex(_));
    Ok(())
}

// Original 9 corruption tests folded into `hnsw_corruption_variants_fail_closed` above.

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

fn small_graph_config(dim: usize, m_max_0: usize, ef: usize) -> VaultConfig {
    let mut config = VaultConfig::device();
    config.dimensions = dim;
    config.embedding_model = Some("test/model@v1".to_owned());
    config.map_size = 64 * 1024 * 1024;
    config.hnsw.m_max_0 = m_max_0;
    config.hnsw.ef_construction = ef;
    config.hnsw.ef_search = ef;
    config
}

/// Asserts the symmetric-link invariant over the entire neighbors DB:
/// every stored link has its reverse, except the orphan-protection case
/// where a node's single remaining link may be one-way. Every referenced
/// neighbor must have a row (no dangling ids).
fn assert_symmetric_links(store: &Store, txn: &RoTxn<'_>) -> Result<()> {
    for entry in store.hnsw_neighbors.iter(txn)? {
        let (key, raw) = entry?;
        let node = parse_entity_id(&key, ERR_NEIGHBOR_KEY_BYTES)?;
        let list = decode_neighbors(&raw, false)?;
        for neighbor in &list {
            let back_raw = store.hnsw_neighbors.get(txn, neighbor.as_bytes())?;
            let back_raw = back_raw.unwrap_or_else(|| {
                panic!("dangling link {node:?} -> {neighbor:?}: neighbor row missing")
            });
            let back = decode_neighbors(&back_raw, false)?;
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
            !neighbor_bytes_contain(&raw, &from)?,
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
    assert_matches!(insert_err, Error::CorruptedIndex(_));

    let mut wtxn = vault.store.env.write_txn()?;
    let deindex_err = hnsw_deindex(&vault.store, &mut wtxn, &a)
        .expect_err("deindex must reject a malformed symmetric marker");
    assert_matches!(deindex_err, Error::CorruptedIndex(_));
    Ok(())
}

// ===== EMB-2 (ONE-1334) MRL funnel =====

fn funnel_config(dims: usize, fast_dims: Option<u16>, ef: usize) -> VaultConfig {
    let mut config = VaultConfig::device();
    config.dimensions = dims;
    config.fast_dims = fast_dims;
    config.embedding_model = Some("test/model@v1".to_owned());
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

/// Three vectors whose prefix ranking and full-dim ranking provably differ:
/// v1/v2 share a prefix with opposite tails, v3 is prefix-close to neither.
fn skip_rescore_fixture() -> Vec<Vec<f32>> {
    vec![
        vec![1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0],
        vec![1.0, 0.0, 0.0, 0.0, -1.0, 0.0, 0.0, 0.0],
        vec![0.9, 0.1, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0],
    ]
}

/// Qodo #473-F4: a stored row with fewer components than the scoring prefix
/// must fail closed — never silently score on a partial prefix, where its
/// shorter norm could make the corrupt row look CLOSER than healthy rows.
/// Covers both the traversal (prefix) path and the full-dim rescore path.
#[test]
fn truncated_stored_row_fails_closed_under_funnel_scoring() -> Result<()> {
    const DIMS: usize = 8;
    const FAST: usize = 4;
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), funnel_config(DIMS, Some(FAST as u16), 128))?;
    let vectors = skip_rescore_fixture();
    let ids = build_funnel_vault(&vault, &vectors)?;
    let query = &vectors[0];

    let healthy = vault.search_vector(query, 3)?;
    assert_eq!(healthy.len(), 3, "healthy baseline must rank all rows");

    // Shorter than fast_dims: valid f32-LE bytes, wrong length — strict row
    // decoding fails closed before traversal prefix scoring can consider it.
    let mut wtxn = vault.store.env.write_txn()?;
    put_vector_raw(&vault.store, &mut wtxn, &ids[1], &[0.1, 0.2])?;
    wtxn.commit()?;
    let err = vault.search_vector(query, 3).unwrap_err();
    assert_matches!(err, Error::CorruptedIndex(_));

    // Length in [fast_dims, dimensions): strict row decoding fails closed
    // before either traversal prefix scoring or full-dim rescore.
    let mut wtxn = vault.store.env.write_txn()?;
    put_vector_raw(
        &vault.store,
        &mut wtxn,
        &ids[1],
        &[1.0, 0.0, 0.0, 0.0, -1.0, 0.0],
    )?;
    wtxn.commit()?;
    let err = vault.search_vector(query, 3).unwrap_err();
    assert_matches!(err, Error::CorruptedIndex(_));

    // The prefix-only hot lane fails at the same strict decode boundary;
    // malformed persisted rows never reach prefix scoring.
    let err = vault
        .query()
        .search_vector(query, 3)
        .skip_vector_rescore(true)
        .limit(3)
        .run()
        .unwrap_err();
    assert_matches!(err, Error::CorruptedIndex(_));
    Ok(())
}

#[test]
fn vector_row_unknown_version_truncated_and_wrong_length_fail_closed() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = EntityId::now();

    // For this four-dimensional vault, only 16-byte legacy rows and 9-byte
    // v1 rows are valid. Each malformed row must fail through the public API.
    for raw in [
        vec![2, 0, 0, 0, 0, 0, 0, 0, 0],
        vec![1, 0, 0, 0, 0, 0, 0],
        vec![0, 0, 0],
    ] {
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vectors.put(&mut wtxn, id.as_bytes(), &raw)?;
        wtxn.commit()?;
        assert_matches!(vault.get_vector(&id), Err(Error::CorruptedIndex(_)));
    }
    Ok(())
}

// ===== ONE-1137: prepared-cosine scoring on the insert/search paths =====
