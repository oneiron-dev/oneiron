use core::assert_matches;
use heed::types::Bytes;

use super::*;
use crate::entity_id::ENTITY_ID_LEN;
use crate::job_queue::{
    ClaimJob, ClaimOutcome, EnqueueJob, EnqueueOutcome, JobQueue, JobQueueRetryReason,
};
use crate::store::{
    GRAPH_VERSION_KEY, MODEL_ID_KEY, TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY, VECTOR_VERSION_KEY,
};
use crate::types::{EdgeKind, HnswConfig, TimeRange, VaultConfig};

fn test_config() -> VaultConfig {
    VaultConfig {
        map_size: 32 * 1024 * 1024,
        dimensions: 4,
        embedding_model: Some("test-model-v1".to_owned()),
        max_readers: 16,
        hnsw: HnswConfig {
            m_max_0: 64,
            ef_construction: 200,
            ef_search: 128,
        },
        text_analyzer: crate::types::TextAnalyzerConfig::default(),
        dict_search_paths: Vec::new(),
        skip_text_index_manifest_check: false,
    }
}

fn test_time_range(start: u64, end: u64) -> TimeRange {
    TimeRange { start, end }
}

fn entity(byte: u8) -> EntityId {
    EntityId::from_bytes_unchecked([byte; ENTITY_ID_LEN])
}

fn read_u64_meta(vault: &Vault, key: &[u8]) -> Result<u64> {
    let rtxn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .hnsw_meta
        .get(&rtxn, key)?
        .ok_or(Error::EntityNotFound)?;
    let value = u64::from_le_bytes(raw.try_into().map_err(|_| Error::InvalidKey)?);
    Ok(value)
}

fn count_entries(db: &heed::Database<Bytes, Bytes>, vault: &Vault) -> Result<usize> {
    let rtxn = vault.store.env.read_txn()?;
    let mut count = 0;
    for entry in db.iter(&rtxn)? {
        entry?;
        count += 1;
    }
    Ok(count)
}

fn read_neighbor_bytes(vault: &Vault, id: &EntityId) -> Result<Vec<u8>> {
    let rtxn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .hnsw_neighbors
        .get(&rtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    Ok(raw.to_vec())
}

#[test]
fn rebuild_hnsw_removes_dead_nodes() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let mut ids = Vec::new();

    for i in 0..50_u8 {
        let id = entity(i.saturating_add(1));
        ids.push(id);
        vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
        vault.put_vector(&id, &[1.0, 0.0, 0.0, i as f32])?;
    }

    {
        let mut wtxn = vault.store.env.write_txn()?;
        for id in ids.iter().take(15) {
            vault.store.vectors.delete(&mut wtxn, id.as_bytes())?;
        }
        wtxn.commit()?;
    }

    let report = vault.maintain().rebuild_hnsw().run()?;
    assert_eq!(report.hnsw_dead_nodes_removed, 15);
    assert_eq!(report.hnsw_live_nodes, 35);

    let count = read_u64_meta(&vault, COUNT_KEY)?;
    assert_eq!(count, 35);
    Ok(())
}

/// `rebuild_hnsw` must not touch unrelated `hnsw_meta` rows. Each variant
/// seeds a different key and confirms its value survives the rebuild.
///
/// Variants:
/// - `graph_version`: `GRAPH_VERSION_KEY` is bumped by edge writes, then
///   the rebuild's `u64` value must match the pre-rebuild snapshot.
/// - `long_interval_schema_version`: raw bytes at
///   `TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY` must match.
/// - `model_id_when_config_matches`: closing the vault and reopening with
///   the same `embedding_model` must leave `MODEL_ID_KEY` untouched
///   (still `"test-model-v1"`).
/// - `unrelated_hnsw_meta`: a custom key `b"custom-meta" -> b"keep-me"`
///   must not be scrubbed.
#[test]
fn rebuild_hnsw_preserves_unrelated_meta() -> Result<()> {
    // graph_version
    {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(80);
        let b = entity(81);

        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
        let before = read_u64_meta(&vault, GRAPH_VERSION_KEY)?;

        let report = vault.maintain().rebuild_hnsw().run()?;
        assert_eq!(
            report.hnsw_dead_nodes_removed, 0,
            "case graph_version: unexpected dead nodes removed"
        );

        let after = read_u64_meta(&vault, GRAPH_VERSION_KEY)?;
        assert_eq!(
            before, after,
            "case graph_version: GRAPH_VERSION_KEY changed by rebuild"
        );
    }

    // long_interval_schema_version
    {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let before = {
            let rtxn = vault.store.env.read_txn()?;
            vault
                .store
                .hnsw_meta
                .get(&rtxn, TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY)?
                .ok_or(Error::EntityNotFound)?
                .to_vec()
        };

        vault.maintain().rebuild_hnsw().run()?;

        let after = {
            let rtxn = vault.store.env.read_txn()?;
            vault
                .store
                .hnsw_meta
                .get(&rtxn, TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY)?
                .ok_or(Error::EntityNotFound)?
                .to_vec()
        };
        assert_eq!(
            before, after,
            "case long_interval_schema_version: schema version changed"
        );
    }

    // model_id_when_config_matches
    {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let id = entity(84);
        vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
        vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;
        drop(vault);

        let vault = Vault::open(temp_dir.path(), test_config())?;

        vault.maintain().rebuild_hnsw().run()?;

        let rtxn = vault.store.env.read_txn()?;
        let stored = vault.store.hnsw_meta.get(&rtxn, MODEL_ID_KEY)?;
        assert_eq!(
            stored,
            Some(b"test-model-v1".as_slice()),
            "case model_id_when_config_matches: MODEL_ID_KEY changed"
        );
    }

    // unrelated_hnsw_meta
    {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = entity(85);

        vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
        vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;

        {
            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .hnsw_meta
                .put(&mut wtxn, b"custom-meta", b"keep-me")?;
            wtxn.commit()?;
        }

        vault.maintain().rebuild_hnsw().run()?;

        let rtxn = vault.store.env.read_txn()?;
        let custom_meta = vault.store.hnsw_meta.get(&rtxn, b"custom-meta")?;
        assert_eq!(
            custom_meta,
            Some(b"keep-me".as_slice()),
            "case unrelated_hnsw_meta: custom row scrubbed"
        );
    }

    Ok(())
}

#[test]
fn rebuild_hnsw_strict_preserves_committed_graph_on_invalid_vector() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let a = entity(86);
    let b = entity(87);

    for (id, vector) in [(a, [1.0, 0.0, 0.0, 0.0]), (b, [0.0, 1.0, 0.0, 0.0])] {
        vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
        vault.put_vector(&id, &vector)?;
    }

    let count_before = read_u64_meta(&vault, COUNT_KEY)?;
    let neighbors_before = read_neighbor_bytes(&vault, &a)?;

    {
        let mut invalid = Vec::new();
        invalid.extend_from_slice(&1.0_f32.to_le_bytes());
        invalid.extend_from_slice(&2.0_f32.to_le_bytes());
        invalid.extend_from_slice(&3.0_f32.to_le_bytes());

        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vectors.put(&mut wtxn, b.as_bytes(), &invalid)?;
        wtxn.commit()?;
    }

    let err = vault.maintain().rebuild_hnsw().run().unwrap_err();
    assert_matches!(
        err,
        Error::DimensionMismatch {
            expected: 4,
            got: 3,
        }
    );

    let count_after = read_u64_meta(&vault, COUNT_KEY)?;
    let neighbors_after = read_neighbor_bytes(&vault, &a)?;
    assert_eq!(count_before, count_after);
    assert_eq!(neighbors_before, neighbors_after);
    assert_eq!(count_entries(&vault.store.hnsw_neighbors, &vault)?, 2);
    Ok(())
}

#[test]
fn rebuild_hnsw_rejects_stale_vector_snapshot() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let a = entity(94);
    let b = entity(95);

    for (id, vector) in [(a, [1.0, 0.0, 0.0, 0.0]), (b, [0.0, 1.0, 0.0, 0.0])] {
        vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
        vault.put_vector(&id, &vector)?;
    }

    let count_before = read_u64_meta(&vault, COUNT_KEY)?;
    let vector_version_before = read_u64_meta(&vault, VECTOR_VERSION_KEY)?;
    let neighbors_before = read_neighbor_bytes(&vault, &a)?;

    let prepared = prepare_rebuild_hnsw(&vault, false)?;
    assert_eq!(prepared.vector_version, vector_version_before);
    assert_eq!(prepared.invalid_vectors_skipped, 0);

    vault.put_vector(&b, &[0.0, 0.5, 0.5, 0.0])?;

    let err = commit_rebuilt_hnsw(&vault, &prepared.rebuilt, prepared.vector_version).unwrap_err();
    assert_matches!(
        err,
        Error::ConcurrentWrite("vectors changed during hnsw rebuild; retry maintenance")
    );

    let count_after = read_u64_meta(&vault, COUNT_KEY)?;
    let vector_version_after = read_u64_meta(&vault, VECTOR_VERSION_KEY)?;
    let neighbors_after = read_neighbor_bytes(&vault, &a)?;
    assert_eq!(count_before, count_after);
    assert_eq!(neighbors_before, neighbors_after);
    assert!(vector_version_after > vector_version_before);
    assert_eq!(count_entries(&vault.store.hnsw_neighbors, &vault)?, 2);
    Ok(())
}

#[test]
fn rebuild_hnsw_heal_invalid_vectors_skips_bad_rows() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let a = entity(88);
    let b = entity(89);

    for (id, vector) in [(a, [1.0, 0.0, 0.0, 0.0]), (b, [0.0, 1.0, 0.0, 0.0])] {
        vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
        vault.put_vector(&id, &vector)?;
    }

    {
        let mut invalid = Vec::new();
        invalid.extend_from_slice(&1.0_f32.to_le_bytes());
        invalid.extend_from_slice(&2.0_f32.to_le_bytes());
        invalid.extend_from_slice(&3.0_f32.to_le_bytes());

        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vectors.put(&mut wtxn, b.as_bytes(), &invalid)?;
        wtxn.commit()?;
    }

    let report = vault.maintain().rebuild_hnsw_heal_invalid_vectors().run()?;
    assert_eq!(report.hnsw_invalid_vectors_skipped, 1);
    assert_eq!(report.hnsw_live_nodes, 1);
    assert_eq!(report.hnsw_dead_nodes_removed, 1);

    let count = read_u64_meta(&vault, COUNT_KEY)?;
    assert_eq!(count, 1);

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .hnsw_neighbors
            .get(&rtxn, b.as_bytes())?
            .is_none()
    );
    assert!(vault.store.vectors.get(&rtxn, b.as_bytes())?.is_some());
    Ok(())
}

#[test]
fn rebuild_hnsw_builder_modes_are_last_call_wins() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let a = entity(96);
    let b = entity(97);

    for (id, vector) in [(a, [1.0, 0.0, 0.0, 0.0]), (b, [0.0, 1.0, 0.0, 0.0])] {
        vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
        vault.put_vector(&id, &vector)?;
    }

    {
        let mut invalid = Vec::new();
        invalid.extend_from_slice(&1.0_f32.to_le_bytes());
        invalid.extend_from_slice(&2.0_f32.to_le_bytes());
        invalid.extend_from_slice(&3.0_f32.to_le_bytes());

        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vectors.put(&mut wtxn, b.as_bytes(), &invalid)?;
        wtxn.commit()?;
    }

    let err = vault
        .maintain()
        .rebuild_hnsw_heal_invalid_vectors()
        .rebuild_hnsw()
        .run()
        .unwrap_err();
    assert_matches!(
        err,
        Error::DimensionMismatch {
            expected: 4,
            got: 3,
        }
    );
    Ok(())
}

#[test]
fn build_hnsw_graph_from_snapshot_rejects_missing_entry_point_vector() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let a = entity(98);
    let b = entity(99);

    for (id, vector) in [(a, [1.0, 0.0, 0.0, 0.0]), (b, [0.0, 1.0, 0.0, 0.0])] {
        vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
        vault.put_vector(&id, &vector)?;
    }

    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vectors.delete(&mut wtxn, a.as_bytes())?;
        wtxn.commit()?;
    }

    let rtxn = vault.store.env.read_txn()?;
    let err = build_hnsw_graph_from_snapshot(
        &vault.store,
        &vault.config,
        &rtxn,
        &[a, b],
        LinkDiscipline::Symmetric,
    )
    .unwrap_err();
    assert_matches!(
        err,
        Error::InvariantViolation(
            "validated rebuild vector disappeared within the same read snapshot"
        )
    );
    Ok(())
}

#[test]
fn cleanup_ppr_cache_evicts_stale_and_expired() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let a = entity(82);
    let b = entity(83);

    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
    let _ = vault.query().search_ppr(&[a], 3).limit(10).run()?;
    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 0.2)?;

    let report = vault.maintain().cleanup_ppr_cache(0).run()?;
    assert!(report.ppr_caches_evicted > 0);
    assert!(report.ppr_deps_cleaned > 0);

    assert_eq!(count_entries(&vault.store.ppr_cache, &vault)?, 0);
    assert_eq!(count_entries(&vault.store.ppr_cache_deps, &vault)?, 0);
    Ok(())
}

#[test]
fn compact_postings_removes_empty_lists() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;

    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.text_postings.put(&mut wtxn, b"empty-a", &[])?;
        vault.store.text_postings.put(&mut wtxn, b"empty-b", &[])?;
        vault
            .store
            .text_postings
            .put(&mut wtxn, b"keep", &[1, 2, 3])?;
        wtxn.commit()?;
    }

    let report = vault.maintain().compact_postings().run()?;
    assert_eq!(report.postings_compacted, 2);

    let rtxn = vault.store.env.read_txn()?;
    assert!(vault.store.text_postings.get(&rtxn, b"empty-a")?.is_none());
    assert!(vault.store.text_postings.get(&rtxn, b"empty-b")?.is_none());
    assert!(vault.store.text_postings.get(&rtxn, b"keep")?.is_some());
    Ok(())
}

#[test]
fn recompute_short_id_hashes_updates_stale() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = entity(84);

    vault
        .batch()
        .put(&id, 1, test_time_range(100, 100), 101, b"initial-payload")
        .commit()?;

    let (short_id_before, hash_before) = {
        let rtxn = vault.store.env.read_txn()?;
        let value = vault
            .store
            .short_ids_reverse
            .get(&rtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let (short_id, hash) = parse_short_id_value(value)?;
        (short_id.to_owned(), hash)
    };

    let mut new_payload = b"updated-payload".to_vec();
    while ((xxh32(&new_payload, 0) % 256) as u8) == hash_before {
        new_payload.push(0);
    }

    {
        let mut wtxn = vault.store.env.write_txn()?;
        let record = vault
            .store
            .entities
            .get(&wtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let mut updated = record[..ENTITY_METADATA_HEADER_LEN].to_vec();
        updated.extend_from_slice(&new_payload);
        vault
            .store
            .entities
            .put(&mut wtxn, id.as_bytes(), &updated)?;
        wtxn.commit()?;
    }

    let report = vault.maintain().recompute_short_id_hashes().run()?;
    assert_eq!(report.short_id_hashes_updated, 1);
    assert_eq!(report.orphan_short_ids_deleted, 0);

    let new_hash = (xxh32(&new_payload, 0) % 256) as u8;
    let rtxn = vault.store.env.read_txn()?;
    let updated_value = vault
        .store
        .short_ids_reverse
        .get(&rtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let (short_id_after, hash_after) = parse_short_id_value(updated_value)?;
    assert_eq!(short_id_after, short_id_before);
    assert_eq!(hash_after, new_hash);

    // The hash is part of the forward KEY: the stale forward row must be
    // gone and the refreshed one must point back at the entity.
    let stale_forward_key = encode_short_id_forward_key(&short_id_before, hash_before);
    let fresh_forward_key = encode_short_id_forward_key(&short_id_before, new_hash);
    assert!(
        vault
            .store
            .short_ids
            .get(&rtxn, &stale_forward_key)?
            .is_none(),
        "stale forward row must be reaped on hash refresh"
    );
    assert_eq!(
        vault.store.short_ids.get(&rtxn, &fresh_forward_key)?,
        Some(id.as_bytes().as_slice())
    );
    Ok(())
}

/// `recompute_short_id_hashes` must reap orphans from both directions.
/// Each case mutates the vault, runs the maintenance pass, and verifies the
/// orphan row(s) are gone.
///
/// Cases (pinned ARCH-0019 directions — `short_ids_reverse` is keyed by
/// entity id, `short_ids` by `(short_id ‖ content_hash)`):
/// - `entity_row_deleted`: the entity-keyed `short_ids_reverse[id]` row
///   exists but its backing `entities[id]` row is gone — both the reverse
///   row and the paired forward row must be reaped.
/// - `reverse_row_deleted`: only the entity-keyed `short_ids_reverse[id]`
///   row is gone, leaving a forward-only orphan — the forward
///   `short_ids[(short_id ‖ hash)]` row must be reaped.
/// - `corrupt_forward_value`: a bogus forward row whose VALUE matches a
///   reserved sentinel pattern (`[0xFF; 16]`). `parse_entity_id` returns
///   `Error::InvalidKey`, which the forward-scan pass must treat as a
///   corrupt row and prune — *not* propagate as an error.
#[test]
fn recompute_short_id_hashes_removes_orphans() -> Result<()> {
    /// What the case mutates after the legit entity has been committed.
    /// May return a follow-up forward key whose row should be checked
    /// post-recompute instead of the legit forward key.
    type Mutation = fn(&Vault, &EntityId) -> Result<Option<Vec<u8>>>;

    struct Case {
        name: &'static str,
        mutate: Mutation,
        /// Whether the legit entity-keyed `short_ids_reverse[id]` row
        /// should be reaped.
        expect_reverse_gone: bool,
    }

    fn delete_entity_row(vault: &Vault, id: &EntityId) -> Result<Option<Vec<u8>>> {
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.entities.delete(&mut wtxn, id.as_bytes())?;
        wtxn.commit()?;
        Ok(None)
    }
    fn delete_reverse_row(vault: &Vault, id: &EntityId) -> Result<Option<Vec<u8>>> {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .short_ids_reverse
            .delete(&mut wtxn, id.as_bytes())?;
        wtxn.commit()?;
        Ok(None)
    }
    /// Writes a `short_ids[(bogus short_id ‖ hash)] = [0xFF; 16]` forward
    /// row. `[0xFF; 16]` is a reserved sentinel pattern (see
    /// `is_reserved_entity_id_bytes` in `types.rs`), so `parse_entity_id`
    /// returns `Error::InvalidKey`. The forward-scan in
    /// `recompute_short_id_hashes` must treat that row as corrupt and
    /// prune it, not propagate the error.
    fn inject_corrupt_forward_value(vault: &Vault, _id: &EntityId) -> Result<Option<Vec<u8>>> {
        // `cl-bogus99` is a synthetic short_id that won't collide with
        // the legit row (counter-issued `cl1`).
        let bogus_forward_key = encode_short_id_forward_key("cl-bogus99", 7);
        let sentinel_value = [0xFF_u8; ENTITY_ID_LEN];
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .short_ids
            .put(&mut wtxn, &bogus_forward_key, &sentinel_value)?;
        wtxn.commit()?;
        Ok(Some(bogus_forward_key))
    }

    let cases: Vec<Case> = vec![
        Case {
            name: "entity_row_deleted",
            mutate: delete_entity_row,
            expect_reverse_gone: true,
        },
        Case {
            name: "reverse_row_deleted",
            mutate: delete_reverse_row,
            expect_reverse_gone: true,
        },
        Case {
            name: "corrupt_forward_value",
            mutate: inject_corrupt_forward_value,
            // Legit reverse row stays untouched.
            expect_reverse_gone: false,
        },
    ];

    for case in cases {
        let case_name = case.name;
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = entity(93);

        vault
            .batch()
            .put(&id, 1, test_time_range(100, 100), 101, b"payload")
            .commit()?;

        let legit_forward_key = {
            let rtxn = vault.store.env.read_txn()?;
            let value = vault
                .store
                .short_ids_reverse
                .get(&rtxn, id.as_bytes())?
                .ok_or(Error::EntityNotFound)?;
            value.to_vec()
        };

        let mutator_forward_key = (case.mutate)(&vault, &id)?;

        let report = vault.maintain().recompute_short_id_hashes().run()?;
        assert_eq!(
            report.short_id_hashes_updated, 0,
            "case {case_name}: unexpected hash updates"
        );
        assert_eq!(
            report.orphan_short_ids_deleted, 1,
            "case {case_name}: expected exactly 1 orphan reaped"
        );

        let rtxn = vault.store.env.read_txn()?;
        if case.expect_reverse_gone {
            assert!(
                vault
                    .store
                    .short_ids_reverse
                    .get(&rtxn, id.as_bytes())?
                    .is_none(),
                "case {case_name}: entity-keyed short_ids_reverse row should be reaped"
            );
        }
        // Pick the forward key to check: mutator return > legit.
        let forward_key: Vec<u8> = mutator_forward_key
            .clone()
            .unwrap_or_else(|| legit_forward_key.clone());
        assert!(
            vault.store.short_ids.get(&rtxn, &forward_key)?.is_none(),
            "case {case_name}: orphaned forward short_ids row should be reaped"
        );
        if !case.expect_reverse_gone {
            assert_eq!(
                vault.store.short_ids.get(&rtxn, &legit_forward_key)?,
                Some(id.as_bytes().as_slice()),
                "case {case_name}: legit forward row must survive"
            );
        }
    }
    Ok(())
}

#[test]
fn recompute_short_id_hashes_repairs_missing_forward_mapping() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = entity(99);

    vault
        .batch()
        .put(&id, 1, test_time_range(100, 100), 101, b"payload")
        .commit()?;

    let forward_key = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?
            .to_vec()
    };

    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.short_ids.delete(&mut wtxn, &forward_key)?;
        wtxn.commit()?;
    }

    let report = vault.maintain().recompute_short_id_hashes().run()?;
    assert_eq!(report.short_id_hashes_updated, 0);
    assert_eq!(report.orphan_short_ids_deleted, 0);

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        vault.store.short_ids.get(&rtxn, &forward_key)?,
        Some(id.as_bytes().as_slice())
    );
    Ok(())
}

#[test]
fn recompute_short_id_hashes_repairs_stale_forward_mapping() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = entity(100);
    let wrong_id = entity(101);

    vault
        .batch()
        .put(&id, 1, test_time_range(100, 100), 101, b"payload")
        .commit()?;

    let forward_key = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?
            .to_vec()
    };

    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .short_ids
            .put(&mut wtxn, &forward_key, wrong_id.as_bytes())?;
        wtxn.commit()?;
    }

    let report = vault.maintain().recompute_short_id_hashes().run()?;
    assert_eq!(report.short_id_hashes_updated, 0);
    assert_eq!(report.orphan_short_ids_deleted, 1);

    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault.store.short_ids.get(&rtxn, &forward_key)?.is_none(),
            "unowned stale forward row should be pruned before repair"
        );
    }

    let report = vault.maintain().recompute_short_id_hashes().run()?;
    assert_eq!(report.short_id_hashes_updated, 0);
    assert_eq!(report.orphan_short_ids_deleted, 0);

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        vault.store.short_ids.get(&rtxn, &forward_key)?,
        Some(id.as_bytes().as_slice())
    );
    Ok(())
}

#[test]
fn recompute_short_id_hashes_processes_custom_ids_near_sentinel_pattern() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let mut raw = [0xFF; ENTITY_ID_LEN];
    raw[0] = 0xFE;
    let id = EntityId::from_bytes(raw)?;

    vault
        .batch()
        .put(&id, 1, test_time_range(100, 100), 101, b"initial-payload")
        .commit()?;

    let hash_before = {
        let rtxn = vault.store.env.read_txn()?;
        let value = vault
            .store
            .short_ids_reverse
            .get(&rtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let (_, hash) = parse_short_id_value(value)?;
        hash
    };

    let mut new_payload = b"updated-payload".to_vec();
    while ((xxh32(&new_payload, 0) % 256) as u8) == hash_before {
        new_payload.push(0);
    }

    {
        let mut wtxn = vault.store.env.write_txn()?;
        let record = vault
            .store
            .entities
            .get(&wtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let mut updated = record[..ENTITY_METADATA_HEADER_LEN].to_vec();
        updated.extend_from_slice(&new_payload);
        vault
            .store
            .entities
            .put(&mut wtxn, id.as_bytes(), &updated)?;
        wtxn.commit()?;
    }

    let report = vault.maintain().recompute_short_id_hashes().run()?;
    assert_eq!(report.short_id_hashes_updated, 1);
    assert_eq!(report.orphan_short_ids_deleted, 0);
    Ok(())
}

#[test]
fn recompute_short_id_hashes_prunes_corrupt_reverse_rows() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = entity(102);

    vault
        .batch()
        .put(&id, 1, test_time_range(100, 100), 101, b"payload")
        .commit()?;

    // `short_ids_reverse` is keyed by 16-byte entity ids; an 8-byte
    // `b"deadbeef"` key is a corrupt row the reverse scan must prune
    // (not propagate as an error).
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .short_ids_reverse
            .put(&mut wtxn, b"deadbeef", &[0xFF; ENTITY_ID_LEN])?;
        wtxn.commit()?;
    }

    let report = vault.maintain().recompute_short_id_hashes().run()?;
    assert_eq!(report.orphan_short_ids_deleted, 1);

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, b"deadbeef")?
            .is_none()
    );
    Ok(())
}

#[test]
fn corrupt_reverse_row_never_reaps_healthy_forward_one_1114() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let healthy = entity(103);

    vault
        .batch()
        .put(&healthy, 1, test_time_range(100, 100), 101, b"payload")
        .commit()?;

    let healthy_forward_key = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, healthy.as_bytes())?
            .ok_or(Error::EntityNotFound)?
            .to_vec()
    };

    // Corrupt reverse KEY (not a 16-byte entity id) with a VALUE that
    // aliases the healthy entity's legitimate forward key. ONE-1114 pins
    // that this row may prune only itself, never the healthy forward row.
    let corrupt_reverse_key = b"bad-key";
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .short_ids_reverse
            .put(&mut wtxn, corrupt_reverse_key, &healthy_forward_key)?;
        wtxn.commit()?;
    }

    let report = vault.maintain().recompute_short_id_hashes().run()?;
    assert_eq!(report.orphan_short_ids_deleted, 1);

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, corrupt_reverse_key)?
            .is_none(),
        "corrupt reverse row should be pruned"
    );
    assert_eq!(
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, healthy.as_bytes())?,
        Some(healthy_forward_key.as_slice()),
        "healthy reverse row must survive"
    );
    assert_eq!(
        vault.store.short_ids.get(&rtxn, &healthy_forward_key)?,
        Some(healthy.as_bytes().as_slice()),
        "healthy forward row must not be reaped by a corrupt reverse row"
    );
    Ok(())
}

#[test]
fn valid_key_absent_entity_aliased_value_never_reaps_healthy_forward_one_1173() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let healthy = entity(104);
    let orphan = entity(105);

    vault
        .batch()
        .put(&healthy, 1, test_time_range(100, 100), 101, b"payload")
        .commit()?;

    let healthy_forward_key = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, healthy.as_bytes())?
            .ok_or(Error::EntityNotFound)?
            .to_vec()
    };

    // Valid reverse KEY with no backing entity, but a VALUE that aliases
    // the healthy entity's forward key. ONE-1173 pins that this can prune
    // only the absent entity's reverse row, never the healthy forward row.
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .short_ids_reverse
            .put(&mut wtxn, orphan.as_bytes(), &healthy_forward_key)?;
        wtxn.commit()?;
    }

    let report = vault.maintain().recompute_short_id_hashes().run()?;
    assert_eq!(report.orphan_short_ids_deleted, 1);

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, orphan.as_bytes())?
            .is_none(),
        "absent entity reverse row should be pruned"
    );
    assert_eq!(
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, healthy.as_bytes())?,
        Some(healthy_forward_key.as_slice()),
        "healthy reverse row must survive"
    );
    assert_eq!(
        vault.store.short_ids.get(&rtxn, &healthy_forward_key)?,
        Some(healthy.as_bytes().as_slice()),
        "healthy forward row must not be reaped by an aliased reverse value"
    );
    Ok(())
}

#[test]
fn valid_key_aliased_value_never_overwrites_healthy_forward_one_1173() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let healthy = entity(106);
    let aliased = entity(107);

    vault
        .batch()
        .put(&healthy, 1, test_time_range(100, 100), 101, b"payload")
        .commit()?;

    let (healthy_forward_key, healthy_hash) = {
        let rtxn = vault.store.env.read_txn()?;
        let value = vault
            .store
            .short_ids_reverse
            .get(&rtxn, healthy.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let (_, hash) = parse_short_id_value(value)?;
        (value.to_vec(), hash)
    };

    let mut aliased_payload = b"aliased-payload".to_vec();
    while ((xxh32(&aliased_payload, 0) % 256) as u8) != healthy_hash {
        aliased_payload.push(0);
    }

    vault
        .batch()
        .put(
            &aliased,
            1,
            test_time_range(100, 100),
            101,
            &aliased_payload,
        )
        .commit()?;

    let aliased_original_forward_key = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, aliased.as_bytes())?
            .ok_or(Error::EntityNotFound)?
            .to_vec()
    };

    // Valid reverse KEY with a backing entity, but a VALUE that aliases a
    // healthy entity's forward key. The hash is matched so the pass reaches
    // the forward-repair arm rather than the hash-refresh arm.
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .short_ids
            .delete(&mut wtxn, &aliased_original_forward_key)?;
        vault
            .store
            .short_ids_reverse
            .put(&mut wtxn, aliased.as_bytes(), &healthy_forward_key)?;
        wtxn.commit()?;
    }

    let report = vault.maintain().recompute_short_id_hashes().run()?;
    assert_eq!(report.short_id_hashes_updated, 0);
    assert_eq!(report.orphan_short_ids_deleted, 1);

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        vault.store.short_ids.get(&rtxn, &healthy_forward_key)?,
        Some(healthy.as_bytes().as_slice()),
        "healthy forward row must not be overwritten by an aliased reverse value"
    );
    assert_eq!(
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, healthy.as_bytes())?,
        Some(healthy_forward_key.as_slice()),
        "healthy reverse row must survive"
    );
    assert_eq!(
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, aliased.as_bytes())?,
        None,
        "backed aliased reverse row should be pruned without touching the healthy forward row"
    );
    assert!(
        vault
            .store
            .short_ids
            .get(&rtxn, &aliased_original_forward_key)?
            .is_none(),
        "the aliased entity's now-unpaired old forward row should be pruned by pass 2"
    );
    Ok(())
}

#[test]
fn recompute_short_id_hashes_keeps_in_pass_reserved_refresh_one_1176() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = entity(108);

    vault
        .batch()
        .put(&id, 1, test_time_range(100, 100), 101, b"payload-old")
        .commit()?;

    let (stale_forward_key, stale_hash) = {
        let rtxn = vault.store.env.read_txn()?;
        let value = vault
            .store
            .short_ids_reverse
            .get(&rtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let (_, hash) = parse_short_id_value(value)?;
        (value.to_vec(), hash)
    };

    let mut payload = b"payload-new".to_vec();
    while ((xxh32(&payload, 0) % 256) as u8) == stale_hash {
        payload.push(0);
    }
    vault
        .batch()
        .put(&id, 1, test_time_range(100, 100), 102, &payload)
        .commit()?;

    let fresh_forward_key = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?
            .to_vec()
    };
    assert_ne!(stale_forward_key, fresh_forward_key);

    // Simulate a crash/replay split where the entity body has the new
    // hash, but reverse points at the old hash and the fresh forward row
    // is missing. Pass 1 must refresh/rewrite it; pass 2 must not reap
    // that just-reserved row as its own orphan.
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .short_ids_reverse
            .put(&mut wtxn, id.as_bytes(), &stale_forward_key)?;
        vault
            .store
            .short_ids
            .delete(&mut wtxn, &fresh_forward_key)?;
        wtxn.commit()?;
    }

    let report = vault.maintain().recompute_short_id_hashes().run()?;
    assert_eq!(report.short_id_hashes_updated, 1);

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        vault.store.short_ids_reverse.get(&rtxn, id.as_bytes())?,
        Some(fresh_forward_key.as_slice()),
        "reverse row should be refreshed to the current content hash"
    );
    assert_eq!(
        vault.store.short_ids.get(&rtxn, &fresh_forward_key)?,
        Some(id.as_bytes().as_slice()),
        "fresh forward row written by this pass must survive pass 2"
    );
    Ok(())
}

#[test]
fn recompute_short_id_hashes_prunes_forward_orphan_via_pass_two() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = entity(104);

    vault
        .batch()
        .put(&id, 1, test_time_range(100, 100), 101, b"payload")
        .commit()?;

    let forward_key = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?
            .to_vec()
    };

    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .short_ids_reverse
            .delete(&mut wtxn, id.as_bytes())?;
        wtxn.commit()?;
    }

    let report = vault.maintain().recompute_short_id_hashes().run()?;
    assert_eq!(report.orphan_short_ids_deleted, 1);

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault.store.short_ids.get(&rtxn, &forward_key)?.is_none(),
        "forward-only orphan should be reaped by pass 2"
    );
    Ok(())
}

#[test]
fn rebuild_hnsw_heal_invalid_vectors_skips_reserved_id_rows() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let live = entity(105);

    vault.put_entity(&live, 1, test_time_range(1, 1), 1, b"node")?;
    vault.put_vector(&live, &[1.0, 0.0, 0.0, 0.0])?;

    {
        let mut wtxn = vault.store.env.write_txn()?;
        let valid_vector = [
            1.0_f32.to_le_bytes(),
            0.0_f32.to_le_bytes(),
            0.0_f32.to_le_bytes(),
            0.0_f32.to_le_bytes(),
        ]
        .concat();
        vault
            .store
            .vectors
            .put(&mut wtxn, &[0xFF; ENTITY_ID_LEN], &valid_vector)?;
        wtxn.commit()?;
    }

    let report = vault.maintain().rebuild_hnsw_heal_invalid_vectors().run()?;
    assert_eq!(report.hnsw_invalid_vectors_skipped, 1);
    assert_eq!(report.hnsw_live_nodes, 1);
    Ok(())
}

#[test]
fn run_all_operations() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let a = entity(90);
    let b = entity(91);
    let c = entity(92);

    for id in [a, b, c] {
        vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
    }

    vault.put_vector(&a, &[1.0, 0.0, 0.0, 0.0])?;
    vault.put_vector(&b, &[0.0, 1.0, 0.0, 0.0])?;
    vault.put_vector(&c, &[0.0, 0.0, 1.0, 0.0])?;

    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vectors.delete(&mut wtxn, c.as_bytes())?;
        vault.store.entities.delete(&mut wtxn, c.as_bytes())?;
        vault
            .store
            .text_postings
            .put(&mut wtxn, b"empty-maintain", &[])?;
        wtxn.commit()?;
    }

    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
    let _ = vault.query().search_ppr(&[a], 3).limit(10).run()?;
    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 0.25)?;

    let current_hash = {
        let rtxn = vault.store.env.read_txn()?;
        let value = vault
            .store
            .short_ids_reverse
            .get(&rtxn, a.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let (_, hash) = parse_short_id_value(value)?;
        hash
    };
    let mut drifted_payload = b"hash-drifted".to_vec();
    while ((xxh32(&drifted_payload, 0) % 256) as u8) == current_hash {
        drifted_payload.push(0);
    }

    {
        let mut wtxn = vault.store.env.write_txn()?;
        let record = vault
            .store
            .entities
            .get(&wtxn, a.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let mut updated = record[..ENTITY_METADATA_HEADER_LEN].to_vec();
        updated.extend_from_slice(&drifted_payload);
        vault
            .store
            .entities
            .put(&mut wtxn, a.as_bytes(), &updated)?;
        wtxn.commit()?;
    }

    let report = vault
        .maintain()
        .rebuild_hnsw()
        .cleanup_ppr_cache(0)
        .compact_postings()
        .recompute_short_id_hashes()
        .run()?;

    assert!(report.hnsw_dead_nodes_removed > 0);
    assert!(report.hnsw_live_nodes > 0);
    assert!(report.ppr_caches_evicted > 0);
    assert!(report.ppr_deps_cleaned > 0);
    assert!(report.postings_compacted > 0);
    assert!(report.orphan_short_ids_deleted > 0);
    assert!(report.short_id_hashes_updated > 0);
    Ok(())
}

#[test]
fn run_no_operations() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;

    let report = vault.maintain().run()?;
    assert_eq!(report, MaintenanceReport::default());
    Ok(())
}

#[test]
fn job_queue_cleanup_maintenance_reports_counts_and_requeues() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let queue = JobQueue::new(&vault);

    let EnqueueOutcome::Enqueued(job) = queue.enqueue(EnqueueJob {
        kind: "claim_extraction".to_owned(),
        payload: b"payload".to_vec(),
        dedupe_key: Some("turn:maintenance".to_owned()),
        run_id: Some("run-maintenance".to_owned()),
        now: 1,
    })?
    else {
        panic!("expected enqueue");
    };
    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimJob {
        lease_owner: "worker-a".to_owned(),
        now: 2,
    })?
    else {
        panic!("expected claim");
    };
    assert_eq!(claimed.id, job.id);

    let report = vault.maintain().cleanup_job_queue_leases(1).run()?;
    assert_eq!(report.job_queue_cleanup.pending, 1);
    assert_eq!(report.job_queue_cleanup.running, 0);
    assert_eq!(report.job_queue_cleanup.failed, 0);
    assert_eq!(report.job_queue_cleanup.done, 0);
    assert_eq!(report.job_queue_cleanup.stale_requeued, 1);
    assert_eq!(
        report
            .job_queue_cleanup
            .retry_reason_count(JobQueueRetryReason::LeaseTimeout),
        1
    );

    let ClaimOutcome::Claimed(reclaimed) = queue.claim(ClaimJob {
        lease_owner: "worker-b".to_owned(),
        now: crate::unix_seconds_now(),
    })?
    else {
        panic!("expected reclaimed job");
    };
    assert_eq!(reclaimed.id, job.id);
    assert_eq!(reclaimed.lease_owner.as_deref(), Some("worker-b"));

    Ok(())
}

#[test]
fn job_queue_cleanup_maintenance_rejects_zero_timeout() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;

    let err = vault
        .maintain()
        .cleanup_job_queue_leases(0)
        .run()
        .unwrap_err();
    assert_matches!(
        err,
        Error::InvalidJobQueueRecord("lease timeout must be > 0")
    );

    Ok(())
}

#[test]
fn clear_text_index_removes_all_text_rows_and_rewrites_manifest() -> Result<()> {
    use crate::store::{
        TEXT_ANALYZER_MANIFEST_HASH_KEY, TEXT_BM25_FIELD_SCHEMA_HASH_KEY,
        TEXT_INDEX_SCHEMA_VERSION_KEY,
    };

    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let a = entity(120);
    let b = entity(121);

    vault
        .batch()
        .put(&a, 1, test_time_range(1, 1), 1, b"a")
        .put(&b, 1, test_time_range(1, 1), 1, b"b")
        .text(&a, &[("body", "hello world")])
        .text(&b, &[("body", "world of rust")])
        .commit()?;

    let hits = vault.search_text("world", 10)?;
    assert_eq!(hits.len(), 2);

    let manifest_hash_before = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .vault_meta
            .get(&rtxn, TEXT_ANALYZER_MANIFEST_HASH_KEY)?
            .map(|b| b.to_vec())
    };
    assert!(manifest_hash_before.is_some());

    let report = vault.maintain().clear_text_index().run()?;
    assert!(report.text_postings_removed > 0);
    assert!(report.text_meta_removed > 0);
    assert!(report.text_forward_removed > 0);
    assert!(report.text_doc_field_lengths_removed > 0);
    assert!(report.text_bm25_field_stats_removed > 0);

    assert_eq!(count_entries(&vault.store.text_postings, &vault)?, 0);
    assert_eq!(count_entries(&vault.store.text_meta, &vault)?, 0);
    assert_eq!(count_entries(&vault.store.text_forward, &vault)?, 0);
    assert_eq!(
        count_entries(&vault.store.text_doc_field_lengths, &vault)?,
        0
    );
    assert_eq!(
        count_entries(&vault.store.text_bm25_field_stats, &vault)?,
        0
    );

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .vault_meta
            .get(&rtxn, TEXT_INDEX_SCHEMA_VERSION_KEY)?
            .is_some()
    );
    assert!(
        vault
            .store
            .vault_meta
            .get(&rtxn, TEXT_ANALYZER_MANIFEST_HASH_KEY)?
            .is_some()
    );
    assert!(
        vault
            .store
            .vault_meta
            .get(&rtxn, TEXT_BM25_FIELD_SCHEMA_HASH_KEY)?
            .is_some()
    );
    drop(rtxn);

    // Entities still present — clear_text_index only touches text DBs.
    assert!(vault.get_entity_type(&a)?.is_some());
    assert!(vault.get_entity_type(&b)?.is_some());

    // Index reusable after clear.
    vault
        .batch()
        .text(&a, &[("body", "hello again")])
        .commit()?;
    let hits = vault.search_text("hello", 10)?;
    assert!(!hits.is_empty());
    Ok(())
}

#[test]
fn rebuild_hnsw_empty_vault() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;

    let report = vault.maintain().rebuild_hnsw().run()?;
    assert_eq!(report.hnsw_dead_nodes_removed, 0);
    assert_eq!(report.hnsw_live_nodes, 0);
    assert_eq!(report.hnsw_invalid_vectors_skipped, 0);
    Ok(())
}
