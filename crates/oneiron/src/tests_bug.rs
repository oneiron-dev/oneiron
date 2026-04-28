use crate::store::Store;
use crate::types::EDGE_VALUE_LEN;
use crate::*;

fn non_finite_edge_value(weight: f32) -> [u8; EDGE_VALUE_LEN] {
    let mut value = [0_u8; EDGE_VALUE_LEN];
    value[..4].copy_from_slice(&weight.to_le_bytes());
    value
}

#[test]
fn test_intra_batch_cycle() {
    let temp_dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp_dir.path(), VaultConfig::device()).unwrap();

    let a = EntityId::now();
    let b = EntityId::now();

    vault
        .batch()
        .put(&a, 61, TimeRange { start: 1, end: 1 }, 2, b"a")
        .put(&b, 61, TimeRange { start: 3, end: 3 }, 4, b"b")
        .commit()
        .unwrap();

    let result = vault
        .batch()
        .edge_checked(&a, &b, 1.0)
        .edge_checked(&b, &a, 1.0)
        .commit();

    assert!(
        matches!(result, Err(Error::CycleDetected)),
        "Intra-batch cycle should return CycleDetected, got {result:?}"
    );

    // Verify abort rolled back both edges
    assert!(
        !vault.edge_exists(&a, EdgeKind::ChildOf, &b).unwrap(),
        "a→b edge should not persist after cycle abort"
    );
    assert!(
        !vault.edge_exists(&b, EdgeKind::ChildOf, &a).unwrap(),
        "b→a edge should not persist after cycle abort"
    );
}

#[test]
fn learned_range_rejects_corrupted_key_length() {
    let temp_dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp_dir.path(), VaultConfig::device()).unwrap();

    let mut bad_key = Vec::with_capacity(23);
    bad_key.extend_from_slice(&5_u64.to_be_bytes());
    bad_key.extend_from_slice(&[0xff; 15]);

    vault
        .with_write_txn(|wtxn| {
            vault
                .store
                .temporal_learned
                .put(wtxn, &bad_key, &[])
                .unwrap();
            Ok(())
        })
        .unwrap();

    let result = vault.entities_in_learned_range(0, 10);
    assert!(
        matches!(result, Err(Error::CorruptedIndex("temporal learned key"))),
        "expected corrupted temporal learned key, got {result:?}"
    );
}

#[test]
fn learned_range_seek_starts_at_lower_bound() {
    let temp_dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp_dir.path(), VaultConfig::device()).unwrap();
    let id = EntityId::now();

    vault
        .with_write_txn(|wtxn| {
            vault
                .store
                .temporal_learned
                .put(wtxn, &[0_u8; 23], &[])
                .unwrap();
            Ok(())
        })
        .unwrap();
    vault
        .put_entity(&id, 0, TimeRange { start: 20, end: 20 }, 20, b"in-range")
        .unwrap();

    let result = vault.entities_in_learned_range(10, 30).unwrap();
    assert_eq!(result, vec![id]);
}

#[test]
fn sources_reject_corrupted_edge_key_length() {
    let temp_dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp_dir.path(), VaultConfig::device()).unwrap();
    let parent = EntityId::now();

    vault
        .batch()
        .put(&parent, 61, TimeRange { start: 1, end: 1 }, 2, b"parent")
        .commit()
        .unwrap();

    let mut bad_key = Vec::with_capacity(32);
    bad_key.extend_from_slice(parent.as_bytes());
    bad_key.push(EdgeKind::ChildOf as u8);
    bad_key.extend_from_slice(&[0_u8; 15]);

    vault
        .with_write_txn(|wtxn| {
            vault
                .store
                .edges_in
                .put(wtxn, &bad_key, &[0_u8; EDGE_VALUE_LEN])
                .unwrap();
            Ok(())
        })
        .unwrap();

    let result = vault.sources(&parent, EdgeKind::ChildOf, None);
    assert!(
        matches!(result, Err(Error::CorruptedIndex("edge record"))),
        "expected corrupted edge record, got {result:?}"
    );
}

#[test]
fn targets_reject_non_finite_persisted_edge_payload() {
    let temp_dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp_dir.path(), VaultConfig::device()).unwrap();
    let src = EntityId::now();
    let tgt = EntityId::now();
    let value = non_finite_edge_value(f32::NAN);

    vault
        .with_write_txn(|wtxn| {
            let key = Store::encode_edge_key(&src, EdgeKind::BelongsTo, &tgt);
            vault.store.edges_out.put(wtxn, &key, &value).unwrap();
            Ok(())
        })
        .unwrap();

    let result = vault.targets(&src, EdgeKind::BelongsTo, None);
    assert!(
        matches!(result, Err(Error::CorruptedIndex("edge record"))),
        "expected corrupted edge record, got {result:?}"
    );
}

#[test]
fn subtree_rejects_non_finite_persisted_edge_payload() {
    let temp_dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp_dir.path(), VaultConfig::device()).unwrap();
    let root = EntityId::now();
    let child = EntityId::now();
    let value = non_finite_edge_value(f32::NAN);

    vault
        .with_write_txn(|wtxn| {
            let key = Store::encode_edge_key(&root, EdgeKind::ChildOf, &child);
            vault.store.edges_in.put(wtxn, &key, &value).unwrap();
            Ok(())
        })
        .unwrap();

    let result = vault.subtree(&root, 1);
    assert!(
        matches!(result, Err(Error::CorruptedIndex("edge record"))),
        "expected corrupted edge record, got {result:?}"
    );
}

#[test]
fn ancestors_reject_non_finite_persisted_edge_payload() {
    let temp_dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp_dir.path(), VaultConfig::device()).unwrap();
    let child = EntityId::now();
    let parent = EntityId::now();
    let value = non_finite_edge_value(f32::NAN);

    vault
        .with_write_txn(|wtxn| {
            let key = Store::encode_edge_key(&child, EdgeKind::ChildOf, &parent);
            vault.store.edges_out.put(wtxn, &key, &value).unwrap();
            Ok(())
        })
        .unwrap();

    let result = vault.ancestors(&child);
    assert!(
        matches!(result, Err(Error::CorruptedIndex("edge record"))),
        "expected corrupted edge record, got {result:?}"
    );
}

#[test]
fn edges_out_rejects_non_finite_persisted_edge_payload() {
    let temp_dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp_dir.path(), VaultConfig::device()).unwrap();
    let src = EntityId::now();
    let tgt = EntityId::now();

    vault
        .batch()
        .put(&src, 61, TimeRange { start: 1, end: 1 }, 2, b"src")
        .put(&tgt, 61, TimeRange { start: 1, end: 1 }, 2, b"tgt")
        .commit()
        .unwrap();

    let key = Store::encode_edge_key(&src, EdgeKind::ChildOf, &tgt);
    let value = non_finite_edge_value(f32::NAN);

    vault
        .with_write_txn(|wtxn| {
            vault.store.edges_out.put(wtxn, &key, &value).unwrap();
            Ok(())
        })
        .unwrap();

    let result = vault.edges_out(&src);
    assert!(
        matches!(result, Err(Error::CorruptedIndex("edge record"))),
        "expected corrupted edge record, got {result:?}"
    );
}

#[test]
fn delete_entity_rejects_non_finite_persisted_edge_payload() {
    let temp_dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp_dir.path(), VaultConfig::device()).unwrap();
    let src = EntityId::now();
    let tgt = EntityId::now();

    vault
        .batch()
        .put(&src, 61, TimeRange { start: 1, end: 1 }, 2, b"src")
        .put(&tgt, 61, TimeRange { start: 1, end: 1 }, 2, b"tgt")
        .commit()
        .unwrap();

    let key_out = Store::encode_edge_key(&src, EdgeKind::ChildOf, &tgt);
    let key_in = Store::encode_edge_key(&tgt, EdgeKind::ChildOf, &src);
    let value = non_finite_edge_value(f32::INFINITY);

    vault
        .with_write_txn(|wtxn| {
            vault.store.edges_out.put(wtxn, &key_out, &value).unwrap();
            vault.store.edges_in.put(wtxn, &key_in, &value).unwrap();
            Ok(())
        })
        .unwrap();

    let result = vault.delete_entity(&src);
    assert!(
        matches!(result, Err(Error::CorruptedIndex("edge record"))),
        "expected corrupted edge record, got {result:?}"
    );
}

#[test]
fn batch_in_put_failure_does_not_commit_partial_entity_update() {
    let temp_dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp_dir.path(), VaultConfig::device()).unwrap();
    let id = EntityId::now();
    let old_occurred = TimeRange { start: 10, end: 10 };
    let new_occurred = TimeRange { start: 20, end: 25 };

    vault.put_entity(&id, 61, old_occurred, 11, b"old").unwrap();
    let before_raw = vault.get_raw(&id).unwrap().unwrap();

    vault
        .with_write_txn(|wtxn| {
            vault
                .store
                .short_ids
                .put(wtxn, id.as_bytes(), &[1])
                .unwrap();
            Ok(())
        })
        .unwrap();

    vault
        .with_write_txn(|wtxn| {
            let err = vault
                .batch_in()
                .put(&id, 62, new_occurred, 21, b"new")
                .apply(wtxn)
                .expect_err("expected malformed short id value to fail");
            assert!(matches!(err, Error::CorruptedIndex("short id value")));
            Ok(())
        })
        .unwrap();

    let after_raw = vault.get_raw(&id).unwrap().unwrap();
    assert_eq!(after_raw, before_raw);

    let rtxn = vault.store.env.read_txn().unwrap();
    let old_type_key = Store::encode_type_key(61, &id);
    let new_type_key = Store::encode_type_key(62, &id);
    let old_start_key = Store::encode_temporal_key(old_occurred.start, &id);
    let new_start_key = Store::encode_temporal_key(new_occurred.start, &id);
    let new_end_key = Store::encode_temporal_key(new_occurred.end, &id);
    let old_learned_key = Store::encode_temporal_key(11, &id);
    let new_learned_key = Store::encode_temporal_key(21, &id);

    assert!(
        vault
            .store
            .type_index
            .get(&rtxn, &old_type_key)
            .unwrap()
            .is_some()
    );
    assert!(
        vault
            .store
            .type_index
            .get(&rtxn, &new_type_key)
            .unwrap()
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_occurred_start
            .get(&rtxn, &old_start_key)
            .unwrap()
            .is_some()
    );
    assert!(
        vault
            .store
            .temporal_occurred_start
            .get(&rtxn, &new_start_key)
            .unwrap()
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &new_end_key)
            .unwrap()
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_learned
            .get(&rtxn, &old_learned_key)
            .unwrap()
            .is_some()
    );
    assert!(
        vault
            .store
            .temporal_learned
            .get(&rtxn, &new_learned_key)
            .unwrap()
            .is_none()
    );
}
