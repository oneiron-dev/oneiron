use super::EDGE_VALUE_LEN;
use crate::store::Store;
use crate::*;

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
        "Intra-batch cycle should return CycleDetected, got {:?}",
        result
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

    let result = vault.entities_in_learned_range(0, 10);
    assert!(
        matches!(result, Err(Error::CorruptedIndex("temporal learned key"))),
        "expected corrupted temporal learned key, got {result:?}"
    );
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
    let mut value = [0_u8; EDGE_VALUE_LEN];
    value[..4].copy_from_slice(&f32::NAN.to_le_bytes());

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
