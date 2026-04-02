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
