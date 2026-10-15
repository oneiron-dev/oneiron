//! Vector writes, HNSW search/recall, validation and sync-protocol error taxonomy.

use super::*;

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

    assert!(vault.delete_entity_with_options(
        &deleted,
        crate::deletion::DeleteEntityOptions { purge: true }
    )?);

    let results = vault.search_vector(&[0.98_f32, 0.05, 0.0, 0.0], 3)?;
    assert!(!results.iter().any(|item| item.id == deleted));
    assert!(results.iter().any(|item| item.id == entry));
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
    assert!(vault.delete_entity_with_options(
        &entry,
        crate::deletion::DeleteEntityOptions { purge: true }
    )?);

    let results = vault.search_vector(&[0.0_f32, 1.0, 0.0, 0.0], 5)?;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, survivor);

    Ok(())
}
