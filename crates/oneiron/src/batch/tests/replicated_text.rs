//! Replicated body overwrites must not expose loser search postings.

use super::*;

#[test]
fn replicated_overwrite_deindexes_storage_managed_text() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    vault.put_entity(&id, ENTITY_TYPE_TURN, test_time_range(1, 1), 1, b"old")?;
    vault.with_write_txn(|txn| {
        crate::bm25::index_text(
            &vault.store,
            txn,
            &vault.analyzer,
            &id,
            &[("body".to_owned(), "loseruniquetoken".to_owned())],
        )?;
        Ok(())
    })?;
    assert_eq!(vault.search_text("loseruniquetoken", 10)?.len(), 1);

    vault
        .batch()
        .put_replicated(&id, ENTITY_TYPE_TURN, test_time_range(2, 2), 2, b"winner")
        .commit()?;
    vault.with_write_txn(|txn| {
        let row = vault.store.entities.get(txn, id.as_bytes())?.unwrap();
        assert_eq!(&row[ENTITY_METADATA_HEADER_LEN..], b"winner");
        assert!(vault.store.text_forward.get(txn, id.as_bytes())?.is_none());
        assert!(
            vault
                .store
                .text_doc_field_lengths
                .get(txn, id.as_bytes())?
                .is_none()
        );
        for item in vault.store.text_postings.iter(txn)? {
            let (_term, posting) = item?;
            assert!(
                !posting.starts_with(id.as_bytes()),
                "loser posting survived overwrite"
            );
        }
        Ok(())
    })?;
    assert!(vault.search_text("loseruniquetoken", 10)?.is_empty());
    Ok(())
}
