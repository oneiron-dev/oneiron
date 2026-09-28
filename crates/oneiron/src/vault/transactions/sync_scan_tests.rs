//! Host scans refuse undeclared sync-state rows even under a broad prefix.
use crate::error::{Error, StoreError};
use crate::test_util::{embedding_test_config, open_test_vault_with};

#[test]
fn broad_host_scans_refuse_undeclared_rows_without_hiding_declared_rows() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let declared = "rm:w:2026-03";
    let undeclared = "rm:z:legacy";
    vault.sync_state_put(declared, b"declared").unwrap();
    vault
        .with_write_txn(|txn| vault.store.sync_state.put(txn, undeclared, b"legacy"))
        .unwrap();

    for prefix in ["rm:", "r"] {
        assert!(matches!(
            vault.sync_state_keys_with_prefix(prefix),
            Err(Error::Store(StoreError::SideTableKeyUndeclared { key })) if key == undeclared
        ));
        let mut visited = Vec::new();
        let error = vault
            .with_write_txn(|txn| {
                vault.sync_state_visit_prefix_in_write_txn(txn, prefix, |key, value| {
                    visited.push((key.to_owned(), value.to_vec()));
                    Ok::<(), Error>(())
                })
            })
            .unwrap_err();
        assert!(matches!(
            error,
            Error::Store(StoreError::SideTableKeyUndeclared { key }) if key == undeclared
        ));
        assert_eq!(visited, vec![(declared.to_owned(), b"declared".to_vec())]);
    }

    vault
        .with_write_txn(|txn| vault.store.sync_state.delete(txn, undeclared).map(|_| ()))
        .unwrap();
    assert_eq!(
        vault.sync_state_keys_with_prefix("rm:").unwrap(),
        vec![declared]
    );
}
