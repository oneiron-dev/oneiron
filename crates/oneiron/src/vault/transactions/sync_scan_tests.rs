//! Host sync-state doors: scans refuse undeclared rows even under a broad prefix, and writes
//! refuse the families only the engine's own doors write.
use crate::error::{Error, StoreError};
use crate::test_util::{embedding_test_config, entity, open_test_vault_with};

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

/// A hard delete's fence and hard-delete marker are written only by the delete doors: the
/// host's generic door can neither forge one for a live id nor lower or drop the delete's own.
#[test]
fn the_generic_door_neither_forges_nor_drops_a_deletion_fence_or_marker() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let erased = entity(0x41);
    vault
        .batch()
        .put(
            &erased,
            1,
            crate::TimeRange { start: 1, end: 1 },
            1,
            b"erased",
        )
        .commit()
        .expect("put");
    vault
        .delete_entity_with_reason(&erased, crate::deletion::DeleteReason::GdprDelete)
        .expect("hard delete");
    let read = |key: &str| vault.sync_state_get(key).expect("read");
    let (fence, marker) = (
        format!("df:{}", erased.to_hex()),
        crate::deletion::local_hard_delete_key(&erased),
    );
    let fence_row = read(&fence).expect("the delete fenced its id");
    let marker_row = read(&marker).expect("the delete marked its id");
    let live = entity(0x42);
    let forged = [
        format!("df:{}", live.to_hex()),
        crate::deletion::local_hard_delete_key(&live),
    ];

    for key in [&fence, &marker, &forged[0], &forged[1]] {
        assert!(
            matches!(vault.sync_state_put(key, b""), Err(Error::InvalidConfig(_))),
            "{key}"
        );
        assert!(
            matches!(
                vault.with_write_txn(|txn| vault.sync_state_put_in_write_txn(txn, key, b"")),
                Err(Error::InvalidConfig(_))
            ),
            "{key}"
        );
        assert!(
            matches!(vault.sync_state_delete(key), Err(Error::InvalidConfig(_))),
            "{key}"
        );
    }

    assert_eq!(read(&fence), Some(fence_row));
    assert_eq!(read(&marker), Some(marker_row));
    assert!(forged.iter().all(|key| read(key).is_none()));
}
