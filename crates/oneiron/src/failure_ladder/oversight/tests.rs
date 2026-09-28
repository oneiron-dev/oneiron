use super::*;

fn activity_bytes(reviewed_at: Option<u64>) -> Vec<u8> {
    rmp_serde::to_vec_named(&Activity {
        proposed_at: 20,
        reviewed_at,
        escalated: false,
    })
    .unwrap()
}

#[test]
fn decoded_activity_refuses_review_before_proposal() {
    for reviewed_at in [None, Some(20), Some(21)] {
        assert!(Activity::decode(&activity_bytes(reviewed_at)).is_ok());
    }
    assert!(matches!(
        Activity::decode(&activity_bytes(Some(19))),
        Err(Error::CorruptedIndex(_))
    ));
}

#[test]
fn corrupted_activity_cannot_emit_or_accept_review() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let case = "11111111111111111111111111111111";
    let key = ACTIVITY.key_bytes(&case.to_owned());
    vault.with_write_txn(|txn| {
        vault
            .store
            .vault_meta
            .put(txn, &key, &activity_bytes(Some(19)))?;
        Ok(())
    })?;
    assert!(matches!(
        vault.emit_healer_oversight(30),
        Err(Error::CorruptedIndex(_))
    ));
    assert!(matches!(
        vault.record_healer_review(case, 30, false),
        Err(Error::CorruptedIndex(_))
    ));
    Ok(())
}
