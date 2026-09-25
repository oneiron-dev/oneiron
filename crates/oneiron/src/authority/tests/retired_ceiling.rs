//! Historic ceiling bytes remain verifiable but no local ceiling verb remains.
use super::support::*;
use super::*;
#[test]
fn historical_ceiling_decodes_but_new_local_emission_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    let root = ed_key(144);
    let genesis = genesis_entry(144, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    vault
        .put_authority_log_entry(&genesis, crate::TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
    let entry = sign_ed(
        unsigned_entry(
            Some(genesis_vault_id(&genesis).unwrap()),
            1,
            vec![authority_entry_hash(&genesis).unwrap()],
            AuthorityOp::RetiredCeiling {
                authority_key: authority_key_from_ed(&root),
                actor_class: "agent".to_owned(),
                ceiling: 1,
            },
            authority_key_from_ed(&root),
            2,
        ),
        &root,
    );
    let bytes = encode_authority_log_entry_body(&entry).unwrap();
    let decoded = decode_authority_log_entry_body(&bytes).unwrap();
    assert_eq!(decoded, entry);
    assert_eq!(
        authority_entry_hash(&decoded).unwrap(),
        authority_entry_hash(&entry).unwrap()
    );
    assert!(
        vault
            .put_authority_log_entry(&entry, crate::TimeRange { start: 2, end: 2 }, 2)
            .is_err()
    );
    assert!(
        vault
            .get_authority_log_entry(&authority_log_entity_id(&entry).unwrap())
            .unwrap()
            .is_none()
    );
    vault.import_signed_authority_history(&[bytes]).unwrap();
    assert!(vault.authority_fold().unwrap().actor_bindings.is_empty());
}
