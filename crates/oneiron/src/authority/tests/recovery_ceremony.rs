//! Mandatory recovery-secret setup and in-chain re-rooting.
use super::support::*;
use super::*;

#[test]
fn genesis_secret_step_cannot_be_skipped_and_dismissal_is_visible() {
    let key = ed_key(73);
    let mut genesis = genesis_entry(73, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    if let AuthorityOp::Genesis { recovery, .. } = &mut genesis.op {
        *recovery = GenesisRecoveryStep::acknowledge(&[7; 32], false).unwrap();
    }
    genesis = sign_ed(genesis, &key);
    let bytes = encode_authority_log_entry_body(&genesis).unwrap();
    let mut value = rmpv::decode::read_value(&mut std::io::Cursor::new(&bytes)).unwrap();
    if let rmpv::Value::Map(entries) = &mut value {
        let op = entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("op"))
            .unwrap();
        if let rmpv::Value::Map(fields) = &mut op.1 {
            fields.retain(|(key, _)| key.as_str() != Some("recovery_secret_step"));
        }
    }
    let mut skipped = Vec::new();
    rmpv::encode::write_value(&mut skipped, &value).unwrap();
    assert!(decode_authority_log_entry_body(&skipped).is_err());
    let fold = fold_authority_log(&[genesis.clone()]);
    assert!(fold.genesis_fragile);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll = enroll_device_entry(
        vault_id,
        &genesis,
        &key,
        EnrollSpec {
            seed: 74,
            roles: ROLE_AGENT,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let hash = authority_entry_hash(&enroll).unwrap();
    let entries = [genesis, enroll];
    let seen = BTreeMap::from([(hash, 10)]);
    assert!(fold_authority_log_with_seen_times(&entries, &seen, 10).genesis_fragile);
    assert!(
        !fold_authority_log_with_seen_times(&entries, &seen, 10 + DEFAULT_PENDING_WIDEN_DELAY_SECS)
            .genesis_fragile
    );
}

#[test]
fn migration_preserves_genesis_and_does_not_restore_instant_widen_authority() {
    let old = ed_key(75);
    let new = ed_key(76);
    let genesis = genesis_entry(75, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let reroot = sign_ed(
        unsigned_entry(
            Some(vault_id),
            1,
            vec![authority_entry_hash(&genesis).unwrap()],
            AuthorityOp::ReRoot {
                new_device: device(
                    authority_key_from_ed(&new),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Hardware,
                ),
            },
            authority_key_from_ed(&old),
            2,
        ),
        &old,
    );
    let bytes = encode_authority_log_entry_body(&reroot).unwrap();
    assert_eq!(decode_authority_log_entry_body(&bytes).unwrap(), reroot);
    let migrated = fold_authority_log(&[genesis.clone(), reroot.clone()]);
    assert_eq!(migrated.vault_id, Some(vault_id));
    assert!(migrated.roster[&authority_key_from_ed(&old)].revoked);
    assert!(!migrated.roster[&authority_key_from_ed(&new)].revoked);
    assert!(migrated.pending_widens.is_empty());
    let enroll = enroll_device_entry(
        vault_id,
        &reroot,
        &new,
        EnrollSpec {
            seed: 77,
            roles: ROLE_AGENT,
            tier: AuthorityTier::Software,
            seq: 0,
            ts: 3,
        },
    );
    let hash = authority_entry_hash(&enroll).unwrap();
    let seen = BTreeMap::from([(hash, 10)]);
    let entries = [genesis, reroot, enroll];
    let pending = fold_authority_log_with_seen_times(&entries, &seen, 10);
    assert!(pending.pending_widens.contains_key(&hash));
    let cleared =
        fold_authority_log_with_seen_times(&entries, &seen, 10 + DEFAULT_PENDING_WIDEN_DELAY_SECS);
    assert!(!cleared.roster[&authority_key_from_ed(&ed_key(77))].revoked);
    assert_eq!(cleared.vault_id, Some(vault_id));
}
