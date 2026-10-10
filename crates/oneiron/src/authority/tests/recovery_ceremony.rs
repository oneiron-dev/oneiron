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
    let fold = fold_legacy_authority_log(&[genesis.clone()]);
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
    // Enrolling a second device closes the genesis window at once.
    assert!(!fold_legacy_authority_log_with_seen_times(&entries, &seen, 10).genesis_fragile);
}
