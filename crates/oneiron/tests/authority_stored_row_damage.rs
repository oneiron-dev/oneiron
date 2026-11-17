#![cfg(oneiron_test_support)]
//! L9-50 (ARCH-0006a #list-read-built): an authority reader reports a damaged
//! stored row as `CorruptedIndex`, never as a refusal or a bad setting.

use std::sync::Arc;

use oneiron::authority::{HOST_ISSUER_SEED_BYTES, HostSlipIssuer};
use oneiron::test_doors::authority_stored_damage::{
    damage_first_stored_authority_log_body, put_raw_authority_observation_policy,
};
use oneiron::{Error, Vault, VaultConfig};

/// A policy row as the store holds one written before the log's bounds:
/// the stale-roster window, the ingest window and the ingest threshold,
/// each eight bytes big-endian.
fn policy_row(stale_roster_window_secs: u64, ingest_window_secs: u64, threshold: u64) -> Vec<u8> {
    [stale_roster_window_secs, ingest_window_secs, threshold]
        .iter()
        .flat_map(|value| value.to_be_bytes())
        .collect()
}

#[test]
fn a_damaged_stored_authority_log_body_folds_as_corrupted_index() {
    let dir = tempfile::tempdir().expect("vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = HostSlipIssuer::from_seed(&[0x51; HOST_ISSUER_SEED_BYTES]).expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    let fold = vault.authority_fold().expect("the rooted vault folds");
    assert!(fold.vault_id.is_some(), "the root stored a genesis row");

    damage_first_stored_authority_log_body(&vault).expect("one stored row damaged");

    let error = vault
        .authority_fold()
        .expect_err("a fold over a damaged stored row answers no fold");
    assert!(
        matches!(error, Error::CorruptedIndex(_)),
        "a damaged stored authority row is store damage, not a refusal: {error:?}"
    );
}

#[test]
fn a_stored_observation_policy_that_fails_its_check_reads_as_corrupted_index() {
    let dir = tempfile::tempdir().expect("vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("fresh vault");

    put_raw_authority_observation_policy(&vault, &policy_row(60, 30, 1))
        .expect("a valid policy row");
    let policy = vault
        .authority_observation_policy()
        .expect("a valid stored policy reads");
    assert_eq!(
        policy.ingest_window_secs, 30,
        "the door wrote the policy row"
    );

    put_raw_authority_observation_policy(&vault, &policy_row(60, 0, 1))
        .expect("a policy row with a zero ingest window");
    let error = vault
        .authority_observation_policy()
        .expect_err("a stored policy that fails its check does not read");
    assert!(
        matches!(error, Error::CorruptedIndex(_)),
        "a stored policy that fails its check is store damage, not a setting: {error:?}"
    );
    let error = vault
        .authority_fold()
        .expect_err("every fold reads the policy row");
    assert!(
        matches!(error, Error::CorruptedIndex(_)),
        "the fold reports the damaged policy row as store damage: {error:?}"
    );
}
