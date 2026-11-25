//! A delayed unlock cannot put a replaced data key back (data-key
//! generations, PR 1): an unlock whose password wrap opened before a new
//! generation committed is refused when it would hold its key after the act,
//! and the vault keeps the new key.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test vault_data_key_generation_stale_unlock`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::authority::{ActAuthority, ActSurface};
use oneiron::recovery::checkpoint::CheckpointKey;
use oneiron::test_doors::data_key_stale_unlock::unlock_with_password_across;
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};
use oneiron::world_keys::{DataKeyGenerationCause, DataKeyGenerationWays, VaultKeyUnlock};

const PASSWORD: &[u8] = b"correct horse battery staple";

#[test]
fn an_unlock_opened_before_a_new_generation_does_not_hold_the_replaced_key() {
    let directory = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(&directory.path().join("vault")).expect("owner vault");
    vault.ensure_vault_key().expect("mint the vault data key");
    vault
        .set_vault_key_password(PASSWORD, None)
        .expect("a vault password");
    let owner_proof = owner(&vault).expect("owner proof");

    // The unlock opens the password wrap; the act commits and holds the new
    // key; then the unlock tries to hold the key it opened.
    let mut committed = None;
    let held = unlock_with_password_across(&vault, PASSWORD, || {
        let outcome = vault
            .start_data_key_generation_as(
                &ActAuthority::Owner(owner_proof, ActSurface::ThisInstall),
                DataKeyGenerationCause::OwnerRequest,
                &DataKeyGenerationWays {
                    password: Some(PASSWORD),
                    passkeys: Vec::new(),
                    escrows: Vec::new(),
                    confirmed_removals: BTreeSet::new(),
                },
            )
            .expect("the owner starts a new generation while the unlock waits");
        committed = Some(outcome.commitment);
    });
    let committed = committed.expect("the act ran between the open and the hold");
    let Err(error) = held else {
        panic!("the delayed unlock must not hold the replaced key");
    };
    assert!(
        error.to_string().contains("moved to a new generation"),
        "the refusal says the key moved on: {error}"
    );

    // The vault still holds the new key: what it seals now carries the new
    // commitment, and the password's new wrap opens it.
    let after = directory.path().join("after");
    vault
        .snapshot_checkpoint(&after, 100)
        .expect("seal a checkpoint after the delayed unlock");
    assert_eq!(
        CheckpointKey::unlocks(&after)
            .expect("the checkpoint's clear head")
            .commitment,
        committed,
        "the checkpoint is sealed under the new generation's key"
    );
    CheckpointKey::unlock(&after, &VaultKeyUnlock::Password(PASSWORD))
        .expect("the password's new wrap opens the checkpoint sealed after");
}
