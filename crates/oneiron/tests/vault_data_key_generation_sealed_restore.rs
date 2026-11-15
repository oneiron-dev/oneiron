//! A copy restored beside a page-sealed vault after a data-key generation act
//! that never committed: the live seal opens the staged, uncommitted key
//! first, but the copy's pages go under the key its restored state names, so
//! the copy's own mirror opens it after a close.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test vault_data_key_generation_sealed_restore`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActAuthority, ActSurface};
use oneiron::recovery::checkpoint::{CheckpointKey, RestoreReason};
use oneiron::test_doors::data_key_sealed_vault::{
    abort_data_key_generation_after_stage, create_sealed_owner_vault,
};
use oneiron::test_doors::steward::owner;
use oneiron::world_keys::{DataKeyGenerationWays, VaultKeyUnlock, unlock_page_seal};
use oneiron::{Vault, VaultConfig};

#[test]
fn a_copy_restored_beside_after_an_uncommitted_act_reopens_under_its_own_mirror() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("vault");
    let keystore = Arc::new(oneiron_keystore::MemoryKeystore::default());
    let vault =
        create_sealed_owner_vault(&path, Arc::clone(&keystore)).expect("a sealed owner vault");
    vault
        .add_vault_key_device()
        .expect("this install's device wrap");
    let owner_proof = owner(&vault).expect("owner proof");
    abort_data_key_generation_after_stage(
        &vault,
        &ActAuthority::Owner(owner_proof, ActSurface::ThisInstall),
        &DataKeyGenerationWays {
            password: None,
            passkeys: Vec::new(),
            escrows: Vec::new(),
            confirmed_removals: BTreeSet::new(),
        },
    )
    .expect("the act aborts after the stage");
    drop(vault);

    // The staged mirror names both generations: the live seal opens the
    // uncommitted key first, and the vault holds the committed one.
    let live_seal = unlock_page_seal(&path, &VaultKeyUnlock::Device(keystore.as_ref()))
        .expect("unlock the sealed vault");
    let mut config = VaultConfig::device();
    config.page_seal = Some(live_seal.clone());
    let vault = Vault::open(&path, config).expect("reopen the sealed vault");
    vault.install_device_keystore(Arc::clone(&keystore));
    let checkpoint = directory.path().join("checkpoint");
    vault
        .snapshot_checkpoint(&checkpoint, 100)
        .expect("seal a checkpoint on the committed generation");
    let signer = vault
        .checkpoint_signer()
        .expect("the vault's checkpoint signer");
    drop(vault);
    let key = CheckpointKey::unlock(&checkpoint, &VaultKeyUnlock::Device(keystore.as_ref()))
        .expect("this install's device wrap opens the checkpoint")
        .trusting(vec![signer]);

    let copy = directory.path().join("copy");
    let mut beside = VaultConfig::device();
    beside.page_seal = Some(
        live_seal
            .fresh_incarnation()
            .expect("a fresh incarnation of the live seal"),
    );
    let (restored, _) = Vault::restore_checkpoint(
        &checkpoint,
        &key,
        &copy,
        beside,
        RestoreReason::Restore,
        200,
    )
    .expect("the copy restores beside the live vault");
    drop(restored);

    let seal = unlock_page_seal(&copy, &VaultKeyUnlock::Device(keystore.as_ref()))
        .expect("the copy's own mirror unlocks it after a close");
    let mut config = VaultConfig::device();
    config.page_seal = Some(seal);
    let _copy = Vault::open(&copy, config).expect("the copy reopens under its own mirror");
}
