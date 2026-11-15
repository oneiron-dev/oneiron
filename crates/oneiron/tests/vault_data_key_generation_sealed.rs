//! A page-sealed vault's data-key generations (PR 2): the owner starts a new
//! generation on the maximum tier, the vault's pages stay under the key of the
//! incarnation they were written under, and the mirror names both generations
//! while the act runs, so a crash on either side of the commit still opens.
//! A mirror saved before the act opens nothing after it; an act that never
//! committed leaves the vault on its old generation; an act whose mirror
//! rewrite never ran opens on the new one.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test vault_data_key_generation_sealed`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use oneiron::authority::{ActAuthority, ActSurface};
use oneiron::error::{Error, SecretError};
use oneiron::recovery::checkpoint::CheckpointKey;
use oneiron::test_doors::data_key_sealed_vault::{
    abort_data_key_generation_after_stage, create_sealed_owner_vault,
    start_data_key_generation_without_mirror_finish,
};
use oneiron::test_doors::steward::owner;
use oneiron::world_keys::{
    DataKeyGenerationCause, DataKeyGenerationWays, VaultKeyUnlock, page_seal_custody_path,
    unlock_page_seal,
};
use oneiron::{Vault, VaultConfig};

const PASSWORD: &[u8] = b"correct horse battery staple";

/// A sealed owner's vault on a fresh in-memory device keystore.
fn sealed_vault(path: &Path) -> (Vault, Arc<oneiron_keystore::MemoryKeystore>) {
    let keystore = Arc::new(oneiron_keystore::MemoryKeystore::default());
    let vault =
        create_sealed_owner_vault(path, Arc::clone(&keystore)).expect("a sealed owner vault");
    (vault, keystore)
}

/// This install's device wrap id, written to the keystore just installed.
fn device_wrap(vault: &Vault) -> String {
    vault
        .add_vault_key_device()
        .expect("this install's device wrap")
        .id
}

fn wrap_ids(vault: &Vault) -> Vec<String> {
    let mut ids: Vec<String> = vault
        .vault_key_wraps()
        .expect("the vault key's wraps")
        .into_iter()
        .map(|info| info.id)
        .collect();
    ids.sort();
    ids
}

fn commitment_of(image: &Path) -> [u8; 32] {
    CheckpointKey::unlocks(image)
        .expect("the checkpoint's clear head")
        .commitment
}

/// Reopens the sealed vault at `path` through this install's device wrap.
fn reopen_sealed(path: &Path, keystore: &Arc<oneiron_keystore::MemoryKeystore>) -> Vault {
    let seal = unlock_page_seal(path, &VaultKeyUnlock::Device(keystore.as_ref()))
        .expect("unlock the sealed vault");
    let mut config = VaultConfig::device();
    config.page_seal = Some(seal);
    let vault = Vault::open(path, config).expect("reopen the sealed vault");
    vault.install_device_keystore(Arc::clone(keystore));
    vault
}

#[test]
fn a_sealed_vault_unlocks_after_a_new_generation_with_the_new_device_wrap() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("vault");
    let (vault, keystore) = sealed_vault(&path);
    device_wrap(&vault);
    vault
        .check_page_custody()
        .expect("the mirror carries a wrap");
    let before = directory.path().join("before");
    vault
        .snapshot_checkpoint(&before, 100)
        .expect("seal a checkpoint before the act");
    let commitment_before = commitment_of(&before);

    let owner_proof = owner(&vault).expect("owner proof");
    let outcome = vault
        .start_data_key_generation_as(
            &ActAuthority::Owner(owner_proof, ActSurface::ThisInstall),
            DataKeyGenerationCause::OwnerRequest,
            &DataKeyGenerationWays {
                password: None,
                passkeys: Vec::new(),
                escrows: Vec::new(),
                confirmed_removals: BTreeSet::new(),
            },
        )
        .expect("the owner starts a new generation");
    assert_eq!(outcome.generation, 1);
    assert!(
        outcome.pages_keep_earlier_key,
        "the sealed pages keep their incarnation's key"
    );
    assert!(
        !outcome.mirror_pending,
        "the mirror rewrite ran with the act"
    );
    assert_ne!(
        outcome.commitment, commitment_before,
        "the new generation seals under a new commitment"
    );
    drop(vault);

    let vault = reopen_sealed(&path, &keystore);
    vault.check_page_custody().expect("the mirror is current");
    let after = directory.path().join("after");
    vault
        .snapshot_checkpoint(&after, 101)
        .expect("seal a checkpoint after the reopen");
    assert_eq!(outcome.commitment, commitment_of(&after));
    CheckpointKey::unlock(&after, &VaultKeyUnlock::Device(keystore.as_ref()))
        .expect("this install's device wrap opens the checkpoint sealed after");
}

#[test]
fn a_mirror_saved_before_the_act_opens_nothing_after_it() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("vault");
    let (vault, keystore) = sealed_vault(&path);
    let device = device_wrap(&vault);
    vault
        .set_vault_key_password(PASSWORD, None)
        .expect("a vault password");
    let mirror_path = page_seal_custody_path(&path).expect("the mirror's path");
    let saved = std::fs::read(&mirror_path).expect("the mirror's bytes before the act");

    let owner_proof = owner(&vault).expect("owner proof");
    let mut confirmed = BTreeSet::new();
    confirmed.insert("password".to_owned());
    for id in wrap_ids(&vault) {
        if id.starts_with("device:") && id != device {
            confirmed.insert(id);
        }
    }
    vault
        .start_data_key_generation_as(
            &ActAuthority::Owner(owner_proof, ActSurface::ThisInstall),
            DataKeyGenerationCause::OwnerRequest,
            &DataKeyGenerationWays {
                password: None,
                passkeys: Vec::new(),
                escrows: Vec::new(),
                confirmed_removals: confirmed,
            },
        )
        .expect("the owner starts a new generation");
    drop(vault);

    let current = std::fs::read(&mirror_path).expect("the mirror's bytes after the act");
    assert!(
        unlock_page_seal(&path, &VaultKeyUnlock::Password(PASSWORD)).is_err(),
        "the removed password opens nothing under the current mirror"
    );
    std::fs::write(&mirror_path, &saved).expect("put the saved mirror back");
    let seal = unlock_page_seal(&path, &VaultKeyUnlock::Password(PASSWORD))
        .expect("the old wrap opens the old key");
    let mut config = VaultConfig::device();
    config.page_seal = Some(seal);
    let Err(error) = Vault::open(&path, config) else {
        panic!("a stale seal opens no vault");
    };
    assert!(
        matches!(error, Error::Secret(SecretError::StalePageSealCredential)),
        "a stale seal is refused by kind: {error}"
    );

    std::fs::write(&mirror_path, &current).expect("put the current mirror back");
    let _vault = reopen_sealed(&path, &keystore);
}

#[test]
fn an_act_that_never_committed_leaves_a_sealed_vault_on_its_old_generation() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("vault");
    let (vault, keystore) = sealed_vault(&path);
    device_wrap(&vault);
    let before = directory.path().join("before");
    vault
        .snapshot_checkpoint(&before, 100)
        .expect("seal a checkpoint before the aborted act");
    let commitment_before = commitment_of(&before);

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

    let vault = reopen_sealed(&path, &keystore);
    let after = directory.path().join("after");
    vault
        .snapshot_checkpoint(&after, 101)
        .expect("seal a checkpoint after the reopen");
    assert_eq!(
        commitment_of(&after),
        commitment_before,
        "the vault that never committed seals under its old commitment"
    );
    drop(vault);

    let _vault = reopen_sealed(&path, &keystore);
}

#[test]
fn an_act_whose_mirror_rewrite_never_ran_opens_on_the_new_generation() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("vault");
    let (vault, keystore) = sealed_vault(&path);
    device_wrap(&vault);

    let owner_proof = owner(&vault).expect("owner proof");
    let outcome = start_data_key_generation_without_mirror_finish(
        &vault,
        &ActAuthority::Owner(owner_proof, ActSurface::ThisInstall),
        &DataKeyGenerationWays {
            password: None,
            passkeys: Vec::new(),
            escrows: Vec::new(),
            confirmed_removals: BTreeSet::new(),
        },
    )
    .expect("the act commits without its mirror rewrite");
    assert_eq!(outcome.generation, 1);
    drop(vault);

    let vault = reopen_sealed(&path, &keystore);
    let after = directory.path().join("after");
    vault
        .snapshot_checkpoint(&after, 100)
        .expect("seal a checkpoint after the reopen");
    assert_eq!(
        commitment_of(&after),
        outcome.commitment,
        "the vault opens on the generation it committed"
    );
}

#[test]
fn a_mirror_whose_key_chain_is_cut_is_not_ready() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("vault");
    let (vault, _keystore) = sealed_vault(&path);
    device_wrap(&vault);
    let owner_proof = owner(&vault).expect("owner proof");
    vault
        .start_data_key_generation_as(
            &ActAuthority::Owner(owner_proof, ActSurface::ThisInstall),
            DataKeyGenerationCause::OwnerRequest,
            &DataKeyGenerationWays {
                password: None,
                passkeys: Vec::new(),
                escrows: Vec::new(),
                confirmed_removals: BTreeSet::new(),
            },
        )
        .expect("the owner starts a new generation");
    vault
        .check_page_custody()
        .expect("the rewritten mirror carries the new key and its link");

    // The new key's header with its link cut, replaced whole: an unlock of
    // it reaches the new key but not the one the pages are sealed under.
    let mirror_path = page_seal_custody_path(&path).expect("the mirror's path");
    let raw = std::fs::read(&mirror_path).expect("read the mirror");
    let mut mirror: serde_json::Value = serde_json::from_slice(&raw).expect("the mirror is JSON");
    let header = mirror
        .get_mut("carried")
        .and_then(serde_json::Value::as_object_mut)
        .expect("the mirror's key header");
    assert!(
        header.remove("links").is_some(),
        "the header carries the new generation's link"
    );
    let cut = directory.path().join("mirror-cut");
    std::fs::write(
        &cut,
        serde_json::to_vec(&mirror).expect("encode the mirror"),
    )
    .expect("write the cut mirror");
    std::fs::rename(&cut, &mirror_path).expect("replace the mirror");

    let Err(error) = vault.check_page_custody() else {
        panic!("a mirror whose key chain is cut must not pass the ready check");
    };
    assert!(
        matches!(
            error,
            Error::Secret(SecretError::WorldKeyRefused(reason)) if reason.contains("key chain")
        ),
        "the ready check refuses the cut chain: {error}"
    );
}
