//! A vault's data-key generations (PR 1): the owner starts a new generation,
//! everything sealed after opens only with the new key, and everything sealed
//! before still opens with the old one, reached through the link chain. A
//! checkpoint sealed after refuses the old password and the old escrow
//! capsule; a checkpoint sealed before still opens and restores. A custody
//! head published before does not open with the key after, the first
//! publication after the act seals the head again under the new key, and a
//! pass that read its recipients before the act seals nothing under the
//! replaced key. An unconfirmed way, and a presented password or passkey
//! that does not open its wrap, refuse the act and write nothing.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test vault_data_key_generation`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use oneiron::authority::{ActAuthority, ActSurface};
use oneiron::dreamer_wake::ProjectorPolicy;
use oneiron::federation::EngineControlActor;
use oneiron::recovery::checkpoint::{CheckpointKey, RestoreReason};
use oneiron::secret_custody::{
    CustodyClass, CustodyTier, OwnerSecretRegistration, RequestedBinding,
};
use oneiron::test_doors::data_key_custody_head::{
    open_custody_head_with_checkpoint_key, publish_custody_with_recipients_read_before,
    read_published_head,
};
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};
use oneiron::world_keys::{
    DataKeyGenerationCause, DataKeyGenerationWays, VaultKeyStatus, VaultKeyUnlock, escrow_recipient,
};
use oneiron::{Vault, VaultConfig};
use zeroize::Zeroizing;

const PASSWORD: &[u8] = b"correct horse battery staple";

/// An owner's vault with its data key held on this install's keystore.
fn keyed_vault(path: &Path) -> Vault {
    let vault = open_owner_carrier_vault(path).expect("owner vault");
    vault.ensure_vault_key().expect("mint the vault data key");
    vault
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

/// This install's device wrap id, written to the keystore just installed.
fn device_wrap(vault: &Vault) -> String {
    vault
        .add_vault_key_device()
        .expect("this install's device wrap")
        .id
}

#[test]
fn a_checkpoint_sealed_after_a_new_generation_does_not_open_with_the_old_key() {
    let directory = tempfile::tempdir().expect("tempdir");
    let vault = keyed_vault(&directory.path().join("vault"));
    // Our own keystore, so the Device positive control is ours.
    let keystore = Arc::new(oneiron_keystore::MemoryKeystore::default());
    vault.install_device_keystore(Arc::clone(&keystore));
    let device = device_wrap(&vault);
    vault
        .set_vault_key_password(PASSWORD, None)
        .expect("a vault password");
    let recipient = escrow_recipient(&[7u8; 32]).expect("escrow recipient");
    let owner_proof = owner(&vault).expect("owner proof");
    vault
        .add_vault_key_escrow_as(&owner_proof, "box", recipient.public_key())
        .expect("a host escrow");
    let capsule = vault
        .vault_key_escrow_capsules()
        .expect("escrow capsules")
        .into_iter()
        .find(|capsule| capsule.label == "box")
        .expect("the box's capsule, as a registry would keep it")
        .capsule;
    let before = directory.path().join("before");
    vault
        .snapshot_checkpoint(&before, 100)
        .expect("seal a checkpoint before the act");
    let signer = vault
        .checkpoint_signer()
        .expect("the vault's checkpoint signer");
    let c0_key = CheckpointKey::unlock(&before, &VaultKeyUnlock::Password(PASSWORD))
        .expect("the old password opens the checkpoint sealed before")
        .trusting(vec![signer]);
    CheckpointKey::unlock(
        &before,
        &VaultKeyUnlock::EscrowCapsule {
            label: "box",
            capsule: &capsule,
            secret: &recipient,
        },
    )
    .expect("the old capsule opens the checkpoint sealed before");

    // The act, with the password and the escrow confirmed away. The install
    // is stable per vault, so the device wrap above replaced the mint's one
    // in place: it is the only device wrap, and the act keeps it.
    let mut confirmed = BTreeSet::new();
    confirmed.insert("password".to_owned());
    confirmed.insert("escrow:box".to_owned());
    for id in wrap_ids(&vault) {
        if id.starts_with("device:") && id != device {
            confirmed.insert(id);
        }
    }
    let uncovered = vault
        .data_key_generation_preview(&DataKeyGenerationWays {
            password: None,
            passkeys: Vec::new(),
            escrows: Vec::new(),
            confirmed_removals: BTreeSet::new(),
        })
        .expect("preview");
    let mut previewed: Vec<String> = uncovered.iter().map(|info| info.id.clone()).collect();
    previewed.sort();
    let mut expected: Vec<String> = confirmed.iter().cloned().collect();
    expected.sort();
    assert_eq!(
        previewed, expected,
        "the preview names every way no presented way covers"
    );
    let outcome = vault
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
    assert_eq!(outcome.generation, 1);
    assert_eq!(outcome.removed.len(), 2, "the password and the escrow go");
    assert_eq!(
        outcome.rewrapped.len(),
        1,
        "this install's device wrap stays"
    );
    assert_eq!(outcome.rewrapped[0].id, device);

    let after = directory.path().join("after");
    vault
        .snapshot_checkpoint(&after, 101)
        .expect("seal a checkpoint after the act");
    assert_eq!(outcome.commitment, commitment_of(&after));

    assert!(
        CheckpointKey::unlock(&after, &VaultKeyUnlock::Password(PASSWORD)).is_err(),
        "the old password does not open what was sealed after"
    );
    assert!(
        CheckpointKey::unlock(
            &after,
            &VaultKeyUnlock::EscrowCapsule {
                label: "box",
                capsule: &capsule,
                secret: &recipient,
            },
        )
        .is_err(),
        "the old capsule does not open what was sealed after"
    );
    assert!(
        Vault::restore_checkpoint(
            &after,
            &c0_key,
            &directory.path().join("restored"),
            VaultConfig::device(),
            RestoreReason::Restore,
            200,
        )
        .is_err(),
        "the old key does not restore what was sealed after"
    );
    CheckpointKey::unlock(&after, &VaultKeyUnlock::Device(keystore.as_ref()))
        .expect("this install's device wrap opens the checkpoint sealed after");
    assert_ne!(
        commitment_of(&after),
        commitment_of(&before),
        "the new generation seals under a new commitment"
    );
}

#[test]
fn a_checkpoint_sealed_before_a_new_generation_still_opens_and_restores() {
    let directory = tempfile::tempdir().expect("tempdir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let owner_proof = owner(&vault).expect("owner proof");
    vault
        .set_vault_key_password(PASSWORD, None)
        .expect("a vault password");
    let _ = vault
        .set_dreamer_projector_policy_by(
            EngineControlActor::Owner(&owner_proof),
            ProjectorPolicy {
                min_new_statements: 3,
            },
        )
        .expect("write a row before the checkpoint");
    let before = directory.path().join("before");
    vault
        .snapshot_checkpoint(&before, 100)
        .expect("seal a checkpoint before the act");

    let ways = DataKeyGenerationWays {
        password: Some(PASSWORD),
        passkeys: Vec::new(),
        escrows: Vec::new(),
        confirmed_removals: BTreeSet::new(),
    };
    let preview = vault.data_key_generation_preview(&ways).expect("preview");
    assert!(preview.is_empty(), "every way is covered: {preview:?}");
    let outcome = vault
        .start_data_key_generation_as(
            &ActAuthority::Owner(owner_proof, ActSurface::ThisInstall),
            DataKeyGenerationCause::OwnerRequest,
            &ways,
        )
        .expect("the owner starts a new generation");
    assert_eq!(outcome.generation, 1);
    assert!(outcome.removed.is_empty(), "nothing is removed");
    let rewrapped: BTreeSet<String> = outcome
        .rewrapped
        .iter()
        .map(|info| info.id.clone())
        .collect();
    assert!(
        rewrapped.contains("password"),
        "the password is rewrapped: {rewrapped:?}"
    );

    let key = vault.checkpoint_key().expect("the live vault's key");
    let (restored, _) = Vault::restore_checkpoint(
        &before,
        &key,
        &directory.path().join("restored"),
        VaultConfig::device(),
        RestoreReason::Restore,
        200,
    )
    .expect("the live vault restores the checkpoint sealed before");
    assert_eq!(
        restored
            .dreamer_projector_policy()
            .expect("the restored vault's policy")
            .min_new_statements,
        3,
        "the restored vault reads the row written before"
    );
    CheckpointKey::unlock(&before, &VaultKeyUnlock::Password(PASSWORD))
        .expect("the checkpoint sealed before still opens with the old password");
}

#[test]
fn the_new_password_wrap_opens_a_checkpoint_sealed_after() {
    let directory = tempfile::tempdir().expect("tempdir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let owner_proof = owner(&vault).expect("owner proof");
    vault
        .set_vault_key_password(PASSWORD, None)
        .expect("a vault password");
    let ways = DataKeyGenerationWays {
        password: Some(PASSWORD),
        passkeys: Vec::new(),
        escrows: Vec::new(),
        confirmed_removals: BTreeSet::new(),
    };
    let outcome = vault
        .start_data_key_generation_as(
            &ActAuthority::Owner(owner_proof, ActSurface::ThisInstall),
            DataKeyGenerationCause::OwnerRequest,
            &ways,
        )
        .expect("the owner starts a new generation");
    assert_eq!(outcome.generation, 1);
    assert!(outcome.removed.is_empty(), "nothing is removed");

    let after = directory.path().join("after");
    vault
        .snapshot_checkpoint(&after, 100)
        .expect("seal a checkpoint after the act");
    CheckpointKey::unlock(&after, &VaultKeyUnlock::Password(PASSWORD))
        .expect("the same password opens the checkpoint sealed after");
}

#[test]
fn an_unconfirmed_way_refuses_the_act_and_writes_nothing() {
    let directory = tempfile::tempdir().expect("tempdir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let owner_proof = owner(&vault).expect("owner proof");
    vault
        .set_vault_key_password(PASSWORD, None)
        .expect("a vault password");
    let wraps = vault.vault_key_wraps().expect("the wraps before");
    assert_eq!(
        vault.vault_key_status().expect("status"),
        VaultKeyStatus::Unlocked
    );
    let before = directory.path().join("before");
    vault
        .snapshot_checkpoint(&before, 100)
        .expect("seal a checkpoint before the refused act");

    // The outcome has no Debug impl, so the refusal is matched.
    let Err(error) = vault.start_data_key_generation_as(
        &ActAuthority::Owner(owner_proof, ActSurface::ThisInstall),
        DataKeyGenerationCause::OwnerRequest,
        &DataKeyGenerationWays {
            password: None,
            passkeys: Vec::new(),
            escrows: Vec::new(),
            confirmed_removals: BTreeSet::new(),
        },
    ) else {
        panic!("an unconfirmed way refuses the act");
    };
    assert!(
        error.to_string().contains("would stop unlocking"),
        "the refusal names what would stop: {error}"
    );
    assert_eq!(
        vault.vault_key_wraps().expect("the wraps after"),
        wraps,
        "a refused act changes no wrap"
    );
    assert_eq!(
        vault.vault_key_status().expect("status"),
        VaultKeyStatus::Unlocked,
        "a refused act keeps the key held"
    );

    let after = directory.path().join("after");
    vault
        .snapshot_checkpoint(&after, 101)
        .expect("seal a checkpoint after the refused act");
    assert_eq!(
        commitment_of(&after),
        commitment_of(&before),
        "a refused act seals under the same commitment"
    );
}

/// Registers one secret in custody. It is this device's only, so its keys
/// stay in local custody and a head carries no owner-only entry for it.
fn register_custody_secret(vault: &Vault) {
    register_custody_secret_named(vault, "deploy-key");
}

/// [`register_custody_secret`] under `name`.
fn register_custody_secret_named(vault: &Vault, name: &str) {
    let owner_proof = owner(vault).expect("owner proof");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("wall time")
        .as_secs();
    vault
        .register_secret_as_owner(
            &owner_proof,
            &OwnerSecretRegistration {
                name,
                class: CustodyClass::CustodyPortable,
                device_only: true,
                rung: CustodyTier::T1Leased,
                bindings: vec![RequestedBinding {
                    effector: "deploy".to_owned(),
                    tier_ceiling: None,
                    scopes: vec!["read".to_owned()],
                }],
                manifest: None,
                value: b"fixture-value",
            },
            now,
        )
        .expect("the owner registers a secret");
}

/// The act keeping only this install's device wrap: every other device wrap
/// is confirmed away.
fn start_generation_keeping_this_device(vault: &Vault, device: &str) {
    let owner_proof = owner(vault).expect("owner proof");
    let mut confirmed = BTreeSet::new();
    for id in wrap_ids(vault) {
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
}

#[test]
fn a_custody_head_published_before_a_new_generation_does_not_open_with_the_key_after() {
    let directory = tempfile::tempdir().expect("tempdir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let keystore = Arc::new(oneiron_keystore::MemoryKeystore::default());
    vault.install_device_keystore(Arc::clone(&keystore));
    let device = device_wrap(&vault);
    register_custody_secret(&vault);
    let folder = directory.path().join("custody");
    std::fs::create_dir_all(&folder).expect("the custody folder");
    vault
        .publish_custody(&folder, &[], None)
        .expect("publish a head before the act");
    let head = read_published_head(&folder).expect("the published head");

    start_generation_keeping_this_device(&vault, &device);
    let after = directory.path().join("after");
    vault
        .snapshot_checkpoint(&after, 100)
        .expect("seal a checkpoint after the act");
    let key = CheckpointKey::unlock(&after, &VaultKeyUnlock::Device(keystore.as_ref()))
        .expect("the checkpoint sealed after opens on this install");
    // A holder of the replaced key could seal a head of its own beside a
    // newer backup: only the backup's own generation opens a head.
    let opened = open_custody_head_with_checkpoint_key(&head, &key);
    assert!(
        opened.is_err(),
        "a head sealed under the replaced key must not open with the key after: {opened:?}"
    );
}

#[test]
fn the_first_custody_pass_after_a_new_generation_seals_the_head_again_under_the_new_key() {
    let directory = tempfile::tempdir().expect("tempdir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let keystore = Arc::new(oneiron_keystore::MemoryKeystore::default());
    vault.install_device_keystore(Arc::clone(&keystore));
    let device = device_wrap(&vault);
    register_custody_secret(&vault);
    let folder = directory.path().join("custody");
    std::fs::create_dir_all(&folder).expect("the custody folder");
    vault
        .publish_custody(&folder, &[], None)
        .expect("publish a head before the act");
    let head_before = read_published_head(&folder).expect("the head before");
    let before = directory.path().join("before");
    vault
        .snapshot_checkpoint(&before, 100)
        .expect("seal a checkpoint before the act");
    let key_before = CheckpointKey::unlock(&before, &VaultKeyUnlock::Device(keystore.as_ref()))
        .expect("the checkpoint sealed before opens on this install");

    start_generation_keeping_this_device(&vault, &device);
    // Nothing in custody changed: the new generation alone seals every head
    // again.
    vault
        .publish_custody(&folder, &[], None)
        .expect("publish after the act");
    let head_after = read_published_head(&folder).expect("the head after");
    assert_ne!(
        head_after, head_before,
        "the first pass after the act seals the head again"
    );
    let after = directory.path().join("after");
    vault
        .snapshot_checkpoint(&after, 101)
        .expect("seal a checkpoint after the act");
    let key_after = CheckpointKey::unlock(&after, &VaultKeyUnlock::Device(keystore.as_ref()))
        .expect("the checkpoint sealed after opens on this install");
    let unopened = open_custody_head_with_checkpoint_key(&head_after, &key_after)
        .expect("the head sealed again opens with the new key");
    assert!(
        unopened
            .iter()
            .all(|scope| scope == "OwnerOnly" || scope.starts_with("WorldPad")),
        "every compartment a data key opens opened: {unopened:?}"
    );
    let replaced = open_custody_head_with_checkpoint_key(&head_after, &key_before);
    assert!(
        replaced.is_err(),
        "the head sealed again must not open with the replaced key: {replaced:?}"
    );
}

#[test]
fn a_pass_that_read_its_recipients_before_a_new_generation_seals_nothing_under_the_old_key() {
    let directory = tempfile::tempdir().expect("tempdir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let keystore = Arc::new(oneiron_keystore::MemoryKeystore::default());
    vault.install_device_keystore(Arc::clone(&keystore));
    let device = device_wrap(&vault);
    register_custody_secret(&vault);
    let folder = directory.path().join("custody");
    std::fs::create_dir_all(&folder).expect("the custody folder");
    vault
        .publish_custody(&folder, &[], None)
        .expect("publish a head before the act");
    let head_before = read_published_head(&folder).expect("the head before");
    let before = directory.path().join("before");
    vault
        .snapshot_checkpoint(&before, 100)
        .expect("seal a checkpoint before the act");
    let key_before = CheckpointKey::unlock(&before, &VaultKeyUnlock::Device(keystore.as_ref()))
        .expect("the checkpoint sealed before opens on this install");

    // The pass reads the old key's subkey, then the act commits and a secret
    // is registered after it, then the pass seals: a pass whose policy lock
    // did not take (FIX 7314).
    publish_custody_with_recipients_read_before(&vault, &folder, || {
        start_generation_keeping_this_device(&vault, &device);
        register_custody_secret_named(&vault, "release-key");
    })
    .expect("the pass runs");
    let head_after = read_published_head(&folder).expect("the head after the pass");
    let replaced = open_custody_head_with_checkpoint_key(&head_after, &key_before);
    assert!(
        head_after == head_before || replaced.is_err(),
        "a head sealed after the act must not open with the replaced key: {replaced:?}"
    );

    // The next pass reads the new key and seals the head again under it.
    vault
        .publish_custody(&folder, &[], None)
        .expect("the next pass");
    let head_next = read_published_head(&folder).expect("the head of the next pass");
    assert_ne!(head_next, head_before, "the next pass seals the head again");
    let replaced = open_custody_head_with_checkpoint_key(&head_next, &key_before);
    assert!(
        replaced.is_err(),
        "the head the next pass sealed must not open with the replaced key: {replaced:?}"
    );
}

#[test]
fn a_presented_password_that_does_not_open_its_wrap_refuses_the_act() {
    let directory = tempfile::tempdir().expect("tempdir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let owner_proof = owner(&vault).expect("owner proof");
    vault
        .set_vault_key_password(PASSWORD, None)
        .expect("a vault password");
    let wraps = vault.vault_key_wraps().expect("the wraps before");
    let before = directory.path().join("before");
    vault
        .snapshot_checkpoint(&before, 100)
        .expect("seal a checkpoint before the refused act");

    // The outcome has no Debug impl, so the refusal is matched.
    let Err(error) = vault.start_data_key_generation_as(
        &ActAuthority::Owner(owner_proof, ActSurface::ThisInstall),
        DataKeyGenerationCause::OwnerRequest,
        &DataKeyGenerationWays {
            password: Some(b"another password entirely"),
            passkeys: Vec::new(),
            escrows: Vec::new(),
            confirmed_removals: BTreeSet::new(),
        },
    ) else {
        panic!("a password that does not open the vault's password wrap must refuse the act");
    };
    assert!(
        error.to_string().contains("does not open its wrap"),
        "the refusal names the way: {error}"
    );
    assert_eq!(
        vault.vault_key_wraps().expect("the wraps after"),
        wraps,
        "a refused act changes no wrap"
    );
    let after = directory.path().join("after");
    vault
        .snapshot_checkpoint(&after, 101)
        .expect("seal a checkpoint after the refused act");
    assert_eq!(
        commitment_of(&after),
        commitment_of(&before),
        "a refused act seals under the same commitment"
    );
    CheckpointKey::unlock(&after, &VaultKeyUnlock::Password(PASSWORD))
        .expect("the vault's own password still opens");
}

#[test]
fn a_presented_passkey_that_does_not_open_its_wrap_refuses_the_act() {
    let directory = tempfile::tempdir().expect("tempdir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let owner_proof = owner(&vault).expect("owner proof");
    let enrolled = Zeroizing::new([3u8; 32]);
    let presented = Zeroizing::new([4u8; 32]);
    vault
        .add_vault_key_passkey("credential-a", &enrolled)
        .expect("a passkey wrap");
    let wraps = vault.vault_key_wraps().expect("the wraps before");

    let Err(error) = vault.start_data_key_generation_as(
        &ActAuthority::Owner(owner_proof, ActSurface::ThisInstall),
        DataKeyGenerationCause::OwnerRequest,
        &DataKeyGenerationWays {
            password: None,
            passkeys: vec![("credential-a", &presented)],
            escrows: Vec::new(),
            confirmed_removals: BTreeSet::new(),
        },
    ) else {
        panic!("a passkey output that does not open the credential's wrap must refuse the act");
    };
    assert!(
        error.to_string().contains("does not open its wrap"),
        "the refusal names the way: {error}"
    );
    assert_eq!(
        vault.vault_key_wraps().expect("the wraps after"),
        wraps,
        "a refused act changes no wrap"
    );
}
