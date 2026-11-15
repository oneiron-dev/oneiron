//! A vault's data-key generations (PR 1): the owner starts a new generation,
//! everything sealed after opens only with the new key, and everything sealed
//! before still opens with the old one, reached through the link chain. A
//! checkpoint sealed after refuses the old password and the old escrow
//! capsule; a checkpoint sealed before still opens and restores; a custody
//! head published before opens with a key unlocked after. An unconfirmed way
//! refuses the act and writes nothing.
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
    open_custody_head_with_checkpoint_key, read_published_head,
};
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};
use oneiron::world_keys::{
    DataKeyGenerationCause, DataKeyGenerationWays, VaultKeyStatus, VaultKeyUnlock, escrow_recipient,
};
use oneiron::{Vault, VaultConfig};

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

#[test]
fn a_custody_head_published_before_opens_with_a_key_unlocked_after() {
    let directory = tempfile::tempdir().expect("tempdir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let keystore = Arc::new(oneiron_keystore::MemoryKeystore::default());
    vault.install_device_keystore(Arc::clone(&keystore));
    let device = device_wrap(&vault);
    let owner_proof = owner(&vault).expect("owner proof");
    // One secret in custody. It is this device's only, so its keys stay in
    // local custody and the head carries no owner-only entry for it.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("wall time")
        .as_secs();
    vault
        .register_secret_as_owner(
            &owner_proof,
            &OwnerSecretRegistration {
                name: "deploy-key",
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
    let folder = directory.path().join("custody");
    std::fs::create_dir_all(&folder).expect("the custody folder");
    vault
        .publish_custody(&folder, &[], None)
        .expect("publish a head before the act");
    let head = read_published_head(&folder).expect("the published head");

    let mut confirmed = BTreeSet::new();
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
    let after = directory.path().join("after");
    vault
        .snapshot_checkpoint(&after, 100)
        .expect("seal a checkpoint after the act");
    let key = CheckpointKey::unlock(&after, &VaultKeyUnlock::Device(keystore.as_ref()))
        .expect("the checkpoint sealed after opens on this install");
    // The head's control compartment opens with the old subkey the new key's
    // link reaches, and so does every host-readable one: what stays shut is
    // only a compartment no data key opens (owner-only, a world's pads).
    let unopened = open_custody_head_with_checkpoint_key(&head, &key)
        .expect("the head published before opens with the key unlocked after");
    assert!(
        unopened
            .iter()
            .all(|scope| scope == "OwnerOnly" || scope.starts_with("WorldPad")),
        "every compartment a data key opens opened: {unopened:?}"
    );
}
