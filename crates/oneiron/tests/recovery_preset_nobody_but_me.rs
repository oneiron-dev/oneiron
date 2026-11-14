//! The "Nobody but me" recovery preset (census L10-18, PR 1;
//! CROSS-ARCH-0019 #vault-20-unlock, PQC-KIT A): the printed sheet alone
//! restores the vault there (L10-18-SWITCH-OFF = B). Entering it issues the
//! sheet, removes the password and passkey wraps and retires every escrow
//! recipient but the world kit's, in one write; while it holds, the add
//! doors refuse those kinds, a presented capsule opens nothing on the live
//! vault nor on a checkpoint sealed under the preset, and a host-managed or
//! supervisor-delivered key cannot enter it.
//!
//! A fresh device is a host with no vault: it opens a sealed checkpoint's
//! carried key header ([`CheckpointKey::unlock`]), or reopens the vault with
//! no keystore, so no device wrap opens.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test recovery_preset_nobody_but_me`.
#![cfg(oneiron_test_support)]

use std::path::Path;

use oneiron::recovery::checkpoint::{CheckpointKey, RestoreReason};
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};
use oneiron::world_keys::{
    RecoveryPreset, RecoverySheet, VaultKeyStatus, VaultKeyUnlock, VaultKeyWrapKind,
    escrow_recipient,
};
use oneiron::{HostingPrivacyPosture, Vault, VaultConfig, VaultDataKeyCustody, VaultPrivacyConfig};
use zeroize::Zeroizing;

const PRESET_REFUSAL: &str = "Nobody but me";

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

fn carried_ids(image: &Path) -> Vec<String> {
    CheckpointKey::unlocks(image)
        .expect("the checkpoint's clear head")
        .wraps
        .into_iter()
        .map(|info| info.id)
        .collect()
}

fn refused_by_preset<T: std::fmt::Debug>(result: oneiron::Result<T>, what: &str) {
    match result {
        Ok(value) => panic!("{what} must be refused under \"Nobody but me\", got {value:?}"),
        Err(error) => assert!(
            error.to_string().contains(PRESET_REFUSAL),
            "{what} is refused by the preset, not for another reason: {error}"
        ),
    }
}

#[test]
fn sheet_alone_restores_under_nobody_but_me() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("vault");
    let vault = keyed_vault(&path);
    let owner_proof = owner(&vault).expect("owner proof");
    assert_eq!(
        vault.recovery_preset().expect("preset"),
        RecoveryPreset::Standard,
        "a new vault starts on the standard preset"
    );

    let mut kept = None;
    let change = vault
        .set_recovery_preset_as(&owner_proof, RecoveryPreset::NobodyButMe, |sheet| {
            kept = Some(sheet.code());
            Ok(())
        })
        .expect("the owner enters \"Nobody but me\"");
    assert_eq!(change.previous, RecoveryPreset::Standard);
    assert_eq!(change.preset, RecoveryPreset::NobodyButMe);
    assert_eq!(
        vault.recovery_preset().expect("preset"),
        RecoveryPreset::NobodyButMe
    );
    let sheet = change.sheet.expect("entering the preset issues the sheet");
    let code = sheet.code();
    assert_eq!(
        kept.as_deref().map(String::as_str),
        Some(code.as_str()),
        "the sheet the owner kept before the write is the one the vault took"
    );
    assert_eq!(
        code.chars().filter(char::is_ascii_alphanumeric).count(),
        56,
        "the printed code is 56 symbols"
    );
    // The owner types the printed code back, in any case and without dashes.
    let typed = RecoverySheet::from_code(&code.replace('-', "").to_lowercase())
        .expect("the printed code reads back");
    assert!(
        wrap_ids(&vault).contains(&"sheet".to_owned()),
        "the vault carries the sheet's wrap"
    );

    let image = directory.path().join("image");
    vault
        .snapshot_checkpoint(&image, 100)
        .expect("seal a checkpoint under the preset");
    assert!(
        carried_ids(&image).contains(&"sheet".to_owned()),
        "the checkpoint carries the sheet's wrap"
    );
    CheckpointKey::unlock(&image, &VaultKeyUnlock::Sheet(&typed))
        .expect("on a host with no vault, the sheet alone opens the checkpoint");

    drop(vault);
    let fresh = Vault::open(&path, VaultConfig::device()).expect("reopen with no keystore");
    assert_eq!(
        fresh.vault_key_status().expect("status"),
        VaultKeyStatus::Locked
    );
    fresh
        .unlock_vault_key_with_sheet(&typed)
        .expect("the sheet alone unlocks the vault key");
    assert_eq!(
        fresh.vault_key_status().expect("status"),
        VaultKeyStatus::Unlocked
    );
}

#[test]
fn passkey_and_password_wraps_go_and_stop_opening_under_nobody_but_me() {
    let directory = tempfile::tempdir().expect("tempdir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let owner_proof = owner(&vault).expect("owner proof");
    let prf = Zeroizing::new([5u8; 32]);
    vault
        .add_vault_key_passkey("phone", &prf)
        .expect("a passkey wrap on the standard preset");
    vault
        .set_vault_key_password(b"correct horse battery staple", None)
        .expect("a vault password on the standard preset");

    let change = vault
        .set_recovery_preset_as(&owner_proof, RecoveryPreset::NobodyButMe, |_| Ok(()))
        .expect("the owner enters \"Nobody but me\"");
    let mut removed: Vec<String> = change.removed.iter().map(|info| info.id.clone()).collect();
    removed.sort();
    assert_eq!(removed, ["passkey:phone", "password"]);
    let ids = wrap_ids(&vault);
    assert!(
        ids.iter()
            .all(|id| id == "sheet" || id.starts_with("device:")),
        "only this device's wrap and the sheet stay: {ids:?}"
    );

    let image = directory.path().join("image");
    vault
        .snapshot_checkpoint(&image, 100)
        .expect("seal a checkpoint under the preset");
    let carried = carried_ids(&image);
    assert!(
        !carried
            .iter()
            .any(|id| id == "password" || id.starts_with("passkey:")),
        "the checkpoint carries no password or passkey wrap: {carried:?}"
    );
    assert!(
        CheckpointKey::unlock(
            &image,
            &VaultKeyUnlock::Passkey {
                credential: "phone",
                prf: &prf,
            },
        )
        .is_err(),
        "the synced passkey no longer restores the vault"
    );
    assert!(
        CheckpointKey::unlock(
            &image,
            &VaultKeyUnlock::Password(b"correct horse battery staple")
        )
        .is_err(),
        "the old password no longer restores the vault"
    );

    refused_by_preset(
        vault.add_vault_key_passkey("laptop", &prf),
        "a new passkey wrap",
    );
    refused_by_preset(
        vault.set_vault_key_password(b"another long password", None),
        "a new vault password",
    );
    assert_eq!(wrap_ids(&vault), ids, "a refused add changes no wrap");
}

#[test]
fn nobody_but_me_retires_a_host_escrow_and_refuses_its_capsule_and_a_new_one() {
    let directory = tempfile::tempdir().expect("tempdir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let owner_proof = owner(&vault).expect("owner proof");
    let recipient = escrow_recipient(&[7u8; 32]).expect("escrow recipient");
    vault
        .add_vault_key_escrow_as(&owner_proof, "box", recipient.public_key())
        .expect("a host escrow on the standard preset");
    let capsule = vault
        .vault_key_escrow_capsules()
        .expect("escrow capsules")
        .into_iter()
        .find(|capsule| capsule.label == "box")
        .expect("the box's capsule, as a registry would keep it")
        .capsule;

    let change = vault
        .set_recovery_preset_as(&owner_proof, RecoveryPreset::NobodyButMe, |_| Ok(()))
        .expect("the owner enters \"Nobody but me\"");
    assert_eq!(
        change
            .retired
            .iter()
            .map(|receipt| receipt.label.as_str())
            .collect::<Vec<_>>(),
        ["box"]
    );
    assert!(
        change.removed.iter().any(|info| matches!(
            &info.kind,
            VaultKeyWrapKind::Escrow { label } if label == "box"
        )),
        "the box's wrap is among the removed"
    );
    let ids = wrap_ids(&vault);
    assert!(!ids.contains(&"escrow:box".to_owned()), "{ids:?}");
    assert!(
        vault
            .vault_key_escrow_retirements()
            .expect("retirements")
            .iter()
            .any(|receipt| receipt.label == "box" && receipt.removed_wrap),
        "the box's label is retired with a receipt"
    );

    refused_by_preset(
        vault.unlock_vault_key_with_escrow_capsule("box", &capsule, &recipient),
        "the host's capsule on the live vault",
    );
    let another = escrow_recipient(&[8u8; 32]).expect("escrow recipient");
    refused_by_preset(
        vault.add_vault_key_escrow_as(&owner_proof, "box2", another.public_key()),
        "a new host escrow",
    );
    assert_eq!(wrap_ids(&vault), ids, "a refused add changes no wrap");
}

/// A capsule a host escrow kept from before the change still opens a
/// checkpoint sealed before it, as the data key does not rotate, and never
/// one sealed under the preset: its key header names the preset (review of
/// #7766, round 1).
#[test]
fn a_checkpoint_sealed_under_nobody_but_me_refuses_an_earlier_capsule() {
    let directory = tempfile::tempdir().expect("tempdir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let owner_proof = owner(&vault).expect("owner proof");
    let recipient = escrow_recipient(&[7u8; 32]).expect("escrow recipient");
    vault
        .add_vault_key_escrow_as(&owner_proof, "box", recipient.public_key())
        .expect("a host escrow on the standard preset");
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
        .expect("seal a checkpoint on the standard preset");

    vault
        .set_recovery_preset_as(&owner_proof, RecoveryPreset::NobodyButMe, |_| Ok(()))
        .expect("the owner enters \"Nobody but me\"");
    let after = directory.path().join("after");
    vault
        .snapshot_checkpoint(&after, 101)
        .expect("seal a checkpoint under the preset");

    let presented = |image: &Path| {
        CheckpointKey::unlock(
            image,
            &VaultKeyUnlock::EscrowCapsule {
                label: "box",
                capsule: &capsule,
                secret: &recipient,
            },
        )
        .map(|_| ())
    };
    presented(&before).expect("the earlier capsule still opens what was sealed before the change");
    refused_by_preset(
        presented(&after),
        "the earlier capsule on a checkpoint sealed under the preset",
    );

    // A key the capsule opened from the earlier checkpoint stops at the
    // later one too: the refusal reads the header its signature covers, not
    // the header the key was unlocked from (review of #7766, round 1).
    let signer = vault
        .checkpoint_signer()
        .expect("the vault's checkpoint signer");
    let earlier_key = CheckpointKey::unlock(
        &before,
        &VaultKeyUnlock::EscrowCapsule {
            label: "box",
            capsule: &capsule,
            secret: &recipient,
        },
    )
    .expect("the capsule opens the earlier checkpoint")
    .trusting(vec![signer]);
    refused_by_preset(
        Vault::restore_checkpoint(
            &after,
            &earlier_key,
            &directory.path().join("restored"),
            VaultConfig::device(),
            RestoreReason::Restore,
            200,
        )
        .map(|_| ()),
        "a key the earlier capsule opened, restoring a checkpoint sealed under the preset",
    );
}

/// The sheet is kept before the write that removes the old wraps: a keep
/// that fails changes nothing, and the password still opens the vault
/// (review of #7766, round 1).
#[test]
fn a_failed_sheet_keep_leaves_the_standard_preset_and_its_wraps() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("vault");
    let vault = keyed_vault(&path);
    let owner_proof = owner(&vault).expect("owner proof");
    vault
        .set_vault_key_password(b"correct horse battery staple", None)
        .expect("a vault password on the standard preset");
    let ids = wrap_ids(&vault);

    let mut offered_before_the_write = false;
    let refused = vault.set_recovery_preset_as(&owner_proof, RecoveryPreset::NobodyButMe, |_| {
        offered_before_the_write = wrap_ids(&vault).contains(&"password".to_owned());
        Err(oneiron::Error::Io(std::io::Error::other(
            "no space left for the sheet's file",
        )))
    });
    assert!(refused.is_err(), "a failed keep refuses the change");
    assert!(
        offered_before_the_write,
        "the sheet is offered while the password wrap is still there"
    );
    assert_eq!(
        vault.recovery_preset().expect("preset"),
        RecoveryPreset::Standard
    );
    assert_eq!(wrap_ids(&vault), ids, "a failed keep changes no wrap");

    drop(vault);
    let fresh = Vault::open(&path, VaultConfig::device()).expect("reopen with no keystore");
    fresh
        .unlock_vault_key_with_password(b"correct horse battery staple")
        .expect("the password still opens the vault");
}

#[test]
fn nobody_but_me_is_refused_under_a_supervisor_delivered_key() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.privacy = VaultPrivacyConfig {
        posture: HostingPrivacyPosture::SelfHostLocal,
        data_key_custody: VaultDataKeyCustody::SupervisorDelivered,
    };
    let vault = Vault::open(&directory.path().join("vault"), config).expect("managed vault");
    assert!(
        vault
            .admit_vault_key(&[9u8; 32])
            .expect("the supervisor delivers the key"),
        "the vault takes the delivered key as new"
    );
    let owner_proof = owner(&vault).expect("owner proof");
    let refusal = vault
        .set_recovery_preset_as(&owner_proof, RecoveryPreset::NobodyButMe, |_| Ok(()))
        .expect_err("a host-delivered key cannot be \"Nobody but me\"");
    assert!(
        refusal.to_string().contains("owner-held data key"),
        "refused for its custody: {refusal}"
    );
    assert_eq!(
        vault.recovery_preset().expect("preset"),
        RecoveryPreset::Standard
    );
}

#[test]
fn the_preset_in_force_changes_nothing_and_leaving_it_changes_no_wrap() {
    let directory = tempfile::tempdir().expect("tempdir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let owner_proof = owner(&vault).expect("owner proof");
    vault
        .set_recovery_preset_as(&owner_proof, RecoveryPreset::NobodyButMe, |_| Ok(()))
        .expect("enter the preset");
    let entered = wrap_ids(&vault);

    let again = vault
        .set_recovery_preset_as(&owner_proof, RecoveryPreset::NobodyButMe, |_| {
            panic!("the preset in force draws no sheet to keep")
        })
        .expect("the preset in force again");
    assert_eq!(again.previous, RecoveryPreset::NobodyButMe);
    assert!(again.sheet.is_none(), "no second sheet is issued");
    assert!(again.removed.is_empty() && again.retired.is_empty());
    assert_eq!(wrap_ids(&vault), entered);

    let left = vault
        .set_recovery_preset_as(&owner_proof, RecoveryPreset::Standard, |_| {
            panic!("leaving the preset draws no sheet")
        })
        .expect("leave the preset");
    assert_eq!(left.previous, RecoveryPreset::NobodyButMe);
    assert!(left.sheet.is_none() && left.removed.is_empty());
    assert_eq!(wrap_ids(&vault), entered, "leaving changes no wrap");
    vault
        .add_vault_key_passkey("phone", &Zeroizing::new([5u8; 32]))
        .expect("the standard preset takes a passkey again");
}

#[test]
fn the_world_kit_escrow_label_is_its_confirms_alone() {
    let directory = tempfile::tempdir().expect("tempdir");
    let vault = keyed_vault(&directory.path().join("vault"));
    let owner_proof = owner(&vault).expect("owner proof");
    let recipient = escrow_recipient(&[7u8; 32]).expect("escrow recipient");
    let refusal = vault
        .add_vault_key_escrow_as(&owner_proof, "world-kit", recipient.public_key())
        .expect_err("a host escrow may not take the world kit's label");
    assert!(
        refusal.to_string().contains("confirming a kit"),
        "refused for the label: {refusal}"
    );
    assert!(!wrap_ids(&vault).contains(&"escrow:world-kit".to_owned()));
}
