//! A vault data-key generation's delivery to the owner's other devices (PR 3):
//! the act appends one owner-signed authority entry carrying a sealed capsule
//! of the new key per other trusted owner machine, and a device that folds a
//! counted entry with a capsule for itself adopts the new generation with no
//! owner unlock. Device B reads a checkpoint sealed on device A after A's
//! act, with no unlock on B; a device under "Nobody but me" adopts too; two
//! generations started at once are adopted by no device; and an entry whose
//! link does not reach the stored key is not adopted.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test vault_data_key_generation_devices`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use oneiron::authority::{ActAuthority, ActSurface, MachineOwnership, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::recovery::checkpoint::{CheckpointKey, RestoreReason};
use oneiron::test_doors::data_key_generation_devices::{
    clone_held_data_key, open_device_vault_adopting_storage_id, stored_data_key_state,
};
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};
use oneiron::world_keys::{
    DataKeyGenerationCause, DataKeyGenerationOutcome, DataKeyGenerationWays, RecoveryPreset,
};
use oneiron::{EntityId, Vault, VaultConfig};

/// The acting vault with its data key held on this install's keystore.
fn keyed_home(path: &Path) -> (Vault, AuthenticatedOwner) {
    let vault = open_owner_carrier_vault(path).expect("owner vault");
    vault.ensure_vault_key().expect("mint the vault data key");
    let proof = owner(&vault).expect("owner proof");
    (vault, proof)
}

/// The owner's device: its own install under the home's storage id, enrolled
/// as his, holding the home's authority history, as sync leaves it.
struct Device {
    vault: Vault,
    machine: EntityId,
    held: BTreeSet<Vec<u8>>,
}

fn enroll_device(home: &Vault, owner_home: &AuthenticatedOwner, path: &Path) -> Device {
    let vault = open_device_vault_adopting_storage_id(path, home).expect("the device's install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let home_id = home
        .authority_fold()
        .expect("the home's fold")
        .vault_id
        .expect("a rooted vault");
    let key = vault
        .machine_encryption_key(home_id)
        .expect("the device's encryption key");
    let request = vault
        .machine_enrolment_request(home_id, key)
        .expect("the device's enrolment request");
    home.enroll_machine(
        owner_home,
        ActSurface::ThisInstall,
        &request,
        MachineRole::Owned(MachineOwnership::Yours),
        None,
    )
    .expect("the owner enrols the device as his");
    vault
        .ensure_embedded_owner_actor()
        .expect("the owner on the device");
    let mut device = Device {
        vault,
        machine: request.machine,
        held: BTreeSet::new(),
    };
    device.take(home);
    device
}

impl Device {
    /// Imports the rows of the home's history this device does not hold yet.
    /// The import receives any data-key generation it lands.
    fn take(&mut self, home: &Vault) {
        let new: Vec<Vec<u8>> = home
            .export_signed_authority_history()
            .expect("the home's history")
            .into_iter()
            .filter(|row| !self.held.contains(row))
            .collect();
        self.vault
            .import_signed_authority_history(&new)
            .expect("the device takes the rows");
        self.held.extend(new);
    }

    /// Imports the rows of several histories this device does not hold yet
    /// in one import, so the fold judges them together.
    fn take_combined(&mut self, homes: &[&Vault]) {
        let mut new: Vec<Vec<u8>> = Vec::new();
        for home in homes {
            for row in home
                .export_signed_authority_history()
                .expect("the home's history")
            {
                if !self.held.contains(&row) && !new.contains(&row) {
                    new.push(row);
                }
            }
        }
        self.vault
            .import_signed_authority_history(&new)
            .expect("the device takes the rows");
        self.held.extend(new);
    }

    /// This device's stored data-key commitment and generation.
    fn data_key_state(&self) -> ([u8; 32], u32) {
        stored_data_key_state(&self.vault).expect("the device's data-key state")
    }
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

/// The owner's act on a device-only vault: every device wrap but this
/// install's is confirmed away, and this install's is kept.
fn act_device_only(home: &Vault) -> DataKeyGenerationOutcome {
    let owner_proof = owner(home).expect("owner proof");
    let mut device_ids: Vec<String> = wrap_ids(home)
        .into_iter()
        .filter(|id| id.starts_with("device:"))
        .collect();
    device_ids.sort();
    let mut confirmed = BTreeSet::new();
    for id in device_ids.iter().skip(1) {
        confirmed.insert(id.clone());
    }
    let previewed = home
        .data_key_generation_preview(&DataKeyGenerationWays {
            password: None,
            passkeys: Vec::new(),
            escrows: Vec::new(),
            confirmed_removals: BTreeSet::new(),
        })
        .expect("preview");
    let mut previewed: Vec<String> = previewed.iter().map(|info| info.id.clone()).collect();
    previewed.sort();
    let mut expected: Vec<String> = confirmed.iter().cloned().collect();
    expected.sort();
    assert_eq!(
        previewed, expected,
        "the preview names every way no presented way covers"
    );
    home.start_data_key_generation_as(
        &ActAuthority::Owner(owner_proof, ActSurface::ThisInstall),
        DataKeyGenerationCause::OwnerRequest,
        &DataKeyGenerationWays {
            password: None,
            passkeys: Vec::new(),
            escrows: Vec::new(),
            confirmed_removals: confirmed,
        },
    )
    .expect("the owner starts a new generation")
}

#[test]
fn device_b_reads_a_checkpoint_sealed_on_a_after_as_new_generation_with_no_unlock() {
    let directory = tempfile::tempdir().expect("tempdir");
    let (vault_a, owner_a) = keyed_home(&directory.path().join("a"));
    let mut device_b = enroll_device(&vault_a, &owner_a, &directory.path().join("b"));
    clone_held_data_key(&vault_a, &device_b.vault).expect("B takes D(0)");

    let outcome = act_device_only(&vault_a);
    assert_eq!(outcome.generation, 1);
    let after = directory.path().join("after");
    vault_a
        .snapshot_checkpoint(&after, 101)
        .expect("seal a checkpoint after the act");
    assert_eq!(outcome.commitment, commitment_of(&after));

    device_b.take(&vault_a);
    let fold_b = device_b.vault.authority_fold().expect("B's fold");
    let folded = fold_b
        .data_key_generation(1)
        .expect("A's delivery counts on B");
    assert!(!folded.conflicted, "one generation counts alone");
    assert!(
        folded
            .deliveries
            .iter()
            .flat_map(|delivery| &delivery.capsules)
            .any(|(to, _)| *to == device_b.machine),
        "the delivery carries a capsule for B"
    );
    let (commitment_b, generation_b) = device_b.data_key_state();
    assert_eq!(generation_b, 1, "B adopted the new generation");
    assert_eq!(commitment_b, commitment_of(&after), "B names the new key");

    // No password, passkey or sheet was ever presented on B: its checkpoint
    // key restores what A sealed after the act. Trust is pinned to A's
    // install signer, as each install signs its own checkpoints.
    let signer_a = vault_a.checkpoint_signer().expect("A's signer");
    let key_b = device_b
        .vault
        .checkpoint_key()
        .expect("B's checkpoint key")
        .trusting(vec![signer_a]);
    let (restored, _) = Vault::restore_checkpoint(
        &after,
        &key_b,
        &directory.path().join("restored"),
        VaultConfig::device(),
        RestoreReason::Restore,
        200,
    )
    .expect("B's key restores A's post-act checkpoint");
    assert_eq!(
        stored_data_key_state(&restored)
            .expect("the restored vault's state")
            .1,
        1,
        "the restored vault stands on the new generation"
    );
}

#[test]
fn a_device_under_nobody_but_me_adopts_the_new_generation() {
    let directory = tempfile::tempdir().expect("tempdir");
    let (vault_a, owner_a) = keyed_home(&directory.path().join("a"));
    let mut device_b = enroll_device(&vault_a, &owner_a, &directory.path().join("b"));
    clone_held_data_key(&vault_a, &device_b.vault).expect("B takes D(0)");
    let owner_b = owner(&device_b.vault).expect("owner proof on B");
    device_b
        .vault
        .set_recovery_preset_as(&owner_b, RecoveryPreset::NobodyButMe, |_| Ok(()))
        .expect("B enters Nobody but me");

    let outcome = act_device_only(&vault_a);
    assert_eq!(outcome.generation, 1);
    let after = directory.path().join("after");
    vault_a
        .snapshot_checkpoint(&after, 101)
        .expect("seal a checkpoint after the act");
    assert_eq!(outcome.commitment, commitment_of(&after));

    device_b.take(&vault_a);
    let (commitment_b, generation_b) = device_b.data_key_state();
    assert_eq!(
        generation_b, 1,
        "a device under Nobody but me adopts the new generation"
    );
    assert_eq!(commitment_b, commitment_of(&after), "B names the new key");
    let signer_a = vault_a.checkpoint_signer().expect("A's signer");
    let key_b = device_b
        .vault
        .checkpoint_key()
        .expect("B's checkpoint key")
        .trusting(vec![signer_a]);
    Vault::restore_checkpoint(
        &after,
        &key_b,
        &directory.path().join("restored"),
        VaultConfig::device(),
        RestoreReason::Restore,
        200,
    )
    .expect("B's key restores A's post-act checkpoint");
}

#[test]
fn two_generations_started_at_once_are_adopted_by_no_device() {
    let directory = tempfile::tempdir().expect("tempdir");
    let (vault_a, owner_a) = keyed_home(&directory.path().join("a"));
    let mut device_b = enroll_device(&vault_a, &owner_a, &directory.path().join("b"));
    clone_held_data_key(&vault_a, &device_b.vault).expect("B takes D(0)");
    let device_c = enroll_device(&vault_a, &owner_a, &directory.path().join("c"));
    clone_held_data_key(&vault_a, &device_c.vault).expect("C takes D(0)");

    let before = directory.path().join("before");
    vault_a
        .snapshot_checkpoint(&before, 100)
        .expect("seal a checkpoint before the acts");
    let commitment_0 = commitment_of(&before);

    // A and C each run the act without syncing: two generation 1s with
    // different keys.
    let outcome_a = act_device_only(&vault_a);
    let outcome_c = act_device_only(&device_c.vault);
    assert_ne!(
        outcome_a.commitment, outcome_c.commitment,
        "two acts mint different keys"
    );

    // B judges both in one import, so neither is adopted alone first.
    device_b.take_combined(&[&vault_a, &device_c.vault]);
    let fold_b = device_b.vault.authority_fold().expect("B's fold");
    let folded = fold_b
        .data_key_generation(1)
        .expect("both deliveries count on B");
    assert!(folded.conflicted, "two commitments conflict the generation");
    let (commitment_b, generation_b) = device_b.data_key_state();
    assert_eq!(
        generation_b, 0,
        "B adopts neither of two concurrent generations"
    );
    assert_eq!(commitment_b, commitment_0, "B still names D(0)");

    // B's checkpoint key is still D(0)'s: it restores what was sealed under it.
    let signer_a = vault_a.checkpoint_signer().expect("A's signer");
    let key_b = device_b
        .vault
        .checkpoint_key()
        .expect("B's checkpoint key")
        .trusting(vec![signer_a]);
    Vault::restore_checkpoint(
        &before,
        &key_b,
        &directory.path().join("restored"),
        VaultConfig::device(),
        RestoreReason::Restore,
        200,
    )
    .expect("B's key restores what was sealed under D(0)");
}

#[test]
fn an_entry_whose_link_does_not_reach_the_stored_key_is_not_adopted() {
    let directory = tempfile::tempdir().expect("tempdir");
    let (vault_a, owner_a) = keyed_home(&directory.path().join("a"));
    // B holds its own key, never A's D(0): A's link reaches a key B does
    // not store.
    let mut device_b = enroll_device(&vault_a, &owner_a, &directory.path().join("b"));
    device_b
        .vault
        .ensure_vault_key()
        .expect("B mints its own data key");
    let (commitment_own, _) = device_b.data_key_state();

    let outcome = act_device_only(&vault_a);
    assert_eq!(outcome.generation, 1);
    let after = directory.path().join("after");
    vault_a
        .snapshot_checkpoint(&after, 101)
        .expect("seal a checkpoint after the act");
    assert_eq!(outcome.commitment, commitment_of(&after));

    device_b.take(&vault_a);
    let fold_b = device_b.vault.authority_fold().expect("B's fold");
    assert!(
        fold_b
            .data_key_generation(1)
            .is_some_and(|folded| !folded.conflicted),
        "A's delivery counts on B"
    );
    let (commitment_b, generation_b) = device_b.data_key_state();
    assert_eq!(
        generation_b, 0,
        "the entry's link does not reach B's stored key, so B adopts nothing"
    );
    assert_eq!(commitment_b, commitment_own, "B still names its own key");
    let signer_a = vault_a.checkpoint_signer().expect("A's signer");
    let key_b = device_b
        .vault
        .checkpoint_key()
        .expect("B's checkpoint key")
        .trusting(vec![signer_a]);
    assert!(
        Vault::restore_checkpoint(
            &after,
            &key_b,
            &directory.path().join("restored"),
            VaultConfig::device(),
            RestoreReason::Restore,
            200,
        )
        .is_err(),
        "B's key opens nothing sealed under A's new key"
    );
}
