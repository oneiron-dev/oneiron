//! The owner removes a device's owner key (row AUTH-5 PR b).
//!
//! A revoke of an owner key counts only with an owner key's proof: the install
//! must hold one. Removing a device's machine ends its owner key with it; the
//! key door removes one key and keeps its machine. Removing the last device key
//! asks first and stores nothing until the owner confirms. The recovery root's
//! authority key is never a device key: it stays, and it counts as the recovery
//! root, not in the device keys.
//!
//! Real hosted vaults whose serving install holds its owner key, with a second
//! machine and key enrolled for the device under test.

#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActAuthority, ActSurface, AuthorityKey, AuthorityVaultId, CheckpointPolicyView, HostSlipIssuer,
    LastDeviceKeyConfirmation, MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
    MachineDeviceClass, MachineEncryptionKey, MachineEnrolmentRequest, MachineOwnership,
    MachineProfile, MachineRemoval, MachineRole, OwnerAct, OwnerKeyEnrollment, OwnerKeyRemoval,
    machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::RecordError;
use oneiron::recovery::{
    KitIssue, KitSecretKind, PassphraseCost, PieceHome, issue_recovery_root_kit, restore_kit,
};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::owner_key_release::release_owner_keys;
use oneiron::world_keys::RecoveryRootSeed;
use oneiron::{EntityId, Error, HostingPrivacyPosture, Vault, VaultConfig};

/// The seed of the second machine's machine key.
const JOINING_SEED: u8 = 68;

fn signing(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn owner() -> EntityId {
    EntityId::from_bytes([0x71; 16]).expect("an id")
}

/// `node`'s profile of `machine` in `role` at `revision`, carried by
/// `carried` when it is an owner act.
fn node_profile(
    vault_id: AuthorityVaultId,
    machine: EntityId,
    node: &SigningKey,
    role: MachineRole,
    revision: u64,
    carried: Option<(EntityId, OwnerAct)>,
) -> MachineProfile {
    let machine_key = node.verifying_key().to_bytes();
    let encryption_key = MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    };
    let machine_proof = node
        .sign(&machine_profile_proof_transcript(
            &vault_id,
            machine,
            &machine_key,
            MachineDeviceClass::Computer,
            &encryption_key,
        ))
        .to_bytes();
    MachineProfile {
        machine,
        owner: owner(),
        machine_key,
        device_class: MachineDeviceClass::Computer,
        encryption_key,
        role,
        revision,
        machine_proof,
        seen_world_edits: BTreeSet::new(),
        carrier: carried.as_ref().map(|(carrier, _)| *carrier),
        act: carried.map(|(_, act)| act),
    }
}

/// One vault as a managed host serves it: the Hosted posture, rooted under
/// the test host, this install profiled `Unanswered`, and the embedded owner
/// authenticated. The vault drops first.
struct RemovalVault {
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

impl RemovalVault {
    fn hosted() -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let mut config = VaultConfig::device();
        config.privacy.posture = HostingPrivacyPosture::Hosted;
        let vault = Vault::open(dir.path(), config).expect("hosted vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile under the host root");
        let (_, owner) = embedded_owner(&vault).expect("authenticated embedded owner");
        Self {
            vault,
            issuer,
            owner,
            _dir: dir,
        }
    }

    /// This install's MACHINE row.
    fn install(&self) -> EntityId {
        self.vault
            .local_machine()
            .expect("read this install")
            .expect("this install is profiled")
            .id
    }

    /// The owner enrols this install's owner signing key: the roster then
    /// holds a key that proves for him, and this handle holds it.
    fn enrol_owner_key(&self) {
        self.vault
            .enrol_device_owner_signing_key(
                &ActAuthority::Owner(self.owner.clone(), ActSurface::ThisInstall),
                &self.issuer,
            )
            .expect("the owner enrols this install's owner signing key");
    }

    /// Another machine's request to join this vault: its own keys, and its
    /// own proof over them for this vault.
    fn joining_machine(&self) -> MachineEnrolmentRequest {
        let vault_id = self
            .vault
            .authority_fold()
            .expect("authority fold")
            .vault_id
            .expect("the vault is rooted");
        let machine = EntityId::from_bytes([0x76; 16]).expect("an id");
        let profile = node_profile(
            vault_id,
            machine,
            &signing(JOINING_SEED),
            MachineRole::Unanswered,
            1,
            None,
        );
        MachineEnrolmentRequest {
            vault_id,
            machine,
            machine_key: profile.machine_key,
            device_class: profile.device_class,
            encryption_key: profile.encryption_key,
            machine_proof: profile.machine_proof,
        }
    }

    /// The owner enrols a second machine as his and a second owner key whose
    /// enrolment names it, from `second_signing_key`'s proof of possession.
    /// Answers the machine and the enrolled key.
    fn enrol_second_machine_and_key(
        &self,
        second_signing_key: &SigningKey,
    ) -> (EntityId, [u8; 32]) {
        let request = self.joining_machine();
        let landing = self
            .vault
            .enroll_machine(
                &self.owner,
                ActSurface::ThisInstall,
                &request,
                MachineRole::Owned(MachineOwnership::Yours),
                None,
            )
            .expect("the owner enrols the second machine");
        assert!(
            landing.held().is_none(),
            "the second machine stands with the owner's key"
        );
        let second_key = second_signing_key.verifying_key().to_bytes();
        let authority = ActAuthority::Owner(self.owner.clone(), ActSurface::ThisInstall);
        let challenge = self
            .vault
            .owner_key_enrollment_challenge_as(&authority, request.machine, &second_key)
            .expect("the second key's challenge");
        let receipt = self
            .vault
            .enrol_owner_signing_key_as_host(
                &authority,
                OwnerKeyEnrollment {
                    machine: request.machine,
                    public_key: second_key,
                    proof: second_signing_key.sign(&challenge).to_bytes().to_vec(),
                },
                &self.issuer,
            )
            .expect("the owner enrols the second key on the second machine");
        assert_eq!(
            receipt.public_key, second_key,
            "the receipt names the second key"
        );
        assert_eq!(
            receipt.machine, request.machine,
            "the receipt names the second machine"
        );
        (request.machine, second_key)
    }
}

#[test]
fn removing_a_devices_machine_ends_its_owner_key() {
    let removal_vault = RemovalVault::hosted();
    removal_vault.enrol_owner_key();
    let first_key = removal_vault
        .vault
        .enrolled_owner_keys()
        .expect("enrolled owner keys")
        .into_iter()
        .find(|enrolled| enrolled.live)
        .expect("the install's owner key is enrolled")
        .public_key;
    let second_signing_key = SigningKey::from_bytes(&[71; 32]);
    let (machine_b, second_key) = removal_vault.enrol_second_machine_and_key(&second_signing_key);
    let landing = removal_vault
        .vault
        .set_machine_role(
            &removal_vault.owner,
            ActSurface::ThisInstall,
            machine_b,
            MachineRole::Removed,
            None,
        )
        .expect("the owner removes the second machine");
    assert!(
        landing.held().is_none(),
        "the removal stands with the owner's key"
    );
    let enrolled_keys = removal_vault
        .vault
        .enrolled_owner_keys()
        .expect("enrolled owner keys");
    let second_enrolled = enrolled_keys
        .iter()
        .find(|enrolled| enrolled.public_key == second_key)
        .expect("the second key is enrolled");
    assert!(
        !second_enrolled.live,
        "a removed machine's owner key ends with it (AUTH-5, Astra threat 5)"
    );
    let first_enrolled = enrolled_keys
        .iter()
        .find(|enrolled| enrolled.public_key == first_key)
        .expect("the first key is enrolled");
    assert!(
        first_enrolled.live,
        "the other device's owner key stays live (AUTH-5 PR b)"
    );
}

impl RemovalVault {
    /// How many authority log rows the fold holds valid.
    fn stored_rows(&self) -> usize {
        self.vault
            .authority_fold()
            .expect("authority fold")
            .valid_entries
            .len()
    }

    /// A refused act left nothing: the fold holds `rows` valid rows as
    /// before it, and no choice waits.
    fn assert_nothing_stored_since(&self, rows: usize) {
        let fold = self.vault.authority_fold().expect("authority fold");
        assert_eq!(fold.valid_entries.len(), rows, "the refusal stores no row");
        assert_eq!(
            fold.waiting_owner_choices(),
            &BTreeSet::new(),
            "nothing waits: the door stored nothing"
        );
    }

    /// The owner clears his checkpoint root choice through this install.
    fn clear_checkpoint_policy(&self) -> oneiron::Result<CheckpointPolicyView> {
        self.vault.set_checkpoint_policy_as(
            &ActAuthority::Owner(self.owner.clone(), ActSurface::ThisInstall),
            None,
            None,
        )
    }

    /// The owner enrols the recovery root's authority key on this install's
    /// machine, from a fresh kit. Answers the enrolled key.
    fn enrol_recovery_root_key(&self) -> [u8; 32] {
        let vault_id = self
            .vault
            .authority_fold()
            .expect("authority fold")
            .vault_id
            .expect("a rooted vault");
        let machine = self.install();
        let authority = ActAuthority::Owner(self.owner.clone(), ActSurface::ThisInstall);
        let seed = RecoveryRootSeed::generate().expect("a root seed");
        let pieces = issue_recovery_root_kit(
            &KitIssue {
                vault_id,
                homes: [
                    PieceHome::ThisMachine,
                    PieceHome::OtherMachine(EntityId::now()),
                    PieceHome::OtherMachine(EntityId::now()),
                ],
                passphrase: None,
                cost: PassphraseCost::FLOOR,
                only_machine: false,
            },
            &seed.kit_bytes(),
        )
        .expect("the kit")
        .into_pieces();
        let restored = restore_kit(
            vault_id,
            KitSecretKind::RecoveryRoot,
            &[&pieces[0], &pieces[1]],
            None,
        )
        .expect("two stored pieces restore the seed");
        let receipt = self
            .vault
            .enrol_recovery_authority_key_as_host(
                &authority,
                machine,
                &RecoveryRootSeed::from_restored_kit(restored).expect("the seed"),
                &self.issuer,
            )
            .expect("the owner enrols the root's authority key");
        receipt.public_key
    }
}

/// What a choice door answers where the vault holds an owner key and this
/// install holds none: the owner-key refusal.
fn assert_owner_key_refusal<T: std::fmt::Debug>(answer: oneiron::Result<T>) {
    assert!(
        matches!(answer, Err(Error::Record(RecordError::OwnerKeyRequired))),
        "the door refuses for the owner's key: {answer:?}"
    );
}

#[test]
fn the_owner_removes_another_devices_key_and_keeps_its_machine() {
    let removal_vault = RemovalVault::hosted();
    removal_vault.enrol_owner_key();
    let first_key = removal_vault
        .vault
        .enrolled_owner_keys()
        .expect("enrolled owner keys")
        .into_iter()
        .find(|enrolled| enrolled.live)
        .expect("the install's owner key is enrolled")
        .public_key;
    let second_signing_key = SigningKey::from_bytes(&[72; 32]);
    let (machine_b, second_key) = removal_vault.enrol_second_machine_and_key(&second_signing_key);
    let key_removal = removal_vault
        .vault
        .remove_owner_key(
            &removal_vault.owner,
            second_key,
            LastDeviceKeyConfirmation::NotGiven,
        )
        .expect("the owner removes the second key");
    let (ended, remaining) = match key_removal {
        OwnerKeyRemoval::Removed { ended, remaining } => (ended, remaining),
        OwnerKeyRemoval::LastDeviceKey(remaining) => {
            panic!("another device's key is not the last one: {remaining:?}")
        }
    };
    assert_eq!(
        ended.public_key, second_key,
        "the removal ends the named key (AUTH-5 PR b)"
    );
    assert_eq!(
        ended.machine, machine_b,
        "the ended key names the second machine (AUTH-5 PR b)"
    );
    assert_eq!(
        ended.signed_by,
        AuthorityKey::Ed25519(first_key),
        "an owner key signs the revoke (AUTH-5 PR b)"
    );
    assert_eq!(
        remaining.device_keys, 1,
        "one device key remains (AUTH-5 PR b)"
    );
    assert!(
        !remaining.recovery_root,
        "no recovery root is enrolled (AUTH-5 PR b)"
    );
    let enrolled_keys = removal_vault
        .vault
        .enrolled_owner_keys()
        .expect("enrolled owner keys");
    assert!(
        !enrolled_keys
            .iter()
            .find(|enrolled| enrolled.public_key == second_key)
            .expect("the second key is enrolled")
            .live,
        "the removed key ends (AUTH-5 PR b)"
    );
    assert!(
        enrolled_keys
            .iter()
            .find(|enrolled| enrolled.public_key == first_key)
            .expect("the first key is enrolled")
            .live,
        "the other device's key stays live (AUTH-5 PR b)"
    );
    let fold = removal_vault
        .vault
        .authority_fold()
        .expect("authority fold");
    let head = fold
        .machine(machine_b)
        .and_then(|machine| machine.roster.as_ref())
        .expect("the second machine stands on the roster");
    assert!(
        !head.removed,
        "the key's machine stands: only the key ends (AUTH-5 PR b)"
    );
    assert_ne!(
        head.profile.role,
        MachineRole::Removed,
        "the key's machine is not removed (AUTH-5 PR b)"
    );
}

#[test]
fn a_device_removes_its_own_owner_key() {
    let removal_vault = RemovalVault::hosted();
    removal_vault.enrol_owner_key();
    let first_key = removal_vault
        .vault
        .enrolled_owner_keys()
        .expect("enrolled owner keys")
        .into_iter()
        .find(|enrolled| enrolled.live)
        .expect("the install's owner key is enrolled")
        .public_key;
    let second_signing_key = SigningKey::from_bytes(&[73; 32]);
    let (_, second_key) = removal_vault.enrol_second_machine_and_key(&second_signing_key);
    let key_removal = removal_vault
        .vault
        .remove_owner_key(
            &removal_vault.owner,
            first_key,
            LastDeviceKeyConfirmation::NotGiven,
        )
        .expect("the device removes its own key");
    match key_removal {
        OwnerKeyRemoval::Removed { ended, remaining } => {
            assert_eq!(
                ended.signed_by,
                AuthorityKey::Ed25519(first_key),
                "a key removes itself with its own proof (AUTH-5 PR b)"
            );
            assert_eq!(
                remaining.device_keys, 1,
                "one device key remains (AUTH-5 PR b)"
            );
        }
        OwnerKeyRemoval::LastDeviceKey(remaining) => {
            panic!("another key remains, so no ask: {remaining:?}")
        }
    }
    let answer = removal_vault.vault.remove_owner_key(
        &removal_vault.owner,
        second_key,
        LastDeviceKeyConfirmation::Given,
    );
    assert!(
        matches!(answer, Err(Error::Record(RecordError::OwnerKeyRequired))),
        "this install holds no owner key any more (AUTH-5 PR b): {answer:?}"
    );
}

#[test]
fn removing_the_last_device_key_asks_first() {
    let removal_vault = RemovalVault::hosted();
    removal_vault.enrol_owner_key();
    let first_key = removal_vault
        .vault
        .enrolled_owner_keys()
        .expect("enrolled owner keys")
        .into_iter()
        .find(|enrolled| enrolled.live)
        .expect("the install's owner key is enrolled")
        .public_key;
    let rows = removal_vault.stored_rows();
    let key_removal = removal_vault
        .vault
        .remove_owner_key(
            &removal_vault.owner,
            first_key,
            LastDeviceKeyConfirmation::NotGiven,
        )
        .expect("the door asks first");
    match key_removal {
        OwnerKeyRemoval::LastDeviceKey(remaining) => {
            assert_eq!(
                remaining.device_keys, 0,
                "no device key would remain (AUTH-5 PR b)"
            );
            assert!(
                remaining.needs_recovery(),
                "a later change needs recovery (AUTH-5 PR b)"
            );
        }
        OwnerKeyRemoval::Removed { .. } => {
            panic!("the last device key asks first (AUTH-5 PR b)")
        }
    }
    removal_vault.assert_nothing_stored_since(rows);
    assert!(
        removal_vault
            .vault
            .enrolled_owner_keys()
            .expect("enrolled owner keys")
            .iter()
            .find(|enrolled| enrolled.public_key == first_key)
            .expect("the first key is enrolled")
            .live,
        "the ask stores nothing: the key stays live (AUTH-5 PR b)"
    );
    let key_removal = removal_vault
        .vault
        .remove_owner_key(
            &removal_vault.owner,
            first_key,
            LastDeviceKeyConfirmation::Given,
        )
        .expect("the owner confirms the last key's removal");
    assert!(
        matches!(key_removal, OwnerKeyRemoval::Removed { .. }),
        "the confirmation ends the key (AUTH-5 PR b): {key_removal:?}"
    );
    assert!(
        !removal_vault
            .vault
            .enrolled_owner_keys()
            .expect("enrolled owner keys")
            .iter()
            .find(|enrolled| enrolled.public_key == first_key)
            .expect("the first key is enrolled")
            .live,
        "the last device key ends (AUTH-5 PR b)"
    );
    let rows = removal_vault.stored_rows();
    assert_owner_key_refusal(removal_vault.clear_checkpoint_policy());
    removal_vault.assert_nothing_stored_since(rows);
}

#[test]
fn the_recovery_roots_key_is_not_a_device_key() {
    let removal_vault = RemovalVault::hosted();
    removal_vault.enrol_owner_key();
    let first_key = removal_vault
        .vault
        .enrolled_owner_keys()
        .expect("enrolled owner keys")
        .into_iter()
        .find(|enrolled| enrolled.live)
        .expect("the install's owner key is enrolled")
        .public_key;
    let root_key = removal_vault.enrol_recovery_root_key();
    let key_removal = removal_vault
        .vault
        .remove_owner_key(
            &removal_vault.owner,
            first_key,
            LastDeviceKeyConfirmation::NotGiven,
        )
        .expect("the door asks first");
    match key_removal {
        OwnerKeyRemoval::LastDeviceKey(remaining) => {
            assert_eq!(
                remaining.device_keys, 0,
                "no device key would remain (AUTH-5 PR b)"
            );
            assert!(
                remaining.recovery_root,
                "the recovery root's key is not a device key (AUTH-5 PR b)"
            );
        }
        OwnerKeyRemoval::Removed { .. } => {
            panic!("the last device key asks first, beside the root (AUTH-5 PR b)")
        }
    }
    let answer = removal_vault.vault.remove_owner_key(
        &removal_vault.owner,
        root_key,
        LastDeviceKeyConfirmation::Given,
    );
    assert!(
        matches!(answer, Err(Error::Record(RecordError::AuthorityRefused(_)))),
        "the key door refuses the root's key (AUTH-5 PR b): {answer:?}"
    );
    assert!(
        removal_vault
            .vault
            .enrolled_owner_keys()
            .expect("enrolled owner keys")
            .iter()
            .find(|enrolled| enrolled.public_key == root_key)
            .expect("the root's key is enrolled")
            .live,
        "the root's key stays live (AUTH-5 PR b)"
    );
}

#[test]
fn an_install_with_no_owner_key_removes_no_key() {
    let removal_vault = RemovalVault::hosted();
    removal_vault.enrol_owner_key();
    let second_signing_key = SigningKey::from_bytes(&[74; 32]);
    let (machine_b, second_key) = removal_vault.enrol_second_machine_and_key(&second_signing_key);
    release_owner_keys(&removal_vault.vault);
    let rows = removal_vault.stored_rows();
    let answer = removal_vault.vault.remove_owner_key(
        &removal_vault.owner,
        second_key,
        LastDeviceKeyConfirmation::Given,
    );
    assert!(
        matches!(answer, Err(Error::Record(RecordError::OwnerKeyRequired))),
        "an install that holds no owner key removes no key (AUTH-5 PR b): {answer:?}"
    );
    removal_vault.assert_nothing_stored_since(rows);
    let machine_removal = removal_vault
        .vault
        .remove_machine(
            &removal_vault.owner,
            ActSurface::ThisInstall,
            machine_b,
            None,
            LastDeviceKeyConfirmation::NotGiven,
        )
        .expect("the machine removal is written");
    match machine_removal {
        MachineRemoval::Written(receipt) => {
            assert!(
                receipt.ended_keys.is_empty(),
                "no key ends without an owner key to sign it (AUTH-5 PR b)"
            );
            assert_eq!(
                receipt.live_keys,
                vec![second_key],
                "the machine still holds its key (AUTH-5 PR b)"
            );
        }
        MachineRemoval::LastDeviceKey(remaining) => {
            panic!("without a key to sign, nothing ends so nothing asks: {remaining:?}")
        }
    }
    assert!(
        removal_vault
            .vault
            .enrolled_owner_keys()
            .expect("enrolled owner keys")
            .iter()
            .find(|enrolled| enrolled.public_key == second_key)
            .expect("the second key is enrolled")
            .live,
        "the key stays live (AUTH-5 PR b)"
    );
}

#[test]
fn the_machine_removal_door_lists_the_keys_it_ended() {
    let removal_vault = RemovalVault::hosted();
    removal_vault.enrol_owner_key();
    let second_signing_key = SigningKey::from_bytes(&[75; 32]);
    let (machine_b, second_key) = removal_vault.enrol_second_machine_and_key(&second_signing_key);
    let machine_removal = removal_vault
        .vault
        .remove_machine(
            &removal_vault.owner,
            ActSurface::ThisInstall,
            machine_b,
            None,
            LastDeviceKeyConfirmation::NotGiven,
        )
        .expect("the owner removes the second machine");
    match machine_removal {
        MachineRemoval::Written(receipt) => {
            assert!(
                receipt.landing.held().is_none(),
                "the removal stands with the owner's key (AUTH-5 PR b)"
            );
            assert_eq!(
                receipt.ended_keys,
                vec![second_key],
                "the removal ends the machine's key (AUTH-5 PR b)"
            );
            assert!(
                receipt.live_keys.is_empty(),
                "no key of the machine stays live (AUTH-5 PR b)"
            );
            assert_eq!(
                receipt.remaining.device_keys, 1,
                "one device key remains (AUTH-5 PR b)"
            );
        }
        MachineRemoval::LastDeviceKey(remaining) => {
            panic!("another key remains, so no ask: {remaining:?}")
        }
    }
}

#[test]
fn removing_the_machine_of_the_last_device_key_asks_first() {
    let removal_vault = RemovalVault::hosted();
    removal_vault.enrol_owner_key();
    let machine_a = removal_vault.install();
    let rows = removal_vault.stored_rows();
    let machine_removal = removal_vault
        .vault
        .remove_machine(
            &removal_vault.owner,
            ActSurface::ThisInstall,
            machine_a,
            None,
            LastDeviceKeyConfirmation::NotGiven,
        )
        .expect("the door asks first");
    match machine_removal {
        MachineRemoval::LastDeviceKey(remaining) => {
            assert_eq!(
                remaining.device_keys, 0,
                "no device key would remain (AUTH-5 PR b)"
            );
        }
        MachineRemoval::Written(_) => {
            panic!("the last device key asks first (AUTH-5 PR b)")
        }
    }
    removal_vault.assert_nothing_stored_since(rows);
    let answer = removal_vault.vault.set_machine_role(
        &removal_vault.owner,
        ActSurface::ThisInstall,
        machine_a,
        MachineRole::Removed,
        None,
    );
    assert!(
        matches!(answer, Err(Error::Record(RecordError::AuthorityRefused(_)))),
        "the door that cannot ask refuses (AUTH-5 PR b): {answer:?}"
    );
    removal_vault.assert_nothing_stored_since(rows);
}

#[test]
fn the_confirmed_removal_of_the_last_device_keys_machine_ends_the_key() {
    let removal_vault = RemovalVault::hosted();
    removal_vault.enrol_owner_key();
    let first_key = removal_vault
        .vault
        .enrolled_owner_keys()
        .expect("enrolled owner keys")
        .into_iter()
        .find(|enrolled| enrolled.live)
        .expect("the install's owner key is enrolled")
        .public_key;
    let machine_a = removal_vault.install();
    let machine_removal = removal_vault
        .vault
        .remove_machine(
            &removal_vault.owner,
            ActSurface::ThisInstall,
            machine_a,
            None,
            LastDeviceKeyConfirmation::Given,
        )
        .expect("the owner confirms the removal");
    match machine_removal {
        MachineRemoval::Written(receipt) => {
            assert_eq!(
                receipt.ended_keys,
                vec![first_key],
                "the removal ends the last device key (AUTH-5 PR b)"
            );
            assert_eq!(
                receipt.remaining.device_keys, 0,
                "no device key remains (AUTH-5 PR b)"
            );
        }
        MachineRemoval::LastDeviceKey(_) => {
            panic!("the confirmation ends the key (AUTH-5 PR b)")
        }
    }
    assert!(
        !removal_vault
            .vault
            .enrolled_owner_keys()
            .expect("enrolled owner keys")
            .iter()
            .find(|enrolled| enrolled.public_key == first_key)
            .expect("the first key is enrolled")
            .live,
        "the last device key ends with its machine (AUTH-5 PR b)"
    );
}
