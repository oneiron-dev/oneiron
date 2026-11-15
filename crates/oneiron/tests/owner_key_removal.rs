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
//!
//! Four sibling-branch cases: a key enrolled for two machines ends with
//! either machine, removing a machine again ends a key enrolled for it on a
//! branch the removal never saw, two removals that cross both show in the
//! changes list, and a key enrolled as a device's and as the recovery root's
//! ends with its machine.
//!
//! The key list says before a removal what it ends: a key's row names every
//! machine a counted enrolment names for it, and says whether one marks it
//! the recovery root's. A removal that ends such a key says that it ends the
//! recovery root's key, in its question and in its receipt.
//!
//! Both doors mark the rows they wrote for the vault's loaded windows, so the
//! host and every replica see the keys ended without a window reload.

#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActAuthority, ActSurface, AuthorityAttestation,
    AuthorityEntryHash, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
    AuthorityTier, AuthorityVaultId, CheckpointPolicyView, DeviceAuthority, EnrolledOwnerKeyKind,
    HostSlipIssuer, LastDeviceKeyConfirmation, MACHINE_ENCRYPTION_KEY_LEN,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass, MachineEncryptionKey,
    MachineEnrolmentRequest, MachineOwnership, MachineProfile, MachineRemoval, MachineRole,
    OwnerAct, OwnerActKind, OwnerKeyChangeKind, OwnerKeyEnrollment, OwnerKeyRemoval, ROLE_OWNER,
    authority_entry_hash, authority_log_entity_id_from_hash, authority_transcript,
    decode_authority_log_entry_body, machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::RecordError;
use oneiron::recovery::{
    KitIssue, KitSecretKind, PassphraseCost, PieceHome, issue_recovery_root_kit, restore_kit,
};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::owner_key_release::release_owner_keys;
use oneiron::world_keys::RecoveryRootSeed;
use oneiron::{EntityId, Error, HostingPrivacyPosture, TimeRange, Vault, VaultConfig};
use oneiron_authority::authority::{
    OWNER_KEY_ENROLLMENT_SEEN, OWNER_KEY_POSSESSION_KIND, OwnerKeyEnroll,
    RECOVERY_AUTHORITY_POSSESSION_KIND, owner_key_enrollment_target,
    recovery_authority_enrollment_challenge,
};

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

/// The seed of the third machine's machine key.
const MACHINE_C_SEED: u8 = 69;

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs()
}

impl RemovalVault {
    /// Another machine's request to join this vault, for `machine_bytes`
    /// with `seed`'s machine key: its own keys, and its own proof over them
    /// for this vault.
    fn joining_machine_with(&self, machine_bytes: [u8; 16], seed: u8) -> MachineEnrolmentRequest {
        let vault_id = self
            .vault
            .authority_fold()
            .expect("authority fold")
            .vault_id
            .expect("the vault is rooted");
        let machine = EntityId::from_bytes(machine_bytes).expect("an id");
        let profile = node_profile(
            vault_id,
            machine,
            &signing(seed),
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

    /// The owner enrols the machine `machine_bytes` with `seed`'s machine
    /// key as his. Answers the machine.
    fn enrol_machine_with(&self, machine_bytes: [u8; 16], seed: u8) -> EntityId {
        let request = self.joining_machine_with(machine_bytes, seed);
        let landing = self
            .vault
            .enroll_machine(
                &self.owner,
                ActSurface::ThisInstall,
                &request,
                MachineRole::Owned(MachineOwnership::Yours),
                None,
            )
            .expect("the owner enrols the machine");
        assert!(
            landing.held().is_none(),
            "the machine stands with the owner's key"
        );
        request.machine
    }

    /// The owner enrols the raw key `signing_key` holds on `machine`
    /// through the host predecessor. Answers the key and its enrolment.
    fn enrol_owner_key_on_machine(
        &self,
        machine: EntityId,
        signing_key: &SigningKey,
    ) -> ([u8; 32], AuthorityEntryHash) {
        let public_key = signing_key.verifying_key().to_bytes();
        let authority = ActAuthority::Owner(self.owner.clone(), ActSurface::ThisInstall);
        let challenge = self
            .vault
            .owner_key_enrollment_challenge_as(&authority, machine, &public_key)
            .expect("the key's challenge");
        let receipt = self
            .vault
            .enrol_owner_signing_key_as_host(
                &authority,
                OwnerKeyEnrollment {
                    machine,
                    public_key,
                    proof: signing_key.sign(&challenge).to_bytes().to_vec(),
                },
                &self.issuer,
            )
            .expect("the owner enrols the key on the machine");
        assert_eq!(receipt.public_key, public_key, "the receipt names the key");
        assert_eq!(receipt.machine, machine, "the receipt names the machine");
        (public_key, receipt.entry)
    }

    /// The sibling enrolment row of the key `new_signing_key` holds for
    /// `holder`, carried by `carrier`, with `attestation_kind` at
    /// `timestamp`: `predecessor_signing_key` signs at `sequence` on
    /// `parents`, the carrier's install key cosigns, and the new key proves
    /// possession for the holder under the challenge of `attestation_kind`
    /// (the recovery kind has a possession domain of its own, so only the
    /// key's holder enrols one key both ways). Answers the row and its entry
    /// without storing it.
    fn sibling_enrolment_row(
        &self,
        parents: Vec<AuthorityEntryHash>,
        sequence: u64,
        predecessor_signing_key: &SigningKey,
        carrier: EntityId,
        carrier_signing_key: &SigningKey,
        holder: EntityId,
        new_signing_key: &SigningKey,
        attestation_kind: &str,
        timestamp: u64,
    ) -> (AuthorityLogEntry, AuthorityEntryHash) {
        let fold = self.vault.authority_fold().expect("authority fold");
        let vault_id = fold.vault_id.expect("the vault is rooted");
        let owner = self.vault.ensure_embedded_owner_actor().expect("the owner");
        let public_key = new_signing_key.verifying_key().to_bytes();
        let target =
            owner_key_enrollment_target(&vault_id, &public_key).expect("the enrolment target");
        let challenge = if attestation_kind == RECOVERY_AUTHORITY_POSSESSION_KIND {
            recovery_authority_enrollment_challenge(&vault_id, holder, &public_key, owner)
                .expect("the recovery kind's challenge")
        } else {
            let authority = ActAuthority::Owner(self.owner.clone(), ActSurface::ThisInstall);
            self.vault
                .owner_key_enrollment_challenge_as(&authority, holder, &public_key)
                .expect("the key's challenge")
        };
        let proof = new_signing_key.sign(&challenge).to_bytes().to_vec();
        let operation = AuthorityOp::OwnerKeyEnroll(OwnerKeyEnroll {
            act: OwnerAct::by_owner(
                owner,
                OwnerActKind::OwnerKeyEnrollment,
                target,
                ActSurface::ThisInstall,
                OWNER_KEY_ENROLLMENT_SEEN,
            ),
            machine: holder,
            carrier,
            device: DeviceAuthority {
                key: AuthorityKey::Ed25519(public_key),
                transport_key_binding: [0; 32],
                attestation: AuthorityAttestation {
                    kind: attestation_kind.to_owned(),
                    evidence: proof,
                },
                tier: AuthorityTier::Software,
                roles: ROLE_OWNER,
            },
        });
        let predecessor_key =
            AuthorityKey::Ed25519(predecessor_signing_key.verifying_key().to_bytes());
        let carrier_key = AuthorityKey::Ed25519(carrier_signing_key.verifying_key().to_bytes());
        let mut entry = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: Some(vault_id),
            seq: sequence,
            parent_hashes: parents,
            op: operation,
            signer: AuthoritySignature {
                suite: predecessor_key.suite(),
                public_key: predecessor_key,
                signature: vec![0; 64],
            },
            cosigns: vec![AuthoritySignature {
                suite: carrier_key.suite(),
                public_key: carrier_key,
                signature: vec![0; 64],
            }],
            ts: timestamp,
        };
        let transcript = authority_transcript(&entry).expect("the transcript");
        entry.signer.signature = predecessor_signing_key
            .sign(&transcript)
            .to_bytes()
            .to_vec();
        entry.cosigns[0].signature = carrier_signing_key.sign(&transcript).to_bytes().to_vec();
        let enrolment = authority_entry_hash(&entry).expect("a hash");
        (entry, enrolment)
    }

    /// The sibling enrolment of the key `new_signing_key` holds for `holder`,
    /// carried by `carrier`: `predecessor_signing_key` signs at `sequence` on `parents`,
    /// the carrier's install key cosigns, and the new key proves possession
    /// for the holder. Stores it as the log holds it and answers its entry.
    fn store_sibling_enrolment(
        &self,
        parents: Vec<AuthorityEntryHash>,
        sequence: u64,
        predecessor_signing_key: &SigningKey,
        carrier: EntityId,
        carrier_signing_key: &SigningKey,
        holder: EntityId,
        new_signing_key: &SigningKey,
    ) -> AuthorityEntryHash {
        let now = now_seconds();
        let (entry, enrolment) = self.sibling_enrolment_row(
            parents,
            sequence,
            predecessor_signing_key,
            carrier,
            carrier_signing_key,
            holder,
            new_signing_key,
            OWNER_KEY_POSSESSION_KIND,
            now,
        );
        self.vault
            .put_authority_log_entry(
                &entry,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )
            .expect("the sibling enrolment lands");
        enrolment
    }

    /// The sibling revocation row of `revoked` at `timestamp`, signed by
    /// `signer` at `sequence` on `parents` with no cosign. Answers the row
    /// and its entry without storing it.
    fn sibling_revoke_row(
        &self,
        parents: Vec<AuthorityEntryHash>,
        sequence: u64,
        signer: &SigningKey,
        revoked: [u8; 32],
        timestamp: u64,
    ) -> (AuthorityLogEntry, AuthorityEntryHash) {
        let fold = self.vault.authority_fold().expect("authority fold");
        let vault_id = fold.vault_id.expect("the vault is rooted");
        let signer_key = AuthorityKey::Ed25519(signer.verifying_key().to_bytes());
        let mut entry = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: Some(vault_id),
            seq: sequence,
            parent_hashes: parents,
            op: AuthorityOp::RevokeDevice {
                revoked_key: AuthorityKey::Ed25519(revoked),
            },
            signer: AuthoritySignature {
                suite: signer_key.suite(),
                public_key: signer_key,
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts: timestamp,
        };
        let transcript = authority_transcript(&entry).expect("the transcript");
        entry.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
        let removal = authority_entry_hash(&entry).expect("a hash");
        (entry, removal)
    }

    /// The authority log's heads: the rows no row names as a parent.
    fn authority_heads(&self) -> Vec<AuthorityEntryHash> {
        let rows: Vec<AuthorityLogEntry> = self
            .vault
            .export_signed_authority_history()
            .expect("the signed history")
            .iter()
            .map(|bytes| decode_authority_log_entry_body(bytes).expect("a row"))
            .collect();
        let parents: BTreeSet<AuthorityEntryHash> = rows
            .iter()
            .flat_map(|row| row.parent_hashes.iter().copied())
            .collect();
        rows.iter()
            .map(|row| authority_entry_hash(row).expect("a hash"))
            .filter(|hash| !parents.contains(hash))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// The signer's next sequence in the stored history.
    fn next_sequence_for(&self, signer: &AuthorityKey) -> u64 {
        self.vault
            .export_signed_authority_history()
            .expect("the signed history")
            .iter()
            .map(|bytes| decode_authority_log_entry_body(bytes).expect("a row"))
            .filter(|row| row.signer_key() == signer)
            .map(|row| row.seq + 1)
            .max()
            .unwrap_or(0)
            .max(1)
    }
}

#[test]
fn a_key_enrolled_for_two_machines_ends_with_either_machine() {
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
    let machine_b = removal_vault.enrol_machine_with([0x76; 16], JOINING_SEED);
    let machine_c = removal_vault.enrol_machine_with([0x77; 16], MACHINE_C_SEED);
    let machine_c_signing_key = signing(MACHINE_C_SEED);
    let predecessor_signing_key = SigningKey::from_bytes(&[76; 32]);
    let install = removal_vault.install();
    let (_, branch_parent) =
        removal_vault.enrol_owner_key_on_machine(install, &predecessor_signing_key);
    let shared_signing_key = SigningKey::from_bytes(&[77; 32]);
    let shared_key = shared_signing_key.verifying_key().to_bytes();
    let (_, first_enrolment) =
        removal_vault.enrol_owner_key_on_machine(machine_b, &shared_signing_key);
    let second_enrolment = removal_vault.store_sibling_enrolment(
        vec![branch_parent],
        1,
        &predecessor_signing_key,
        machine_c,
        &machine_c_signing_key,
        machine_c,
        &shared_signing_key,
    );
    let fold = removal_vault
        .vault
        .authority_fold()
        .expect("authority fold");
    assert!(
        fold.valid_entries.contains(&first_enrolment),
        "a key enrolled for two machines counts both enrolments before either machine ends: the first enrolment counts"
    );
    assert!(
        fold.valid_entries.contains(&second_enrolment),
        "a key enrolled for two machines counts both enrolments before either machine ends: the second enrolment counts"
    );
    let enrolled_keys = removal_vault
        .vault
        .enrolled_owner_keys()
        .expect("enrolled owner keys");
    let matching_keys: Vec<_> = enrolled_keys
        .iter()
        .filter(|enrolled| enrolled.public_key == shared_key)
        .collect();
    assert_eq!(
        matching_keys.len(),
        1,
        "a key enrolled for two machines lists once"
    );
    assert!(
        matching_keys[0].live,
        "a key enrolled for two machines stays live before either machine ends"
    );
    let kept_machine = matching_keys[0].machine;
    assert!(
        kept_machine == machine_b || kept_machine == machine_c,
        "a key enrolled for two machines keeps one of its two enrolments"
    );
    let other_machine = if kept_machine == machine_b {
        machine_c
    } else {
        machine_b
    };
    let machine_removal = removal_vault
        .vault
        .remove_machine(
            &removal_vault.owner,
            ActSurface::ThisInstall,
            other_machine,
            None,
            LastDeviceKeyConfirmation::NotGiven,
        )
        .expect(
            "a machine removal ends every live device owner key that any counted enrolment names for that machine",
        );
    match machine_removal {
        MachineRemoval::Written(receipt) => {
            assert!(
                receipt.landing.held().is_none(),
                "a machine removal ends every live device owner key that any counted enrolment names for that machine: the removal stands"
            );
            assert_eq!(
                receipt.ended_keys,
                vec![shared_key],
                "a machine removal ends every live device owner key that any counted enrolment names for that machine"
            );
            let enrolled_keys = removal_vault
                .vault
                .enrolled_owner_keys()
                .expect("enrolled owner keys");
            assert!(
                !enrolled_keys
                    .iter()
                    .find(|enrolled| enrolled.public_key == shared_key)
                    .expect("the shared key is enrolled")
                    .live,
                "a machine removal ends every live device owner key that any counted enrolment names for that machine: the shared key ends"
            );
            assert!(
                enrolled_keys
                    .iter()
                    .find(|enrolled| enrolled.public_key == first_key)
                    .expect("the first key is enrolled")
                    .live,
                "a machine removal ends only the removed machine's keys: the other device's key stays live"
            );
        }
        MachineRemoval::LastDeviceKey(remaining) => {
            panic!(
                "a machine removal ends every live device owner key that any counted enrolment names for that machine: another key remains, so no ask: {remaining:?}"
            )
        }
    }
}

#[test]
fn removing_a_machine_again_ends_a_key_enrolled_for_it_on_a_branch_the_removal_never_saw() {
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
    let machine_c = removal_vault.enrol_machine_with([0x77; 16], MACHINE_C_SEED);
    let machine_c_signing_key = signing(MACHINE_C_SEED);
    let predecessor_signing_key = SigningKey::from_bytes(&[76; 32]);
    let (predecessor_key, branch_parent) =
        removal_vault.enrol_owner_key_on_machine(machine_c, &predecessor_signing_key);
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
                "the removal stands with the owner's key"
            );
            assert_eq!(
                receipt.ended_keys,
                vec![second_key],
                "a machine removal ends the machine's key"
            );
        }
        MachineRemoval::LastDeviceKey(remaining) => {
            panic!("another key remains, so no ask: {remaining:?}")
        }
    }
    let late_signing_key = SigningKey::from_bytes(&[78; 32]);
    let late_key = late_signing_key.verifying_key().to_bytes();
    let late_enrolment = removal_vault.store_sibling_enrolment(
        vec![branch_parent],
        1,
        &predecessor_signing_key,
        machine_c,
        &machine_c_signing_key,
        machine_b,
        &late_signing_key,
    );
    let fold = removal_vault
        .vault
        .authority_fold()
        .expect("authority fold");
    assert!(
        fold.valid_entries.contains(&late_enrolment),
        "a key enrolled for a removed machine on a branch the removal never saw still counts"
    );
    let enrolled_keys = removal_vault
        .vault
        .enrolled_owner_keys()
        .expect("enrolled owner keys");
    assert!(
        enrolled_keys
            .iter()
            .find(|enrolled| enrolled.public_key == late_key)
            .expect("the late key is enrolled")
            .live,
        "a key enrolled for a removed machine on a branch the removal never saw stays live until the machine is removed again"
    );
    let head = fold
        .machine(machine_b)
        .and_then(|machine| machine.roster.as_ref())
        .expect("the second machine stands on the roster");
    assert!(
        head.removed,
        "the machine stays removed before it is removed again"
    );
    assert_eq!(
        head.profile.role,
        MachineRole::Removed,
        "the machine stays removed before it is removed again"
    );
    let second_removal = removal_vault
        .vault
        .remove_machine(
            &removal_vault.owner,
            ActSurface::ThisInstall,
            machine_b,
            None,
            LastDeviceKeyConfirmation::NotGiven,
        )
        .expect(
            "when the fold already holds a machine removed, removing it again ends the live device owner keys that still name it",
        );
    match second_removal {
        MachineRemoval::Written(receipt) => {
            assert!(
                receipt.landing.held().is_none(),
                "when the fold already holds a machine removed, removing it again answers the removal as it stands"
            );
            assert_eq!(
                receipt.ended_keys,
                vec![late_key],
                "when the fold already holds a machine removed, removing it again ends the live device owner keys that still name it"
            );
            assert!(
                receipt.live_keys.is_empty(),
                "when the fold already holds a machine removed, removing it again leaves no key of the machine live"
            );
            let enrolled_keys = removal_vault
                .vault
                .enrolled_owner_keys()
                .expect("enrolled owner keys");
            assert!(
                !enrolled_keys
                    .iter()
                    .find(|enrolled| enrolled.public_key == late_key)
                    .expect("the late key is enrolled")
                    .live,
                "when the fold already holds a machine removed, removing it again ends the key enrolled for it on the branch the removal never saw"
            );
            assert!(
                enrolled_keys
                    .iter()
                    .find(|enrolled| enrolled.public_key == first_key)
                    .expect("the first key is enrolled")
                    .live,
                "removing a machine again ends only that machine's keys: the other device's key stays live"
            );
            assert!(
                enrolled_keys
                    .iter()
                    .find(|enrolled| enrolled.public_key == predecessor_key)
                    .expect("the predecessor key is enrolled")
                    .live,
                "removing a machine again ends only that machine's keys: the predecessor key stays live"
            );
        }
        MachineRemoval::LastDeviceKey(remaining) => {
            panic!("another key remains, so no ask: {remaining:?}")
        }
    }
}

#[test]
fn two_removals_that_cross_both_show_in_the_changes_list() {
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
    let (_, second_key) = removal_vault.enrol_second_machine_and_key(&second_signing_key);
    let predecessor_signing_key = SigningKey::from_bytes(&[76; 32]);
    let install = removal_vault.install();
    let (predecessor_key, _) =
        removal_vault.enrol_owner_key_on_machine(install, &predecessor_signing_key);
    let parents = removal_vault.authority_heads();
    assert!(
        !parents.is_empty(),
        "two removals that cross start from the heads after both enrolments"
    );
    let predecessor_sequence = removal_vault.next_sequence_for(&AuthorityKey::Ed25519(
        predecessor_signing_key.verifying_key().to_bytes(),
    ));
    let second_sequence = removal_vault.next_sequence_for(&AuthorityKey::Ed25519(
        second_signing_key.verifying_key().to_bytes(),
    ));
    let now = now_seconds();
    let (first_entry, first_removal) = removal_vault.sibling_revoke_row(
        parents.clone(),
        predecessor_sequence,
        &predecessor_signing_key,
        second_key,
        now,
    );
    let (second_entry, second_removal) = removal_vault.sibling_revoke_row(
        parents,
        second_sequence,
        &second_signing_key,
        predecessor_key,
        now,
    );
    removal_vault
        .vault
        .put_authority_log_entries(&[
            (
                first_entry,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            ),
            (
                second_entry,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            ),
        ])
        .expect("two removals that cross land in one batch");
    let enrolled_keys = removal_vault
        .vault
        .enrolled_owner_keys()
        .expect("enrolled owner keys");
    assert!(
        !enrolled_keys
            .iter()
            .find(|enrolled| enrolled.public_key == predecessor_key)
            .expect("the first key is enrolled")
            .live,
        "two removals that cross end both keys: the first key ends"
    );
    assert!(
        !enrolled_keys
            .iter()
            .find(|enrolled| enrolled.public_key == second_key)
            .expect("the second key is enrolled")
            .live,
        "two removals that cross end both keys: the second key ends"
    );
    assert!(
        enrolled_keys
            .iter()
            .find(|enrolled| enrolled.public_key == first_key)
            .expect("the install key is enrolled")
            .live,
        "two removals that cross end only their two keys: the install key stays live"
    );
    let fold = removal_vault
        .vault
        .authority_fold()
        .expect("authority fold");
    assert!(
        !fold.valid_entries.contains(&first_removal),
        "two removals that cross count neither entry: the first removal is uncounted"
    );
    assert!(
        !fold.valid_entries.contains(&second_removal),
        "two removals that cross count neither entry: the crossing removal is uncounted"
    );
    let changes = removal_vault
        .vault
        .owner_key_changes(&removal_vault.owner)
        .expect("the owner reads the key changes");
    let first_line = changes
        .iter()
        .find(|change| {
            change.entry == first_removal
                && change.change.key().map(|key| key.public_key) == Some(second_key)
        })
        .expect("two removals that cross both show in the changes list: the first removal shows");
    assert!(
        !matches!(first_line.change, OwnerKeyChangeKind::Enrolled(_)),
        "two removals that cross both show in the changes list: the first line is no enrolment"
    );
    let crossing_line = changes
        .iter()
        .find(|change| {
            change.entry == second_removal
                && change.change.key().map(|key| key.public_key) == Some(predecessor_key)
        })
        .expect(
            "two removals that cross both show in the changes list: the crossing removal shows",
        );
    assert!(
        !matches!(crossing_line.change, OwnerKeyChangeKind::Enrolled(_)),
        "two removals that cross both show in the changes list: the crossing line is no enrolment"
    );
}

#[test]
fn a_key_enrolled_as_a_devices_and_as_the_recovery_roots_ends_with_its_machine() {
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
    let machine_b = removal_vault.enrol_machine_with([0x76; 16], JOINING_SEED);
    let machine_b_signing_key = signing(JOINING_SEED);
    let predecessor_signing_key = SigningKey::from_bytes(&[76; 32]);
    let install = removal_vault.install();
    let (_, branch_parent) =
        removal_vault.enrol_owner_key_on_machine(install, &predecessor_signing_key);
    let shared_signing_key = SigningKey::from_bytes(&[77; 32]);
    let shared_key = shared_signing_key.verifying_key().to_bytes();
    let (_, device_enrolment) =
        removal_vault.enrol_owner_key_on_machine(machine_b, &shared_signing_key);
    let start = now_seconds();
    let mut chosen = None;
    for offset in 0..64u64 {
        let timestamp = start + offset;
        let (entry, hash) = removal_vault.sibling_enrolment_row(
            vec![branch_parent],
            1,
            &predecessor_signing_key,
            machine_b,
            &machine_b_signing_key,
            machine_b,
            &shared_signing_key,
            RECOVERY_AUTHORITY_POSSESSION_KIND,
            timestamp,
        );
        if hash < device_enrolment {
            chosen = Some((entry, hash, timestamp));
            break;
        }
    }
    let (recovery_entry, recovery_enrolment, recovery_time) = chosen.expect(
        "a recovery enrolment hashes smaller than the device enrolment within 64 timestamps",
    );
    removal_vault
        .vault
        .put_authority_log_entry(
            &recovery_entry,
            TimeRange {
                start: recovery_time,
                end: recovery_time,
            },
            recovery_time,
        )
        .expect("the sibling recovery enrolment lands");
    let fold = removal_vault
        .vault
        .authority_fold()
        .expect("authority fold");
    assert!(
        fold.valid_entries.contains(&device_enrolment),
        "a key enrolled as a device's and as the recovery root's counts both enrolments before its machine ends: the device enrolment counts"
    );
    assert!(
        fold.valid_entries.contains(&recovery_enrolment),
        "a key enrolled as a device's and as the recovery root's counts both enrolments before its machine ends: the recovery enrolment counts"
    );
    let enrolled_keys = removal_vault
        .vault
        .enrolled_owner_keys()
        .expect("enrolled owner keys");
    let matching_keys: Vec<_> = enrolled_keys
        .iter()
        .filter(|enrolled| enrolled.public_key == shared_key)
        .collect();
    assert_eq!(
        matching_keys.len(),
        1,
        "a key enrolled as a device's and as the recovery root's lists once"
    );
    assert!(
        matching_keys[0].live,
        "a key enrolled as a device's and as the recovery root's stays live before its machine ends"
    );
    assert_eq!(
        matching_keys[0].kind,
        EnrolledOwnerKeyKind::RecoveryAuthority,
        "a key enrolled as a device's and as the recovery root's keeps the recovery enrolment"
    );
    assert_eq!(
        matching_keys[0].entry, recovery_enrolment,
        "a key enrolled as a device's and as the recovery root's keeps the smaller entry"
    );
    let machine_removal = removal_vault
        .vault
        .remove_machine(
            &removal_vault.owner,
            ActSurface::ThisInstall,
            machine_b,
            None,
            LastDeviceKeyConfirmation::NotGiven,
        )
        .expect(
            "a machine removal ends every live device owner key that any counted enrolment names for that machine",
        );
    match machine_removal {
        MachineRemoval::Written(receipt) => {
            assert!(
                receipt.landing.held().is_none(),
                "a machine removal ends every live device owner key that any counted enrolment names for that machine: the removal stands"
            );
            assert_eq!(
                receipt.ended_keys,
                vec![shared_key],
                "a machine removal ends every live device owner key that any counted enrolment names for that machine"
            );
            let enrolled_keys = removal_vault
                .vault
                .enrolled_owner_keys()
                .expect("enrolled owner keys");
            assert!(
                !enrolled_keys
                    .iter()
                    .find(|enrolled| enrolled.public_key == shared_key)
                    .expect("the shared key is enrolled")
                    .live,
                "a machine removal ends every live device owner key that any counted enrolment names for that machine: the shared key ends"
            );
            assert!(
                enrolled_keys
                    .iter()
                    .find(|enrolled| enrolled.public_key == first_key)
                    .expect("the first key is enrolled")
                    .live,
                "a machine removal ends only the removed machine's keys: the other device's key stays live"
            );
        }
        MachineRemoval::LastDeviceKey(remaining) => {
            panic!(
                "a machine removal ends every live device owner key that any counted enrolment names for that machine: another key remains, so no ask: {remaining:?}"
            )
        }
    }
}

#[test]
fn the_key_list_names_every_machine_whose_removal_ends_a_key() {
    let removal_vault = RemovalVault::hosted();
    removal_vault.enrol_owner_key();
    let install = removal_vault.install();
    let first_key = removal_vault
        .vault
        .enrolled_owner_keys()
        .expect("enrolled owner keys")
        .into_iter()
        .find(|enrolled| enrolled.live)
        .expect("the install's owner key is enrolled")
        .public_key;
    let machine_b = removal_vault.enrol_machine_with([0x76; 16], JOINING_SEED);
    let machine_c = removal_vault.enrol_machine_with([0x77; 16], MACHINE_C_SEED);
    let machine_c_signing_key = signing(MACHINE_C_SEED);
    let predecessor_signing_key = SigningKey::from_bytes(&[76; 32]);
    let (_, branch_parent) =
        removal_vault.enrol_owner_key_on_machine(install, &predecessor_signing_key);
    let shared_signing_key = SigningKey::from_bytes(&[77; 32]);
    let shared_key = shared_signing_key.verifying_key().to_bytes();
    let (_, first_enrolment) =
        removal_vault.enrol_owner_key_on_machine(machine_b, &shared_signing_key);
    let second_enrolment = removal_vault.store_sibling_enrolment(
        vec![branch_parent],
        1,
        &predecessor_signing_key,
        machine_c,
        &machine_c_signing_key,
        machine_c,
        &shared_signing_key,
    );
    let fold = removal_vault
        .vault
        .authority_fold()
        .expect("authority fold");
    assert!(
        fold.valid_entries.contains(&first_enrolment),
        "the key list names every machine whose removal ends a key: the first enrolment counts"
    );
    assert!(
        fold.valid_entries.contains(&second_enrolment),
        "the key list names every machine whose removal ends a key: the second enrolment counts"
    );
    let enrolled_keys = removal_vault
        .vault
        .enrolled_owner_keys()
        .expect("enrolled owner keys");
    let shared = enrolled_keys
        .iter()
        .find(|enrolled| enrolled.public_key == shared_key)
        .expect("the shared key is enrolled");
    assert_eq!(
        shared.device_machines,
        BTreeSet::from([machine_b, machine_c]),
        "the key list names every machine whose removal ends a key: both machines of a key enrolled for two"
    );
    assert!(
        !shared.recovery_authority,
        "the key list names every machine whose removal ends a key: no enrolment marks the shared key the recovery root's"
    );
    let first = enrolled_keys
        .iter()
        .find(|enrolled| enrolled.public_key == first_key)
        .expect("the first key is enrolled");
    assert_eq!(
        first.device_machines,
        BTreeSet::from([install]),
        "the key list names every machine whose removal ends a key: a key enrolled once names its one machine"
    );
    assert!(
        !first.recovery_authority,
        "the key list names every machine whose removal ends a key: a plain device key is not the recovery root's"
    );
}

#[test]
fn the_key_list_marks_a_key_enrolled_both_ways_as_the_recovery_roots() {
    for recovery_enrolment_listed in [false, true] {
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
        let machine_b = removal_vault.enrol_machine_with([0x76; 16], JOINING_SEED);
        let machine_b_signing_key = signing(JOINING_SEED);
        let predecessor_signing_key = SigningKey::from_bytes(&[76; 32]);
        let install = removal_vault.install();
        let (_, branch_parent) =
            removal_vault.enrol_owner_key_on_machine(install, &predecessor_signing_key);
        let shared_signing_key = SigningKey::from_bytes(&[77; 32]);
        let shared_key = shared_signing_key.verifying_key().to_bytes();
        let (_, device_enrolment) =
            removal_vault.enrol_owner_key_on_machine(machine_b, &shared_signing_key);
        let start = now_seconds();
        let mut chosen = None;
        for offset in 0..64u64 {
            let timestamp = start + offset;
            let (entry, hash) = removal_vault.sibling_enrolment_row(
                vec![branch_parent],
                1,
                &predecessor_signing_key,
                machine_b,
                &machine_b_signing_key,
                machine_b,
                &shared_signing_key,
                RECOVERY_AUTHORITY_POSSESSION_KIND,
                timestamp,
            );
            if (hash < device_enrolment) == recovery_enrolment_listed {
                chosen = Some((entry, hash, timestamp));
                break;
            }
        }
        let (recovery_entry, recovery_enrolment, recovery_time) = chosen.expect(
            "a recovery enrolment hashes on the wanted side of the device enrolment within 64 timestamps",
        );
        removal_vault
            .vault
            .put_authority_log_entry(
                &recovery_entry,
                TimeRange {
                    start: recovery_time,
                    end: recovery_time,
                },
                recovery_time,
            )
            .expect("the sibling recovery enrolment lands");
        let fold = removal_vault
            .vault
            .authority_fold()
            .expect("authority fold");
        assert!(
            fold.valid_entries.contains(&device_enrolment),
            "the key list marks a key enrolled both ways as the recovery root's: the device enrolment counts"
        );
        assert!(
            fold.valid_entries.contains(&recovery_enrolment),
            "the key list marks a key enrolled both ways as the recovery root's: the recovery enrolment counts"
        );
        let enrolled_keys = removal_vault
            .vault
            .enrolled_owner_keys()
            .expect("enrolled owner keys");
        let shared = enrolled_keys
            .iter()
            .find(|enrolled| enrolled.public_key == shared_key)
            .expect("the shared key is enrolled");
        let (listed_entry, listed_kind) = if recovery_enrolment_listed {
            (recovery_enrolment, EnrolledOwnerKeyKind::RecoveryAuthority)
        } else {
            (device_enrolment, EnrolledOwnerKeyKind::Device)
        };
        assert_eq!(
            shared.entry, listed_entry,
            "the key list marks a key enrolled both ways as the recovery root's: the row keeps the smaller entry"
        );
        assert_eq!(
            shared.kind, listed_kind,
            "the key list marks a key enrolled both ways as the recovery root's: the row's kind is the listed enrolment's"
        );
        assert!(
            shared.recovery_authority,
            "the key list marks a key enrolled both ways as the recovery root's, whichever enrolment the row lists (recovery enrolment listed: {recovery_enrolment_listed})"
        );
        assert_eq!(
            shared.device_machines,
            BTreeSet::from([machine_b]),
            "the key list marks a key enrolled both ways as the recovery root's: the row names the machine whose removal ends it, whichever enrolment the row lists (recovery enrolment listed: {recovery_enrolment_listed})"
        );
        let first = enrolled_keys
            .iter()
            .find(|enrolled| enrolled.public_key == first_key)
            .expect("the first key is enrolled");
        assert!(
            !first.recovery_authority,
            "the key list marks a key enrolled both ways as the recovery root's: a plain device key is not"
        );
    }
}

impl RemovalVault {
    /// Enrols the key `shared_signing_key` holds both ways: as a device's
    /// key for `device_machine` through the door, and as the recovery
    /// root's on a sibling branch that the second machine `carrier` carries
    /// (`carrier_signing_key` is its machine key). Both enrolments count.
    /// Answers the key.
    fn enrol_key_both_ways(
        &self,
        device_machine: EntityId,
        carrier: EntityId,
        carrier_signing_key: &SigningKey,
        shared_signing_key: &SigningKey,
    ) -> [u8; 32] {
        let predecessor_signing_key = SigningKey::from_bytes(&[76; 32]);
        let (_, branch_parent) =
            self.enrol_owner_key_on_machine(self.install(), &predecessor_signing_key);
        let (shared_key, device_enrolment) =
            self.enrol_owner_key_on_machine(device_machine, shared_signing_key);
        let recovery_time = now_seconds();
        let (recovery_entry, recovery_enrolment) = self.sibling_enrolment_row(
            vec![branch_parent],
            1,
            &predecessor_signing_key,
            carrier,
            carrier_signing_key,
            carrier,
            shared_signing_key,
            RECOVERY_AUTHORITY_POSSESSION_KIND,
            recovery_time,
        );
        self.vault
            .put_authority_log_entry(
                &recovery_entry,
                TimeRange {
                    start: recovery_time,
                    end: recovery_time,
                },
                recovery_time,
            )
            .expect("the sibling recovery enrolment lands");
        let fold = self.vault.authority_fold().expect("authority fold");
        assert!(
            fold.valid_entries.contains(&device_enrolment),
            "a key enrolled both ways: the device enrolment counts"
        );
        assert!(
            fold.valid_entries.contains(&recovery_enrolment),
            "a key enrolled both ways: the recovery enrolment counts"
        );
        shared_key
    }
}

#[test]
fn a_removal_that_ends_a_key_enrolled_both_ways_says_it_ends_the_recovery_roots() {
    // The receipt: the key is the second machine's, and other device keys
    // remain, so the removal asks nothing and lands.
    let removal_vault = RemovalVault::hosted();
    removal_vault.enrol_owner_key();
    let machine_b = removal_vault.enrol_machine_with([0x76; 16], JOINING_SEED);
    let shared_key = removal_vault.enrol_key_both_ways(
        machine_b,
        machine_b,
        &signing(JOINING_SEED),
        &SigningKey::from_bytes(&[77; 32]),
    );
    let machine_removal = removal_vault
        .vault
        .remove_machine(
            &removal_vault.owner,
            ActSurface::ThisInstall,
            machine_b,
            None,
            LastDeviceKeyConfirmation::NotGiven,
        )
        .expect("the removal of the second machine lands");
    match machine_removal {
        MachineRemoval::Written(receipt) => {
            assert_eq!(
                receipt.ended_keys,
                vec![shared_key],
                "a removal that ends a key enrolled both ways: the key ends with its machine"
            );
            assert!(
                receipt.remaining.ends_recovery_root,
                "a removal that ends a key enrolled both ways says in its receipt that it ended the recovery root's key"
            );
            assert!(
                !receipt.remaining.recovery_root,
                "a removal that ends a key enrolled both ways leaves no recovery root's key live"
            );
        }
        MachineRemoval::LastDeviceKey(remaining) => {
            panic!(
                "a removal that ends a key enrolled both ways: other device keys remain, so no ask: {remaining:?}"
            )
        }
    }

    // The question: the key is this install's own machine's, beside its two
    // other device keys, so removing this machine would end every device key.
    let removal_vault = RemovalVault::hosted();
    removal_vault.enrol_owner_key();
    let install = removal_vault.install();
    let machine_b = removal_vault.enrol_machine_with([0x76; 16], JOINING_SEED);
    removal_vault.enrol_key_both_ways(
        install,
        machine_b,
        &signing(JOINING_SEED),
        &SigningKey::from_bytes(&[77; 32]),
    );
    let rows = removal_vault.stored_rows();
    let machine_removal = removal_vault
        .vault
        .remove_machine(
            &removal_vault.owner,
            ActSurface::ThisInstall,
            install,
            None,
            LastDeviceKeyConfirmation::NotGiven,
        )
        .expect("the removal of this install's machine asks first");
    match machine_removal {
        MachineRemoval::LastDeviceKey(remaining) => {
            assert_eq!(
                remaining.device_keys, 0,
                "a removal that would end a key enrolled both ways: no device key would remain"
            );
            assert!(
                remaining.ends_recovery_root,
                "a removal that would end a key enrolled both ways says in its question that it ends the recovery root's key"
            );
            assert!(
                !remaining.recovery_root,
                "a removal that would end a key enrolled both ways would leave no recovery root's key live"
            );
        }
        MachineRemoval::Written(receipt) => {
            panic!(
                "a removal that would end the last device keys asks first and writes nothing: {receipt:?}"
            )
        }
    }
    removal_vault.assert_nothing_stored_since(rows);
}

#[test]
fn a_removal_that_ends_only_device_keys_does_not_say_it_ends_the_recovery_roots() {
    let removal_vault = RemovalVault::hosted();
    removal_vault.enrol_owner_key();
    let second_signing_key = SigningKey::from_bytes(&[71; 32]);
    let (_, second_key) = removal_vault.enrol_second_machine_and_key(&second_signing_key);
    let removal = removal_vault
        .vault
        .remove_owner_key(
            &removal_vault.owner,
            second_key,
            LastDeviceKeyConfirmation::NotGiven,
        )
        .expect("the owner removes the second key");
    match removal {
        OwnerKeyRemoval::Removed { ended, remaining } => {
            assert_eq!(
                ended.public_key, second_key,
                "a removal that ends only device keys: the second key ends"
            );
            assert!(
                !remaining.ends_recovery_root,
                "a removal that ends only device keys does not say it ended the recovery root's key"
            );
        }
        OwnerKeyRemoval::LastDeviceKey(remaining) => {
            panic!(
                "a removal that ends only device keys: this install's key remains, so no ask: {remaining:?}"
            )
        }
    }
}

impl RemovalVault {
    /// Every pending-mirror marker this vault holds: a window, then the row
    /// the window is owed.
    fn pending_mirror_markers(&self) -> Vec<String> {
        let mut markers = Vec::new();
        let mut after: Option<String> = None;
        loop {
            after = self
                .vault
                .sync_state_prefix_page("lm:w:", after.as_deref(), 256, |key, _| {
                    markers.push(key.to_owned());
                    Ok(())
                })
                .expect("a page of the pending-mirror markers");
            if after.is_none() {
                break;
            }
        }
        markers
    }

    /// Asserts that a pending-mirror marker names the authority row of
    /// `entry`.
    fn assert_marked_for_the_live_mirror(&self, entry: &AuthorityEntryHash, row: &str) {
        let id = authority_log_entity_id_from_hash(entry)
            .expect("the row's id")
            .to_hex();
        let markers = self.pending_mirror_markers();
        assert!(
            markers
                .iter()
                .any(|marker| marker.ends_with(&format!(":{id}"))),
            "a removal's rows are marked for the live mirror: {row} {id} carries a marker for its window: {markers:?}"
        );
    }
}

/// Every row a removal door wrote carries a pending-mirror marker for its
/// window once the write committed, as the recovery root's door's rows do, so
/// the host and every replica see the keys ended without a window reload.
#[test]
fn a_removals_rows_are_marked_for_the_live_mirror() {
    // The key door: the revocation's row.
    let removal_vault = RemovalVault::hosted();
    removal_vault.enrol_owner_key();
    let (_, second_key) =
        removal_vault.enrol_second_machine_and_key(&SigningKey::from_bytes(&[73; 32]));
    let removal = removal_vault
        .vault
        .remove_owner_key(
            &removal_vault.owner,
            second_key,
            LastDeviceKeyConfirmation::NotGiven,
        )
        .expect("the owner removes the second key");
    let ended = match removal {
        OwnerKeyRemoval::Removed { ended, .. } => ended,
        OwnerKeyRemoval::LastDeviceKey(remaining) => {
            panic!("this install's key remains, so the key door asks nothing: {remaining:?}")
        }
    };
    removal_vault.assert_marked_for_the_live_mirror(&ended.entry, "the key door's revocation");

    // The machine door: the removal's own row, and the revocation of the
    // machine's key.
    let removal_vault = RemovalVault::hosted();
    removal_vault.enrol_owner_key();
    let (machine_b, second_key) =
        removal_vault.enrol_second_machine_and_key(&SigningKey::from_bytes(&[73; 32]));
    let removal = removal_vault
        .vault
        .remove_machine(
            &removal_vault.owner,
            ActSurface::ThisInstall,
            machine_b,
            None,
            LastDeviceKeyConfirmation::NotGiven,
        )
        .expect("the owner removes the second machine");
    let receipt = match removal {
        MachineRemoval::Written(receipt) => receipt,
        MachineRemoval::LastDeviceKey(remaining) => {
            panic!("this install's key remains, so the machine door asks nothing: {remaining:?}")
        }
    };
    assert_eq!(
        receipt.ended_keys,
        vec![second_key],
        "the removal ends the machine's key"
    );
    let removed = receipt
        .landing
        .machine()
        .and_then(|machine| machine.roster.as_ref())
        .expect("the removal stands on the roster's chain")
        .entry;
    removal_vault.assert_marked_for_the_live_mirror(&removed, "the machine door's removal");
    let revocation = removal_vault
        .vault
        .owner_key_changes(&removal_vault.owner)
        .expect("the owner reads the key changes")
        .into_iter()
        .find(|change| {
            matches!(change.change, OwnerKeyChangeKind::Removed(key) if key.public_key == second_key)
        })
        .expect("the changes list shows the key's removal")
        .entry;
    removal_vault.assert_marked_for_the_live_mirror(&revocation, "the machine door's revocation");
}
