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
    ActAuthority, ActSurface, AuthorityVaultId, HostSlipIssuer, MACHINE_ENCRYPTION_KEY_LEN,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass, MachineEncryptionKey,
    MachineEnrolmentRequest, MachineOwnership, MachineProfile, MachineRole, OwnerAct,
    OwnerKeyEnrollment, machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EntityId, HostingPrivacyPosture, Vault, VaultConfig};

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
