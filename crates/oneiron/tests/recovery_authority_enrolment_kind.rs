//! Pass 27 R4 PR 2 (OPUS-SPLIT-6's 15 Nov 23:17 ASK, answered 23:26): the
//! recovery root's authority key enrols under an attestation kind of its
//! own, `recovery-authority-possession/v1`, so a reader tells it from a
//! device's key by the enrollment row alone. A device's key keeps
//! `owner-key-possession/v1`. Both rows count, and both decode from the
//! exported history.
//!
//! Red on R4 PR 1's head 4494593651b1: the root's key enrols as a device's
//! key, so its row names `owner-key-possession/v1`.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test recovery_authority_enrolment_kind`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActAuthority, ActSurface, AuthorityKey, AuthorityOp, MachineRole, OwnerKeyEnrollment,
    decode_authority_log_entry_body,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::recovery::{
    KitIssue, KitSecretKind, PassphraseCost, PieceHome, issue_recovery_root_kit, restore_kit,
};
use oneiron::store::GateDecisionId;
use oneiron::test_support::bind_host_owner;
use oneiron::world_keys::RecoveryRootSeed;
use oneiron::{EntityId, HostingPrivacyPosture, Vault, VaultConfig};

/// The attestation kind of a device's enrolled key.
const DEVICE_KIND: &str = "owner-key-possession/v1";
/// The attestation kind of the recovery root's enrolled authority key.
const RECOVERY_AUTHORITY_KIND: &str = "recovery-authority-possession/v1";

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

#[test]
fn the_roots_authority_key_enrols_under_its_own_attestation_kind() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    let vault = Vault::open(dir.path(), config).expect("the hosted vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::HostedNode)
        .expect("this install's live machine profile");
    let person = vault.ensure_embedded_owner_actor().expect("the owner");
    bind_host_owner(&vault, &issuer, person).expect("the owner's binding");
    let vault_id = vault
        .authority_fold()
        .expect("the fold")
        .vault_id
        .expect("a rooted vault");
    let machine = vault
        .prepare_install_signing()
        .expect("this install's machine");
    let authority = ActAuthority::Owner(proof(&vault, person), ActSurface::ThisInstall);

    // A device's key.
    let device_key = SigningKey::from_bytes(&[21; 32]);
    let device_public = device_key.verifying_key().to_bytes();
    let challenge = vault
        .owner_key_enrollment_challenge_as(&authority, machine, &device_public)
        .expect("the challenge");
    vault
        .enrol_owner_signing_key_as_host(
            &authority,
            OwnerKeyEnrollment {
                machine,
                public_key: device_public,
                proof: device_key.sign(&challenge).to_bytes().to_vec(),
            },
            &issuer,
        )
        .expect("the owner enrols a device key");

    // The kit's root: its authority key, enrolled through its own door.
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
    let receipt = vault
        .enrol_recovery_authority_key_as_host(
            &authority,
            machine,
            &RecoveryRootSeed::from_restored_kit(restored).expect("the seed"),
            &issuer,
        )
        .expect("the owner enrols the root's authority key");
    let root_public = receipt.public_key;
    assert_ne!(root_public, device_public);

    // Each enrollment row names its key's kind, and the exported history
    // decodes with both.
    let kinds: BTreeMap<[u8; 32], String> = vault
        .export_signed_authority_history()
        .expect("the history")
        .iter()
        .map(|bytes| decode_authority_log_entry_body(bytes).expect("a row"))
        .filter_map(|row| match row.op {
            AuthorityOp::OwnerKeyEnroll(enroll) => match enroll.device.key {
                AuthorityKey::Ed25519(key) => Some((key, enroll.device.attestation.kind)),
                AuthorityKey::P256(_) => None,
            },
            _ => None,
        })
        .collect();
    assert_eq!(
        kinds.get(&device_public).map(String::as_str),
        Some(DEVICE_KIND),
        "a device's key keeps the device kind"
    );
    assert_eq!(
        kinds.get(&root_public).map(String::as_str),
        Some(RECOVERY_AUTHORITY_KIND),
        "the root's authority key enrols under its own kind"
    );
}
