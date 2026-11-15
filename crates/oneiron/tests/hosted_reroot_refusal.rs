//! Pass 27 R4 (Engine NOTE 15 Nov 22:10, WAYBACK-E2 = A): the engine refuses
//! a ReRoot signed by the recovery root's authority key on a hosted vault
//! while its roster holds a live owner key. Such a ReRoot revokes every
//! roster row, the custodial root included, and every slip the host minted
//! stops verifying (NOTE WAYBACK-REROOT-TRACE, 15 Nov 22:02); the root's door
//! serves there with the two ordinary ops instead. The refusal sits in the
//! engine, so the stopped-vault CLI, which has no posture check of its own,
//! meets it too.
//!
//! Red on the anchor top 6166098690ef: `recover_owner_authority_from_kit`
//! re-roots the hosted vault and the custodial root is revoked.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test hosted_reroot_refusal`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActAuthority, ActSurface, AuthorityAttestation, AuthorityKey, AuthorityTier, DeviceAuthority,
    MachineRole, OwnerKeyEnrollment, ROLE_ADMIN, ROLE_OWNER,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::recovery::{
    KitIssue, KitSecretKind, PassphraseCost, PieceHome, issue_recovery_root_kit, restore_kit,
};
use oneiron::store::GateDecisionId;
use oneiron::test_support::bind_host_owner;
use oneiron::world_keys::RecoveryRootSeed;
use oneiron::{EntityId, HostingPrivacyPosture, Vault, VaultConfig};

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

fn live(vault: &Vault, key: &AuthorityKey) -> bool {
    vault
        .authority_fold()
        .expect("the fold")
        .roster
        .get(key)
        .is_some_and(|device| !device.revoked)
}

#[test]
fn a_hosted_vault_refuses_a_reroot_while_an_owner_key_lives() {
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

    // The owner's device key, enrolled under the custodial root.
    let device_key = SigningKey::from_bytes(&[21; 32]);
    let public_key = device_key.verifying_key().to_bytes();
    let challenge = vault
        .owner_key_enrollment_challenge_as(&authority, machine, &public_key)
        .expect("the challenge");
    vault
        .enrol_owner_signing_key_as_host(
            &authority,
            OwnerKeyEnrollment {
                machine,
                public_key,
                proof: device_key.sign(&challenge).to_bytes().to_vec(),
            },
            &issuer,
        )
        .expect("the owner enrols a device key");

    // The kit's root, its authority key enrolled before the loss.
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
    let restore = || {
        restore_kit(
            vault_id,
            KitSecretKind::RecoveryRoot,
            &[&pieces[0], &pieces[1]],
            None,
        )
        .expect("two stored pieces restore the seed")
    };
    let receipt = vault
        .enrol_recovery_authority_key_as_host(
            &authority,
            machine,
            &RecoveryRootSeed::from_restored_kit(restore()).expect("the seed"),
            &issuer,
        )
        .expect("the owner enrols the root's authority key");
    let root_key = AuthorityKey::Ed25519(receipt.public_key);
    let host_root = issuer.public_key();
    assert!(live(&vault, &root_key) && live(&vault, &host_root));

    let stored = vault
        .export_signed_authority_history()
        .expect("the history")
        .len();
    let successor = DeviceAuthority {
        key: AuthorityKey::Ed25519(SigningKey::from_bytes(&[41; 32]).verifying_key().to_bytes()),
        transport_key_binding: [7; 32],
        attestation: AuthorityAttestation {
            kind: "SoftwareArgon2id".to_owned(),
            evidence: vec![1, 2, 3],
        },
        tier: AuthorityTier::Software,
        roles: ROLE_OWNER | ROLE_ADMIN,
    };
    let refused = vault.recover_owner_authority_from_kit(restore(), successor);

    assert!(
        refused.is_err(),
        "a ReRoot on a hosted vault with a live owner key is refused; the root's door serves there"
    );
    assert_eq!(
        vault
            .export_signed_authority_history()
            .expect("the history")
            .len(),
        stored,
        "the refusal writes nothing"
    );
    assert!(live(&vault, &host_root), "the custodial root stays live");
    assert!(
        live(&vault, &root_key),
        "the root's authority key stays live"
    );
    assert!(
        live(
            &vault,
            &AuthorityKey::Ed25519(device_key.verifying_key().to_bytes())
        ),
        "the device key stays live"
    );
}
