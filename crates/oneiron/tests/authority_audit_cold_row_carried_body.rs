//! FIX [KEY-CHANGE-RECEIPT-COLD-ROWS]: on a vault that adopted a checkpoint
//! image, the owner's authority audit lists each covered row this vault does
//! not store as a cold row. The image carries the signed body of every
//! covered owner key enrolment and removal (fold schema 55), and the key
//! changes list names them from those bodies. The audit read only the row
//! summary, so its cold row of the same entry named no op, key or machine:
//! the two owner surfaces of one snapshot disagreed. A cold row whose body
//! the image carries now names what that body says, as the stored row does.
//!
//! The fixture: a hosted vault enrols this install's owner key and a second
//! machine's key, removes the second key, and builds and attests its image.
//! A fresh install of the same vault adopts that image and stores none of
//! its rows.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test authority_audit_cold_row_carried_body`.

#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActAuthority, ActSurface, AuthorityKey, AuthorityVaultId, LastDeviceKeyConfirmation,
    MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass,
    MachineEncryptionKey, MachineEnrolmentRequest, MachineOwnership, MachineProfile, MachineRole,
    OwnerKeyChangeKind, OwnerKeyEnrollment, OwnerKeyRemoval, authority_log_entity_id_from_hash,
    machine_profile_proof_transcript,
};
use oneiron::receipt::AuthorityAuditQuery;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EntityId, HostingPrivacyPosture, OpenOptions, Vault, VaultStorageId};
use oneiron_testkit::FakeClock;

/// The seed of the second machine's machine key.
const SECOND_MACHINE_SEED: u8 = 68;

/// The seed of the second machine's owner key.
const SECOND_KEY_SEED: u8 = 72;

/// The fields a row names from its entry's signed body: the op, its fields,
/// and the signer's own words (advisory clock, cosigners, vault).
const BODY_FIELDS: [&str; 16] = [
    "event_kind",
    "source_op",
    "detail",
    "advisory_ts",
    "cosigner_keys",
    "vault_ref",
    "subject_ref",
    "grant_ref",
    "receipt_ref",
    "affected_grants",
    "claim_ref",
    "holder_ref",
    "parent_ref",
    "peer_vault_ref",
    "epoch",
    "expires_at",
];

fn hosted_config(clock: &FakeClock) -> oneiron::VaultConfig {
    let mut config = clock.vault_config();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    config
}

/// The second machine's request to join `vault_id`: its own keys, and its own
/// proof over them for this vault.
fn second_machine(vault_id: AuthorityVaultId) -> MachineEnrolmentRequest {
    let machine = EntityId::from_bytes([0x76; 16]).expect("an id");
    let node = SigningKey::from_bytes(&[SECOND_MACHINE_SEED; 32]);
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
    let profile = MachineProfile {
        machine,
        owner: EntityId::from_bytes([0x71; 16]).expect("an id"),
        machine_key,
        device_class: MachineDeviceClass::Computer,
        encryption_key,
        role: MachineRole::Unanswered,
        revision: 1,
        machine_proof,
        seen_world_edits: BTreeSet::new(),
        carrier: None,
        act: None,
        restored_from: None,
    };
    MachineEnrolmentRequest {
        vault_id,
        machine,
        machine_key: profile.machine_key,
        device_class: profile.device_class,
        encryption_key: profile.encryption_key,
        machine_proof: profile.machine_proof,
        restored_from: None,
    }
}

fn whole_audit() -> AuthorityAuditQuery {
    AuthorityAuditQuery {
        limit: Some(500),
        ..AuthorityAuditQuery::default()
    }
}

/// A hosted vault enrols a second machine's owner key and removes it, and a
/// fresh install adopts its attested image. The adopter's audit lists the
/// enrolment and the removal as cold rows, and each names what the source's
/// stored row of the same entry names: the op, the key, the machine, the
/// signer's clock. The adopter's key changes list names both entries too.
/// Red at main c8e2f038: the cold row of the enrolment names no `source_op`.
#[test]
fn a_cold_row_whose_body_the_adopted_image_carries_names_its_key_change() {
    let clock = FakeClock::default();
    let source_dir = tempfile::tempdir().expect("tempdir");
    let source = Vault::open(source_dir.path(), hosted_config(&clock)).expect("the hosted vault");
    source.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&source);
    source
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's machine profile under the host root");
    let (_, owner) = embedded_owner(&source).expect("the authenticated embedded owner");
    let authority = ActAuthority::Owner(owner.clone(), ActSurface::ThisInstall);
    source
        .enrol_device_owner_signing_key(&authority, &issuer)
        .expect("the owner enrols this install's owner signing key");

    let vault_id = source
        .authority_fold()
        .expect("the fold")
        .vault_id
        .expect("the vault is rooted");
    let request = second_machine(vault_id);
    let landing = source
        .enroll_machine(
            &owner,
            ActSurface::ThisInstall,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner enrols the second machine");
    assert!(
        landing.held().is_none(),
        "FIXTURE: the second machine stands with the owner's key"
    );
    let second_signing_key = SigningKey::from_bytes(&[SECOND_KEY_SEED; 32]);
    let second_key = second_signing_key.verifying_key().to_bytes();
    let challenge = source
        .owner_key_enrollment_challenge_as(&authority, request.machine, &second_key)
        .expect("the second key's challenge");
    source
        .enrol_owner_signing_key_as_host(
            &authority,
            OwnerKeyEnrollment {
                machine: request.machine,
                public_key: second_key,
                proof: second_signing_key.sign(&challenge).to_bytes().to_vec(),
            },
            &issuer,
        )
        .expect("the owner enrols the second key on the second machine");
    let OwnerKeyRemoval::Removed { .. } = source
        .remove_owner_key(&owner, second_key, LastDeviceKeyConfirmation::NotGiven)
        .expect("the owner removes the second key")
    else {
        panic!("FIXTURE: another device's key is not the last one");
    };

    let changes = source
        .owner_key_changes(&owner)
        .expect("the source's key changes");
    let change_of = |kind: OwnerKeyChangeKind| {
        changes
            .iter()
            .find(|change| {
                change.change == kind && change.public_key == AuthorityKey::Ed25519(second_key)
            })
            .unwrap_or_else(|| panic!("FIXTURE: the source lists the second key {kind:?}"))
            .entry
    };
    let changed = [
        change_of(OwnerKeyChangeKind::Enrolled),
        change_of(OwnerKeyChangeKind::Removed),
    ];
    let stored = source
        .authority_audit(&owner, &whole_audit())
        .expect("the source's audit");

    let image_id = source
        .write_authority_checkpoint_v2(&issuer)
        .expect("the source builds and attests its image");
    let pin = source
        .authority_checkpoint_pin([7; 32])
        .expect("the pin")
        .expect("FIXTURE: the source's image reached quorum");
    assert_eq!(pin.checkpoint, image_id, "FIXTURE: the pin names the image");
    let bundle = source
        .authority_checkpoint_bundle(&image_id)
        .expect("the bundle")
        .expect("FIXTURE: the source keeps the image");
    let image = source
        .authority_checkpoint_v2(&image_id)
        .expect("the image")
        .expect("FIXTURE: the source keeps the image");
    for entry in &changed {
        assert!(
            image.rows.get(entry).is_some_and(|row| row.body.is_some()),
            "FIXTURE: the image covers the key change and carries its body"
        );
    }

    let adopter_dir = tempfile::tempdir().expect("tempdir");
    let adopter = Vault::open_owned_with(
        adopter_dir.path(),
        hosted_config(&clock),
        OpenOptions::default().adopt_storage_id(VaultStorageId::from_verified_pin(&pin)),
    )
    .expect("the adopting install");
    let adopted = match image.building_pin {
        Some(root) => adopter.adopt_recovered_authority_checkpoint(
            &pin,
            &bundle.image,
            &bundle.attestations,
            pin.digest().expect("the pin's digest"),
            root,
        ),
        None => adopter.adopt_authority_checkpoint(&pin, &bundle.image, &bundle.attestations),
    };
    assert_eq!(
        adopted.expect("the adopting install adopts the source's image"),
        image_id
    );
    let adopter_owner_id = adopter
        .ensure_embedded_owner_actor()
        .expect("the adopter's embedded owner");
    let adopter_owner = adopter
        .authenticate_owner(
            adopter_owner_id,
            &adopter_owner_id.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("the adopter's owner proof");
    let page = adopter
        .authority_audit(&adopter_owner, &whole_audit())
        .expect("the adopter's audit");

    for entry in &changed {
        let entry_ref = authority_log_entity_id_from_hash(entry).expect("the entry's id");
        assert!(
            page.rows.iter().all(|row| row.entry_ref != entry_ref),
            "FIXTURE: the adopter stores no row of the key change"
        );
        let cold = page
            .cold_attested
            .iter()
            .find(|cold| cold.entry_ref == entry_ref)
            .expect("FIXTURE: the adopter's audit lists the key change as a cold row");
        let source_row = stored
            .rows
            .iter()
            .find(|row| row.entry_ref == entry_ref)
            .expect("FIXTURE: the source's audit lists the key change");
        let cold = serde_json::to_value(cold).expect("the cold row as JSON");
        let source_row = serde_json::to_value(source_row).expect("the stored row as JSON");
        let carried = &cold["carried_body"];
        for field in BODY_FIELDS {
            assert_eq!(
                carried[field], source_row[field],
                "the cold row of a key change whose body the adopted image carries names its \
                 {field} as the stored row does: {cold}"
            );
        }
    }

    let adopter_changes = adopter
        .owner_key_changes(&adopter_owner)
        .expect("the adopter's key changes");
    for entry in &changed {
        assert!(
            adopter_changes.iter().any(|change| change.entry == *entry),
            "the adopter's key changes list names the key change its audit names"
        );
    }
}
