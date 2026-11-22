//! Row RESTORED-COPIES-R2-TESTS: the round 2 fixes of the blind review of
//! stack #9512 (row RESTORED-COPIES-ENROL-EACH-OTHER), as behaviour.
//!
//! - An owner's pairing link pairs a copy whose enrolment the vault holds:
//!   the redemption carries the owner's answer above the held revision.
//!   Before, it kept the link's pairing act above revision 1, which the fold
//!   refuses (REVIEW-9509/9511 round 2, redeem.rs:492). The same redemption
//!   without the copy's machine key over it is refused: a held enrolment's
//!   logged proof is no fresh evidence (REVIEW-9510 round 2, redeem.rs:469).
//! - A carried "yours" answer over a held "yours" enrolment under the same
//!   keys needs the owner's proof: a held chain never makes its machine read
//!   as already the owner's. Before, a joined carrier with no owner key made
//!   it stand (REVIEW-9509 round 2, restored_join.rs:192).
//! - Two branches that name different origins for one machine leave it
//!   conflicted, whatever their revision numbers. Before, the higher
//!   revision won clean and the restore mark was gone (REVIEW-9509 round 2,
//!   machine_profile/merge.rs:25).
//! - A restore --join the door refuses after its preflight commits nothing,
//!   not even the authority clock reading. Before, its first read was
//!   `authority_fold`, which commits the clock floor before the writer's own
//!   refusals (REVIEW-9524 P1, restored_join_door.rs:126).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test restored_machine_round2_guards`.

#![cfg(oneiron_test_support)]

use std::path::Path;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActSurface, HostSlipIssuer, MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
    MachineAnswerLanding, MachineDeviceClass, MachineEncryptionKey, MachineEnrolmentRequest,
    MachineOwnership, MachineRole, PairingPrincipal, machine_profile_proof_transcript,
    pairing_binding_transcript_pinned, restored_machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::Scope;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::restored_enrolment::{
    authority_clock_floor, file_restored_enrolment, file_restored_enrolment_in_role,
};
use oneiron::test_support::test_host_issuer;
use oneiron::{EntityId, Vault, VaultConfig};

const YOURS: MachineRole = MachineRole::Owned(MachineOwnership::Yours);
/// The seed of the connection key a redeemed pairing link binds.
const CONNECTION_SEED: u8 = 91;
/// The seed of the machine key, and of the id, of the machine two branches
/// answer for.
const TARGET_SEED: u8 = 0x73;

fn signing(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// The vault's first install: rooted, with its owner bound and its own
/// serving profile in `role`. It never restored, so it is joined. With
/// `owner_key`, it holds the vault's root as its owner key, as a serving
/// host does, so its "yours" answers are proved.
struct Host {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    proof: AuthenticatedOwner,
    vault_id: [u8; 32],
}

fn rooted_host(role: MachineRole, owner_key: bool) -> Host {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the host install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, role)
        .expect("the host install profile");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner binding");
    if owner_key {
        vault.hold_checkpoint_root_signer(Arc::new(test_host_issuer()));
    }
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof");
    let vault_id = vault
        .authority_vault_id()
        .expect("the fold")
        .expect("a rooted vault");
    Host {
        _dir: dir,
        vault,
        issuer,
        owner,
        proof,
        vault_id,
    }
}

/// A copy restored beside `host` from a checkpoint image, with its own
/// keystore, the root seed it was restored with, its owner proof and its
/// enrolment request.
struct Copy {
    vault: Vault,
    proof: AuthenticatedOwner,
    request: MachineEnrolmentRequest,
}

fn restored_copy(host: &Host, backups: &Path, name: &str) -> Copy {
    let image = backups.join(format!("{name}.image"));
    host.vault
        .snapshot_checkpoint(&image, 100)
        .expect("FIXTURE: the image");
    let key = host.vault.checkpoint_key().expect("FIXTURE: its key");
    let origin = host
        .vault
        .side_restore_source()
        .expect("FIXTURE: the beside restore source");
    let (vault, _) = Vault::restore_checkpoint_beside(
        &image,
        &key,
        &backups.join(name),
        VaultConfig::device(),
        &origin,
        200,
    )
    .expect("FIXTURE: a copy of the image");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.hold_checkpoint_root_signer(Arc::new(test_host_issuer()));
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the owner on the copy");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: an owner proof on the copy");
    let encryption_key = vault
        .machine_encryption_key(host.vault_id)
        .expect("FIXTURE: the copy's encryption key");
    let request = vault
        .machine_enrolment_request(host.vault_id, encryption_key)
        .expect("FIXTURE: the copy's enrolment request");
    Copy {
        vault,
        proof,
        request,
    }
}

/// Every authority row `from` holds, landed on `to`.
fn sync_authority(from: &Vault, to: &Vault) {
    let history = from
        .export_signed_authority_history()
        .expect("FIXTURE: export authority history");
    to.import_signed_authority_history(&history, &std::collections::BTreeMap::new())
        .expect("FIXTURE: import authority history");
}

/// Whether `machine`'s roster revision stands live on `vault`'s fold.
fn stands(vault: &Vault, machine: EntityId) -> bool {
    vault
        .authority_fold()
        .expect("the fold")
        .machine(machine)
        .and_then(|folded| folded.roster.as_ref())
        .is_some_and(|roster| roster.is_live())
}

/// `copy` redeems a fresh "yours" pairing link of `host` with its own
/// request, and, with `possession`, its machine key's signature over this
/// redemption.
fn redeem_on_host(
    host: &Host,
    copy: &Copy,
    possession: bool,
) -> oneiron::Result<oneiron::authority::PairingRedeemed> {
    let link = host
        .vault
        .issue_machine_pairing_link(
            &host.issuer,
            &host.proof,
            ActSurface::ThisInstall,
            Scope::top(),
            3600,
            PairingPrincipal::default(),
            MachineOwnership::Yours,
        )
        .expect("FIXTURE: the owner makes a machine pairing link on the host");
    let holder = copy.request.machine.to_hex();
    let connection = signing(CONNECTION_SEED);
    let binding_key = connection.verifying_key().to_bytes();
    let binding_transcript =
        pairing_binding_transcript_pinned(&link.code, &binding_key, &holder, link.pin.as_ref())
            .expect("FIXTURE: the binding transcript");
    let binding = connection.sign(&binding_transcript).to_bytes();
    let proof = possession.then(|| {
        copy.vault
            .machine_possession_proof(&copy.request, &binding_transcript)
            .expect("FIXTURE: the copy's machine key signs the redemption")
    });
    host.vault.redeem_pairing_link_with_possession(
        &host.issuer,
        &link.code,
        &holder,
        binding_key,
        &binding,
        Some(&copy.request),
        proof.as_ref(),
    )
}

#[test]
fn an_owned_link_pairs_a_held_copy_with_its_machine_key_only() {
    let host = rooted_host(MachineRole::Unanswered, true);
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path(), "a");
    file_restored_enrolment(&host.vault, &host.issuer, host.owner, &copy.request)
        .expect("FIXTURE: the host holds the copy's root-signed enrolment");
    assert!(
        !stands(&host.vault, copy.request.machine),
        "FIXTURE: the enrolment is held, not joined"
    );

    assert!(
        redeem_on_host(&host, &copy, false).is_err(),
        "a held enrolment's logged proof must not stand in for the machine key"
    );
    assert!(
        !stands(&host.vault, copy.request.machine),
        "the refused redemption pairs nothing"
    );

    redeem_on_host(&host, &copy, true)
        .expect("an owned link pairs a copy whose enrolment the host holds");
    assert!(
        stands(&host.vault, copy.request.machine),
        "the paired copy stands on the host"
    );
}

#[test]
fn a_carried_yours_answer_over_a_held_yours_enrolment_needs_the_owners_proof() {
    // The host carries as one of the owner's own machines, and holds no
    // owner key: its "yours" answers need the owner's proof from elsewhere.
    let host = rooted_host(YOURS, false);
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path(), "e");
    file_restored_enrolment_in_role(&host.vault, &host.issuer, host.owner, &copy.request, YOURS)
        .expect("FIXTURE: the host holds the copy's root-signed yours enrolment");
    assert!(
        !stands(&host.vault, copy.request.machine),
        "FIXTURE: the enrolment is held, not joined"
    );

    let landing = host
        .vault
        .enroll_machine(
            &host.proof,
            ActSurface::ThisInstall,
            &copy.request,
            YOURS,
            None,
        )
        .expect("the carried answer is stored");
    assert!(
        matches!(landing, MachineAnswerLanding::Held { .. }),
        "a held yours enrolment must not make its machine read as already the owner's"
    );
    assert!(
        !stands(&host.vault, copy.request.machine),
        "the answer stands for nothing until the owner proves it"
    );
}

/// The request of the machine from [`TARGET_SEED`], signed by its own key,
/// in `class`, born of `origin` when one is named.
fn target_request(
    vault_id: [u8; 32],
    class: MachineDeviceClass,
    origin: Option<[u8; 32]>,
) -> MachineEnrolmentRequest {
    let machine = EntityId::from_bytes([TARGET_SEED; 16]).expect("FIXTURE: the machine id");
    let key = signing(TARGET_SEED);
    let machine_key = key.verifying_key().to_bytes();
    let encryption_key = MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    };
    let transcript = match &origin {
        Some(image) => restored_machine_profile_proof_transcript(
            &vault_id,
            machine,
            &machine_key,
            class,
            &encryption_key,
            image,
        ),
        None => machine_profile_proof_transcript(
            &vault_id,
            machine,
            &machine_key,
            class,
            &encryption_key,
        ),
    };
    MachineEnrolmentRequest {
        vault_id,
        machine,
        machine_key,
        device_class: class,
        encryption_key,
        machine_proof: key.sign(&transcript).to_bytes(),
        restored_from: origin,
    }
}

#[test]
fn branches_naming_different_origins_leave_the_machine_conflicted() {
    let host = rooted_host(MachineRole::Unanswered, true);
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path(), "g");
    copy.vault
        .join_restored_install(&host.issuer, &copy.proof, MachineRole::Unanswered)
        .expect("FIXTURE: the owner's word joins the copy");
    let origin = copy
        .request
        .restored_from
        .expect("FIXTURE: the copy's origin");

    // On the host's branch the machine stands with no origin, at revision 2
    // (a class revision).
    for class in [MachineDeviceClass::Computer, MachineDeviceClass::Phone] {
        host.vault
            .enroll_machine(
                &host.proof,
                ActSurface::ThisInstall,
                &target_request(host.vault_id, class, None),
                YOURS,
                None,
            )
            .expect("FIXTURE: the host answers for the machine");
    }
    let target = EntityId::from_bytes([TARGET_SEED; 16]).expect("FIXTURE: the machine id");
    let on_host = host
        .vault
        .authority_fold()
        .expect("FIXTURE: the host's fold")
        .machine(target)
        .and_then(|folded| folded.roster.clone())
        .expect("FIXTURE: the machine on the host");
    assert!(
        on_host.is_live()
            && on_host.profile.revision == 2
            && on_host.profile.restored_from.is_none(),
        "FIXTURE: revision 2, no origin, on the host's branch"
    );
    // On the copy's branch the same machine, under the same keys and role,
    // stands at revision 1, born of the copy's image.
    copy.vault
        .enroll_machine(
            &copy.proof,
            ActSurface::ThisInstall,
            &target_request(host.vault_id, MachineDeviceClass::Computer, Some(origin)),
            YOURS,
            None,
        )
        .expect("FIXTURE: the joined copy answers for the machine");
    assert!(
        stands(&copy.vault, target),
        "FIXTURE: the machine stands on the copy's branch"
    );

    sync_authority(&copy.vault, &host.vault);
    let merged = host
        .vault
        .authority_fold()
        .expect("the host's fold")
        .machine(target)
        .and_then(|folded| folded.roster.clone())
        .expect("the machine on the host");
    assert!(
        merged.conflicted && !merged.is_live(),
        "branches that name different origins leave the machine conflicted, \
         whatever their revisions (head revision {}, origin {:?})",
        merged.profile.revision,
        merged.profile.restored_from
    );
}

#[test]
fn a_refused_join_commits_no_clock_reading() {
    let host = rooted_host(MachineRole::Unanswered, true);
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path(), "c");
    // The host holds the copy's enrolment as a "yours" answer, so an
    // unanswered join of it is not this install's ask: the writer refuses
    // it after the preflight passed.
    file_restored_enrolment_in_role(&host.vault, &host.issuer, host.owner, &copy.request, YOURS)
        .expect("FIXTURE: the host holds the copy's root-signed yours enrolment");
    sync_authority(&host.vault, &copy.vault);
    // The copy's clock observes once, then the wall clock moves past the
    // floor that stored.
    copy.vault
        .authority_fold()
        .expect("FIXTURE: the copy's fold");
    std::thread::sleep(std::time::Duration::from_millis(1_500));
    let before = authority_clock_floor(&copy.vault).expect("FIXTURE: the copy's clock floor");
    assert!(before.is_some(), "FIXTURE: the copy's clock has a floor");

    let refused =
        copy.vault
            .join_restored_install(&host.issuer, &copy.proof, MachineRole::Unanswered);
    assert!(
        refused.is_err(),
        "an enrolment that is not this install's ask refuses the join"
    );
    assert_eq!(
        authority_clock_floor(&copy.vault).expect("the copy's clock floor"),
        before,
        "a refused join commits no clock reading"
    );
}
