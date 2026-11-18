//! Row RESTORED-COPIES-ENROL-EACH-OTHER, round 1 of the blind review of
//! stack #9512 (REVIEW-9509 and REVIEW-9511 P1s): the doors around a copy
//! restored from a checkpoint image.
//!
//! - A joined machine pairs a copy whose root-signed enrolment it already
//!   holds: the answer is numbered above the held revision, so the fold that
//!   lays the held chain under it takes it. Before, the answer took revision
//!   1, equal to the held head, and the fold refused it.
//! - A copy that has not joined refuses at the serving-profile door before
//!   any identity is minted: no machine id is written. Before, the door
//!   minted the id and then refused.
//! - A copy that has not joined pairs no machine through a link it issued:
//!   the root's bootstrap arm serves a fresh first install, never a copy.
//!   Before, the copy's root enrolled the redeeming machine.
//! - A managed vault's restore marks no copy (RESTORED-COPIES-JOIN-SCOPE =
//!   A: its host root enrols the node its restores land); an owner-rooted
//!   vault's restore of the same image does. Before, every restore that kept
//!   the image's custody marked the copy.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test restored_machine_join_guards`.

#![cfg(oneiron_test_support)]

use std::path::Path;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActSurface, HostSlipIssuer, MachineEnrolmentRequest, MachineOwnership, MachineRole,
    PairingPrincipal, pairing_binding_transcript_pinned,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::Scope;
use oneiron::recovery::checkpoint::RestoreReason;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::restored_enrolment::file_restored_enrolment;
use oneiron::test_support::test_host_issuer;
use oneiron::{EntityId, HostingPrivacyPosture, Vault, VaultConfig};

const YOURS: MachineRole = MachineRole::Owned(MachineOwnership::Yours);
/// The seed of the connection key a redeemed pairing link binds.
const CONNECTION_SEED: u8 = 91;

fn signing(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// The vault's first install: rooted, with its owner bound and its own
/// unanswered serving profile. It never restored, so it is joined.
struct Host {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    proof: AuthenticatedOwner,
    vault_id: [u8; 32],
}

fn rooted_host() -> Host {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the host install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("the host install profile");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner binding");
    // The host holds the vault's root as its owner key, as a serving host
    // does, so its "yours" answers are proved (row CARRIER-OWNER-PROOF).
    vault.hold_checkpoint_root_signer(Arc::new(test_host_issuer()));
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

/// Copies restored beside `host` from ONE checkpoint image, one per name,
/// under `backups`: each with its own keystore and the root seed it was
/// restored with, and no identity minted yet.
fn restored_copies(host: &Host, backups: &Path, names: &[&str]) -> Vec<Vault> {
    let image = backups.join("image");
    host.vault
        .snapshot_checkpoint(&image, 100)
        .expect("FIXTURE: the shared image");
    let key = host.vault.checkpoint_key().expect("FIXTURE: its key");
    let origin = host
        .vault
        .side_restore_source()
        .expect("FIXTURE: the beside restore source");
    names
        .iter()
        .map(|name| {
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
            vault
        })
        .collect()
}

/// A restored copy with its owner proof and enrolment request.
struct Copy {
    vault: Vault,
    proof: AuthenticatedOwner,
    request: MachineEnrolmentRequest,
}

fn with_request(host: &Host, vault: Vault) -> Copy {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the owner on the copy");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: an owner proof on the copy");
    let key = vault
        .machine_encryption_key(host.vault_id)
        .expect("FIXTURE: the copy's encryption key");
    let request = vault
        .machine_enrolment_request(host.vault_id, key)
        .expect("FIXTURE: the copy's enrolment request");
    Copy {
        vault,
        proof,
        request,
    }
}

/// A fresh install asking to join `vault_id`: never restored.
fn fresh_install(vault_id: [u8; 32]) -> (tempfile::TempDir, MachineEnrolmentRequest) {
    let dir = tempfile::tempdir().expect("tempdir");
    let install =
        Vault::open(dir.path(), VaultConfig::default()).expect("FIXTURE: a fresh install");
    install.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let key = install
        .machine_encryption_key(vault_id)
        .expect("FIXTURE: its encryption key");
    let request = install
        .machine_enrolment_request(vault_id, key)
        .expect("FIXTURE: its enrolment request");
    (dir, request)
}

/// Every authority row `from` holds, landed on `to`.
fn sync_authority(from: &Vault, to: &Vault) {
    let history = from
        .export_signed_authority_history()
        .expect("FIXTURE: export authority history");
    to.import_signed_authority_history(&history)
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

/// What `vault` would name as its origin in an enrolment request.
fn origin_named(vault: &Vault, vault_id: [u8; 32]) -> Option<[u8; 32]> {
    let key = vault
        .machine_encryption_key(vault_id)
        .expect("FIXTURE: the restored vault's encryption key");
    vault
        .machine_enrolment_request(vault_id, key)
        .expect("FIXTURE: the restored vault's enrolment request")
        .restored_from
}

#[test]
fn a_joined_machine_pairs_a_copy_whose_held_enrolment_it_holds() {
    let host = rooted_host();
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copies(&host, backups.path(), &["a"])
        .pop()
        .map(|vault| with_request(&host, vault))
        .expect("FIXTURE: copy a");
    file_restored_enrolment(&copy.vault, &host.issuer, host.owner, &copy.request)
        .expect("FIXTURE: the copy's root-signed enrolment lands");
    sync_authority(&copy.vault, &host.vault);
    assert!(
        !stands(&host.vault, copy.request.machine),
        "FIXTURE: the host holds the copy's enrolment, not yet joined"
    );

    host.vault
        .enroll_machine(
            &host.proof,
            ActSurface::ThisInstall,
            &copy.request,
            YOURS,
            None,
        )
        .expect("the host, a joined machine, pairs a copy whose enrolment it holds");
    assert!(
        stands(&host.vault, copy.request.machine),
        "the paired copy stands on the host"
    );
}

#[test]
fn an_unjoined_copy_refuses_before_it_mints_an_identity() {
    let host = rooted_host();
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copies(&host, backups.path(), &["d"])
        .pop()
        .expect("FIXTURE: copy d");
    assert!(
        copy.local_machine()
            .expect("FIXTURE: the copy's machine")
            .is_none(),
        "FIXTURE: a restore drops the image's machine identity"
    );

    assert!(
        copy.ensure_serving_install_profile(&host.issuer, MachineRole::Unanswered)
            .is_err(),
        "a restored copy must not enrol itself through the root's bootstrap arm"
    );
    assert!(
        copy.local_machine().expect("the copy's machine").is_none(),
        "the refused door must mint no machine identity"
    );
}

#[test]
fn an_unjoined_copy_pairs_no_machine_through_its_root() {
    let host = rooted_host();
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copies(&host, backups.path(), &["b"])
        .pop()
        .map(|vault| with_request(&host, vault))
        .expect("FIXTURE: copy b");
    let link = copy
        .vault
        .issue_machine_pairing_link(
            &host.issuer,
            &copy.proof,
            ActSurface::ThisInstall,
            Scope::top(),
            3600,
            PairingPrincipal::default(),
            MachineOwnership::Yours,
        )
        .expect("FIXTURE: the owner makes a machine pairing link on the copy");
    let (_fresh_dir, fresh) = fresh_install(host.vault_id);
    let holder = fresh.machine.to_hex();
    let connection = signing(CONNECTION_SEED);
    let binding_key = connection.verifying_key().to_bytes();
    let binding_transcript =
        pairing_binding_transcript_pinned(&link.code, &binding_key, &holder, link.pin.as_ref())
            .expect("FIXTURE: the binding transcript");
    let binding = connection.sign(&binding_transcript).to_bytes();

    let redeemed = copy.vault.redeem_pairing_link_with_possession(
        &host.issuer,
        &link.code,
        &holder,
        binding_key,
        &binding,
        Some(&fresh),
        None,
    );
    assert!(
        redeemed.is_err(),
        "a copy that has not joined must pair no machine through its root"
    );
    assert!(
        !stands(&copy.vault, fresh.machine),
        "no machine the copy's root enrolled stands"
    );
}

#[test]
fn a_managed_vaults_restore_marks_no_copy() {
    let host = rooted_host();
    let backups = oneiron::test_support::restore_tempdir();
    let image = backups.path().join("image");
    host.vault
        .snapshot_checkpoint(&image, 100)
        .expect("FIXTURE: the image");
    let key = host.vault.checkpoint_key().expect("FIXTURE: its key");
    let restore = |name: &str, posture: HostingPrivacyPosture| {
        let mut config = VaultConfig::device();
        config.privacy.posture = posture;
        let (vault, _) = Vault::restore_checkpoint(
            &image,
            &key,
            &backups.path().join(name),
            config,
            RestoreReason::Restore,
            200,
        )
        .expect("FIXTURE: a restore of the image");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        vault
    };

    let managed = restore("managed", HostingPrivacyPosture::Hosted);
    assert_eq!(
        origin_named(&managed, host.vault_id),
        None,
        "a managed vault's restore must not mark its node as born of a restore"
    );
    let owned = restore("owned", HostingPrivacyPosture::SelfHostLocal);
    assert!(
        origin_named(&owned, host.vault_id).is_some(),
        "an owner-rooted vault's restore marks its copy"
    );
}
