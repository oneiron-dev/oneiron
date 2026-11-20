//! Row RESTORED-COPIES-ENROL-EACH-OTHER, PR 2, round 1 of the blind review
//! of stack #9512 (REVIEW-9510 and REVIEW-9511 P1s): the owner's join door
//! for a copy restored from a checkpoint image.
//!
//! - A copy the owner joined and then removed is never joined again: the
//!   door's no-op answers only for a machine that stands live under this
//!   install's keys. Before, the door returned the removed machine as a
//!   success.
//! - An enrolment the vault holds for this install's machine is joined only
//!   when it is this install's ask: its keys, class, origin, owner and the
//!   role the owner names. Before, the door joined whatever enrolment named
//!   the machine.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test restored_machine_owner_join_guards`.

#![cfg(oneiron_test_support)]

use std::path::Path;
use std::sync::Arc;

use oneiron::authority::{
    ActSurface, HostSlipIssuer, MachineEnrolmentRequest, MachineOwnership, MachineRole,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::restored_enrolment::file_restored_enrolment;
use oneiron::test_support::test_host_issuer;
use oneiron::{EntityId, Vault, VaultConfig};

const YOURS: MachineRole = MachineRole::Owned(MachineOwnership::Yours);

/// The vault's first install: rooted, with its owner bound and its own
/// unanswered serving profile. Its owner loses it once the image is taken.
struct Host {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
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
    let vault_id = vault
        .authority_vault_id()
        .expect("the fold")
        .expect("a rooted vault");
    Host {
        _dir: dir,
        vault,
        issuer,
        owner,
        vault_id,
    }
}

/// One copy restored from the shared image, with its own keystore, owner
/// proof and enrolment request, holding the vault's root as its owner key:
/// the escrowed root seed the owner restored with.
struct Copy {
    vault: Vault,
    proof: AuthenticatedOwner,
    request: MachineEnrolmentRequest,
}

/// One copy restored beside `host` from a checkpoint image, under `backups`.
fn restored_copy(host: &Host, backups: &Path, name: &str) -> Copy {
    let image = backups.join("image");
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

/// Whether `machine`'s roster revision stands live on `vault`'s fold.
fn stands(vault: &Vault, machine: EntityId) -> bool {
    vault
        .authority_fold()
        .expect("the fold")
        .machine(machine)
        .and_then(|folded| folded.roster.as_ref())
        .is_some_and(|roster| roster.is_live())
}

#[test]
fn a_removed_copy_is_never_joined_again() {
    let host = rooted_host();
    let backups = oneiron::test_support::restore_tempdir();
    let a = restored_copy(&host, backups.path(), "a");
    let issuer = host.issuer;
    drop(host.vault);

    a.vault
        .join_restored_install(&issuer, &a.proof, MachineRole::Unanswered)
        .expect("FIXTURE: the owner's word joins the copy");
    assert!(
        stands(&a.vault, a.request.machine),
        "FIXTURE: copy a joined"
    );
    a.vault
        .set_machine_role(
            &a.proof,
            ActSurface::ThisInstall,
            a.request.machine,
            MachineRole::Removed,
            None,
        )
        .expect("FIXTURE: the owner removes copy a");
    assert!(
        !stands(&a.vault, a.request.machine),
        "FIXTURE: copy a removed"
    );

    assert!(
        a.vault
            .join_restored_install(&issuer, &a.proof, MachineRole::Unanswered)
            .is_err(),
        "the join door must not report a removed copy as joined"
    );
    assert!(
        !stands(&a.vault, a.request.machine),
        "a removed machine never comes back"
    );
}

#[test]
fn a_held_enrolment_that_is_not_this_ask_is_not_joined() {
    let host = rooted_host();
    let backups = oneiron::test_support::restore_tempdir();
    let a = restored_copy(&host, backups.path(), "a");
    let (issuer, owner) = (host.issuer, host.owner);
    drop(host.vault);
    // The vault holds an unanswered enrolment of this install's machine.
    file_restored_enrolment(&a.vault, &issuer, owner, &a.request)
        .expect("FIXTURE: a held enrolment of copy a");
    assert!(
        !stands(&a.vault, a.request.machine),
        "FIXTURE: the enrolment is held"
    );

    // The owner names another role than the held enrolment's.
    assert!(
        a.vault
            .join_restored_install(&issuer, &a.proof, YOURS)
            .is_err(),
        "the owner's word must not join an enrolment that is not this install's ask"
    );
    assert!(
        !stands(&a.vault, a.request.machine),
        "the held enrolment stays held"
    );

    // Guard: the word that is this install's ask joins it.
    a.vault
        .join_restored_install(&issuer, &a.proof, MachineRole::Unanswered)
        .expect("the owner's word joins the held enrolment it matches");
    assert!(
        stands(&a.vault, a.request.machine),
        "copy a joined on its held enrolment"
    );
}
