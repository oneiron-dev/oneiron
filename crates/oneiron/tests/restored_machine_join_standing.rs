//! Row RESTORED-COPIES-ENROL-EACH-OTHER (P1; Setting DESIGN pass 15e "Joined",
//! RULING SETTING-UNTANGLE = A; scope RULING RESTORED-COPIES-JOIN-SCOPE = A):
//! a copy restored from a checkpoint image is not a machine of the vault until
//! a machine that has joined joins it. Two copies of one image never join each
//! other: neither enrols on the root's bootstrap arm, neither carries the
//! owner's act for the other, and a root-signed enrolment of either stands
//! for nothing until an entry signed by a joined machine descends from it.
//! A joined machine's entry joins exactly the enrolments among its ancestors.
//!
//! On main both copies enrol themselves through the root's bootstrap arm and
//! carry for each other.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test restored_machine_join_standing`.

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

/// One copy restored from the shared image, with its own keystore, owner
/// proof and enrolment request.
struct Copy {
    vault: Vault,
    proof: AuthenticatedOwner,
    request: MachineEnrolmentRequest,
}

/// Copies restored beside `host` from ONE checkpoint image, one per name,
/// under `backups`.
fn copies_of_one_image(host: &Host, backups: &Path, names: &[&str]) -> Vec<Copy> {
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
            // Each copy holds the root seed it was restored with, as the
            // owner key that proves his "yours" answers once it has joined.
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
        })
        .collect()
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

#[test]
fn two_copies_of_one_image_never_join_each_other() {
    let host = rooted_host();
    let backups = oneiron::test_support::restore_tempdir();
    let copies = copies_of_one_image(&host, backups.path(), &["a", "b"]);
    let (a, b) = (&copies[0], &copies[1]);

    // Neither copy enrols itself on the root's bootstrap arm, though each
    // holds the vault's root.
    for copy in &copies {
        assert!(
            copy.vault
                .ensure_serving_install_profile(&host.issuer, MachineRole::Unanswered)
                .is_err(),
            "a restored copy must not enrol itself through the root's bootstrap arm"
        );
        assert!(
            !stands(&copy.vault, copy.request.machine),
            "a restored copy that has not joined must not stand"
        );
    }
    sync_authority(&a.vault, &b.vault);
    sync_authority(&b.vault, &a.vault);

    // Neither carries the owner's act for the other.
    assert!(
        a.vault
            .enroll_machine(&a.proof, ActSurface::ThisInstall, &b.request, YOURS, None)
            .is_err(),
        "a copy that has not joined must not carry the owner's act for its sibling"
    );
    for copy in &copies {
        for other in &copies {
            assert!(
                !stands(&copy.vault, other.request.machine),
                "no copy stands on any copy's fold"
            );
        }
    }

    // A joined machine pairs one copy; that copy, joined, carries for the other.
    host.vault
        .enroll_machine(
            &host.proof,
            ActSurface::ThisInstall,
            &a.request,
            YOURS,
            None,
        )
        .expect("the host, a joined machine, pairs copy a");
    assert!(stands(&host.vault, a.request.machine), "copy a joined");
    sync_authority(&host.vault, &a.vault);
    assert!(
        stands(&a.vault, a.request.machine),
        "copy a reads itself joined"
    );
    a.vault
        .enroll_machine(&a.proof, ActSurface::ThisInstall, &b.request, YOURS, None)
        .expect("copy a, joined, pairs copy b");
    assert!(
        stands(&a.vault, b.request.machine),
        "copy b joined through a"
    );
}

#[test]
fn a_root_signed_enrolment_joins_only_through_a_joined_machines_entry() {
    let host = rooted_host();
    let backups = oneiron::test_support::restore_tempdir();
    let copies = copies_of_one_image(&host, backups.path(), &["a", "c"]);
    let (a, c) = (&copies[0], &copies[1]);

    // Each copy's own root-signed enrolment: no door writes one, so the
    // test door signs it under the root each copy holds.
    for copy in &copies {
        file_restored_enrolment(&copy.vault, &host.issuer, host.owner, &copy.request)
            .expect("FIXTURE: the copy's root-signed enrolment lands");
        assert!(
            !stands(&copy.vault, copy.request.machine),
            "a restored copy's root-signed enrolment must stand for nothing"
        );
    }
    sync_authority(&a.vault, &c.vault);
    sync_authority(&c.vault, &a.vault);
    for copy in &copies {
        for other in &copies {
            assert!(
                !stands(&copy.vault, other.request.machine),
                "two copies holding each other's enrolments must not join each other"
            );
        }
    }

    // The host takes copy a's enrolment, then carries an act of its own: the
    // act descends from a's enrolment and joins it.
    sync_authority(&a.vault, &host.vault);
    assert!(
        !stands(&host.vault, a.request.machine),
        "the host holds a's enrolment, not yet joined"
    );
    let (_fresh_dir, fresh) = fresh_install(host.vault_id);
    host.vault
        .enroll_machine(&host.proof, ActSurface::ThisInstall, &fresh, YOURS, None)
        .expect("the host carries an act of its own");
    assert!(
        stands(&host.vault, a.request.machine),
        "a joined machine's entry after a's enrolment joins it"
    );

    // Copy c's enrolment reaches the host after that act: no joined
    // machine's entry descends from it, so it stays as it was.
    sync_authority(&c.vault, &host.vault);
    assert!(
        !stands(&host.vault, c.request.machine),
        "a's join must not join c, whose enrolment the act never saw"
    );
    assert!(stands(&host.vault, a.request.machine), "a stays joined");

    // Copy a reads the join, and stands as any machine does.
    sync_authority(&host.vault, &a.vault);
    assert!(
        stands(&a.vault, a.request.machine),
        "copy a reads itself joined"
    );
    a.vault
        .ensure_serving_install_profile(&host.issuer, MachineRole::Unanswered)
        .expect("a joined copy's profile stands");
}
