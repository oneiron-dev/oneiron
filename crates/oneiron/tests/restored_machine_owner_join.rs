//! Row RESTORED-COPIES-ENROL-EACH-OTHER, PR 2 (P1; Setting DESIGN pass 15e
//! "Joined", the second way; RULING RESTORED-COPIES-JOIN-SCOPE = A): when no
//! machine of the vault that has joined is left to pair a copy restored from
//! a checkpoint image, the owner's word that no other machine is left joins
//! it. The word is an owner act, proved like any other: a key the vault
//! trusts as the owner's, held on the copy, signs it. It joins the one copy
//! it names, and nothing is written when no such key is held.
//!
//! On PR 1 (173a5cece9d3) a restored copy with no joined machine left can
//! never join: the root's bootstrap arm refuses it and nothing carries for it.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test restored_machine_owner_join`.

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

/// The copy holds the vault's root as its owner key: the escrowed root seed
/// the owner restored with.
fn hold_owner_key(copy: &Copy) {
    copy.vault
        .hold_checkpoint_root_signer(Arc::new(test_host_issuer()));
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

#[test]
fn the_owners_word_joins_a_restored_copy_when_no_machine_is_left() {
    let host = rooted_host();
    let backups = oneiron::test_support::restore_tempdir();
    let copies = copies_of_one_image(&host, backups.path(), &["a"]);
    let a = &copies[0];
    // The owner lost the host: no joined machine is left to pair the copy.
    let issuer = host.issuer;
    drop(host.vault);
    hold_owner_key(a);

    a.vault
        .join_restored_install(&issuer, &a.proof, MachineRole::Unanswered)
        .expect("the owner's word, proved by his key, joins the restored copy");
    assert!(
        stands(&a.vault, a.request.machine),
        "the copy reads itself joined"
    );

    // Joined, it carries the owner's acts as any machine does.
    let (_fresh_dir, fresh) = fresh_install(a.request.vault_id);
    a.vault
        .enroll_machine(&a.proof, ActSurface::ThisInstall, &fresh, YOURS, None)
        .expect("the joined copy pairs a new install");
    assert!(stands(&a.vault, fresh.machine), "the new install joined");

    // A second word changes nothing.
    a.vault
        .join_restored_install(&issuer, &a.proof, MachineRole::Unanswered)
        .expect("a second word over a joined copy is a no-op");
    assert!(stands(&a.vault, a.request.machine), "the copy stays joined");
}

#[test]
fn the_owners_word_needs_an_owner_key_held_on_the_copy() {
    let host = rooted_host();
    let backups = oneiron::test_support::restore_tempdir();
    let copies = copies_of_one_image(&host, backups.path(), &["b"]);
    let b = &copies[0];

    // The recovery credential opened the image; it proves nobody's will.
    assert!(
        b.vault
            .join_restored_install(&host.issuer, &b.proof, MachineRole::Unanswered)
            .is_err(),
        "with no owner key held, the owner's word must not join the copy"
    );
    assert!(
        !stands(&b.vault, b.request.machine),
        "the copy stays unjoined"
    );
    assert!(
        b.vault
            .authority_fold()
            .expect("the fold")
            .restored_enrolments()
            .is_empty(),
        "a refused word files no enrolment"
    );
}

#[test]
fn the_owners_word_joins_only_the_copy_it_names() {
    let host = rooted_host();
    let backups = oneiron::test_support::restore_tempdir();
    let copies = copies_of_one_image(&host, backups.path(), &["a", "c"]);
    let (a, c) = (&copies[0], &copies[1]);
    let (issuer, owner) = (host.issuer, host.owner);
    drop(host.vault);

    // Copy c's root-signed enrolment reaches copy a before the word.
    file_restored_enrolment(&c.vault, &issuer, owner, &c.request)
        .expect("FIXTURE: copy c's root-signed enrolment lands");
    sync_authority(&c.vault, &a.vault);
    assert!(!stands(&a.vault, c.request.machine), "c held on a");

    hold_owner_key(a);
    a.vault
        .join_restored_install(&issuer, &a.proof, MachineRole::Unanswered)
        .expect("the owner's word joins copy a");
    assert!(stands(&a.vault, a.request.machine), "copy a joined");
    assert!(
        !stands(&a.vault, c.request.machine),
        "the word names a's enrolment alone: c stays as it was"
    );

    // Copy c reads a's word and stays unjoined there too.
    sync_authority(&a.vault, &c.vault);
    assert!(
        !stands(&c.vault, c.request.machine),
        "a's word must not join c on c"
    );
    assert!(stands(&c.vault, a.request.machine), "c reads a joined");
}
