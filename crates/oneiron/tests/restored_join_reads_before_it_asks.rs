//! [RESTORED-JOIN-DOOR-ASKS-BEFORE-ITS-ALREADY-JOINED-RETURN]
//! The owner's join door for a copy restored from a checkpoint image
//! (`Vault::join_restored_install`) asks for the person only for a join
//! that has work to do. Before the ask it reads every answer the writer
//! gives without the owner's proof:
//!
//! - the machine that already stands live under this install's keys is
//!   returned, and nobody is asked;
//! - a machine that stands any other way (removed), a held enrolment that is
//!   not this install's ask, an owner proof of another vault and the role
//!   `Removed` are refused, and nobody is asked;
//! - an install whose signing seed is gone is still asked: only readying it
//!   can say which machine it is.
//!
//! Each test puts a fresh prompt gate with an empty script on the handle
//! before the call it judges: a prompt past the script is declined, so a
//! door that asked would answer the declined confirm.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test restored_join_reads_before_it_asks`.

#![cfg(oneiron_test_support)]

use std::path::Path;
use std::sync::Arc;

use oneiron::authority::{
    ActSurface, HostSlipIssuer, MachineEnrolmentRequest, MachineOwnership, MachineRole,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::{GateError, OwnerPresenceRefusal, RecordError};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::restored_enrolment::file_restored_enrolment;
use oneiron::test_support::{
    bind_host_owner, provision_engine_machines, restore_tempdir, test_host_issuer,
};
use oneiron::{EntityId, Error, Vault, VaultConfig};
use oneiron_keystore::{
    ManualPresenceClock, MemoryKeystore, PresenceError, PresenceGate, PresenceWindow,
    ScriptedPresence,
};

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
    vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
    let issuer = provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("the host install profile");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    bind_host_owner(&vault, &issuer, owner).expect("the owner binding");
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

/// An owner proof on `vault` for `person`, with no credential bound to it.
fn owner_proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(
            person,
            &person.to_hex(),
            true,
            GateDecisionId::from_bytes([2; 16]),
        )
        .expect("FIXTURE: an owner proof")
}

/// One copy restored from the host's image, with its own keystore, owner
/// proof and enrolment request, holding the vault's root as its owner key:
/// the escrowed root seed the owner restored with. Making the request
/// readies the copy's identity, so its keys are held from here on.
struct Copy {
    vault: Vault,
    proof: AuthenticatedOwner,
    request: MachineEnrolmentRequest,
    keystore: Arc<MemoryKeystore>,
}

/// One copy restored beside `host` from a checkpoint image, under `backups`.
fn restored_copy(host: &Host, backups: &Path) -> Copy {
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
        &backups.join("copy"),
        VaultConfig::device(),
        &origin,
        200,
    )
    .expect("FIXTURE: a copy of the image");
    let keystore = Arc::new(MemoryKeystore::default());
    vault.install_device_keystore(keystore.clone());
    vault.hold_checkpoint_root_signer(Arc::new(test_host_issuer()));
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the owner on the copy");
    let proof = owner_proof(&vault, owner);
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
        keystore,
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

/// Puts a fresh prompt gate on the handle and returns the device that counts prompts.
fn scripted_gate(
    vault: &Vault,
    answers: impl IntoIterator<Item = Result<(), PresenceError>>,
) -> Arc<ScriptedPresence> {
    let presence = Arc::new(ScriptedPresence::new(answers));
    let window = PresenceWindow::new(ManualPresenceClock::new(1_000_000, 1_000_000));
    let gate = PresenceGate::new(presence.clone(), window);
    vault.install_presence_gate(Arc::new(gate));
    presence
}

/// The owner's word joins `copy` under a gate that confirms once, and the
/// door asked exactly once: the control for every "asks nobody" below.
fn join_with_one_confirm(copy: &Copy, issuer: &HostSlipIssuer) {
    let presence = scripted_gate(&copy.vault, [Ok(())]);
    copy.vault
        .join_restored_install(issuer, &copy.proof, MachineRole::Unanswered)
        .expect("CONTROL: the owner's word joins the copy");
    assert_eq!(
        presence.prompts(),
        1,
        "CONTROL: a join with work to do asks for the person once"
    );
    assert!(
        stands(&copy.vault, copy.request.machine),
        "CONTROL: the copy joined"
    );
}

/// The words of an authority refusal, or a panic naming what came instead.
fn authority_refusal<T: std::fmt::Debug>(answer: &oneiron::Result<T>, what: &str) -> &'static str {
    match answer {
        Err(Error::Record(RecordError::AuthorityRefused(reason))) => *reason,
        other => panic!("{what}: expected an authority refusal, got {other:?}"),
    }
}

/// This install's machine under the keystore that is on the handle now.
fn machine(vault: &Vault) -> EntityId {
    vault
        .prepare_install_signing()
        .expect("this install's machine")
}

/// Drops the loaded install signing keys and leaves no seed in their slot.
fn install_empty_keystore(vault: &Vault) {
    vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
}

/// Reads the machine by readying the keys after its own keystore is back on the handle.
fn machine_under_own_keystore(copy: &Copy) -> EntityId {
    copy.vault.install_device_keystore(copy.keystore.clone());
    machine(&copy.vault)
}

/// A second join of an install that already joined returns its machine and
/// asks nobody: there is nothing to authorize.
#[test]
fn a_second_join_of_a_joined_install_returns_its_machine_and_asks_nobody() {
    let host = rooted_host();
    let backups = restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    let issuer = host.issuer;
    drop(host.vault);
    join_with_one_confirm(&copy, &issuer);
    let standing = copy
        .vault
        .authority_fold()
        .expect("the fold")
        .machine(copy.request.machine)
        .cloned()
        .expect("the joined machine");

    let presence = scripted_gate(&copy.vault, []);
    let again = copy
        .vault
        .join_restored_install(&issuer, &copy.proof, MachineRole::Unanswered)
        .expect("a second join of a joined install returns the machine that stands");
    assert_eq!(
        presence.prompts(),
        0,
        "a join with nothing to authorize asked for the person"
    );
    assert_eq!(again, standing, "the door returns the machine as it stands");
}

/// A copy the owner joined and then removed is refused on the door's read:
/// a removed machine never comes back, and nobody is asked to confirm a
/// join that cannot happen.
#[test]
fn a_removed_copy_is_refused_on_the_read_and_asks_nobody() {
    let host = rooted_host();
    let backups = restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    let issuer = host.issuer;
    drop(host.vault);
    join_with_one_confirm(&copy, &issuer);
    // The removal is an owner act of its own; its gate confirms.
    scripted_gate(&copy.vault, [Ok(()), Ok(())]);
    copy.vault
        .set_machine_role(
            &copy.proof,
            ActSurface::ThisInstall,
            copy.request.machine,
            MachineRole::Removed,
            None,
        )
        .expect("FIXTURE: the owner removes the copy");
    assert!(
        !stands(&copy.vault, copy.request.machine),
        "FIXTURE: the copy is removed"
    );

    let presence = scripted_gate(&copy.vault, []);
    let refused = copy
        .vault
        .join_restored_install(&issuer, &copy.proof, MachineRole::Unanswered);
    let reason = authority_refusal(&refused, "a join of a removed copy");
    assert!(
        reason.contains("not live under this install's keys"),
        "the refusal names the machine that stands but not live: {reason}"
    );
    assert_eq!(
        presence.prompts(),
        0,
        "a join the read refuses asked for the person"
    );
    assert!(
        !stands(&copy.vault, copy.request.machine),
        "a removed machine never comes back"
    );
}

/// An enrolment the vault holds for this install's machine that is not this
/// install's ask is refused on the door's read, and nobody is asked. The
/// word that is this install's ask then joins it, and asks once.
#[test]
fn a_held_enrolment_that_is_not_this_ask_is_refused_on_the_read_and_asks_nobody() {
    let host = rooted_host();
    let backups = restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    let (issuer, owner) = (host.issuer, host.owner);
    drop(host.vault);
    // The vault holds an unanswered enrolment of this install's machine.
    file_restored_enrolment(&copy.vault, &issuer, owner, &copy.request)
        .expect("FIXTURE: a held enrolment of the copy");
    assert!(
        !stands(&copy.vault, copy.request.machine),
        "FIXTURE: the enrolment is held"
    );

    // The owner names another role than the held enrolment's.
    let presence = scripted_gate(&copy.vault, []);
    let refused = copy
        .vault
        .join_restored_install(&issuer, &copy.proof, YOURS);
    let reason = authority_refusal(&refused, "a join in another role than the held enrolment's");
    assert!(
        reason.contains("holds an enrolment of this install's machine"),
        "the refusal names the held enrolment that differs: {reason}"
    );
    assert_eq!(
        presence.prompts(),
        0,
        "a join the read refuses asked for the person"
    );
    assert!(
        !stands(&copy.vault, copy.request.machine),
        "the held enrolment stays held"
    );

    join_with_one_confirm(&copy, &issuer);
}

/// An owner proof of another vault is refused on the door's read and never
/// raises the prompt.
#[test]
fn an_owner_proof_of_another_vault_is_refused_on_the_read_and_asks_nobody() {
    let host = rooted_host();
    let other = rooted_host();
    let foreign = owner_proof(&other.vault, other.owner);
    let backups = restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    let issuer = host.issuer;
    drop(host.vault);

    let presence = scripted_gate(&copy.vault, []);
    let refused = copy
        .vault
        .join_restored_install(&issuer, &foreign, MachineRole::Unanswered);
    assert!(
        matches!(
            refused,
            Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(_)))
        ),
        "another vault's owner proof is refused as no owner of this vault: {refused:?}"
    );
    assert_eq!(
        presence.prompts(),
        0,
        "another vault's owner proof raised the prompt"
    );
    assert!(
        !stands(&copy.vault, copy.request.machine),
        "the copy stays unjoined"
    );

    join_with_one_confirm(&copy, &issuer);
}

/// A join that names the role `Removed` is refused before the ask, and
/// before this install's identity is readied: under an empty keystore the
/// readying would forget the install's machine.
#[test]
fn a_join_in_the_removed_role_is_refused_before_the_ask_and_readies_nothing() {
    let host = rooted_host();
    let backups = restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    let issuer = host.issuer;
    drop(host.vault);

    let before = machine(&copy.vault);
    install_empty_keystore(&copy.vault);
    let presence = scripted_gate(&copy.vault, []);
    let refused = copy
        .vault
        .join_restored_install(&issuer, &copy.proof, MachineRole::Removed);
    assert!(
        matches!(
            refused,
            Err(Error::Record(RecordError::InvalidAuthorityLogBody(_)))
        ),
        "the role `Removed` joins nothing: {refused:?}"
    );
    assert_eq!(
        presence.prompts(),
        0,
        "a join in the role `Removed` asked for the person"
    );
    assert_eq!(
        machine_under_own_keystore(&copy),
        before,
        "a refused join readied the signing keys and replaced the machine"
    );

    join_with_one_confirm(&copy, &issuer);
}

/// A joined install whose signing seed is gone is still asked: the read
/// returns the standing machine only to an install that holds its keys, and
/// only readying this one can say which machine it is.
#[test]
fn a_joined_install_that_lost_its_signing_seed_is_still_asked() {
    let host = rooted_host();
    let backups = restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    let issuer = host.issuer;
    drop(host.vault);
    join_with_one_confirm(&copy, &issuer);

    let before = machine(&copy.vault);
    install_empty_keystore(&copy.vault);
    let presence = scripted_gate(&copy.vault, [Err(PresenceError::Declined)]);
    let refused = copy
        .vault
        .join_restored_install(&issuer, &copy.proof, MachineRole::Unanswered);
    assert!(
        matches!(
            refused,
            Err(Error::Record(RecordError::OwnerPresenceRequired {
                here: OwnerPresenceRefusal::Declined
            }))
        ),
        "an install that does not hold the standing machine's keys is asked, and the declined \
         confirm refuses: {refused:?}"
    );
    assert_eq!(
        presence.prompts(),
        1,
        "the door did not ask an install whose signing seed is gone"
    );
    assert_eq!(
        machine_under_own_keystore(&copy),
        before,
        "a declined confirm readied the signing keys and replaced the machine"
    );
}
