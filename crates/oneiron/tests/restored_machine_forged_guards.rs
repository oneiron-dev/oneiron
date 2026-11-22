//! Row RESTORED-COPIES-R2-TESTS, part 2: the fixes of stack #9512's review
//! rounds that only a hand-signed row reaches, as behaviour. Most cases lay a
//! row below its signer's sequence floor: the same signer signs a sibling of
//! a higher sequence that does not descend from it (`rows_floor`), so the
//! row lands restriction only. The rows come from the door
//! `test_doors::restored_enrolment::forged_rows`; no public writer signs
//! below its own next sequence or over parents it picks.
//!
//! - The root's enrolment of a machine born of a restore is the entry the
//!   writer returns, beside unpinned anchors' marks of the machine. Before, it
//!   returned the first held enrolment of the machine by hash, and the owner's
//!   join door then named a mark (REVIEW-9539 P1, machine_answers.rs:472; fix
//!   #9534 3051bfa4). Red at 815730df, each machine with odds 3 in 4.
//! - An unpinned anchor's mark of a machine, under other keys, refuses no
//!   genuine pairing of it. Before, the pairing read every held enrolment
//!   and refused (REVIEW-9509 round 2 P1, machine_answers.rs:168; fix
//!   223e0f18). Red at 3b98c1ed.
//! - A frontier join below its signer's floor joins no held enrolment.
//!   Before, it joined the enrolments among its ancestors (REVIEW-9509
//!   round 2 P1, entry_transition.rs:263; fix 223e0f18). Red at 3b98c1ed.
//! - An owner's join under another owner id than the held enrolment names
//!   is refused, and so is one over a removal of the target (REVIEW-9510
//!   round 2 P1, restored_join.rs:305 and :312; fix 6545623d). Red at
//!   3b98c1ed.
//! - A refused serving profile of an unjoined copy commits no clock reading.
//!   Before, `authority_fold` committed one ahead of the refusal (REVIEW-9509
//!   machine_identity.rs:472; fix 223e0f18). Red at 3b98c1ed.
//! - A carried answer below its carrier's floor leaves a held target held.
//!   Before, the held chain it was judged on stayed standing (REVIEW-9524
//!   P1; fix 39976c09). Red at 04f15516.
//! - A first pairing of a copy below its carrier's floor makes no carrier of
//!   the copy: the copy's frontier join then joins no other copy (REVIEW-9524
//!   round 2 P1, restored_join.rs:236; fix 92c5ba34). Red at 39976c09.
//! - A carried removal below its carrier's floor stands past a sibling
//!   branch's owner join of the target (REVIEW-9524 round 2 P1,
//!   restored_join.rs:277; fix 92c5ba34). Red at 39976c09.
//! - The owner's join of a copy that a pinned anchor's mark holds, with no
//!   roster enrolment, files the root's roster enrolment and joins it.
//!   Before, the door named the mark, whose join heads no roster chain, so
//!   the join was refused and rolled back (REVIEW-9539 round 2 P1,
//!   restored_join_door.rs:179). Red at 2efec88a.
//!
//! The red commits hold this file and its door over the commit before each
//! fix (for 3b98c1ed also the clock door of 04f15516).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test restored_machine_forged_guards`.

#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActSurface, AuthorityEntryHash, AuthorityOp, HostSlipIssuer, MACHINE_ENCRYPTION_KEY_LEN,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineAdmitter, MachineDeviceClass, MachineEncryptionKey,
    MachineEnrolmentRequest, MachineOwnership, MachineProfile, MachineRole, OwnerAct, OwnerActKind,
    RestoredJoinEnrolment, RestoredMachineJoin, restored_machine_join_seen,
    restored_machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::restored_enrolment::forged_rows::{
    RowSigner, SignedRow, install_key, publish_pinned_root_and_mark,
    publish_unpinned_root_and_mark, put_signed_row,
};
use oneiron::test_doors::restored_enrolment::{authority_clock_floor, file_restored_enrolment};
use oneiron::test_support::test_host_issuer;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_authority::authority::{FrontierJoin, FrontierJoinFamily, FrontierJoinScope};

const YOURS: MachineRole = MachineRole::Owned(MachineOwnership::Yours);
/// The seed of a key no install holds, which a stranger's request for a
/// copy's machine id is signed with.
const STRANGER_SEED: u8 = 0x5d;
/// The bytes of an owner id no authority row binds.
const UNBOUND_OWNER: u8 = 0xa6;

/// The vault's first install: rooted, with its owner bound and its own
/// serving profile in `role`. It never restored, so it is joined. With
/// `owner_key`, it holds the vault's root as its owner key, as a serving
/// host does, so its answers are proved.
struct Host {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    proof: AuthenticatedOwner,
    vault_id: [u8; 32],
    /// The install's machine and the install key it carries acts with.
    machine: EntityId,
    key: SigningKey,
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
    let (machine, key) = install_key(&vault).expect("the host's install key");
    Host {
        _dir: dir,
        vault,
        issuer,
        owner,
        proof,
        vault_id,
        machine,
        key,
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

/// Whether `vault`'s fold counts `entry`.
fn counted(vault: &Vault, entry: &AuthorityEntryHash) -> bool {
    vault
        .authority_fold()
        .expect("the fold")
        .valid_entries
        .contains(entry)
}

/// Whether the enrolment `entry` is held on `vault`'s fold and waits to join.
fn waits(vault: &Vault, entry: &AuthorityEntryHash) -> bool {
    vault
        .authority_fold()
        .expect("the fold")
        .restored_enrolments()
        .get(entry)
        .is_some_and(|held| held.joined_by.is_none())
}

/// The held revision the enrolment `entry` names on `vault`'s fold.
fn held_profile(vault: &Vault, entry: &AuthorityEntryHash) -> MachineProfile {
    vault
        .authority_fold()
        .expect("FIXTURE: the fold")
        .restored_enrolments()
        .get(entry)
        .expect("FIXTURE: the enrolment is held")
        .profile
        .clone()
}

/// Two rows of `host`'s log for a floor sibling to name, read before a case
/// lays a row of its own: the host install's roster revision and one other
/// counted row. A sibling over them sees nothing a case lays after.
fn rows_before(host: &Host) -> BTreeSet<AuthorityEntryHash> {
    let fold = host
        .vault
        .authority_fold()
        .expect("FIXTURE: the host's fold");
    let serving = fold
        .machine(host.machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("FIXTURE: the host's roster revision")
        .entry;
    let other = fold
        .valid_entries
        .iter()
        .copied()
        .find(|entry| *entry != serving)
        .expect("FIXTURE: a second counted row");
    BTreeSet::from([serving, other])
}

/// A join of the main log's heads in `machine`'s install family.
fn frontier_join(machine: EntityId) -> AuthorityOp {
    AuthorityOp::FrontierJoin(FrontierJoin {
        family: FrontierJoinFamily::Install(machine),
        scope: FrontierJoinScope::Main,
    })
}

/// The host's install signs a frontier join over `before` at `seq` (its next
/// sequence when `None`): a row above the ones a case laid, which does not
/// descend from them, so each lands below its floor.
fn floor_sibling(host: &Host, seq: Option<u64>, before: BTreeSet<AuthorityEntryHash>) {
    let sibling = put_signed_row(
        &host.vault,
        RowSigner::Install(&host.key),
        frontier_join(host.machine),
        seq,
        before,
    )
    .expect("FIXTURE: the floor sibling is stored");
    assert!(
        counted(&host.vault, &sibling.entry),
        "FIXTURE: the floor sibling counts"
    );
}

/// A request for `machine`, born of `origin`, under a key no install holds
/// and signed by it: what a stranger's install would ask with.
fn stranger_request(vault_id: [u8; 32], copy: &MachineEnrolmentRequest) -> MachineEnrolmentRequest {
    let key = SigningKey::from_bytes(&[STRANGER_SEED; 32]);
    let machine_key = key.verifying_key().to_bytes();
    let encryption_key = MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    };
    let origin = copy.restored_from.expect("FIXTURE: the copy's origin");
    let transcript = restored_machine_profile_proof_transcript(
        &vault_id,
        copy.machine,
        &machine_key,
        copy.device_class,
        &encryption_key,
        &origin,
    );
    MachineEnrolmentRequest {
        vault_id,
        machine: copy.machine,
        machine_key,
        device_class: copy.device_class,
        encryption_key,
        machine_proof: key.sign(&transcript).to_bytes(),
        restored_from: Some(origin),
    }
}

/// A request for the machine from `seed`, under its own key, born of one
/// fixed image.
fn restored_request(vault_id: [u8; 32], seed: u8) -> MachineEnrolmentRequest {
    let machine = EntityId::from_bytes([seed; 16]).expect("FIXTURE: the machine id");
    let key = SigningKey::from_bytes(&[seed; 32]);
    let machine_key = key.verifying_key().to_bytes();
    let class = MachineDeviceClass::Computer;
    let encryption_key = MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    };
    let origin = [0x0d; 32];
    let transcript = restored_machine_profile_proof_transcript(
        &vault_id,
        machine,
        &machine_key,
        class,
        &encryption_key,
        &origin,
    );
    MachineEnrolmentRequest {
        vault_id,
        machine,
        machine_key,
        device_class: class,
        encryption_key,
        machine_proof: key.sign(&transcript).to_bytes(),
        restored_from: Some(origin),
    }
}

#[test]
fn the_roots_enrolment_is_the_entry_returned_beside_unpinned_marks() {
    let host = rooted_host(MachineRole::Unanswered, true);
    for seed in 0x40..0x46 {
        let request = restored_request(host.vault_id, seed);
        for _ in 0..3 {
            publish_unpinned_root_and_mark(&host.vault, host.owner, &request)
                .expect("FIXTURE: an anchor this install does not pin marks the machine");
        }
        let enrolment = file_restored_enrolment(&host.vault, &host.issuer, host.owner, &request)
            .expect("the root files the machine's enrolment");
        let fold = host.vault.authority_fold().expect("the host's fold");
        let held = fold
            .restored_enrolments()
            .get(&enrolment)
            .expect("the entry returned is a held enrolment");
        assert!(
            held.admitter == MachineAdmitter::Roster
                && held.profile.role == MachineRole::Unanswered,
            "the entry returned is the root's roster enrolment, never an anchor's mark \
             (machine seed {seed:#x}, admitter {:?})",
            held.admitter
        );
    }
}

#[test]
fn an_unpinned_anchors_mark_refuses_no_pairing() {
    let host = rooted_host(MachineRole::Unanswered, true);
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path(), "t1");
    let target = copy.request.machine;
    let mark = publish_unpinned_root_and_mark(
        &host.vault,
        host.owner,
        &stranger_request(host.vault_id, &copy.request),
    )
    .expect("FIXTURE: an anchor this install does not pin marks the copy's machine");
    let fold = host
        .vault
        .authority_fold()
        .expect("FIXTURE: the host's fold");
    assert!(fold.pinned_root.is_none(), "FIXTURE: the host pins no root");
    assert!(
        waits(&host.vault, &mark),
        "FIXTURE: the vault holds the mark, under other keys"
    );

    let landing = host
        .vault
        .enroll_machine(
            &host.proof,
            ActSurface::ThisInstall,
            &copy.request,
            MachineRole::Unanswered,
            None,
        )
        .expect("an unpinned anchor's mark of the machine refuses no pairing of it");
    assert!(landing.held().is_none(), "the pairing is not held");
    assert!(stands(&host.vault, target), "the paired copy stands");
}

#[test]
fn a_floored_frontier_join_joins_nothing() {
    let host = rooted_host(MachineRole::Unanswered, true);
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path(), "t2");
    let target = copy.request.machine;
    let before = rows_before(&host);
    let enrolment = file_restored_enrolment(&host.vault, &host.issuer, host.owner, &copy.request)
        .expect("FIXTURE: the host holds the copy's root-signed enrolment");
    let mut parents = before.clone();
    parents.insert(enrolment);
    let join = put_signed_row(
        &host.vault,
        RowSigner::Install(&host.key),
        frontier_join(host.machine),
        None,
        parents,
    )
    .expect("FIXTURE: the host's join over the enrolment is stored");
    floor_sibling(&host, Some(join.seq + 1), before);

    assert!(
        counted(&host.vault, &join.entry),
        "FIXTURE: the join counts; only its floor keeps it from joining"
    );
    assert!(
        waits(&host.vault, &enrolment),
        "a frontier join below its signer's floor joins no held enrolment"
    );
    assert!(!stands(&host.vault, target), "the copy does not stand");
}

/// The host's root, the owner key a self-host proves acts with, signs the
/// owner's join of `enrolment` for `owner` alone, over `parents`.
fn owner_join(
    host: &Host,
    owner: EntityId,
    target: EntityId,
    enrolment: AuthorityEntryHash,
    parents: BTreeSet<AuthorityEntryHash>,
) -> SignedRow {
    let act = OwnerAct::by_owner(
        owner,
        OwnerActKind::RestoredMachineJoin,
        target,
        ActSurface::ThisInstall,
        restored_machine_join_seen(&enrolment),
    );
    put_signed_row(
        &host.vault,
        RowSigner::OwnerProof,
        AuthorityOp::RestoredMachineJoin(RestoredMachineJoin {
            act,
            enrolment: RestoredJoinEnrolment::Held(enrolment),
        }),
        None,
        parents,
    )
    .expect("FIXTURE: the owner's join is stored")
}

#[test]
fn an_owner_join_under_another_owner_id_refuses() {
    let host = rooted_host(MachineRole::Unanswered, true);
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path(), "t6a");
    let target = copy.request.machine;
    let enrolment = file_restored_enrolment(&host.vault, &host.issuer, host.owner, &copy.request)
        .expect("FIXTURE: the host holds the copy's enrolment, for its bound owner");
    let unbound = EntityId::from_bytes([UNBOUND_OWNER; 16]).expect("FIXTURE: an owner id");

    let join = owner_join(
        &host,
        unbound,
        target,
        enrolment,
        BTreeSet::from([enrolment]),
    );
    assert!(
        !counted(&host.vault, &join.entry),
        "a join under an owner id the enrolment does not name is refused"
    );
    assert!(waits(&host.vault, &enrolment), "the enrolment still waits");
    assert!(!stands(&host.vault, target), "the copy does not stand");
}

#[test]
fn an_owner_join_over_a_removal_refuses() {
    let host = rooted_host(MachineRole::Unanswered, true);
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path(), "t6b");
    let target = copy.request.machine;
    let enrolment = file_restored_enrolment(&host.vault, &host.issuer, host.owner, &copy.request)
        .expect("FIXTURE: the host holds the copy's root-signed enrolment");
    // The root removes the machine at revision 2, over its held revision 1.
    let removal = MachineProfile {
        role: MachineRole::Removed,
        revision: 2,
        ..held_profile(&host.vault, &enrolment)
    };
    let removal = put_signed_row(
        &host.vault,
        RowSigner::OwnerProof,
        AuthorityOp::MachineProfile(removal),
        None,
        BTreeSet::from([enrolment]),
    )
    .expect("FIXTURE: the root's removal is stored");
    assert!(
        counted(&host.vault, &removal.entry),
        "FIXTURE: the root's removal counts"
    );

    let join = owner_join(
        &host,
        host.owner,
        target,
        enrolment,
        BTreeSet::from([removal.entry]),
    );
    assert!(
        !counted(&host.vault, &join.entry),
        "a join over a removal of its target is refused"
    );
    assert!(
        !stands(&host.vault, target),
        "a removed machine never stands again"
    );
}

#[test]
fn an_unjoined_copys_refused_serving_profile_commits_no_clock_reading() {
    let host = rooted_host(MachineRole::Unanswered, true);
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path(), "ensure");
    // The copy's clock observes once, then the wall clock moves past the
    // floor that stored.
    copy.vault
        .authority_fold()
        .expect("FIXTURE: the copy's fold");
    std::thread::sleep(std::time::Duration::from_millis(1_500));
    let before = authority_clock_floor(&copy.vault).expect("FIXTURE: the copy's clock floor");
    assert!(before.is_some(), "FIXTURE: the copy's clock has a floor");

    let refused = copy
        .vault
        .ensure_serving_install_profile(&host.issuer, MachineRole::Unanswered);
    assert!(
        refused.is_err(),
        "an unjoined copy's serving profile is refused"
    );
    assert_eq!(
        authority_clock_floor(&copy.vault).expect("the copy's clock floor"),
        before,
        "the refusal commits no clock reading"
    );
}

#[test]
fn a_floored_carried_answer_leaves_its_target_held() {
    // The host carries as one of the owner's own machines and holds no
    // owner key: its "yours" answer for the copy needs the owner's proof.
    let host = rooted_host(YOURS, false);
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path(), "t3");
    let target = copy.request.machine;
    let before = rows_before(&host);
    let enrolment = file_restored_enrolment(&host.vault, &host.issuer, host.owner, &copy.request)
        .expect("FIXTURE: the host holds the copy's root-signed enrolment");
    let answer = MachineProfile {
        role: YOURS,
        revision: 2,
        seen_world_edits: BTreeSet::new(),
        carrier: Some(host.machine),
        act: Some(OwnerAct::by_owner(
            host.owner,
            OwnerActKind::MachineAnswer,
            target,
            ActSurface::ThisInstall,
            [0; 32],
        )),
        ..held_profile(&host.vault, &enrolment)
    };
    let answer = put_signed_row(
        &host.vault,
        RowSigner::Install(&host.key),
        AuthorityOp::MachineProfile(answer),
        None,
        BTreeSet::from([enrolment]),
    )
    .expect("FIXTURE: the host's carried answer is stored");
    floor_sibling(&host, Some(answer.seq + 1), before);

    assert!(
        counted(&host.vault, &answer.entry),
        "FIXTURE: the carried answer counts"
    );
    let fold = host.vault.authority_fold().expect("the host's fold");
    assert!(
        fold.machine(target).is_none(),
        "nothing of a held target stands from an answer below its carrier's floor"
    );
    assert!(waits(&host.vault, &enrolment), "its enrolment still waits");
}

#[test]
fn a_floored_first_pairing_makes_no_carrier_of_a_copy() {
    let host = rooted_host(YOURS, true);
    let backups = oneiron::test_support::restore_tempdir();
    let paired = restored_copy(&host, backups.path(), "t4a");
    let held = restored_copy(&host, backups.path(), "t4b");
    let before = rows_before(&host);
    // The owner pairs copy A from the host, with his proof: A holds no
    // enrolment, so this is its first revision.
    host.vault
        .enroll_machine(
            &host.proof,
            ActSurface::ThisInstall,
            &paired.request,
            YOURS,
            None,
        )
        .expect("FIXTURE: the owner pairs copy A");
    let pairing = host
        .vault
        .authority_fold()
        .expect("FIXTURE: the host's fold")
        .machine(paired.request.machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("FIXTURE: copy A stands on the host")
        .entry;
    let enrolment = file_restored_enrolment(&host.vault, &host.issuer, host.owner, &held.request)
        .expect("FIXTURE: the host holds copy B's root-signed enrolment");
    floor_sibling(&host, None, before);
    assert!(
        counted(&host.vault, &pairing),
        "FIXTURE: the pairing counts"
    );

    // Copy A's install key joins the heads its pairing and B's enrolment
    // left.
    let (machine, key) = install_key(&paired.vault).expect("FIXTURE: copy A's install key");
    assert_eq!(machine, paired.request.machine, "FIXTURE: copy A's machine");
    let join = put_signed_row(
        &host.vault,
        RowSigner::Install(&key),
        frontier_join(machine),
        None,
        BTreeSet::from([pairing, enrolment]),
    )
    .expect("FIXTURE: copy A's join is stored");

    assert!(
        !counted(&host.vault, &join.entry),
        "a copy whose first pairing sits below its carrier's floor carries nothing"
    );
    assert!(
        waits(&host.vault, &enrolment),
        "copy B's enrolment still waits"
    );
    assert!(
        !stands(&host.vault, held.request.machine),
        "copy B does not stand"
    );
    assert!(
        host.vault
            .authority_fold()
            .expect("the host's fold")
            .machine(machine)
            .is_none(),
        "nothing of copy A stands from a floored first pairing"
    );
}

#[test]
fn a_floored_removal_stands_past_a_sibling_join() {
    let host = rooted_host(YOURS, true);
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path(), "t5");
    let target = copy.request.machine;
    let before = rows_before(&host);
    let enrolment = file_restored_enrolment(&host.vault, &host.issuer, host.owner, &copy.request)
        .expect("FIXTURE: the host holds the copy's root-signed enrolment");

    // Branch Y: the owner's word on the copy joins its held revision 1.
    sync_authority(&host.vault, &copy.vault);
    copy.vault
        .join_restored_install(&host.issuer, &copy.proof, MachineRole::Unanswered)
        .expect("FIXTURE: the owner's word joins the copy");
    assert!(
        stands(&copy.vault, target),
        "FIXTURE: the copy stands on its branch"
    );

    // Branch X: the host carries the owner's proved removal at revision 2,
    // below its floor.
    let removal = MachineProfile {
        role: MachineRole::Removed,
        revision: 2,
        seen_world_edits: BTreeSet::new(),
        carrier: Some(host.machine),
        act: Some(OwnerAct::by_owner(
            host.owner,
            OwnerActKind::MachineRemoval,
            target,
            ActSurface::ThisInstall,
            [0; 32],
        )),
        ..held_profile(&host.vault, &enrolment)
    };
    let removal = put_signed_row(
        &host.vault,
        RowSigner::InstallWithOwnerProof(&host.key),
        AuthorityOp::MachineProfile(removal),
        None,
        BTreeSet::from([enrolment]),
    )
    .expect("FIXTURE: the host's carried removal is stored");
    floor_sibling(&host, Some(removal.seq + 1), before);
    assert!(
        counted(&host.vault, &removal.entry),
        "FIXTURE: the removal counts"
    );

    sync_authority(&copy.vault, &host.vault);
    let roster = host
        .vault
        .authority_fold()
        .expect("the host's fold")
        .machine(target)
        .and_then(|folded| folded.roster.clone())
        .expect("the copy's machine on the host");
    assert!(
        roster.removed && !roster.is_live(),
        "a removal below its carrier's floor stands past a sibling branch's join \
         (head revision {}, removed {})",
        roster.profile.revision,
        roster.removed
    );
    assert!(
        !stands(&host.vault, target),
        "the removed copy does not stand"
    );
}

#[test]
fn the_owners_join_files_a_roster_enrolment_beside_a_pinned_anchors_mark() {
    let host = rooted_host(MachineRole::Unanswered, true);
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path(), "t7");
    let target = copy.request.machine;
    let mark = publish_pinned_root_and_mark(&copy.vault, host.owner, &copy.request)
        .expect("FIXTURE: the copy pins an owner root whose anchor marks the copy");
    let fold = copy
        .vault
        .authority_fold()
        .expect("FIXTURE: the copy's fold");
    assert!(
        fold.pinned_root.is_some(),
        "FIXTURE: the copy pins the root"
    );
    let held = fold
        .restored_enrolments()
        .get(&mark)
        .expect("FIXTURE: the anchor's mark is held");
    assert!(
        matches!(held.admitter, MachineAdmitter::Anchor(_))
            && held.joined_by.is_none()
            && held.profile.role == YOURS,
        "FIXTURE: the pinned anchor's mark of the copy waits, as the owner's own"
    );
    assert!(
        fold.counted_waiting_enrolments(target)
            .all(|(_, held)| held.admitter != MachineAdmitter::Roster),
        "FIXTURE: no roster enrolment of the copy waits"
    );

    let joined = copy
        .vault
        .join_restored_install(&host.issuer, &copy.proof, YOURS)
        .expect("the owner's word joins a copy that a pinned anchor's mark holds");
    let roster = joined
        .roster
        .as_ref()
        .expect("the joined copy has a roster head");
    assert!(
        roster.is_live() && roster.profile.role == YOURS,
        "the copy stands on the roster as the owner's own"
    );
    assert_ne!(
        roster.entry, mark,
        "the roster head is the root's roster enrolment, never the anchor's mark"
    );
    assert!(stands(&copy.vault, target), "the copy stands");
}
