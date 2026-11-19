//! Row RESTORED-HELD-RESTRICTION-SIBLING-JOIN: an owner's answer for a
//! machine born of a restore, carried while the machine waits to join and
//! landed below its carrier's sequence floor (restriction only), is held
//! beside the machine's enrolment. Once the machine stands by another way,
//! the held answer lands on its chains as a joined machine's floored
//! revision does: its revision numbers the machine, and its head holds the
//! machine's chain on this install. Before, the machine stood at its older,
//! wider enrolment:
//!
//! - when a sibling branch's owner join of the older enrolment met the held
//!   answer on merge (the merge only united the enrolments);
//! - when the owner's join of the older enrolment descended from the held
//!   answer on one branch (the join stood only the enrolment it names).
//!
//! Each case lays a demotion from "yours" to "work/school" below its
//! carrier's floor: the same install signs a sibling of a higher sequence
//! that does not descend from it. The rows come from the door
//! `test_doors::restored_enrolment::forged_rows`, as in
//! `restored_machine_forged_guards.rs`; no public writer signs below its own
//! next sequence or over parents it picks. The owner's join is the row
//! `Vault::join_restored_install` writes, signed by the same owner proof.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test restored_held_restriction_join`.

#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActSurface, AuthorityEntryHash, AuthorityOp, HostSlipIssuer, MACHINE_ENCRYPTION_KEY_LEN,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass, MachineEncryptionKey,
    MachineEnrolmentRequest, MachineOwnership, MachineProfile, MachineRole, OwnerAct, OwnerActKind,
    RestoredJoinEnrolment, RestoredMachineJoin, restored_machine_join_seen,
    restored_machine_profile_proof_transcript,
};
use oneiron::test_doors::restored_enrolment::file_restored_enrolment_in_role;
use oneiron::test_doors::restored_enrolment::forged_rows::{
    RowSigner, SignedRow, install_key, put_signed_row,
};
use oneiron::test_support::test_host_issuer;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_authority::authority::{FrontierJoin, FrontierJoinFamily, FrontierJoinScope};

const YOURS: MachineRole = MachineRole::Owned(MachineOwnership::Yours);
const WORK_SCHOOL: MachineRole = MachineRole::Owned(MachineOwnership::WorkSchool);

/// The vault's first install: rooted, with its owner bound, its own serving
/// profile "yours" and the vault's root held as its owner key, so its
/// answers are proved. It never restored, so it is joined.
struct Host {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    vault_id: [u8; 32],
    /// The install's machine and the install key it carries acts with.
    machine: EntityId,
    key: SigningKey,
}

fn rooted_host() -> Host {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the host install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, YOURS)
        .expect("the host install profile");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner binding");
    vault.hold_checkpoint_root_signer(Arc::new(test_host_issuer()));
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
        vault_id,
        machine,
        key,
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

/// The root files `request`'s enrolment as the owner's "yours" at revision
/// 1, which the fold holds.
fn yours_enrolment(host: &Host, request: &MachineEnrolmentRequest) -> AuthorityEntryHash {
    let enrolment =
        file_restored_enrolment_in_role(&host.vault, &host.issuer, host.owner, request, YOURS)
            .expect("FIXTURE: the host holds the machine's root-signed enrolment");
    assert!(
        waits(&host.vault, &enrolment),
        "FIXTURE: the enrolment is held"
    );
    enrolment
}

/// The owner's answer "work/school" for `target` at revision 2 over the
/// held `enrolment`, carried by the host.
fn demotion(host: &Host, target: EntityId, enrolment: &AuthorityEntryHash) -> MachineProfile {
    MachineProfile {
        role: WORK_SCHOOL,
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
        ..held_profile(&host.vault, enrolment)
    }
}

/// The host carries `answer`, proved, over `enrolment` alone, then signs a
/// sibling over `before` at the next sequence, so the answer lands below its
/// floor. Returns the answer, which the fold holds, and the sibling.
fn floored_answer(
    host: &Host,
    answer: MachineProfile,
    enrolment: AuthorityEntryHash,
    before: BTreeSet<AuthorityEntryHash>,
) -> (SignedRow, SignedRow) {
    let answer = put_signed_row(
        &host.vault,
        RowSigner::InstallWithOwnerProof(&host.key),
        AuthorityOp::MachineProfile(answer),
        None,
        BTreeSet::from([enrolment]),
    )
    .expect("FIXTURE: the host's carried answer is stored");
    let sibling = put_signed_row(
        &host.vault,
        RowSigner::Install(&host.key),
        AuthorityOp::FrontierJoin(FrontierJoin {
            family: FrontierJoinFamily::Install(host.machine),
            scope: FrontierJoinScope::Main,
        }),
        Some(answer.seq + 1),
        before,
    )
    .expect("FIXTURE: the floor sibling is stored");
    assert!(
        counted(&host.vault, &sibling.entry),
        "FIXTURE: the floor sibling counts"
    );
    assert!(
        counted(&host.vault, &answer.entry),
        "FIXTURE: the answer counts"
    );
    assert!(
        waits(&host.vault, &answer.entry),
        "FIXTURE: the floored answer is held"
    );
    (answer, sibling)
}

/// [`demotion`], carried below the host's floor by [`floored_answer`].
fn floored_demotion(
    host: &Host,
    target: EntityId,
    enrolment: AuthorityEntryHash,
    before: BTreeSet<AuthorityEntryHash>,
) -> (SignedRow, SignedRow) {
    floored_answer(host, demotion(host, target, &enrolment), enrolment, before)
}

/// The owner's word that no other machine is left, joining `enrolment` of
/// `target` over `parents`.
fn owner_join(
    host: &Host,
    target: EntityId,
    enrolment: AuthorityEntryHash,
    parents: BTreeSet<AuthorityEntryHash>,
) -> SignedRow {
    let act = OwnerAct::by_owner(
        host.owner,
        OwnerActKind::RestoredMachineJoin,
        target,
        ActSurface::ThisInstall,
        restored_machine_join_seen(&enrolment),
    );
    let join = put_signed_row(
        &host.vault,
        RowSigner::OwnerProof,
        AuthorityOp::RestoredMachineJoin(RestoredMachineJoin {
            act,
            enrolment: RestoredJoinEnrolment::Held(enrolment),
        }),
        None,
        parents,
    )
    .expect("FIXTURE: the owner's join is stored");
    assert!(
        counted(&host.vault, &join.entry),
        "FIXTURE: the owner's join counts"
    );
    join
}

/// `machine`'s roster head on `vault`'s fold: its revision and role, and
/// whether it reads as the owner's "yours".
fn roster_head(vault: &Vault, machine: EntityId) -> (u64, MachineRole, bool) {
    let roster = vault
        .authority_fold()
        .expect("the fold")
        .machine(machine)
        .and_then(|folded| folded.roster.clone())
        .expect("the machine's roster revision");
    let yours = roster.says_yours();
    (roster.profile.revision, roster.profile.role, yours)
}

#[test]
fn a_floored_demotion_stands_past_a_sibling_join() {
    let host = rooted_host();
    let request = restored_request(host.vault_id, 0x61);
    let target = request.machine;
    let before = rows_before(&host);
    let enrolment = yours_enrolment(&host, &request);

    // Branch Y: the owner's word joins the held revision 1.
    owner_join(&host, target, enrolment, BTreeSet::from([enrolment]));
    assert!(
        stands(&host.vault, target),
        "FIXTURE: the machine stands as \"yours\" on branch Y"
    );

    // Branch X: the host carries the owner's demotion at revision 2 over
    // revision 1 alone, below its floor.
    floored_demotion(&host, target, enrolment, before);

    let (revision, role, yours) = roster_head(&host.vault, target);
    assert_eq!(
        (revision, role),
        (2, WORK_SCHOOL),
        "a demotion below its carrier's floor stands past a sibling branch's join"
    );
    assert!(!yours, "the demoted machine no longer reads as \"yours\"");
    assert!(
        !stands(&host.vault, target),
        "its floored head holds the machine's chain on this install"
    );
}

#[test]
fn the_owners_join_of_an_older_enrolment_stands_a_held_demotion() {
    let host = rooted_host();
    let request = restored_request(host.vault_id, 0x62);
    let target = request.machine;
    let before = rows_before(&host);
    let enrolment = yours_enrolment(&host, &request);
    let (demotion, sibling) = floored_demotion(&host, target, enrolment, before);
    assert!(
        host.vault
            .authority_fold()
            .expect("FIXTURE: the host's fold")
            .machine(target)
            .is_none(),
        "FIXTURE: nothing of the machine stands yet"
    );

    // The owner's word joins revision 1 by name, over the demotion and the
    // floor sibling: the join descends from the held demotion and is the
    // log's one head, so no merge follows it.
    owner_join(
        &host,
        target,
        enrolment,
        BTreeSet::from([demotion.entry, sibling.entry]),
    );
    assert!(
        !waits(&host.vault, &enrolment),
        "FIXTURE: the join joined revision 1"
    );

    let (revision, role, yours) = roster_head(&host.vault, target);
    assert_eq!(
        (revision, role),
        (2, WORK_SCHOOL),
        "the owner's join of an older enrolment stands the held demotion"
    );
    assert!(!yours, "the demoted machine no longer reads as \"yours\"");
    assert!(
        !stands(&host.vault, target),
        "its floored head holds the machine's chain on this install"
    );
}

#[test]
fn a_root_revision_over_a_held_demotion_stands_with_it() {
    let host = rooted_host();
    let request = restored_request(host.vault_id, 0x63);
    let target = request.machine;
    let before = rows_before(&host);
    let enrolment = yours_enrolment(&host, &request);
    let (demotion, sibling) = floored_demotion(&host, target, enrolment, before);
    // The root answers "unanswered" at revision 3 over the held demotion:
    // the machine has not joined, so it is held too.
    let later = put_signed_row(
        &host.vault,
        RowSigner::OwnerProof,
        AuthorityOp::MachineProfile(MachineProfile {
            role: MachineRole::Unanswered,
            revision: 3,
            ..held_profile(&host.vault, &enrolment)
        }),
        None,
        BTreeSet::from([demotion.entry]),
    )
    .expect("FIXTURE: the root's revision 3 is stored");
    assert!(
        counted(&host.vault, &later.entry) && waits(&host.vault, &later.entry),
        "FIXTURE: the root's revision 3 counts and is held"
    );

    owner_join(
        &host,
        target,
        enrolment,
        BTreeSet::from([later.entry, sibling.entry]),
    );

    let (revision, role, yours) = roster_head(&host.vault, target);
    assert_eq!(
        (revision, role),
        (3, MachineRole::Unanswered),
        "a revision held over the held demotion stands with it, as it stands without the floor"
    );
    assert!(!yours, "the machine no longer reads as \"yours\"");
}

#[test]
fn a_held_demotion_naming_a_shared_key_holds_the_other_machine() {
    let host = rooted_host();
    let request = restored_request(host.vault_id, 0x64);
    let target = request.machine;
    let before = rows_before(&host);
    let enrolment = yours_enrolment(&host, &request);
    // The demotion names the host install's own key for the machine, with
    // that key's proof of the machine's profile.
    let held = held_profile(&host.vault, &enrolment);
    let machine_key = host.key.verifying_key().to_bytes();
    let transcript = restored_machine_profile_proof_transcript(
        &host.vault_id,
        target,
        &machine_key,
        held.device_class,
        &held.encryption_key,
        &held.restored_from.expect("FIXTURE: the machine's origin"),
    );
    let answer = MachineProfile {
        machine_key,
        machine_proof: host.key.sign(&transcript).to_bytes(),
        ..demotion(&host, target, &enrolment)
    };
    let (answer, sibling) = floored_answer(&host, answer, enrolment, before);
    assert!(
        stands(&host.vault, host.machine),
        "FIXTURE: the host's install stands"
    );

    owner_join(
        &host,
        target,
        enrolment,
        BTreeSet::from([answer.entry, sibling.entry]),
    );

    assert!(
        !stands(&host.vault, host.machine),
        "a key the held demotion names for the machine, which the host's install claims, \
         holds the host's install too, as it does without the floor"
    );
}
