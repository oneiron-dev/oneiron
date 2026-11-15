//! An owner's machine answer is numbered, copied and checked from the heads
//! its machine stands under on this install: the roster's head and the head
//! of the chain of the anchor this install pins (row
//! MACHINE-REVISION-FOLD-BOUND, PR 1; FIX
//! [FOREIGN-ANCHOR-MARK-BLOCKS-MACHINE-DOORS]; Engine RULING 16 Nov,
//! MACHINE-ANSWER-WRITERS-READ-TRUST-CHAINS = B).
//!
//! Any fresh key publishes an owner root, and that root's anchor marks any
//! machine in its own chain: owned or removed, under any keys that carry
//! their own machine proof, at a revision up to one above the highest head
//! the mark's parents hold. The three writers of the owner's
//! answer (`Vault::set_machine_role`, `Vault::enroll_machine` for a class
//! revision, `Vault::confirm_held_machine_answers`) read every chain of the
//! machine before: the next revision topped every chain, the new profile
//! copied the newest head, and a removed head in any chain refused the
//! answer. So one mark by a root nobody pins blocked a machine's role
//! change, class revision, held confirm and removal, or put its keys into
//! the owner's next role change.
//!
//! The pairing redeem door read every chain too, in front of the class
//! revision: a machine that pairs again under its own identity
//! (`re_paired_standing`) and the key whose possession a redemption proves
//! (`held_machine_possession`). They read the same heads now (Engine RULING
//! 16 Nov, RE-PAIRING-READERS-IN-PR-1 = A).
//!
//! Each test publishes a stranger's root (a fresh `RecoveryRootSeed`), stores
//! one mark of that root's anchor beside the owner's machine, and then acts
//! through the owner's door or the redeem door. No vault here pins a root,
//! so the machine stands under the roster's head alone.
//!
//! The last five tests are PR 2 of the row (FIX 25887): the fold refuses a
//! machine revision numbered more than one above the highest head its
//! machine's chains hold in the entry's parents. Each hand-signs rows that
//! skip a number, on the roster or in a stranger's chain, and reads them
//! refused. So a stranger's mark in the tests before them sits at most one
//! revision above the roster's head, and then names the roster's row among
//! its parents; where the machine has no chain yet it sits at revision 1.

#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActAuthority, ActSurface, AuthorityEntryHash, AuthorityKey,
    AuthorityLogEntry, AuthorityOp, AuthoritySignature, AuthorityVaultId, HostSlipIssuer,
    MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass,
    MachineEncryptionKey, MachineEnrolmentRequest, MachineOwnership, MachineProfile, MachineRole,
    OwnerAct, OwnerActKind, OwnerRootRecord, PairingPrincipal, PairingRedeemed,
    authority_entry_hash, authority_transcript, machine_possession_transcript,
    machine_profile_proof_transcript, pairing_binding_transcript_pinned,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::Scope;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::world_keys::{RecoveryRoot, RecoveryRootSeed};
use oneiron::{EntityId, HostingPrivacyPosture, TimeRange, Vault, VaultConfig};
use oneiron_authority::authority::{
    FrontierJoin, FrontierJoinFamily, FrontierJoinScope, machine_answer_revision,
};

/// The seed of the joining machine's machine key.
const JOINING_SEED: u8 = 68;
/// The seed of the stranger machine key no other key of this file uses.
const STRANGER_MACHINE_SEED: u8 = 71;
/// The seed of the connection key a redeemed pairing link binds.
const CONNECTION_SEED: u8 = 73;
/// The seed of the machine key of a machine no chain names.
const UNNAMED_MACHINE_SEED: u8 = 79;
/// The stored rows' occurred range and learned-at, as the store-door tests use.
const AT: TimeRange = TimeRange { start: 2, end: 2 };

fn signing(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn key_of(signing: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

fn signature_slot(key: AuthorityKey) -> AuthoritySignature {
    AuthoritySignature {
        suite: key.suite(),
        public_key: key,
        signature: vec![0; 64],
    }
}

/// `signer` signs `op` on `parent_hashes`, with one cosign by each of `cosigners`.
fn signed(
    vault_id: Option<AuthorityVaultId>,
    seq: u64,
    parent_hashes: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
    signer: &SigningKey,
    cosigners: &[&SigningKey],
) -> AuthorityLogEntry {
    let mut cosigners = cosigners.to_vec();
    cosigners.sort_by_key(|cosigner| key_of(cosigner));
    let mut row = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id,
        seq,
        parent_hashes,
        op,
        signer: signature_slot(key_of(signer)),
        cosigns: cosigners
            .iter()
            .map(|cosigner| signature_slot(key_of(cosigner)))
            .collect(),
        ts: 1,
    };
    let transcript = authority_transcript(&row).expect("the transcript");
    row.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    for (slot, cosigner) in row.cosigns.iter_mut().zip(&cosigners) {
        slot.signature = cosigner.sign(&transcript).to_bytes().to_vec();
    }
    row
}

fn hash(row: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(row).expect("a hash")
}

fn owner() -> EntityId {
    EntityId::from_bytes([0x71; 16]).expect("an id")
}

/// The stranger root's owner person, distinct from the vault's owner.
fn stranger_owner() -> EntityId {
    EntityId::from_bytes([0xA1; 16]).expect("an id")
}

/// `node`'s act-free profile of `machine` in `role` at `revision` (a `Computer`).
fn node_profile(
    vault_id: AuthorityVaultId,
    machine: EntityId,
    node: &SigningKey,
    role: MachineRole,
    revision: u64,
) -> MachineProfile {
    node_profile_with_class(
        vault_id,
        machine,
        node,
        role,
        revision,
        MachineDeviceClass::Computer,
    )
}

/// `node`'s act-free profile of `machine` in `role` at `revision` under `class`.
fn node_profile_with_class(
    vault_id: AuthorityVaultId,
    machine: EntityId,
    node: &SigningKey,
    role: MachineRole,
    revision: u64,
    class: MachineDeviceClass,
) -> MachineProfile {
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
            class,
            &encryption_key,
        ))
        .to_bytes();
    MachineProfile {
        machine,
        owner: owner(),
        machine_key,
        device_class: class,
        encryption_key,
        role,
        revision,
        machine_proof,
        seen_world_edits: BTreeSet::new(),
        carrier: None,
        act: None,
    }
}

/// A real vault with the doors: this install serving, profiled, and the owner bound.
struct ServedVault {
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

impl ServedVault {
    fn hosted() -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let mut config = VaultConfig::device();
        config.privacy.posture = HostingPrivacyPosture::Hosted;
        let vault = Vault::open(dir.path(), config).expect("hosted vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile under the host root");
        let (_, owner) = embedded_owner(&vault).expect("authenticated embedded owner");
        Self {
            vault,
            issuer,
            owner,
            _dir: dir,
        }
    }

    /// A self-host vault as its own server starts one.
    fn self_host() -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("self-host vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile under the host root");
        let person = vault.ensure_embedded_owner_actor().expect("the owner");
        oneiron::test_support::bind_host_owner(&vault, &issuer, person)
            .expect("the owner's binding");
        let owner = vault
            .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
            .expect("the owner's proof");
        Self {
            vault,
            issuer,
            owner,
            _dir: dir,
        }
    }

    /// The owner enrols this install's owner signing key.
    fn enrol_owner_key(&self) {
        self.vault
            .enrol_device_owner_signing_key(
                &ActAuthority::Owner(self.owner.clone(), ActSurface::ThisInstall),
                &self.issuer,
            )
            .expect("the owner enrols this install's owner signing key");
    }

    /// The vault's id.
    fn vault_id(&self) -> AuthorityVaultId {
        self.vault
            .authority_fold()
            .expect("authority fold")
            .vault_id
            .expect("the vault is rooted")
    }

    /// The entry of `machine`'s roster head.
    fn roster_row(&self, machine: EntityId) -> AuthorityEntryHash {
        self.vault
            .authority_fold()
            .expect("authority fold")
            .machine(machine)
            .and_then(|folded| folded.roster.as_ref())
            .expect("guard: the machine has a roster chain")
            .entry
    }

    /// Another machine's request to join this vault.
    fn joining_machine(&self) -> MachineEnrolmentRequest {
        self.joining_machine_with_class(MachineDeviceClass::Computer)
    }

    /// Another machine's request to join this vault under `class`.
    fn joining_machine_with_class(&self, class: MachineDeviceClass) -> MachineEnrolmentRequest {
        let vault_id = self
            .vault
            .authority_fold()
            .expect("authority fold")
            .vault_id
            .expect("the vault is rooted");
        let machine = EntityId::from_bytes([0x76; 16]).expect("an id");
        let profile = node_profile_with_class(
            vault_id,
            machine,
            &signing(JOINING_SEED),
            MachineRole::Unanswered,
            1,
            class,
        );
        MachineEnrolmentRequest {
            vault_id,
            machine,
            machine_key: profile.machine_key,
            device_class: profile.device_class,
            encryption_key: profile.encryption_key,
            machine_proof: profile.machine_proof,
        }
    }

    /// The owner's list of the acts that wait for his proof.
    fn held(&self) -> oneiron::authority::HeldAnswerListing {
        self.vault
            .held_machine_answers(&self.owner)
            .expect("the held answer list")
    }

    /// The entry of every held answer the list names.
    fn held_entries(&self) -> Vec<AuthorityEntryHash> {
        self.held()
            .answers
            .iter()
            .map(|listed| listed.entry)
            .collect()
    }

    /// The owner confirms the held answers `entries` name through this install.
    fn confirm(
        &self,
        entries: &[AuthorityEntryHash],
    ) -> oneiron::Result<oneiron::authority::ConfirmedHeldAnswers> {
        self.vault
            .confirm_held_machine_answers(&self.owner, ActSurface::ThisInstall, entries)
    }
}

/// A self-host vault whose install holds the owner's key, with machine M
/// enrolled as the owner's at roster revision 1.
fn enrolled_self_host() -> (ServedVault, MachineEnrolmentRequest) {
    let served = ServedVault::self_host();
    served.enrol_owner_key();
    let request = served.joining_machine();
    let landing = served
        .vault
        .enroll_machine(
            &served.owner,
            ActSurface::ThisInstall,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner's enrolment of M lands");
    assert!(landing.held().is_none(), "guard: the landing is not held");
    let fold = served.vault.authority_fold().expect("authority fold");
    let roster = fold
        .machine(request.machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("guard: M has a roster chain");
    assert!(roster.is_live(), "guard: M's roster is live");
    assert_eq!(roster.profile.revision, 1, "guard: M stands at revision 1");
    assert_eq!(
        roster.profile.machine_key, request.machine_key,
        "guard: M stands under its own machine key"
    );
    assert_eq!(
        roster.profile.encryption_key, request.encryption_key,
        "guard: M stands under its own encryption key"
    );
    (served, request)
}

/// A stranger's root published on one held valid row and stored. Returns the
/// root, its anchor signing key, and the root row's hash.
fn publish_stranger_root(
    served: &ServedVault,
    vault_id: AuthorityVaultId,
) -> (RecoveryRoot, SigningKey, AuthorityEntryHash) {
    let seed = RecoveryRootSeed::generate().expect("a fresh stranger root seed");
    let root = seed
        .public(&vault_id)
        .expect("the stranger root's public half");
    let anchor = seed.anchor();
    let parent = served
        .vault
        .authority_fold()
        .expect("authority fold for a parent")
        .valid_entries
        .iter()
        .next()
        .copied()
        .expect("guard: the vault holds a valid row for the root's parent");
    let record = OwnerRootRecord {
        owner: stranger_owner(),
        root: root.id,
        recovery_key: MachineEncryptionKey {
            suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
            key: root.recovery_key.to_bytes(),
        },
        anchor_key: root.anchor_key,
    };
    let entry = signed(
        Some(vault_id),
        1,
        vec![parent],
        AuthorityOp::OwnerRoot(record),
        &anchor,
        &[],
    );
    let root_hash = hash(&entry);
    served
        .vault
        .put_authority_log_entry(&entry, AT, 2)
        .expect("the stranger's root row is stored");
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&root_hash),
        "guard: the stranger's root is in valid_entries"
    );
    (root, anchor, root_hash)
}

/// The stranger's anchor marks M under M's own keys and proof, and the mark
/// is stored. Returns the mark's hash.
fn stranger_mark_with_m_keys(
    served: &ServedVault,
    vault_id: AuthorityVaultId,
    parents: Vec<AuthorityEntryHash>,
    anchor: &SigningKey,
    request: &MachineEnrolmentRequest,
    role: MachineRole,
    revision: u64,
) -> AuthorityEntryHash {
    let profile = MachineProfile {
        machine: request.machine,
        owner: stranger_owner(),
        machine_key: request.machine_key,
        device_class: request.device_class,
        encryption_key: request.encryption_key.clone(),
        role,
        revision,
        machine_proof: request.machine_proof,
        seen_world_edits: BTreeSet::new(),
        carrier: None,
        act: None,
    };
    let entry = signed(
        Some(vault_id),
        2,
        parents,
        AuthorityOp::MachineProfile(profile),
        anchor,
        &[],
    );
    let mark = hash(&entry);
    served
        .vault
        .put_authority_log_entry(&entry, AT, 2)
        .expect("the stranger's mark is stored");
    mark
}

/// The parents of a stranger's mark one revision above `machine`'s roster
/// head: the stranger's root row and the machine's roster row, in hash order.
fn root_and_roster_row(
    served: &ServedVault,
    machine: EntityId,
    root: AuthorityEntryHash,
) -> Vec<AuthorityEntryHash> {
    let mut parents = vec![root, served.roster_row(machine)];
    parents.sort_unstable();
    parents
}

/// The stranger's anchor marks M under M's own keys and proof at `revision`,
/// on the parents and at the anchor's sequence that `on` names, and the mark
/// is stored whether the fold takes it or not. Returns the mark's hash.
fn stranger_mark_at(
    served: &ServedVault,
    on: (Vec<AuthorityEntryHash>, u64),
    anchor: &SigningKey,
    request: &MachineEnrolmentRequest,
    role: MachineRole,
    revision: u64,
) -> AuthorityEntryHash {
    let (parents, seq) = on;
    let profile = MachineProfile {
        machine: request.machine,
        owner: stranger_owner(),
        machine_key: request.machine_key,
        device_class: request.device_class,
        encryption_key: request.encryption_key.clone(),
        role,
        revision,
        machine_proof: request.machine_proof,
        seen_world_edits: BTreeSet::new(),
        carrier: None,
        act: None,
    };
    let entry = signed(
        Some(served.vault_id()),
        seq,
        parents,
        AuthorityOp::MachineProfile(profile),
        anchor,
        &[],
    );
    let mark = hash(&entry);
    served
        .vault
        .put_authority_log_entry(&entry, AT, 2)
        .expect("the stranger's mark is stored");
    mark
}

/// The stranger's anchor marks M under the stranger's own keys with their
/// valid proof, and the mark is stored. Returns the mark's hash.
fn stranger_mark_with_stranger_keys(
    served: &ServedVault,
    vault_id: AuthorityVaultId,
    parents: Vec<AuthorityEntryHash>,
    anchor: &SigningKey,
    machine: EntityId,
    role: MachineRole,
    revision: u64,
) -> AuthorityEntryHash {
    let mut profile = node_profile(
        vault_id,
        machine,
        &signing(STRANGER_MACHINE_SEED),
        role,
        revision,
    );
    profile.owner = stranger_owner();
    let entry = signed(
        Some(vault_id),
        2,
        parents,
        AuthorityOp::MachineProfile(profile),
        anchor,
        &[],
    );
    let mark = hash(&entry);
    served
        .vault
        .put_authority_log_entry(&entry, AT, 2)
        .expect("the stranger's mark is stored");
    mark
}

/// A hosted vault where the node carried M's enrolment with no owner key's
/// proof: the enrolment is held.
fn held_hosted_enrolment() -> (ServedVault, MachineEnrolmentRequest) {
    let served = ServedVault::hosted();
    let request = served.joining_machine();
    let landing = served
        .vault
        .enroll_machine(
            &served.owner,
            ActSurface::ThisInstall,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the enrolment is stored");
    assert!(landing.held().is_some(), "guard: the enrolment is held");
    let listing = served.held();
    assert_eq!(listing.answers.len(), 1, "one held answer: {listing:?}");
    (served, request)
}

/// The owner's removal is numbered from the roster's head: beside a
/// stranger's mark of the machine one revision above that head it lands at
/// revision 2. Before, the next number topped every chain: 3 here, a number
/// the fold now refuses over a roster head at 1.
#[test]
fn the_owner_removes_a_machine_beside_a_stranger_roots_mark() {
    let (served, request) = enrolled_self_host();
    let machine = request.machine;
    let vault_id = served
        .vault
        .authority_fold()
        .expect("authority fold")
        .vault_id
        .expect("the vault is rooted");
    let (root, anchor, root_hash) = publish_stranger_root(&served, vault_id);
    let mark = stranger_mark_with_m_keys(
        &served,
        vault_id,
        root_and_roster_row(&served, machine, root_hash),
        &anchor,
        &request,
        MachineRole::Owned(MachineOwnership::Yours),
        2,
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&mark),
        "guard: the stranger's mark is in valid_entries"
    );
    let anchored = fold
        .machine(machine)
        .and_then(|folded| folded.anchored.get(&root.anchor_key))
        .expect("guard: the view holds F's chain");
    assert_eq!(
        anchored.profile.revision, 2,
        "guard: F's chain stands at revision 2, one above the roster's head"
    );
    let landing = served
        .vault
        .set_machine_role(
            &served.owner,
            ActSurface::ThisInstall,
            machine,
            MachineRole::Removed,
            None,
        )
        .expect("the owner's removal lands beside the stranger's mark");
    assert!(
        landing.held().is_none(),
        "the removal stands, it is not held"
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    let roster = fold
        .machine(machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("M has a roster chain after the removal");
    assert_eq!(
        roster.profile.role,
        MachineRole::Removed,
        "M's roster head is removed"
    );
    assert_eq!(
        roster.profile.revision, 2,
        "M's roster head is at revision 2"
    );
}

/// A stranger's removal mark is no removal of the machine: it refuses
/// neither the owner's role change nor his own removal. Before, the door
/// refused both, because a head was removed.
#[test]
fn the_owner_answers_about_a_machine_beside_a_stranger_roots_removal_mark() {
    let (served, request) = enrolled_self_host();
    let machine = request.machine;
    let vault_id = served
        .vault
        .authority_fold()
        .expect("authority fold")
        .vault_id
        .expect("the vault is rooted");
    let (root, anchor, root_hash) = publish_stranger_root(&served, vault_id);
    let mark = stranger_mark_with_m_keys(
        &served,
        vault_id,
        vec![root_hash],
        &anchor,
        &request,
        MachineRole::Removed,
        1,
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&mark),
        "guard: the stranger's removal mark is in valid_entries"
    );
    let anchored = fold
        .machine(machine)
        .and_then(|folded| folded.anchored.get(&root.anchor_key))
        .expect("guard: the view holds F's chain");
    assert!(anchored.removed, "guard: F's chain reads removed");
    let demote = MachineRole::Owned(MachineOwnership::WorkSchool);
    let landing = served
        .vault
        .set_machine_role(
            &served.owner,
            ActSurface::ThisInstall,
            machine,
            demote,
            None,
        )
        .expect("the owner's role change lands beside the stranger's removal");
    assert!(
        landing.held().is_none(),
        "the role change stands, it is not held"
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    let roster = fold
        .machine(machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("M has a roster chain after the role change");
    assert_eq!(
        roster.profile.role, demote,
        "M's roster head has the new role"
    );
    assert_eq!(
        roster.profile.revision, 2,
        "M's roster head is at revision 2"
    );
    let landing = served
        .vault
        .set_machine_role(
            &served.owner,
            ActSurface::ThisInstall,
            machine,
            MachineRole::Removed,
            None,
        )
        .expect("the owner's removal lands after the role change");
    assert!(
        landing.held().is_none(),
        "the removal stands, it is not held"
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    let roster = fold
        .machine(machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("M has a roster chain after the removal");
    assert_eq!(
        roster.profile.role,
        MachineRole::Removed,
        "M's roster head is removed"
    );
    assert_eq!(
        roster.profile.revision, 3,
        "M's roster head is at revision 3"
    );
}

/// The owner's role change copies the roster's head: beside a stranger's
/// mark under other keys, at a higher revision, it keeps the machine's own
/// keys at revision 2. Before, his answer copied the stranger's keys.
#[test]
fn the_owners_role_change_keeps_a_machines_keys_beside_a_stranger_roots_mark_with_other_keys() {
    let (served, request) = enrolled_self_host();
    let machine = request.machine;
    let vault_id = served
        .vault
        .authority_fold()
        .expect("authority fold")
        .vault_id
        .expect("the vault is rooted");
    let (root, anchor, root_hash) = publish_stranger_root(&served, vault_id);
    let mark = stranger_mark_with_stranger_keys(
        &served,
        vault_id,
        root_and_roster_row(&served, machine, root_hash),
        &anchor,
        machine,
        MachineRole::Owned(MachineOwnership::Yours),
        2,
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&mark),
        "guard: the stranger's mark is in valid_entries"
    );
    let anchored = fold
        .machine(machine)
        .and_then(|folded| folded.anchored.get(&root.anchor_key))
        .expect("guard: the view holds F's chain");
    let stranger_key = signing(STRANGER_MACHINE_SEED).verifying_key().to_bytes();
    assert_eq!(
        anchored.profile.machine_key, stranger_key,
        "guard: the view's chain for F names the other machine key"
    );
    let demote = MachineRole::Owned(MachineOwnership::WorkSchool);
    let landing = served
        .vault
        .set_machine_role(
            &served.owner,
            ActSurface::ThisInstall,
            machine,
            demote,
            None,
        )
        .expect("the owner's role change lands beside the stranger's mark");
    assert!(
        landing.held().is_none(),
        "the role change stands, it is not held"
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    let roster = fold
        .machine(machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("M has a roster chain after the role change");
    assert_eq!(
        roster.profile.machine_key, request.machine_key,
        "M's roster head keeps M's machine key"
    );
    assert_eq!(
        roster.profile.encryption_key, request.encryption_key,
        "M's roster head keeps M's encryption key"
    );
    assert_eq!(
        roster.profile.machine_proof, request.machine_proof,
        "M's roster head keeps M's machine proof"
    );
    assert_eq!(
        roster.profile.role, demote,
        "M's roster head has the new role"
    );
    assert_eq!(
        roster.profile.revision, 2,
        "M's roster head is at revision 2"
    );
}

/// A class revision is numbered from the roster's head: beside a stranger's
/// mark one revision above that head it lands at revision 2. Before, the
/// next number topped every chain: 3 here, a number the fold now refuses
/// over a roster head at 1.
#[test]
fn a_machines_class_revision_lands_beside_a_stranger_roots_mark() {
    let (served, request) = enrolled_self_host();
    let machine = request.machine;
    let vault_id = served
        .vault
        .authority_fold()
        .expect("authority fold")
        .vault_id
        .expect("the vault is rooted");
    let (root, anchor, root_hash) = publish_stranger_root(&served, vault_id);
    let mark = stranger_mark_with_m_keys(
        &served,
        vault_id,
        root_and_roster_row(&served, machine, root_hash),
        &anchor,
        &request,
        MachineRole::Owned(MachineOwnership::Yours),
        2,
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&mark),
        "guard: the stranger's mark is in valid_entries"
    );
    assert!(
        fold.machine(machine)
            .and_then(|folded| folded.anchored.get(&root.anchor_key))
            .is_some_and(|anchored| anchored.profile.revision == 2),
        "guard: the view holds F's chain at revision 2, one above the roster's head"
    );
    let second = served.joining_machine_with_class(MachineDeviceClass::Phone);
    assert_eq!(second.machine, machine, "guard: the class revision names M");
    assert_eq!(
        second.machine_key, request.machine_key,
        "guard: the class revision keeps M's machine key"
    );
    assert_eq!(
        second.encryption_key, request.encryption_key,
        "guard: the class revision keeps M's encryption key"
    );
    assert_ne!(
        second.device_class, request.device_class,
        "guard: the class revision declares another class"
    );
    let landing = served
        .vault
        .enroll_machine(
            &served.owner,
            ActSurface::ThisInstall,
            &second,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the class revision lands beside the stranger's mark");
    assert!(
        landing.held().is_none(),
        "the class revision stands, it is not held"
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    let roster = fold
        .machine(machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("M has a roster chain after the class revision");
    assert_eq!(
        roster.profile.device_class,
        MachineDeviceClass::Phone,
        "M's roster head has the new class"
    );
    assert_eq!(
        roster.profile.revision, 2,
        "M's roster head is at revision 2"
    );
    assert_eq!(
        roster.profile.machine_key, request.machine_key,
        "M's roster head keeps M's keys"
    );
}

/// A class revision checks the keys of the roster's head: beside a
/// stranger's mark under other keys, one revision above that head, it still
/// lands at revision 2. Before, the door refused, because a head named other
/// keys than the request.
#[test]
fn a_machines_class_revision_lands_beside_a_stranger_roots_mark_with_other_keys() {
    let (served, request) = enrolled_self_host();
    let machine = request.machine;
    let vault_id = served
        .vault
        .authority_fold()
        .expect("authority fold")
        .vault_id
        .expect("the vault is rooted");
    let (root, anchor, root_hash) = publish_stranger_root(&served, vault_id);
    let mark = stranger_mark_with_stranger_keys(
        &served,
        vault_id,
        root_and_roster_row(&served, machine, root_hash),
        &anchor,
        machine,
        MachineRole::Owned(MachineOwnership::Yours),
        2,
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&mark),
        "guard: the stranger's mark is in valid_entries"
    );
    assert!(
        fold.machine(machine)
            .and_then(|folded| folded.anchored.get(&root.anchor_key))
            .is_some(),
        "guard: the view holds F's chain"
    );
    let second = served.joining_machine_with_class(MachineDeviceClass::Phone);
    let landing = served
        .vault
        .enroll_machine(
            &served.owner,
            ActSurface::ThisInstall,
            &second,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the class revision lands beside the stranger's mark");
    assert!(
        landing.held().is_none(),
        "the class revision stands, it is not held"
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    let roster = fold
        .machine(machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("M has a roster chain after the class revision");
    assert_eq!(
        roster.profile.revision, 2,
        "M's roster head is at revision 2"
    );
}

/// The owner's confirm is numbered from the standing heads: a held enrolment
/// of a machine that only a stranger's mark names confirms at roster
/// revision 1. Before, the next number topped every chain and the confirm
/// was refused.
#[test]
fn the_owners_confirm_of_a_held_enrolment_lands_beside_a_stranger_roots_mark() {
    let (served, request) = held_hosted_enrolment();
    let machine = request.machine;
    let vault_id = served
        .vault
        .authority_fold()
        .expect("authority fold")
        .vault_id
        .expect("the vault is rooted");
    let (root, anchor, root_hash) = publish_stranger_root(&served, vault_id);
    let mark = stranger_mark_with_m_keys(
        &served,
        vault_id,
        vec![root_hash],
        &anchor,
        &request,
        MachineRole::Owned(MachineOwnership::Yours),
        1,
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&mark),
        "guard: the stranger's mark is in valid_entries"
    );
    assert!(
        fold.machine(machine)
            .and_then(|folded| folded.anchored.get(&root.anchor_key))
            .is_some_and(|anchored| anchored.profile.revision == 1),
        "guard: the view holds F's chain of M"
    );
    served.enrol_owner_key();
    served
        .confirm(&served.held_entries())
        .expect("the owner's confirm lands beside the stranger's mark");
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.trusted_machine(machine).is_some(),
        "the confirmed machine is the owner's"
    );
    let roster = fold
        .machine(machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("M has a roster chain after the confirm");
    assert_eq!(
        roster.profile.revision, 1,
        "M's roster head is at revision 1"
    );
    assert_eq!(
        served.held().answers,
        Vec::new(),
        "nothing asks after the confirm"
    );
}

/// A stranger's mark under other keys never makes a held answer read as one
/// that replaces keys: the list says so, and the confirm lands under the
/// machine's own keys. Before, the list said `replaces_keys` and the confirm
/// was refused.
#[test]
fn a_stranger_roots_mark_with_other_keys_never_makes_a_held_answer_read_as_a_rekey() {
    let (served, request) = held_hosted_enrolment();
    let machine = request.machine;
    let vault_id = served
        .vault
        .authority_fold()
        .expect("authority fold")
        .vault_id
        .expect("the vault is rooted");
    let (_root, anchor, root_hash) = publish_stranger_root(&served, vault_id);
    let mark = stranger_mark_with_stranger_keys(
        &served,
        vault_id,
        vec![root_hash],
        &anchor,
        machine,
        MachineRole::Owned(MachineOwnership::Yours),
        1,
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&mark),
        "guard: the stranger's mark is in valid_entries"
    );
    let listing = served.held();
    assert_eq!(listing.answers.len(), 1, "guard: one held answer");
    assert!(
        !listing.answers[0].replaces_keys,
        "the held answer does not read as a rekey beside the stranger's mark"
    );
    served.enrol_owner_key();
    served
        .confirm(&served.held_entries())
        .expect("the owner's confirm lands beside the stranger's mark");
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.trusted_machine(machine).is_some(),
        "the confirmed machine is the owner's"
    );
    let roster = fold
        .machine(machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("M has a roster chain after the confirm");
    assert_eq!(
        roster.profile.machine_key, request.machine_key,
        "M's roster head names M's own machine key"
    );
    assert_eq!(
        roster.profile.encryption_key, request.encryption_key,
        "M's roster head names M's own encryption key"
    );
}

/// A machine cannot keep itself by carrying a stranger's mark into the main
/// log. M's own install key signs a frontier join whose parents are M's
/// roster row and the stranger's mark of M at revision 1; an admitted
/// machine needs only the carrier rule for a join. The join is a main-log
/// row, so the stranger's chain of M is in the past of every row written
/// after it. The owner's removal reads the roster's head all the same and
/// lands at revision 2: the admitter tells a trusted chain from a
/// stranger's, the row's place in the log does not.
#[test]
fn the_owner_removes_a_machine_whose_own_join_names_a_stranger_roots_mark() {
    let (served, request) = enrolled_self_host();
    let machine = request.machine;
    let vault_id = served
        .vault
        .authority_fold()
        .expect("authority fold")
        .vault_id
        .expect("the vault is rooted");
    let (_root, anchor, root_hash) = publish_stranger_root(&served, vault_id);
    let mark = stranger_mark_with_m_keys(
        &served,
        vault_id,
        vec![root_hash],
        &anchor,
        &request,
        MachineRole::Owned(MachineOwnership::Yours),
        1,
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&mark),
        "guard: the stranger's mark is in valid_entries"
    );
    let roster_row = fold
        .machine(machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("guard: M has a roster chain")
        .entry;
    let mut parents = vec![roster_row, mark];
    parents.sort_unstable();
    let join = signed(
        Some(vault_id),
        1,
        parents,
        AuthorityOp::FrontierJoin(FrontierJoin {
            family: FrontierJoinFamily::Install(machine),
            scope: FrontierJoinScope::Main,
        }),
        &signing(JOINING_SEED),
        &[],
    );
    let join_hash = hash(&join);
    served
        .vault
        .put_authority_log_entry(&join, AT, 2)
        .expect("M's own join is stored");
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&join_hash),
        "guard: M's join of its roster row and the stranger's mark is in valid_entries"
    );
    let landing = served
        .vault
        .set_machine_role(
            &served.owner,
            ActSurface::ThisInstall,
            machine,
            MachineRole::Removed,
            None,
        )
        .expect("the owner's removal lands after M's join named the stranger's mark");
    assert!(
        landing.held().is_none(),
        "the removal stands, it is not held"
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    let roster = fold
        .machine(machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("M has a roster chain after the removal");
    assert_eq!(
        roster.profile.role,
        MachineRole::Removed,
        "M's roster head is removed"
    );
    assert_eq!(
        roster.profile.revision, 2,
        "M's roster head is at revision 2"
    );
}

/// The owner makes M a machine pairing link that answers the role M
/// stands in, and M redeems it with its request and its machine key's
/// possession proof over this redemption: the credential-only
/// re-pairing (FIX 8636). Returns what the redemption gives.
fn re_pair_machine(served: &ServedVault, request: &MachineEnrolmentRequest) -> PairingRedeemed {
    redeem_machine_link(served, request).expect("M pairs again beside the stranger's mark")
}

/// The owner makes M a machine pairing link that answers the role M
/// stands in, and M redeems it with `request` and its machine key's
/// possession proof over this redemption. Returns the redeem door's answer.
fn redeem_machine_link(
    served: &ServedVault,
    request: &MachineEnrolmentRequest,
) -> oneiron::Result<PairingRedeemed> {
    let link = served
        .vault
        .issue_machine_pairing_link(
            &served.issuer,
            &served.owner,
            ActSurface::ThisInstall,
            Scope::top(),
            3600,
            PairingPrincipal::default(),
            MachineOwnership::Yours,
        )
        .expect("the owner makes M a machine pairing link");
    let holder = request.machine.to_hex();
    let connection = signing(CONNECTION_SEED);
    let binding_key = connection.verifying_key().to_bytes();
    let binding_transcript =
        pairing_binding_transcript_pinned(&link.code, &binding_key, &holder, link.pin.as_ref())
            .expect("the binding transcript of M's redemption");
    let binding = connection.sign(&binding_transcript).to_bytes();
    let possession_transcript = machine_possession_transcript(
        &request.vault_id,
        request.machine,
        &request.machine_key,
        &binding_transcript,
    );
    let possession = signing(JOINING_SEED)
        .sign(&possession_transcript)
        .to_bytes();
    served.vault.redeem_pairing_link_with_possession(
        &served.issuer,
        &link.code,
        &holder,
        binding_key,
        &binding,
        Some(request),
        Some(&possession),
    )
}

/// Credential-only re-pairing reads the heads M stands under here:
/// beside a stranger root's mark of M under other keys, one revision above
/// the roster's head, M pairs again and no revision is written. Before, the
/// re-pairing read the newest head over every chain of M, and the stranger's
/// mark refused it.
#[test]
fn a_machine_pairs_again_beside_a_stranger_roots_mark_with_other_keys() {
    let (served, request) = enrolled_self_host();
    let machine = request.machine;
    let vault_id = served
        .vault
        .authority_fold()
        .expect("authority fold")
        .vault_id
        .expect("the vault is rooted");
    let (root, anchor, root_hash) = publish_stranger_root(&served, vault_id);
    let mark = stranger_mark_with_stranger_keys(
        &served,
        vault_id,
        root_and_roster_row(&served, machine, root_hash),
        &anchor,
        machine,
        MachineRole::Owned(MachineOwnership::Yours),
        2,
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&mark),
        "guard: the stranger's mark is in valid_entries"
    );
    let anchored = fold
        .machine(machine)
        .and_then(|folded| folded.anchored.get(&root.anchor_key))
        .expect("guard: the view holds the stranger's chain of M");
    let stranger_key = signing(STRANGER_MACHINE_SEED).verifying_key().to_bytes();
    assert_eq!(
        anchored.profile.machine_key, stranger_key,
        "guard: the view's chain for the stranger names the other machine key"
    );
    let redeemed = re_pair_machine(&served, &request);
    assert!(
        redeemed.re_paired,
        "the redemption is the credential-only re-pairing"
    );
    assert!(
        redeemed.held_answer.is_none(),
        "the re-pairing stands, it is not held"
    );
    let named = redeemed
        .machine
        .as_ref()
        .expect("the redemption names M as it stands")
        .roster
        .as_ref()
        .expect("the named standing has M's roster chain");
    assert_eq!(named.profile.machine, machine, "the redemption names M");
    assert_eq!(
        named.profile.role,
        MachineRole::Owned(MachineOwnership::Yours),
        "the redemption names the role the link answers"
    );
    assert_eq!(
        named.profile.revision, 1,
        "the redemption names M at revision 1"
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    let roster = fold
        .machine(machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("M has a roster chain after the re-pairing");
    assert_eq!(
        roster.profile.revision, 1,
        "M's roster head is still at revision 1: no revision was written"
    );
    assert_eq!(
        roster.profile.machine_key, request.machine_key,
        "M's roster head keeps M's machine key"
    );
    assert_eq!(
        roster.profile.encryption_key, request.encryption_key,
        "M's roster head keeps M's encryption key"
    );
}

/// What one redemption by M left, as far as a stranger's mark must not
/// change it.
#[derive(Debug, PartialEq, Eq)]
struct RedemptionOutcome {
    /// The redeem door gave a credential.
    redeemed: bool,
    /// It was the credential-only re-pairing.
    re_paired: bool,
    /// Its machine answer is held.
    held: bool,
    /// The class of M's roster head after it.
    class: MachineDeviceClass,
    /// The revision of M's roster head after it.
    revision: u64,
}

/// M redeems a fresh machine pairing link with `request`. Returns what that
/// left.
fn redemption_outcome(
    served: &ServedVault,
    request: &MachineEnrolmentRequest,
) -> RedemptionOutcome {
    let redeemed = redeem_machine_link(served, request);
    let fold = served.vault.authority_fold().expect("authority fold");
    let roster = fold
        .machine(request.machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("M has a roster chain after the redemption");
    RedemptionOutcome {
        redeemed: redeemed.is_ok(),
        re_paired: redeemed.as_ref().is_ok_and(|given| given.re_paired),
        held: redeemed
            .as_ref()
            .is_ok_and(|given| given.held_answer.is_some()),
        class: roster.profile.device_class,
        revision: roster.profile.revision,
    }
}

/// A redemption that names another class than the roster holds for M is M's
/// class revision, whatever class a stranger root's mark names: it answers
/// as it does with no mark. Before, the re-pairing read the newest head over
/// every chain as M's class, so a stranger's mark above the roster under the
/// request's class made the redemption the credential-only re-pairing: M
/// took a credential, the roster kept the old class, and no carrier was
/// asked.
#[test]
fn a_stranger_roots_mark_under_the_requests_class_never_makes_a_class_change_a_re_pairing() {
    // With no stranger: what M's redemption under another class gives here.
    let (plain, plain_request) = enrolled_self_host();
    let plain_second = plain.joining_machine_with_class(MachineDeviceClass::Phone);
    assert_ne!(
        plain_second.device_class, plain_request.device_class,
        "guard: the redemption declares another class than the roster holds"
    );
    let without_mark = redemption_outcome(&plain, &plain_second);
    assert!(
        !without_mark.re_paired,
        "guard: with no mark a redemption under another class is never the credential-only \
         re-pairing"
    );

    // Beside a stranger's mark of M under that class, above the roster.
    let (served, request) = enrolled_self_host();
    let machine = request.machine;
    let vault_id = served
        .vault
        .authority_fold()
        .expect("authority fold")
        .vault_id
        .expect("the vault is rooted");
    let second = served.joining_machine_with_class(MachineDeviceClass::Phone);
    assert_eq!(second.machine, machine, "guard: the redemption names M");
    assert_eq!(
        second.machine_key, request.machine_key,
        "guard: the redemption keeps M's machine key"
    );
    assert_eq!(
        second.encryption_key, request.encryption_key,
        "guard: the redemption keeps M's encryption key"
    );
    assert_ne!(
        second.device_class, request.device_class,
        "guard: the redemption declares another class than the roster holds"
    );
    let (root, anchor, root_hash) = publish_stranger_root(&served, vault_id);
    let mark = stranger_mark_with_m_keys(
        &served,
        vault_id,
        root_and_roster_row(&served, machine, root_hash),
        &anchor,
        &second,
        MachineRole::Owned(MachineOwnership::Yours),
        2,
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&mark),
        "guard: the stranger's mark is in valid_entries"
    );
    assert!(
        fold.machine(machine)
            .and_then(|folded| folded.anchored.get(&root.anchor_key))
            .is_some_and(|anchored| {
                anchored.profile.revision == 2
                    && anchored.profile.device_class == MachineDeviceClass::Phone
            }),
        "guard: the view holds the stranger's chain of M above the roster, under the \
         redemption's class"
    );
    let with_mark = redemption_outcome(&served, &second);
    assert!(
        !with_mark.re_paired,
        "the stranger's mark does not make the class change a credential-only re-pairing: \
         beside the mark {with_mark:?}, with no mark {without_mark:?}"
    );
    assert_eq!(
        with_mark, without_mark,
        "beside the stranger's mark the redemption answers as it does with no mark"
    );
}

/// M's raw key carries the owner's `Owned(Yours)` answer about `target` at
/// `revision` on `parents`, signed at `seq`, and the answer is stored.
/// `node` is the key the answer names for `target`: M's own key when M
/// answers about itself. Returns the answer's hash.
fn m_carries_yours(
    served: &ServedVault,
    parents: Vec<AuthorityEntryHash>,
    seq: u64,
    carrier: EntityId,
    target: EntityId,
    node: &SigningKey,
    revision: u64,
) -> AuthorityEntryHash {
    let vault_id = served.vault_id();
    let mut profile = node_profile(
        vault_id,
        target,
        node,
        MachineRole::Owned(MachineOwnership::Yours),
        revision,
    );
    profile.carrier = Some(carrier);
    profile.act = Some(OwnerAct::by_owner(
        owner(),
        OwnerActKind::MachineAnswer,
        target,
        ActSurface::ThisInstall,
        machine_answer_revision(parents.iter().copied()),
    ));
    let entry = signed(
        Some(vault_id),
        seq,
        parents,
        AuthorityOp::MachineProfile(profile),
        &signing(JOINING_SEED),
        &[],
    );
    let answer = hash(&entry);
    served
        .vault
        .put_authority_log_entry(&entry, AT, 2)
        .expect("M's carried answer is stored");
    answer
}

/// A carried answer that skips a revision is refused, and the machine takes
/// its next answer: M's own answer at 3 over the roster head at 1 lands
/// nowhere, and the owner's answer lands at 2. Before, the fold took the
/// answer at 3.
#[test]
fn an_answer_that_skips_a_revision_is_refused_and_the_machine_takes_its_next_answer() {
    let (served, request) = enrolled_self_host();
    let machine = request.machine;
    let roster_row = served.roster_row(machine);
    let row = m_carries_yours(
        &served,
        vec![roster_row],
        1,
        machine,
        machine,
        &signing(JOINING_SEED),
        3,
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        !fold.valid_entries.contains(&row),
        "the fold refuses M's answer at revision 3 over the roster head at 1: {:?}",
        fold.issues
    );
    let roster = fold
        .machine(machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("M has a roster chain after the refused answer");
    assert!(roster.is_live(), "M's roster head is still live");
    assert_eq!(
        roster.profile.revision, 1,
        "M's roster head is still at revision 1"
    );
    let landing = served
        .vault
        .set_machine_role(
            &served.owner,
            ActSurface::ThisInstall,
            machine,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner's next answer for M lands");
    assert!(
        landing.held().is_none(),
        "the owner's answer stands, it is not held"
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    let roster = fold
        .machine(machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("M has a roster chain after the owner's answer");
    assert_eq!(
        roster.profile.revision, 2,
        "M's roster head is at revision 2: {:?}",
        fold.issues
    );
}

/// A carried answer at the last revision a profile can name is refused, and
/// the owner still removes the machine: the row at `u64::MAX` lands nowhere,
/// so the removal lands at revision 2. Before, the row landed and the
/// machine had no next number: no door could answer about it again (FIX
/// 25887).
#[test]
fn an_answer_at_the_last_revision_is_refused_and_the_owner_still_removes_the_machine() {
    let (served, request) = enrolled_self_host();
    let machine = request.machine;
    let roster_row = served.roster_row(machine);
    let row = m_carries_yours(
        &served,
        vec![roster_row],
        1,
        machine,
        machine,
        &signing(JOINING_SEED),
        u64::MAX,
    );
    let landing = served
        .vault
        .set_machine_role(
            &served.owner,
            ActSurface::ThisInstall,
            machine,
            MachineRole::Removed,
            None,
        )
        .expect("the owner removes the machine after a row at the last revision");
    assert!(
        landing.held().is_none(),
        "the removal stands, it is not held"
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    let roster = fold
        .machine(machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("M has a roster chain after the removal");
    assert_eq!(
        roster.profile.role,
        MachineRole::Removed,
        "M's roster head is removed"
    );
    assert_eq!(
        roster.profile.revision, 2,
        "M's roster head is at revision 2"
    );
    assert!(
        !fold.valid_entries.contains(&row),
        "the row at the last revision is not in valid_entries: {:?}",
        fold.issues
    );
}

/// A stranger root's mark that skips a revision is refused: the anchor's
/// marks at `u64::MAX` and at 3 land nowhere and leave the machine no chain
/// of that anchor, while its mark at 2, one above the roster's head, heads
/// the anchor's chain. Before, the fold took a first mark at any number.
#[test]
fn a_stranger_roots_mark_that_skips_a_revision_is_refused() {
    let (served, request) = enrolled_self_host();
    let machine = request.machine;
    let (root, anchor, root_hash) = publish_stranger_root(&served, served.vault_id());
    let yours = MachineRole::Owned(MachineOwnership::Yours);
    let at_the_last = stranger_mark_at(
        &served,
        (vec![root_hash], 2),
        &anchor,
        &request,
        yours,
        u64::MAX,
    );
    let at_three = stranger_mark_at(&served, (vec![root_hash], 3), &anchor, &request, yours, 3);
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        !fold.valid_entries.contains(&at_the_last),
        "the anchor's mark at the last revision is refused: {:?}",
        fold.issues
    );
    assert!(
        !fold.valid_entries.contains(&at_three),
        "the anchor's mark at 3 is refused: {:?}",
        fold.issues
    );
    assert!(
        fold.machine(machine)
            .and_then(|folded| folded.anchored.get(&root.anchor_key))
            .is_none(),
        "M has no chain of that anchor"
    );
    let mark = stranger_mark_at(
        &served,
        (root_and_roster_row(&served, machine, root_hash), 4),
        &anchor,
        &request,
        yours,
        2,
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&mark),
        "the anchor's mark at 2, one above the roster head at 1, is valid: {:?}",
        fold.issues
    );
    let anchored = fold
        .machine(machine)
        .and_then(|folded| folded.anchored.get(&root.anchor_key))
        .expect("the view holds the anchor's chain of M");
    assert_eq!(
        anchored.profile.revision, 2,
        "the anchor's chain is headed at revision 2"
    );
}

/// A stranger root's chain climbs one revision a row: its marks at 2 and 3
/// land, its mark at 5 over them is refused, and the owner's removal still
/// lands at roster revision 2. Before, the mark at 5 landed.
#[test]
fn a_stranger_roots_chain_climbs_one_revision_a_row() {
    let (served, request) = enrolled_self_host();
    let machine = request.machine;
    let (root, anchor, root_hash) = publish_stranger_root(&served, served.vault_id());
    let yours = MachineRole::Owned(MachineOwnership::Yours);
    let first = stranger_mark_at(
        &served,
        (root_and_roster_row(&served, machine, root_hash), 2),
        &anchor,
        &request,
        yours,
        2,
    );
    let second = stranger_mark_at(&served, (vec![first], 3), &anchor, &request, yours, 3);
    let skipping = stranger_mark_at(&served, (vec![second], 4), &anchor, &request, yours, 5);
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&first),
        "the anchor's mark at 2, one above the roster head at 1, is valid: {:?}",
        fold.issues
    );
    assert!(
        fold.valid_entries.contains(&second),
        "the anchor's mark at 3, one above its mark at 2, is valid: {:?}",
        fold.issues
    );
    assert!(
        !fold.valid_entries.contains(&skipping),
        "the anchor's mark at 5 over its chain's head at 3 is refused: {:?}",
        fold.issues
    );
    let anchored = fold
        .machine(machine)
        .and_then(|folded| folded.anchored.get(&root.anchor_key))
        .expect("the view holds the anchor's chain of M");
    assert_eq!(
        anchored.profile.revision, 3,
        "the anchor's chain head stays at revision 3"
    );
    let landing = served
        .vault
        .set_machine_role(
            &served.owner,
            ActSurface::ThisInstall,
            machine,
            MachineRole::Removed,
            None,
        )
        .expect("the owner's removal lands beside the stranger's chain");
    assert!(
        landing.held().is_none(),
        "the removal stands, it is not held"
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    let roster = fold
        .machine(machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("M has a roster chain after the removal");
    assert_eq!(
        roster.profile.role,
        MachineRole::Removed,
        "M's roster head is removed"
    );
    assert_eq!(
        roster.profile.revision, 2,
        "M's roster head is at revision 2"
    );
}

/// An unproven answer that skips a revision is refused and never held: M's
/// answer at 3 about a machine no chain names is neither valid nor held and
/// asks the owner nothing, while the same answer at 1 is held. Before, the
/// answer at 3 was held, and a confirm of it would have landed at 3.
#[test]
fn an_unproven_answer_that_skips_a_revision_is_refused_and_never_held() {
    let (served, request) = enrolled_self_host();
    let machine = request.machine;
    let roster_row = served.roster_row(machine);
    let target = EntityId::from_bytes([0x77; 16]).expect("an id");
    let target_key = signing(UNNAMED_MACHINE_SEED);
    let skipping = m_carries_yours(
        &served,
        vec![roster_row],
        1,
        machine,
        target,
        &target_key,
        3,
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        !fold.valid_entries.contains(&skipping),
        "the unproven answer at revision 3 about a machine no chain names is refused: {:?}",
        fold.issues
    );
    assert!(
        fold.held_machine_answers().get(&target).is_none(),
        "the refused answer is not among the held answers"
    );
    assert!(
        !served.held_entries().contains(&skipping),
        "the refused answer asks the owner nothing"
    );
    let first = m_carries_yours(
        &served,
        vec![roster_row],
        2,
        machine,
        target,
        &target_key,
        1,
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.held_machine_answers()
            .get(&target)
            .is_some_and(|answers| answers.contains_key(&first)),
        "the same answer at revision 1 is held: {:?}",
        fold.issues
    );
    assert!(
        served.held_entries().contains(&first),
        "the held answer at revision 1 asks the owner"
    );
}
