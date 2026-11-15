//! Every fold judge all installs share reads a machine's roster chain alone,
//! never an anchor's (Fable pass 29, step K3; branch
//! opus-anchor-judges/shared-judges-read-roster, on #8673 at a18a1518667c).
//!
//! Any fresh key publishes an owner root, and that root's anchor marks any
//! machine in its own chain, owned or removed, under any keys that carry
//! their own machine proof. Four shared judges read every chain: an owner
//! key enrollment's holding machine was live when no chain removed it and
//! some chain was live; a residence result's signer stood under any chain
//! saying "yours"; a one-machine read pick named a machine some chain
//! admitted; and the ten owner-act gates asking whether a machine's chain
//! names the signing key counted an anchor's chain too. So one stranger's
//! mark refused enrollments for a roster-live machine, admitted residence
//! results and read picks for machines the roster never held, and carried
//! rows signed by keys only the stranger named as far as the carrier rule,
//! which (#8673) refused them as valid, without effect. Now each judge
//! reads the roster's chain alone: the enrollment's machine is live when
//! its roster head is live, the result's signer must be the live, answered
//! roster head's key, the pick names a roster-linked machine, and the
//! names-the-key gates read the roster head or an accepted roster revision.
//! The residence directive doors read the result judge's key too, so no
//! directive is issued to, or run on, a machine whose result never stands.
//!
//! Each test serves a self-host vault that pins no root, so this install
//! stands under the roster's chain alone; T5 alone pins the owner's root.
//! Each test's main assertion is the head's verdict: it fails on the base
//! and passes on the head.

#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActAuthority, ActSurface, AuthorityEntryHash, AuthorityKey,
    AuthorityLogEntry, AuthorityOp, AuthoritySignature, AuthorityVaultId, HostSlipIssuer,
    MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass,
    MachineEncryptionKey, MachineEnrolmentRequest, MachineOwnership, MachineProfile,
    MachineRevision, MachineRole, ModelOrder, OwnerAct, OwnerActKind, OwnerKeyEnrollment,
    OwnerKeyEnrollmentReceipt, OwnerRootRecord, ReadLocation, ResidenceAct, ResidenceDirective,
    ResidenceResult, ResidenceResultStatus, SealedCopies, WorldPrivacy, WorldPrivacyEdit,
    authority_entry_hash, authority_transcript, machine_profile_proof_transcript,
    owner_key_enrollment_challenge,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::world_keys::RecoveryRootSeed;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_authority::authority::{FrontierJoin, FrontierJoinFamily, FrontierJoinScope};

/// The seed of the joining machine's machine key.
const JOINING_SEED: u8 = 68;
/// The seed of the machine key a stranger holds for the machine it marks.
const STRANGER_MACHINE_SEED: u8 = 71;
/// The seeds of the owner keys the tests enrol through the door.
const OWNER_KEY_SEED: u8 = 0xE1;
const OWNER_KEY_SEED_2: u8 = 0xE2;
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

/// `signer` alone signs `op` on `parent_hashes`.
fn signed(
    vault_id: AuthorityVaultId,
    seq: u64,
    parent_hashes: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
    signer: &SigningKey,
) -> AuthorityLogEntry {
    let mut row = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(vault_id),
        seq,
        parent_hashes,
        op,
        signer: signature_slot(key_of(signer)),
        cosigns: Vec::new(),
        ts: 1,
    };
    let transcript = authority_transcript(&row).expect("the transcript");
    row.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    row
}

fn hash(row: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(row).expect("a hash")
}

/// The stranger root's owner person, distinct from the vault's owner.
fn stranger_owner() -> EntityId {
    EntityId::from_bytes([0xA1; 16]).expect("an id")
}

/// A self-host vault as its own server starts one: this install serving and
/// profiled under the host root, and the owner bound and authenticated.
struct ServedVault {
    vault: Vault,
    owner: AuthenticatedOwner,
    /// The owner's PERSON, bound to a live human actor.
    person: EntityId,
    /// This install, the carrier of every owner act its doors sign.
    carrier: EntityId,
    issuer: HostSlipIssuer,
    _dir: tempfile::TempDir,
}

impl ServedVault {
    fn self_host() -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("self-host vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        let carrier = vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile under the host root")
            .roster
            .expect("guard: this install has a roster chain")
            .profile
            .machine;
        let person = vault.ensure_embedded_owner_actor().expect("the owner");
        oneiron::test_support::bind_host_owner(&vault, &issuer, person)
            .expect("the owner's binding");
        let owner = vault
            .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
            .expect("the owner's proof");
        Self {
            vault,
            owner,
            person,
            carrier,
            issuer,
            _dir: dir,
        }
    }

    fn vault_id(&self) -> AuthorityVaultId {
        self.vault
            .authority_fold()
            .expect("authority fold")
            .vault_id
            .expect("the vault is rooted")
    }

    /// This install's roster head.
    fn carrier_roster(&self) -> MachineRevision {
        self.vault
            .authority_fold()
            .expect("authority fold")
            .machine(self.carrier)
            .and_then(|folded| folded.roster.clone())
            .expect("guard: this install has a roster chain")
    }

    /// Another machine's request to join this vault.
    fn joining_machine(&self) -> MachineEnrolmentRequest {
        self.request_for(
            EntityId::from_bytes([0x76; 16]).expect("an id"),
            &signing(JOINING_SEED),
        )
    }

    /// `machine`'s identity under the machine key `node`, with its own proof.
    fn request_for(&self, machine: EntityId, node: &SigningKey) -> MachineEnrolmentRequest {
        let vault_id = self.vault_id();
        let machine_key = node.verifying_key().to_bytes();
        let device_class = MachineDeviceClass::Computer;
        let encryption_key = MachineEncryptionKey {
            suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
            key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
        };
        let machine_proof = node
            .sign(&machine_profile_proof_transcript(
                &vault_id,
                machine,
                &machine_key,
                device_class,
                &encryption_key,
            ))
            .to_bytes();
        MachineEnrolmentRequest {
            vault_id,
            machine,
            machine_key,
            device_class,
            encryption_key,
            machine_proof,
        }
    }

    /// The owner enrols `request` as his own, carried by this install.
    fn enrol(&self, request: &MachineEnrolmentRequest) -> oneiron::Result<()> {
        self.vault
            .enroll_machine(
                &self.owner,
                ActSurface::ThisInstall,
                request,
                MachineRole::Owned(MachineOwnership::Yours),
                None,
            )
            .map(drop)
    }
}

/// A stranger's root published on one held valid row and stored. Returns its
/// anchor signing key and the root row's hash.
fn publish_stranger_root(served: &ServedVault) -> (SigningKey, AuthorityEntryHash) {
    let vault_id = served.vault_id();
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
        vault_id,
        1,
        vec![parent],
        AuthorityOp::OwnerRoot(record),
        &anchor,
    );
    let root_hash = hash(&entry);
    served
        .vault
        .put_authority_log_entry(&entry, AT, 2)
        .expect("the stranger's root row is stored");
    assert!(
        served
            .vault
            .authority_fold()
            .expect("authority fold")
            .valid_entries
            .contains(&root_hash),
        "guard: the stranger's root is in valid_entries"
    );
    (anchor, root_hash)
}

/// The stranger's anchor marks this install removed at revision 1 under the
/// install's own keys and machine proof (seq 2, on the root), then joins
/// that mark into the main log beside the install's roster row (seq 3), so
/// the next owner act's parents carry the mark. Returns the mark's and the
/// join's hashes.
fn stranger_removes_the_carrier(
    served: &ServedVault,
    anchor: &SigningKey,
    root: AuthorityEntryHash,
) -> (AuthorityEntryHash, AuthorityEntryHash) {
    let vault_id = served.vault_id();
    let roster = served.carrier_roster();
    let profile = MachineProfile {
        owner: stranger_owner(),
        role: MachineRole::Removed,
        revision: 1,
        seen_world_edits: BTreeSet::new(),
        carrier: None,
        act: None,
        ..roster.profile.clone()
    };
    let mark = signed(
        vault_id,
        2,
        vec![root],
        AuthorityOp::MachineProfile(profile),
        anchor,
    );
    let mark_hash = hash(&mark);
    served
        .vault
        .put_authority_log_entry(&mark, AT, 2)
        .expect("the stranger's removal mark is stored");
    let mut parents = vec![roster.entry, mark_hash];
    parents.sort_unstable();
    let join = signed(
        vault_id,
        3,
        parents,
        AuthorityOp::FrontierJoin(FrontierJoin {
            family: FrontierJoinFamily::Anchor,
            scope: FrontierJoinScope::Main,
        }),
        anchor,
    );
    let join_hash = hash(&join);
    served
        .vault
        .put_authority_log_entry(&join, AT, 2)
        .expect("the stranger's main-log join is stored");

    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&mark_hash),
        "guard: the stranger's removal mark is in valid_entries"
    );
    assert!(
        fold.valid_entries.contains(&join_hash),
        "guard: the stranger's join of the mark into the main log is in valid_entries"
    );
    let folded = fold
        .machine(served.carrier)
        .expect("guard: this install is a machine of the vault");
    assert!(
        folded
            .anchored
            .get(&anchor.verifying_key().to_bytes())
            .is_some_and(|chain| chain.removed),
        "guard: the stranger's chain holds this install removed"
    );
    assert!(
        folded.roster.as_ref().is_some_and(|chain| chain.is_live()),
        "guard: this install's roster chain stays live"
    );
    (mark_hash, join_hash)
}

/// The stranger's anchor marks `machine` in `role` at `revision` under the
/// held machine key `node` with its own proof (seq 2, on the root): an
/// act-free anchor's own mark, like the carrier test's forgery. Stored;
/// returns the mark's hash.
fn stranger_mark(
    served: &ServedVault,
    anchor: &SigningKey,
    root: AuthorityEntryHash,
    machine: EntityId,
    node: &SigningKey,
    role: MachineRole,
    revision: u64,
) -> AuthorityEntryHash {
    let vault_id = served.vault_id();
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
        owner: stranger_owner(),
        machine_key,
        device_class: MachineDeviceClass::Computer,
        encryption_key,
        role,
        revision,
        machine_proof,
        seen_world_edits: BTreeSet::new(),
        carrier: None,
        act: None,
    };
    let entry = signed(
        vault_id,
        2,
        vec![root],
        AuthorityOp::MachineProfile(profile),
        anchor,
    );
    let mark = hash(&entry);
    served
        .vault
        .put_authority_log_entry(&entry, AT, 2)
        .expect("the stranger's mark is stored");
    mark
}

/// The owner enrols the fresh key `signing(seed)` for the carrier machine,
/// carried by this install with the host root as predecessor. The door
/// answers `Ok` only once the fold counted the enrollment here, with the
/// key live on the roster.
fn enroll_owner_key(served: &ServedVault, seed: u8) -> oneiron::Result<OwnerKeyEnrollmentReceipt> {
    let new_key = signing(seed);
    let public_key = new_key.verifying_key().to_bytes();
    let vault_id = served.vault_id();
    let challenge =
        owner_key_enrollment_challenge(&vault_id, served.carrier, &public_key, served.person)
            .expect("the enrollment challenge");
    let proof = new_key.sign(&challenge).to_bytes().to_vec();
    let authority = ActAuthority::Owner(served.owner.clone(), ActSurface::ThisInstall);
    served.vault.enrol_owner_signing_key_as_host(
        &authority,
        OwnerKeyEnrollment {
            machine: served.carrier,
            public_key,
            proof,
        },
        &served.issuer,
    )
}

/// The owner's edit of `world`'s settings, carried by `machine` and signed
/// by `signer` alone (seq 1: the signer's first row), naming `parents`.
/// Stored; returns the edit's hash.
fn store_world_edit(
    served: &ServedVault,
    parents: Vec<AuthorityEntryHash>,
    machine: EntityId,
    signer: &SigningKey,
    world: EntityId,
    settings: WorldPrivacy,
) -> AuthorityEntryHash {
    let vault_id = served.vault_id();
    let act = OwnerAct::by_owner(
        served.person,
        OwnerActKind::WorldPrivacy,
        world,
        ActSurface::ThisInstall,
        [0; 32],
    );
    let edit = WorldPrivacyEdit {
        world,
        act,
        machine,
        settings,
    };
    let entry = signed(
        vault_id,
        1,
        parents,
        AuthorityOp::WorldPrivacy(edit),
        signer,
    );
    let edit_hash = hash(&entry);
    served
        .vault
        .put_authority_log_entry(&entry, AT, 2)
        .expect("the world edit is stored");
    edit_hash
}

/// T1 (site 1): a stranger's removal mark of a roster-live machine refuses
/// no owner key enrollment for it.
///
/// Direction 2 of the brief: the enrolled machine is live on the roster and
/// a stranger's anchor marks it Removed, joined into the main log so the
/// enrollment's parents carry the mark. Chosen because a public door
/// (`Vault::enrol_owner_signing_key_as_host`) builds the `OwnerKeyEnroll`
/// row, so no hand-built enrollment shape is needed, and the verdict is the
/// door's own answer plus roster membership. Direction 1 (a machine only a
/// stranger marks live) would need a hand-built enrollment under a held
/// predecessor key, which no public seam signs with.
///
/// Base (`owner_key_enrollment.rs:98-102` calling `machine_is_live` at
/// `:120-125`): the holding machine is live when no chain removed it and
/// some chain is live, so the stranger's removal mark makes the enrollment
/// `InvalidEntry`; the door rolls back and answers `NOT_COUNTED`
/// (`owner_key_enrollment_door.rs:274-279`). Head (`:98-102` calling
/// `:124-128`): the machine is live when its roster head is live, so the
/// enrollment counts and the door answers `Ok`.
///
/// Observed through the door's `Result` and, on success,
/// `AuthorityFold::valid_entries` (`.contains` at
/// `authority/valid_entries.rs:39`) and the `roster` map
/// (`authority/fold_state.rs:48`).
#[test]
fn a_strangers_removal_mark_of_the_holding_machine_refuses_no_owner_key_enrollment() {
    let served = ServedVault::self_host();
    let first = enroll_owner_key(&served, OWNER_KEY_SEED)
        .expect("guard: the door enrols a first owner key before any stranger mark");
    assert!(
        served
            .vault
            .authority_fold()
            .expect("authority fold")
            .roster
            .get(&AuthorityKey::Ed25519(first.public_key))
            .is_some_and(|device| !device.revoked),
        "guard: the first key is live on the roster"
    );

    let (anchor, root) = publish_stranger_root(&served);
    let (mark, join) = stranger_removes_the_carrier(&served, &anchor, root);

    let receipt = enroll_owner_key(&served, OWNER_KEY_SEED_2)
        .expect("the owner's enrollment for his roster-live install lands beside a stranger's removal mark of it");
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&receipt.entry),
        "the enrollment is in valid_entries"
    );
    assert!(
        fold.roster
            .get(&AuthorityKey::Ed25519(receipt.public_key))
            .is_some_and(|device| !device.revoked),
        "the enrolled key is live on the roster"
    );
    assert_eq!(
        receipt.machine, served.carrier,
        "the enrollment holds the key on this install"
    );
    for row in [root, mark, join, first.entry] {
        assert!(
            fold.valid_entries.contains(&row),
            "the stranger's root, mark and join, and the first enrollment, stay valid"
        );
    }
}

/// T2 (site 2): a residence result signed under only a stranger's "yours"
/// mark is invalid.
///
/// Machine X has no roster revision; only the stranger's anchor marks X
/// `Owned(Yours)` under the held key K. The directive to X is hand-signed
/// by an owner key the door enrolled (the residence door would refuse X:
/// `issue_residence_directive_as` needs X's live, answered roster head,
/// and the host alone signs directives). The directive
/// names the enrollment and the mark as parents, so its parent state holds
/// the key on the roster (the mark hangs off an arbitrary valid row). The
/// result, X's answer naming the directive's row as a parent, is
/// hand-signed by K.
///
/// Base (`entry_transition.rs:639-649`): the signer stands under any chain
/// saying "yours", so the stranger's mark carries the result and it is
/// valid. Head (`:641-648`): the signer must be the live, answered roster
/// head's key, so X, with no roster revision, carries nothing and the
/// result is `SignerNotInAncestry`. The variant is by elimination: the
/// signer is Ed25519 (`:632-634`), the directive's row is a parent
/// (`:635-640`), and K signed no earlier row, so the machine check is the
/// only failing check.
///
/// Observed through `AuthorityFold::valid_entries` (`.contains` at
/// `authority/valid_entries.rs:39`); a result changes no state, so
/// membership is its whole verdict.
#[test]
fn a_residence_result_signed_under_only_a_strangers_yours_mark_is_invalid() {
    let served = ServedVault::self_host();
    let vault_id = served.vault_id();
    let receipt = enroll_owner_key(&served, OWNER_KEY_SEED)
        .expect("guard: the door enrols the owner key that signs the directive");
    let owner_key = signing(OWNER_KEY_SEED);

    let (anchor, root) = publish_stranger_root(&served);
    let machine = EntityId::from_bytes([0xE2; 16]).expect("an id");
    let node = signing(STRANGER_MACHINE_SEED);
    let mark = stranger_mark(
        &served,
        &anchor,
        root,
        machine,
        &node,
        MachineRole::Owned(MachineOwnership::Yours),
        1,
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&mark),
        "guard: the stranger's mark of X is in valid_entries"
    );
    assert!(
        fold.machine(machine).is_some_and(|folded| folded
            .anchored
            .get(&anchor.verifying_key().to_bytes())
            .is_some_and(|chain| chain.says_yours())
            && folded.roster.is_none()),
        "guard: only the stranger's chain holds X, live and saying yours"
    );

    let directive_id = EntityId::from_bytes([0xD2; 16]).expect("an id");
    let directive = ResidenceDirective {
        id: directive_id,
        machine,
        owner: served.person,
        issued_at: 1,
        act: ResidenceAct::SyncAll,
    };
    let mut directive_parents = vec![receipt.entry, mark];
    directive_parents.sort_unstable();
    let directive_row = signed(
        vault_id,
        1,
        directive_parents,
        AuthorityOp::ResidenceDirective(directive),
        &owner_key,
    );
    let directive_hash = hash(&directive_row);
    served
        .vault
        .put_authority_log_entry(&directive_row, AT, 2)
        .expect("the directive is stored");
    assert!(
        served
            .vault
            .authority_fold()
            .expect("authority fold")
            .valid_entries
            .contains(&directive_hash),
        "guard: the directive to X is in valid_entries"
    );

    let result = ResidenceResult {
        directive: directive_id,
        machine,
        directive_entry: directive_hash,
        finished_at: 2,
        status: ResidenceResultStatus::Applied,
        count: 0,
        reason: None,
    };
    let mut parents = vec![directive_hash, mark];
    parents.sort_unstable();
    let result_row = signed(
        vault_id,
        1,
        parents,
        AuthorityOp::ResidenceResult(result),
        &node,
    );
    let result_hash = hash(&result_row);
    served
        .vault
        .put_authority_log_entry(&result_row, AT, 2)
        .expect("the residence result is stored");

    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        !fold.valid_entries.contains(&result_hash),
        "a residence result signed under only a stranger's yours mark stood"
    );
    for row in [root, mark, directive_hash, receipt.entry] {
        assert!(
            fold.valid_entries.contains(&row),
            "the stranger's root and mark, the directive and the enrollment stay valid"
        );
    }
}

/// T3 (site 3): a one-machine read pick of a machine only a stranger marks
/// yours is invalid.
///
/// The edit is carried by M, the owner's roster-live machine, signed by M's
/// held install key, and reads `OneMachine(T)`, where T has no roster
/// revision and only the stranger's anchor marks T `Owned(Yours)`. The
/// signer gate passes on both trees (the roster names M's key), so only the
/// read-pick judge differs.
///
/// Base (`world_strength.rs:321` calling `Standing::is_admitted` at
/// `machine_standing.rs:277-279`, which reads `FoldedMachine::is_admitted`,
/// any chain saying yours): the stranger's mark admits T, the edit is
/// valid and takes effect. Head (`world_strength.rs:322` calling
/// `is_linked` at `machine_standing.rs:280-282`): T's roster head is
/// missing, so the edit is `InvalidEntry` (`world_strength.rs:324`).
///
/// Observed through `AuthorityFold::valid_entries` (`.contains` at
/// `authority/valid_entries.rs:39`) and the `worlds` map
/// (`authority/fold_state.rs:95`), whose `FoldedWorld.live`
/// (`authority/world_privacy.rs:93`) holds the edit only where it took
/// effect.
#[test]
fn a_one_machine_read_pick_of_only_a_strangers_yours_machine_is_invalid() {
    let served = ServedVault::self_host();
    let request = served.joining_machine();
    served
        .enrol(&request)
        .expect("the owner's enrolment of M lands");
    let machine = request.machine;
    let node = signing(JOINING_SEED);
    let fold = served.vault.authority_fold().expect("authority fold");
    let m_entry = fold
        .machine(machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("guard: M has a roster chain")
        .entry;
    assert!(
        fold.valid_entries.contains(&m_entry),
        "guard: M's enrolment answer is in valid_entries"
    );

    let (anchor, root) = publish_stranger_root(&served);
    let target = EntityId::from_bytes([0xE3; 16]).expect("an id");
    let mark = stranger_mark(
        &served,
        &anchor,
        root,
        target,
        &signing(STRANGER_MACHINE_SEED),
        MachineRole::Owned(MachineOwnership::Yours),
        1,
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&mark),
        "guard: the stranger's mark of T is in valid_entries"
    );
    assert!(
        fold.machine(target).is_some_and(|folded| folded
            .anchored
            .get(&anchor.verifying_key().to_bytes())
            .is_some_and(|chain| chain.says_yours())
            && folded.roster.is_none()),
        "guard: only the stranger's chain holds T, live and saying yours"
    );

    let world = EntityId::from_bytes([0xB3; 16]).expect("an id");
    let settings = WorldPrivacy {
        read: ReadLocation::OneMachine(target),
        sealed: SealedCopies::CloudAndMyMachines,
        models: ModelOrder::Inherit,
    };
    let mut parents = vec![m_entry, mark];
    parents.sort_unstable();
    let edit = store_world_edit(&served, parents, machine, &node, world, settings);

    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        !fold.valid_entries.contains(&edit),
        "a one-machine read pick of a machine only a stranger marks yours stood"
    );
    assert!(
        fold.worlds
            .get(&world)
            .is_none_or(|folded| !folded.live.contains_key(&edit)),
        "the refused pick took effect on the world"
    );
    for row in [root, mark, m_entry] {
        assert!(
            fold.valid_entries.contains(&row),
            "the stranger's root and mark, and M's answer, stay valid"
        );
    }
}

/// T4 (site 4): a world edit signed by a key only a stranger's chain names
/// is invalid at the gate.
///
/// The edit names M, the owner's roster-live machine, but is signed by K,
/// which only the stranger's anchor chain of M names (the mark holds M
/// `Owned(Yours)` under K). Of the ten gated rows the world edit is the
/// simplest to build by hand: an `OwnerAct`, a machine and full settings,
/// with no grant, key or ask state. Its read is `MyMachines`, so only the
/// names-the-key gate differs between the trees.
///
/// Base (`world_strength.rs:307-308` calling `Standing::names_key` at
/// `machine_standing.rs:331-333`, which reads
/// `FoldedMachine::names_key`, any chain): the stranger's chain names K,
/// the gate passes, and the carrier rule then refuses the row as valid,
/// without effect (`refused_world_edits`, `world_strength.rs:333`). Head
/// (`machine_standing.rs:337-339`, reading `roster_names_key` at
/// `machine_profile/mod.rs:439-444`): the roster
/// names only M's key, so the row is `SignerNotInAncestry` at the gate.
///
/// Observed through `AuthorityFold::valid_entries` (`.contains` at
/// `authority/valid_entries.rs:39`) and `refused_world_edits`
/// (`authority/fold_state.rs:98`): on the base the row is in both sets, on
/// the head in neither.
#[test]
fn a_world_edit_signed_by_only_a_strangers_named_key_is_invalid_at_the_gate() {
    let served = ServedVault::self_host();
    let request = served.joining_machine();
    served
        .enrol(&request)
        .expect("the owner's enrolment of M lands");
    let machine = request.machine;
    let fold = served.vault.authority_fold().expect("authority fold");
    let m_entry = fold
        .machine(machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("guard: M has a roster chain")
        .entry;

    let (anchor, root) = publish_stranger_root(&served);
    let stranger_key = signing(STRANGER_MACHINE_SEED);
    let named = stranger_key.verifying_key().to_bytes();
    let mark = stranger_mark(
        &served,
        &anchor,
        root,
        machine,
        &stranger_key,
        MachineRole::Owned(MachineOwnership::Yours),
        1,
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&mark),
        "guard: the stranger's mark of M is in valid_entries"
    );
    assert!(
        fold.machine(machine).is_some_and(|folded| folded
            .anchored
            .get(&anchor.verifying_key().to_bytes())
            .is_some_and(|chain| chain.profile.machine_key == named)),
        "guard: the stranger's chain of M names K"
    );

    let world = EntityId::from_bytes([0xB4; 16]).expect("an id");
    let settings = WorldPrivacy {
        read: ReadLocation::MyMachines,
        sealed: SealedCopies::CloudAndMyMachines,
        models: ModelOrder::Inherit,
    };
    let mut parents = vec![m_entry, mark];
    parents.sort_unstable();
    let edit = store_world_edit(&served, parents, machine, &stranger_key, world, settings);

    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        !fold.valid_entries.contains(&edit),
        "a world edit signed by a key only a stranger's chain names stood"
    );
    assert!(
        !fold.refused_world_edits.contains(&edit),
        "the gated-out edit stands refused without effect"
    );
    for row in [root, mark, m_entry] {
        assert!(
            fold.valid_entries.contains(&row),
            "the stranger's root and mark, and M's answer, stay valid"
        );
    }
}

/// G (guard): the same world edit under the roster-named key stands, with
/// effect, on both trees.
///
/// M's held install key signs an edit M carries with a `MyMachines` read:
/// the names-the-key gate reads the roster on both trees, the carrier rule
/// admits M, and the edit lands in the world's live frontier. It passes on
/// the base and on the head, proving the T4 rigging refuses only the
/// stranger-named key.
///
/// Observed through `AuthorityFold::valid_entries`
/// (`authority/valid_entries.rs:39`), the `worlds` map
/// (`authority/fold_state.rs:95`) with `FoldedWorld.live` and
/// `live_settings` (`authority/world_privacy.rs:93-97`), and
/// `refused_world_edits` (`authority/fold_state.rs:98`).
#[test]
fn a_world_edit_under_the_roster_named_key_stands_with_effect() {
    let served = ServedVault::self_host();
    let request = served.joining_machine();
    served
        .enrol(&request)
        .expect("the owner's enrolment of M lands");
    let machine = request.machine;
    let node = signing(JOINING_SEED);
    let m_entry = served
        .vault
        .authority_fold()
        .expect("authority fold")
        .machine(machine)
        .and_then(|folded| folded.roster.as_ref().map(|chain| chain.entry))
        .expect("guard: M has a roster chain");

    let world = EntityId::from_bytes([0xB0; 16]).expect("an id");
    let settings = WorldPrivacy {
        read: ReadLocation::MyMachines,
        sealed: SealedCopies::CloudAndMyMachines,
        models: ModelOrder::Inherit,
    };
    let edit = store_world_edit(
        &served,
        vec![m_entry],
        machine,
        &node,
        world,
        settings.clone(),
    );

    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&edit),
        "the world edit under the roster-named key did not stand"
    );
    assert!(
        !fold.refused_world_edits.contains(&edit),
        "the standing edit is refused without effect"
    );
    let folded = fold.worlds.get(&world).expect("the edited world is folded");
    assert_eq!(
        folded.live.get(&edit),
        Some(&machine),
        "the edit is live, carried by M"
    );
    assert_eq!(
        folded.live_settings.get(&edit),
        Some(&settings),
        "the live edit states the owner's settings"
    );
}

/// T5 (the residence directive doors; Engine RULING 07:19,
/// ANCHOR-JUDGES-RESIDENCE-DIRECTIVE-DOORS = A): the issue door refuses a
/// directive to a machine only this install's pin calls "yours".
///
/// The owner prepares and activates a root on this install: its anchor marks
/// this install `Owned(Yours)` and the install pins that root, while the
/// install's roster head stays `Unanswered` (a serving install's role). So
/// the install is mine under its pin, and its roster head names no residence
/// signer: the result judge refuses every result it signs (T2).
///
/// Red pin (no door change): `issue_residence_directive_as` checks
/// `machine_proof_key`, which reads the pinned trusted profile first
/// (`machine_profile/mod.rs` `proving_profile`), so it issues a directive
/// whose result never stands. Head: the door reads `residence_signer_key`,
/// the live, answered roster head's key the result judge reads, and refuses
/// with its own message. No elected home is designated, so the door's home
/// check does not refuse it.
#[test]
fn the_residence_directive_door_refuses_a_machine_only_the_pin_calls_yours() {
    let served = ServedVault::self_host();
    let prepared = served
        .vault
        .prepare_owner_root(&served.owner)
        .expect("guard: the owner's root is prepared");
    served
        .vault
        .activate_owner_root(&served.owner, prepared, &BTreeSet::new())
        .expect("guard: the owner's root is activated and pinned");
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.trusted_machine(served.carrier).is_some(),
        "guard: this install is mine under its pin"
    );
    assert!(
        fold.machine(served.carrier)
            .and_then(|folded| folded.roster.as_ref())
            .is_some_and(|roster| roster.is_live() && !roster.profile.role.answered()),
        "guard: this install's roster head is live and unanswered"
    );
    drop(fold);

    let issued = served.vault.issue_residence_directive_as(
        &served.owner,
        &served.issuer,
        EntityId::from_bytes([0xD5; 16]).expect("an id"),
        served.carrier,
        ResidenceAct::Index,
    );
    match issued {
        Ok(state) => {
            panic!("the door issued a directive to a machine whose results never stand: {state:?}")
        }
        Err(error) => assert!(
            error
                .to_string()
                .contains("names a machine the roster links and the owner answered"),
            "the door refused it for another reason: {error}"
        ),
    }
}
