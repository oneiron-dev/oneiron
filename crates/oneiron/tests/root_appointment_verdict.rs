//! The fold's verdict on a root appointment (row OWNER-ANCHOR-ROOT-RECOVERY
//! part (a); PLAN v3 sections 3, 4, 4a and 5; Engine RULINGs 14 Nov 21:01,
//! 21:47 and 22:32).
//!
//! The anchor of an owner root appoints a successor root key when the roster
//! holds no live root key. The verdict is a function of the appointment's own
//! ancestry, so it is the same on every install; only the anchor of an
//! install's pinned root is judged there. Nothing counts an appointment yet:
//! every install refuses it, with its descendants, and names its verdict.
//!
//! Pure folds over hand-signed rows: a genesis root key, an owner root its
//! anchor signs, and the rows that leave the roster with no live root key.

#![cfg(oneiron_test_support)]

use ed25519_dalek::{Signer, SigningKey};
use oneiron::EntityId;
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, AppointmentVerdict, AppointmentVoidReason, AuthorityAttestation,
    AuthorityEntryHash, AuthorityFold, AuthorityFoldIssue, AuthorityKey, AuthorityLogEntry,
    AuthorityOp, AuthoritySignature, AuthorityTier, AuthorityVaultId, DeviceAuthority,
    GenesisRecoveryStep, MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineEncryptionKey, OwnerRootRecord,
    PinnedRoot, ROLE_ADMIN, ROLE_CLOUD, ROLE_OWNER, ROOT_APPOINTMENT_SUCCESSOR_PROOF_KIND,
    RecoveryRootId, RootAppointment, authority_entry_hash, authority_transcript,
    decode_authority_log_entry_body, encode_authority_log_entry_body, genesis_vault_id,
    root_appointment_challenge,
};
use oneiron::test_doors::root_appointment::fold_under_pin;
use oneiron::world_keys::RecoveryRootSeed;

const ROOT_SEED: u8 = 41;
const FIRST_HANDOFF_SEED: u8 = 51;
const SECOND_HANDOFF_SEED: u8 = 52;

fn signing(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn key_of(signing: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

fn device(key: AuthorityKey, roles: u16) -> DeviceAuthority {
    DeviceAuthority {
        key,
        transport_key_binding: [7; 32],
        attestation: AuthorityAttestation {
            kind: "SoftwareArgon2id".to_owned(),
            evidence: vec![1, 2, 3],
        },
        tier: AuthorityTier::Software,
        roles,
    }
}

fn signed(
    vault_id: Option<AuthorityVaultId>,
    seq: u64,
    parent_hashes: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
    signer: &SigningKey,
) -> AuthorityLogEntry {
    let public_key = key_of(signer);
    let mut row = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id,
        seq,
        parent_hashes,
        op,
        signer: AuthoritySignature {
            suite: public_key.suite(),
            public_key,
            signature: vec![0; 64],
        },
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

/// The owner root record of `recovery`'s recovery key under `anchor`.
fn owner_root_record(
    vault_id: AuthorityVaultId,
    recovery: &RecoveryRootSeed,
    anchor: &SigningKey,
) -> OwnerRootRecord {
    let recovery_key = recovery.public(&vault_id).expect("the root").recovery_key;
    let anchor_key = anchor.verifying_key().to_bytes();
    OwnerRootRecord {
        owner: EntityId::from_bytes([0x11; 16]).expect("an id"),
        root: RecoveryRootId::of(&vault_id, &recovery_key, &anchor_key),
        recovery_key: MachineEncryptionKey {
            suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
            key: recovery_key.to_bytes(),
        },
        anchor_key,
    }
}

/// An appointment of `successor` with the roles `roles`, its proof of
/// possession signed over `parents`.
fn appointment_op(
    vault_id: AuthorityVaultId,
    root: RecoveryRootId,
    parents: &[AuthorityEntryHash],
    successor: &SigningKey,
    roles: u16,
) -> AuthorityOp {
    let successor_key = successor.verifying_key().to_bytes();
    let challenge = root_appointment_challenge(&vault_id, &root, parents, &successor_key)
        .expect("the challenge");
    AuthorityOp::RootAppointment(RootAppointment {
        root,
        successor: DeviceAuthority {
            key: AuthorityKey::Ed25519(successor_key),
            transport_key_binding: [0; 32],
            attestation: AuthorityAttestation {
                kind: ROOT_APPOINTMENT_SUCCESSOR_PROOF_KIND.to_owned(),
                evidence: successor.sign(&challenge).to_bytes().to_vec(),
            },
            tier: AuthorityTier::Software,
            roles,
        },
    })
}

/// The appointment `anchor` signs at `seq` on `parents`.
fn appointment_row(
    vault_id: AuthorityVaultId,
    anchor: &SigningKey,
    root: RecoveryRootId,
    seq: u64,
    mut parents: Vec<AuthorityEntryHash>,
    successor: &SigningKey,
) -> AuthorityLogEntry {
    parents.sort_unstable();
    let op = appointment_op(vault_id, root, &parents, successor, ROLE_OWNER | ROLE_ADMIN);
    signed(Some(vault_id), seq, parents, op, anchor)
}

fn verdict(fold: &AuthorityFold, entry: AuthorityEntryHash) -> Option<AppointmentVerdict> {
    fold.issues.iter().find_map(|issue| match issue {
        AuthorityFoldIssue::AppointmentRefused {
            entry: refused,
            verdict,
        } if *refused == entry => Some(*verdict),
        _ => None,
    })
}

fn burned(fold: &AuthorityFold, anchor: &SigningKey) -> bool {
    fold.issues.contains(&AuthorityFoldIssue::AnchorBurned {
        anchor: anchor.verifying_key().to_bytes(),
    })
}

/// A self-hosted vault's log: a genesis root key, and an owner root whose
/// anchor signs it, pinned.
struct Log {
    rows: Vec<AuthorityLogEntry>,
    vault_id: AuthorityVaultId,
    genesis: AuthorityEntryHash,
    root_key: SigningKey,
    anchor: SigningKey,
    owner_root: AuthorityEntryHash,
    pin: PinnedRoot,
}

impl Log {
    fn new() -> Self {
        let root_key = signing(ROOT_SEED);
        let genesis = signed(
            None,
            0,
            Vec::new(),
            AuthorityOp::Genesis {
                device: device(key_of(&root_key), ROLE_OWNER | ROLE_ADMIN),
                genesis_nonce: [3; 32],
                recovery: GenesisRecoveryStep::Saved([1; 32]),
            },
            &root_key,
        );
        let vault_id = genesis_vault_id(&genesis).expect("the vault id");
        let seed = RecoveryRootSeed::generate().expect("a seed");
        let anchor = seed.anchor();
        let record = owner_root_record(vault_id, &seed, &anchor);
        let pin = PinnedRoot {
            id: record.root,
            anchor_key: record.anchor_key,
        };
        let genesis_hash = hash(&genesis);
        let owner_root = signed(
            Some(vault_id),
            1,
            vec![genesis_hash],
            AuthorityOp::OwnerRoot(record),
            &anchor,
        );
        Self {
            vault_id,
            genesis: genesis_hash,
            root_key,
            anchor,
            owner_root: hash(&owner_root),
            pin,
            rows: vec![genesis, owner_root],
        }
    }

    fn push(&mut self, row: AuthorityLogEntry) -> AuthorityEntryHash {
        let hash = hash(&row);
        self.rows.push(row);
        hash
    }

    /// The genesis root key hands the vault to two keys at once. Both
    /// handoffs close in conflict, and the roster keeps no live root key.
    fn fork(&mut self) -> Vec<AuthorityEntryHash> {
        [(1, FIRST_HANDOFF_SEED), (2, SECOND_HANDOFF_SEED)]
            .into_iter()
            .map(|(seq, seed)| {
                let row = signed(
                    Some(self.vault_id),
                    seq,
                    vec![self.genesis],
                    AuthorityOp::ReRoot {
                        new_device: device(key_of(&signing(seed)), ROLE_OWNER | ROLE_ADMIN),
                    },
                    &self.root_key,
                );
                self.push(row)
            })
            .collect()
    }

    /// The pinned anchor appoints `successor` at `seq` on `parents`.
    fn appoint(
        &mut self,
        seq: u64,
        parents: Vec<AuthorityEntryHash>,
        successor: &SigningKey,
    ) -> AuthorityEntryHash {
        let row = appointment_row(
            self.vault_id,
            &self.anchor,
            self.pin.id,
            seq,
            parents,
            successor,
        );
        self.push(row)
    }

    /// The fork's handoffs and the owner root: the ancestry the owner's
    /// door would sign on.
    fn witnesses(&self, fork: &[AuthorityEntryHash]) -> Vec<AuthorityEntryHash> {
        let mut parents = fork.to_vec();
        parents.push(self.owner_root);
        parents
    }

    fn fold(&self) -> AuthorityFold {
        fold_under_pin(&self.rows, Some(&self.pin))
    }
}

/// The pinned anchor appoints a fresh successor over a handoff fork, which
/// left no live root key. Its verdict is Valid, yet nothing counts it yet:
/// it is refused with the successor's own rows, and the successor is not on
/// the roster. An install with no pin does not judge it.
#[test]
fn an_appointment_over_a_handoff_fork_is_valid_and_counts_nowhere_yet() {
    let mut log = Log::new();
    let fork = log.fork();
    let successor = signing(61);
    let appointment = log.appoint(2, log.witnesses(&fork), &successor);
    let successors_row = signed(
        Some(log.vault_id),
        1,
        vec![appointment],
        AuthorityOp::EnrollDevice {
            device: device(key_of(&signing(62)), ROLE_ADMIN),
        },
        &successor,
    );
    log.push(successors_row);

    let fold = log.fold();

    assert_eq!(
        verdict(&fold, appointment),
        Some(AppointmentVerdict::Valid),
        "the pinned anchor's appointment over the fork is valid: {:?}",
        fold.issues
    );
    assert!(!burned(&fold, &log.anchor), "one appointment burns nothing");
    assert!(!fold.valid_entries.contains(&appointment));
    assert!(!fold.roster.contains_key(&key_of(&successor)));
    assert!(!fold.roster.contains_key(&key_of(&signing(62))));
    assert!(
        fold.roster.values().all(|device| device.revoked),
        "the fork left no live root key"
    );
    let unpinned = fold_under_pin(&log.rows, None);
    assert_eq!(
        verdict(&unpinned, appointment),
        Some(AppointmentVerdict::Unjudged)
    );
}

/// An appointment while the genesis root key is still live is void and burns
/// the anchor. A later appointment by the same anchor, over the fork, is
/// then void as burned, with no proof fold of its own.
#[test]
fn an_appointment_over_a_live_root_key_is_void_and_burns_the_anchor() {
    let mut log = Log::new();
    let early = log.appoint(2, vec![log.owner_root], &signing(63));
    let fork = log.fork();
    let late = log.appoint(3, log.witnesses(&fork), &signing(64));

    let fold = log.fold();

    assert_eq!(
        verdict(&fold, early),
        Some(AppointmentVerdict::Void(
            AppointmentVoidReason::RootedAncestry
        )),
        "{:?}",
        fold.issues
    );
    assert!(burned(&fold, &log.anchor));
    assert_eq!(
        verdict(&fold, late),
        Some(AppointmentVerdict::Void(
            AppointmentVoidReason::AnchorBurned
        ))
    );
}

/// Two valid appointments by one anchor, neither in the other's ancestry,
/// burn it (the stolen-kit limit: a thief stops recovery, never wins it).
#[test]
fn two_valid_appointments_beside_each_other_burn_the_anchor() {
    let mut log = Log::new();
    let fork = log.fork();
    let first = log.appoint(2, log.witnesses(&fork), &signing(65));
    let second = log.appoint(2, log.witnesses(&fork), &signing(66));

    let fold = log.fold();

    assert_eq!(verdict(&fold, first), Some(AppointmentVerdict::Valid));
    assert_eq!(verdict(&fold, second), Some(AppointmentVerdict::Valid));
    assert!(burned(&fold, &log.anchor), "{:?}", fold.issues);
}

/// The anchor signs a second owner root and appoints under it beside its
/// appointment under the pinned root. The install judges both, each under
/// its own root, and the pair burns the anchor.
#[test]
fn a_sibling_under_another_root_of_the_same_anchor_burns_it() {
    let mut log = Log::new();
    let other_key = RecoveryRootSeed::generate().expect("a seed");
    let other = owner_root_record(log.vault_id, &other_key, &log.anchor);
    let other_root = other.root;
    let other_row = signed(
        Some(log.vault_id),
        2,
        vec![log.genesis],
        AuthorityOp::OwnerRoot(other),
        &log.anchor,
    );
    let other_hash = log.push(other_row);
    let fork = log.fork();
    let pinned = log.appoint(3, log.witnesses(&fork), &signing(67));
    let mut parents = fork;
    parents.push(other_hash);
    let sibling_row = appointment_row(
        log.vault_id,
        &log.anchor,
        other_root,
        3,
        parents,
        &signing(68),
    );
    let sibling = log.push(sibling_row);

    let fold = log.fold();

    assert_eq!(verdict(&fold, pinned), Some(AppointmentVerdict::Valid));
    assert_eq!(verdict(&fold, sibling), Some(AppointmentVerdict::Valid));
    assert!(burned(&fold, &log.anchor), "{:?}", fold.issues);
}

/// A successor key a row of the ancestry names (here the fork's first
/// handoff key) is refused, and burns nothing: a fresh appointment by the
/// same anchor after it is valid.
#[test]
fn a_successor_the_ancestry_names_is_refused_and_burns_nothing() {
    let mut log = Log::new();
    let fork = log.fork();
    let named = log.appoint(2, log.witnesses(&fork), &signing(FIRST_HANDOFF_SEED));
    let fresh = log.appoint(3, log.witnesses(&fork), &signing(69));

    let fold = log.fold();

    assert_eq!(
        verdict(&fold, named),
        Some(AppointmentVerdict::SuccessorNotFresh),
        "{:?}",
        fold.issues
    );
    assert_eq!(verdict(&fold, fresh), Some(AppointmentVerdict::Valid));
    assert!(!burned(&fold, &log.anchor));
}

/// Another root's anchor appoints over the fork. This install pins the owner
/// root, so it does not judge that appointment; an install that pins the
/// other root judges the same row valid.
#[test]
fn another_anchors_appointment_is_judged_only_where_its_root_is_pinned() {
    let mut log = Log::new();
    let stranger = RecoveryRootSeed::generate().expect("a seed");
    let stranger_anchor = stranger.anchor();
    let record = owner_root_record(log.vault_id, &stranger, &stranger_anchor);
    let stranger_pin = PinnedRoot {
        id: record.root,
        anchor_key: record.anchor_key,
    };
    let stranger_root = signed(
        Some(log.vault_id),
        1,
        vec![log.genesis],
        AuthorityOp::OwnerRoot(record),
        &stranger_anchor,
    );
    let stranger_root = log.push(stranger_root);
    let mut parents = log.fork();
    parents.push(stranger_root);
    let row = appointment_row(
        log.vault_id,
        &stranger_anchor,
        stranger_pin.id,
        2,
        parents,
        &signing(70),
    );
    let appointment = log.push(row);

    assert_eq!(
        verdict(&log.fold(), appointment),
        Some(AppointmentVerdict::Unjudged)
    );
    assert_eq!(
        verdict(&fold_under_pin(&log.rows, Some(&stranger_pin)), appointment),
        Some(AppointmentVerdict::Valid)
    );
}

/// The rows arrive in other orders; the verdict stays.
#[test]
fn every_arrival_order_judges_an_appointment_the_same() {
    let mut log = Log::new();
    let fork = log.fork();
    let appointment = log.appoint(2, log.witnesses(&fork), &signing(71));
    let mut rows = log.rows.clone();

    for _ in 0..rows.len() {
        let fold = fold_under_pin(&rows, Some(&log.pin));
        assert_eq!(
            verdict(&fold, appointment),
            Some(AppointmentVerdict::Valid),
            "{:?}",
            fold.issues
        );
        rows.rotate_left(1);
    }
    rows.reverse();
    assert_eq!(
        verdict(&fold_under_pin(&rows, Some(&log.pin)), appointment),
        Some(AppointmentVerdict::Valid)
    );
}

/// The appointment's sequence must pass the anchor's own rows in its
/// ancestry; at the owner root's sequence it is void.
#[test]
fn an_appointment_at_its_anchors_own_sequence_is_void() {
    let mut log = Log::new();
    let fork = log.fork();
    let appointment = log.appoint(1, log.witnesses(&fork), &signing(72));

    let fold = log.fold();

    assert_eq!(
        verdict(&fold, appointment),
        Some(AppointmentVerdict::Void(
            AppointmentVoidReason::SequenceNotAdvanced
        )),
        "{:?}",
        fold.issues
    );
    assert!(burned(&fold, &log.anchor));
}

/// An appointment whose ancestry holds no owner root of its id is void.
#[test]
fn an_appointment_whose_ancestry_lacks_its_root_is_void() {
    let mut log = Log::new();
    let fork = log.fork();
    let appointment = log.appoint(2, fork, &signing(73));

    let fold = log.fold();

    assert_eq!(
        verdict(&fold, appointment),
        Some(AppointmentVerdict::Void(AppointmentVoidReason::NoOwnerRoot)),
        "{:?}",
        fold.issues
    );
}

/// A settled handoff to an ADMIN key alone leaves no live root key, with no
/// conflict (round-2 finding 2): the pinned anchor's appointment over it is
/// valid.
#[test]
fn an_admin_only_handoff_leaves_no_root_key_and_the_anchor_may_appoint() {
    let mut log = Log::new();
    let admin = signing(74);
    let handoff = signed(
        Some(log.vault_id),
        1,
        vec![log.genesis],
        AuthorityOp::ReRoot {
            new_device: device(key_of(&admin), ROLE_ADMIN),
        },
        &log.root_key,
    );
    let handoff = log.push(handoff);
    let before = log.fold();
    assert!(
        before
            .roster
            .get(&key_of(&admin))
            .is_some_and(|device| !device.revoked),
        "the handoff settles: {:?}",
        before.issues
    );
    let appointment = log.appoint(2, vec![handoff, log.owner_root], &signing(75));

    let fold = log.fold();

    assert_eq!(
        verdict(&fold, appointment),
        Some(AppointmentVerdict::Valid),
        "{:?}",
        fold.issues
    );
}

/// The row survives the wire as signed, and its shape binds it: the proof of
/// possession covers the vault and the parents, the anchor signs alone, and
/// the successor is owner-held with OWNER and ADMIN exactly.
#[test]
fn the_wire_keeps_an_appointment_and_its_shape_binds_it() {
    let mut log = Log::new();
    let fork = log.fork();
    let successor = signing(76);
    let row = appointment_row(
        log.vault_id,
        &log.anchor,
        log.pin.id,
        2,
        log.witnesses(&fork),
        &successor,
    );

    let bytes = encode_authority_log_entry_body(&row).expect("the bytes");
    assert_eq!(
        decode_authority_log_entry_body(&bytes).expect("the row"),
        row
    );
    row.validate_shape().expect("the row's shape");

    let moved = signed(
        Some(log.vault_id),
        2,
        vec![log.owner_root],
        row.op.clone(),
        &log.anchor,
    );
    assert!(
        moved.validate_shape().is_err(),
        "the proof binds the parents"
    );
    let other_vault = signed(
        Some([9; 32]),
        2,
        row.parent_hashes.clone(),
        row.op.clone(),
        &log.anchor,
    );
    assert!(
        other_vault.validate_shape().is_err(),
        "the proof binds the vault"
    );
    let cloud = signed(
        Some(log.vault_id),
        2,
        row.parent_hashes.clone(),
        appointment_op(
            log.vault_id,
            log.pin.id,
            &row.parent_hashes,
            &successor,
            ROLE_OWNER | ROLE_ADMIN | ROLE_CLOUD,
        ),
        &log.anchor,
    );
    assert!(
        cloud.validate_shape().is_err(),
        "a cloud successor is refused"
    );
    let mut cosigned = row.clone();
    cosigned.cosigns.push(AuthoritySignature {
        suite: key_of(&log.root_key).suite(),
        public_key: key_of(&log.root_key),
        signature: vec![0; 64],
    });
    assert!(cosigned.validate_shape().is_err(), "the anchor signs alone");
    let own_successor = signed(
        Some(log.vault_id),
        2,
        row.parent_hashes.clone(),
        appointment_op(
            log.vault_id,
            log.pin.id,
            &row.parent_hashes,
            &log.anchor,
            ROLE_OWNER | ROLE_ADMIN,
        ),
        &log.anchor,
    );
    assert!(
        own_successor.validate_shape().is_err(),
        "the anchor never appoints itself"
    );
}
