//! The fold's verdict on a root appointment, and what a counted one installs
//! (row OWNER-ANCHOR-ROOT-RECOVERY parts (a) and (b1); PLAN v3 sections 3 to
//! 6; Engine RULINGs 14 Nov 21:01, 21:47 and 22:32).
//!
//! The anchor of an owner root appoints a successor root key when the roster
//! holds no live root key. The verdict is a function of the appointment's own
//! ancestry, so it is the same on every install; only the anchor of an
//! install's pinned root is judged there. An install counts a valid
//! appointment that names its pinned root while its log burns no such
//! anchor: the appointment's ancestry keeps the verdicts its own fold gave,
//! every roster key is revoked, the successor is live, and every row an old
//! roster key signs outside that line is sealed. Every other install
//! refuses it, with its descendants, and names its verdict.
//!
//! Pure folds over hand-signed rows: a genesis root key, an owner root its
//! anchor signs, and the rows that leave the roster with no live root key.
//! The PLAN's tests 12 and 16 (what the recovered world keeps) come with
//! part (b2).

#![cfg(oneiron_test_support)]

use ed25519_dalek::{Signer, SigningKey};
use oneiron::EntityId;
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, AppointmentVerdict, AppointmentVoidReason, AuthorityAttestation,
    AuthorityConfirmAction, AuthorityConfirmKind, AuthorityEntryHash, AuthorityFold,
    AuthorityFoldIssue, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
    AuthorityTier, AuthorityVaultId, DeviceAuthority, GenesisRecoveryStep,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineEncryptionKey, OwnerRootRecord, PinnedRoot,
    ROLE_ADMIN, ROLE_AGENT, ROLE_CLOUD, ROLE_OWNER, ROOT_APPOINTMENT_SUCCESSOR_PROOF_KIND,
    RecoveryRootId, RootAppointment, authority_entry_hash, authority_transcript,
    decode_authority_log_entry_body, encode_authority_log_entry_body, genesis_vault_id,
    root_appointment_challenge,
};
use oneiron::test_doors::root_appointment::{
    fold_under_pin, in_host_custody, whole_and_resumed_folds,
};
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

/// The verdict a fold gives `entry`: a counted appointment is a valid entry
/// (only a valid one counts), and a refused one names its verdict.
fn verdict(fold: &AuthorityFold, entry: AuthorityEntryHash) -> Option<AppointmentVerdict> {
    if fold.valid_entries.contains(&entry) {
        return Some(AppointmentVerdict::Valid);
    }
    fold.issues.iter().find_map(|issue| match issue {
        AuthorityFoldIssue::AppointmentRefused {
            entry: refused,
            verdict,
        } if *refused == entry => Some(*verdict),
        _ => None,
    })
}

/// Whether `key` is a live key of the folded roster.
fn live(fold: &AuthorityFold, key: &AuthorityKey) -> bool {
    fold.roster.get(key).is_some_and(|device| !device.revoked)
}

/// Whether the fold names its roster rootless.
fn rootless(fold: &AuthorityFold) -> bool {
    fold.issues.contains(&AuthorityFoldIssue::NoRootKey)
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

    /// `signer` signs `op` at `seq` on `parents`.
    fn sign(
        &mut self,
        signer: &SigningKey,
        seq: u64,
        parents: Vec<AuthorityEntryHash>,
        op: AuthorityOp,
    ) -> AuthorityEntryHash {
        let row = signed(Some(self.vault_id), seq, parents, op, signer);
        self.push(row)
    }

    /// The genesis root key enrols a second root key.
    fn enrol_second_root(&mut self, second: &SigningKey) -> AuthorityEntryHash {
        let root_key = self.root_key.clone();
        self.sign(
            &root_key,
            1,
            vec![self.genesis],
            AuthorityOp::EnrollDevice {
                device: device(key_of(second), ROLE_OWNER | ROLE_ADMIN),
            },
        )
    }
}

/// The pinned anchor appoints a fresh successor over a handoff fork, which
/// left no live root key. Its verdict is Valid and the install that pins its
/// root counts it: the successor is a live root key, and its own rows stand.
/// An install with no pin does not judge it, and keeps no roster effect.
#[test]
fn an_appointment_over_a_handoff_fork_counts_where_its_root_is_pinned() {
    let mut log = Log::new();
    let fork = log.fork();
    let successor = signing(61);
    let appointment = log.appoint(2, log.witnesses(&fork), &successor);
    let enrolled = signing(62);
    let successors_row = signed(
        Some(log.vault_id),
        1,
        vec![appointment],
        AuthorityOp::EnrollDevice {
            device: device(key_of(&enrolled), ROLE_ADMIN),
        },
        &successor,
    );
    let successors_row = log.push(successors_row);

    let fold = log.fold();

    assert!(
        fold.valid_entries.contains(&appointment),
        "the pinned anchor's appointment over the fork counts: {:?}",
        fold.issues
    );
    assert!(!burned(&fold, &log.anchor), "one appointment burns nothing");
    assert!(fold.valid_entries.contains(&successors_row));
    assert!(live(&fold, &key_of(&successor)));
    assert_eq!(
        fold.roster[&key_of(&successor)].roles,
        ROLE_OWNER | ROLE_ADMIN
    );
    assert!(live(&fold, &key_of(&enrolled)));
    for old in [
        &log.root_key,
        &signing(FIRST_HANDOFF_SEED),
        &signing(SECOND_HANDOFF_SEED),
    ] {
        assert!(!live(&fold, &key_of(old)), "an old key stays retired");
    }
    for handoff in &fork {
        assert!(!fold.valid_entries.contains(handoff));
    }
    assert!(!rootless(&fold), "{:?}", fold.issues);
    assert!(
        !fold
            .issues
            .iter()
            .any(|issue| matches!(issue, AuthorityFoldIssue::UnsettledHandoff(_))),
        "the recovered line raises no unsettled handoff: {:?}",
        fold.issues
    );
    let unpinned = fold_under_pin(&log.rows, None);
    assert_eq!(
        verdict(&unpinned, appointment),
        Some(AppointmentVerdict::Unjudged)
    );
    assert!(!unpinned.valid_entries.contains(&successors_row));
    assert!(!unpinned.roster.contains_key(&key_of(&successor)));
    assert!(rootless(&unpinned));
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
/// handoff key) is refused, and burns the anchor as a void appointment does:
/// the door never signs one, so only a probe by a holder of the anchor key
/// is not fresh. A fresh appointment by the same anchor beside it counts
/// nowhere.
#[test]
fn a_successor_the_ancestry_names_is_refused_and_burns_the_anchor() {
    let mut log = Log::new();
    let fork = log.fork();
    let named = log.appoint(2, log.witnesses(&fork), &signing(FIRST_HANDOFF_SEED));
    let fresh_key = signing(69);
    log.appoint(3, log.witnesses(&fork), &fresh_key);

    let fold = log.fold();

    assert_eq!(
        verdict(&fold, named),
        Some(AppointmentVerdict::SuccessorNotFresh),
        "{:?}",
        fold.issues
    );
    assert!(burned(&fold, &log.anchor), "{:?}", fold.issues);
    assert!(
        !live(&fold, &key_of(&fresh_key)),
        "a burned anchor installs nothing"
    );
}

/// On a vault that never lost its root key, a holder of the anchor key
/// appoints a successor that a row of the ancestry names, and then chains a
/// second appointment of it on the first. The first burns the anchor, so the
/// chain costs no further judging, and the root key stays live.
#[test]
fn a_successor_the_ancestry_names_burns_the_anchor_of_a_rooted_vault() {
    let mut log = Log::new();
    let root_key = log.root_key.clone();
    let named_key = signing(103);
    let revocation = log.sign(
        &root_key,
        1,
        vec![log.genesis],
        AuthorityOp::RevokeActor {
            authority_key: key_of(&named_key),
            epoch: 1,
        },
    );
    let first = log.appoint(2, vec![revocation, log.owner_root], &named_key);
    let second = log.appoint(3, vec![first], &named_key);

    let fold = log.fold();

    assert_eq!(
        verdict(&fold, first),
        Some(AppointmentVerdict::SuccessorNotFresh),
        "{:?}",
        fold.issues
    );
    assert!(burned(&fold, &log.anchor), "{:?}", fold.issues);
    assert_eq!(
        verdict(&fold, second),
        Some(AppointmentVerdict::Void(
            AppointmentVoidReason::AnchorBurned
        ))
    );
    assert!(live(&fold, &key_of(&root_key)));
    assert!(!live(&fold, &key_of(&named_key)));
}

/// A successor key that only an actor-binding revocation of the ancestry
/// names, a key the roster never enrolled, is not fresh either: it would
/// inherit that revocation's watermark (Astra split6-anchor threats 8 and 9).
/// It is refused and burns the anchor; a fresh appointment by the same
/// anchor beside it counts nowhere.
#[test]
fn a_successor_only_a_binding_revocation_names_is_refused_and_burns_the_anchor() {
    let mut log = Log::new();
    let root_key = log.root_key.clone();
    let named_key = signing(101);
    let revocation = log.sign(
        &root_key,
        1,
        vec![log.genesis],
        AuthorityOp::RevokeActor {
            authority_key: key_of(&named_key),
            epoch: 1,
        },
    );
    let fork: Vec<AuthorityEntryHash> = [(2, FIRST_HANDOFF_SEED), (3, SECOND_HANDOFF_SEED)]
        .into_iter()
        .map(|(seq, seed)| {
            log.sign(
                &root_key,
                seq,
                vec![revocation],
                AuthorityOp::ReRoot {
                    new_device: device(key_of(&signing(seed)), ROLE_OWNER | ROLE_ADMIN),
                },
            )
        })
        .collect();
    let named = log.appoint(2, log.witnesses(&fork), &named_key);
    let fresh_key = signing(102);
    log.appoint(3, log.witnesses(&fork), &fresh_key);

    let fold = log.fold();

    assert_eq!(
        verdict(&fold, named),
        Some(AppointmentVerdict::SuccessorNotFresh),
        "{:?}",
        fold.issues
    );
    assert!(burned(&fold, &log.anchor), "{:?}", fold.issues);
    assert!(
        !live(&fold, &key_of(&fresh_key)),
        "a burned anchor installs nothing"
    );
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

// Part (b1): what a counted appointment installs (PLAN v3 sections 5 and 6).

/// A roster with no live root key names itself; a live one, or an
/// appointment's successor, does not (E4).
#[test]
fn a_rootless_roster_names_itself() {
    let mut log = Log::new();
    assert!(!rootless(&log.fold()), "the genesis root key is live");
    let fork = log.fork();
    assert!(rootless(&log.fold()), "the fork leaves no live root key");
    log.appoint(2, log.witnesses(&fork), &signing(90));
    assert!(!rootless(&log.fold()), "the successor is a live root key");

    let mut admin_only = Log::new();
    let root_key = admin_only.root_key.clone();
    let genesis = admin_only.genesis;
    admin_only.sign(
        &root_key,
        1,
        vec![genesis],
        AuthorityOp::ReRoot {
            new_device: device(key_of(&signing(91)), ROLE_ADMIN),
        },
    );
    assert!(
        rootless(&admin_only.fold()),
        "a settled handoff to an ADMIN key leaves no root key"
    );
}

/// Two root keys revoke each other on sibling branches: both fences close in
/// conflict and no root key is left (round-1 finding 4). The pinned anchor's
/// appointment over both revocations installs its successor.
#[test]
fn the_owner_gets_out_of_a_revocation_only_cycle() {
    let mut log = Log::new();
    let second = signing(80);
    let enrol = log.enrol_second_root(&second);
    let root_key = log.root_key.clone();
    let revokes_second = log.sign(
        &root_key,
        2,
        vec![enrol],
        AuthorityOp::RevokeDevice {
            revoked_key: key_of(&second),
        },
    );
    let revokes_first = log.sign(
        &second,
        1,
        vec![enrol],
        AuthorityOp::RevokeDevice {
            revoked_key: key_of(&root_key),
        },
    );
    let before = log.fold();
    assert!(rootless(&before), "{:?} {:?}", before.roster, before.issues);

    let successor = signing(81);
    let appointment = log.appoint(
        2,
        vec![revokes_second, revokes_first, log.owner_root],
        &successor,
    );
    let fold = log.fold();

    assert!(
        fold.valid_entries.contains(&appointment),
        "{:?}",
        fold.issues
    );
    assert!(live(&fold, &key_of(&successor)));
    assert!(!live(&fold, &key_of(&root_key)));
    assert!(!live(&fold, &key_of(&second)));
    assert!(!rootless(&fold));
}

/// A revocation and a handoff fence each other (the 20:11 ruling's cycle):
/// both close in conflict, the handoff installs nothing, and no root key is
/// left. The pinned anchor's appointment over both installs its successor.
#[test]
fn the_owner_gets_out_of_a_revoke_fence_cycle() {
    let mut log = Log::new();
    let second = signing(82);
    let enrol = log.enrol_second_root(&second);
    let root_key = log.root_key.clone();
    let revocation = log.sign(
        &root_key,
        2,
        vec![enrol],
        AuthorityOp::RevokeDevice {
            revoked_key: key_of(&second),
        },
    );
    let handed_to = signing(83);
    let handoff = log.sign(
        &second,
        1,
        vec![enrol],
        AuthorityOp::ReRoot {
            new_device: device(key_of(&handed_to), ROLE_OWNER | ROLE_ADMIN),
        },
    );
    let before = log.fold();
    assert!(rootless(&before), "{:?} {:?}", before.roster, before.issues);

    let successor = signing(84);
    let appointment = log.appoint(2, vec![revocation, handoff, log.owner_root], &successor);
    let fold = log.fold();

    assert!(
        fold.valid_entries.contains(&appointment),
        "{:?}",
        fold.issues
    );
    assert!(live(&fold, &key_of(&successor)));
    for old in [&root_key, &second, &handed_to] {
        assert!(!live(&fold, &key_of(old)));
    }
    assert!(!fold.valid_entries.contains(&handoff));
    assert!(!rootless(&fold));
}

/// Only the install that pins the appointment's root counts it: with no pin,
/// or pinned to another anchor's root, the appointment keeps no roster
/// effect and its successor's rows stand nowhere (round-1 finding 8).
#[test]
fn an_uncounted_appointment_keeps_no_roster_effect() {
    let mut log = Log::new();
    let stranger = RecoveryRootSeed::generate().expect("a seed");
    let stranger_anchor = stranger.anchor();
    let record = owner_root_record(log.vault_id, &stranger, &stranger_anchor);
    let stranger_pin = PinnedRoot {
        id: record.root,
        anchor_key: record.anchor_key,
    };
    let genesis = log.genesis;
    log.sign(
        &stranger_anchor,
        1,
        vec![genesis],
        AuthorityOp::OwnerRoot(record),
    );
    let fork = log.fork();
    let successor = signing(85);
    let appointment = log.appoint(2, log.witnesses(&fork), &successor);
    let successors_row = log.sign(
        &successor,
        1,
        vec![appointment],
        AuthorityOp::EnrollDevice {
            device: device(key_of(&signing(86)), ROLE_ADMIN),
        },
    );

    for pin in [None, Some(&stranger_pin)] {
        let fold = fold_under_pin(&log.rows, pin);
        assert!(!fold.valid_entries.contains(&appointment));
        assert!(!fold.valid_entries.contains(&successors_row));
        assert!(!fold.roster.contains_key(&key_of(&successor)));
        assert!(rootless(&fold));
    }
    let fold = log.fold();
    assert!(
        fold.valid_entries.contains(&successors_row),
        "{:?}",
        fold.issues
    );
    assert!(live(&fold, &key_of(&successor)));
}

/// After the appointment counts, rows an old roster key signs outside its
/// line are sealed (round-1 finding 3; E2, E4): a third sibling handoff
/// revealed late, a late enrolment of the successor's key, and a late
/// revocation. Neither raises an unsettled handoff, and the successor stays
/// the live root key with its own roles.
#[test]
fn rows_an_old_key_signs_outside_the_appointment_are_sealed() {
    let mut log = Log::new();
    let fork = log.fork();
    let successor = signing(87);
    let appointment = log.appoint(2, log.witnesses(&fork), &successor);
    let root_key = log.root_key.clone();
    let genesis = log.genesis;
    let late_handoff = log.sign(
        &root_key,
        3,
        vec![genesis],
        AuthorityOp::ReRoot {
            new_device: device(key_of(&signing(53)), ROLE_OWNER | ROLE_ADMIN),
        },
    );
    let late_enrol = log.sign(
        &root_key,
        4,
        vec![genesis],
        AuthorityOp::EnrollDevice {
            device: device(key_of(&successor), ROLE_ADMIN),
        },
    );
    let late_revocation = log.sign(
        &root_key,
        5,
        vec![genesis],
        AuthorityOp::RevokeDevice {
            revoked_key: key_of(&signing(FIRST_HANDOFF_SEED)),
        },
    );

    let fold = log.fold();

    assert!(
        fold.valid_entries.contains(&appointment),
        "{:?}",
        fold.issues
    );
    for sealed in [late_handoff, late_enrol, late_revocation] {
        assert!(!fold.valid_entries.contains(&sealed));
    }
    assert!(
        fold.issues
            .contains(&AuthorityFoldIssue::RetiredSigner(late_handoff))
    );
    assert!(
        !fold
            .issues
            .iter()
            .any(|issue| matches!(issue, AuthorityFoldIssue::UnsettledHandoff(_))),
        "{:?}",
        fold.issues
    );
    assert!(!live(&fold, &key_of(&signing(53))));
    assert!(live(&fold, &key_of(&successor)));
    assert_eq!(
        fold.roster[&key_of(&successor)].roles,
        ROLE_OWNER | ROLE_ADMIN
    );
}

/// A sealed late sibling closes no fence: the successor's own later handoff
/// settles beside it.
#[test]
fn the_successor_hands_off_again_beside_a_sealed_sibling() {
    let mut log = Log::new();
    let fork = log.fork();
    let successor = signing(88);
    let appointment = log.appoint(2, log.witnesses(&fork), &successor);
    let root_key = log.root_key.clone();
    let genesis = log.genesis;
    let late_handoff = log.sign(
        &root_key,
        3,
        vec![genesis],
        AuthorityOp::ReRoot {
            new_device: device(key_of(&signing(54)), ROLE_OWNER | ROLE_ADMIN),
        },
    );
    let next = signing(89);
    let next_handoff = log.sign(
        &successor,
        1,
        vec![appointment],
        AuthorityOp::ReRoot {
            new_device: device(key_of(&next), ROLE_OWNER | ROLE_ADMIN),
        },
    );

    let fold = log.fold();

    assert!(
        fold.valid_entries.contains(&next_handoff),
        "{:?}",
        fold.issues
    );
    assert!(!fold.valid_entries.contains(&late_handoff));
    assert!(live(&fold, &key_of(&next)));
    assert!(!live(&fold, &key_of(&successor)));
    assert!(!rootless(&fold));
}

/// The barrier is path-sensitive (round-2 finding 8): the successor's row
/// that reaches a refused handoff only through the appointment stands; one
/// that also names the refused handoff as a parent does not.
#[test]
fn a_descendant_with_its_own_path_to_a_refused_row_stays_refused() {
    let mut log = Log::new();
    let fork = log.fork();
    let successor = signing(92);
    let appointment = log.appoint(2, log.witnesses(&fork), &successor);
    let through = log.sign(
        &successor,
        1,
        vec![appointment],
        AuthorityOp::EnrollDevice {
            device: device(key_of(&signing(93)), ROLE_ADMIN),
        },
    );
    let beside = log.sign(
        &successor,
        2,
        vec![through, fork[0]],
        AuthorityOp::EnrollDevice {
            device: device(key_of(&signing(94)), ROLE_ADMIN),
        },
    );
    let after = log.sign(
        &successor,
        2,
        vec![through],
        AuthorityOp::EnrollDevice {
            device: device(key_of(&signing(95)), ROLE_ADMIN),
        },
    );

    let fold = log.fold();

    assert!(fold.valid_entries.contains(&through), "{:?}", fold.issues);
    assert!(fold.valid_entries.contains(&after));
    assert!(!fold.valid_entries.contains(&beside));
    assert!(!fold.roster.contains_key(&key_of(&signing(94))));
    assert!(live(&fold, &key_of(&signing(95))));
}

/// The rows arrive in other orders; every install folds the counted
/// appointment's world the same (round-1 finding 6).
#[test]
fn every_install_folds_an_appointment_the_same() {
    let mut log = Log::new();
    let fork = log.fork();
    let successor = signing(96);
    let appointment = log.appoint(2, log.witnesses(&fork), &successor);
    log.sign(
        &successor,
        1,
        vec![appointment],
        AuthorityOp::EnrollDevice {
            device: device(key_of(&signing(97)), ROLE_ADMIN),
        },
    );
    let first = log.fold();
    assert!(
        first.valid_entries.contains(&appointment),
        "{:?}",
        first.issues
    );
    let mut rows = log.rows.clone();
    for _ in 0..rows.len() {
        rows.rotate_left(1);
        let fold = fold_under_pin(&rows, Some(&log.pin));
        assert_eq!(fold.valid_entries, first.valid_entries);
        assert_eq!(fold.roster, first.roster);
    }
    rows.reverse();
    let fold = fold_under_pin(&rows, Some(&log.pin));
    assert_eq!(fold.valid_entries, first.valid_entries);
    assert_eq!(fold.roster, first.roster);
}

/// A sibling appointment by the same anchor that arrives later burns it, and
/// the burn un-counts the first (C3): neither successor is live.
#[test]
fn a_later_burn_uncounts_the_appointment() {
    let mut log = Log::new();
    let fork = log.fork();
    let first_successor = signing(98);
    let first = log.appoint(2, log.witnesses(&fork), &first_successor);
    let counted = log.fold();
    assert!(
        counted.valid_entries.contains(&first),
        "{:?}",
        counted.issues
    );

    let second_successor = signing(99);
    let second = log.appoint(2, log.witnesses(&fork), &second_successor);
    let fold = log.fold();

    assert!(burned(&fold, &log.anchor), "{:?}", fold.issues);
    assert!(!fold.valid_entries.contains(&first));
    assert!(!fold.valid_entries.contains(&second));
    assert!(!fold.roster.contains_key(&key_of(&first_successor)));
    assert!(!fold.roster.contains_key(&key_of(&second_successor)));
    assert!(rootless(&fold));
}

/// A fold resumed past a base that holds a counted appointment reads it as
/// the whole fold does (review R7): the appointment revokes every old roster
/// key, so an approval an old key signed in its line expires once the
/// stale-roster window passes, in the whole fold and in the resumed one.
#[test]
fn a_resumed_fold_expires_an_old_keys_approval_as_the_whole_fold_does() {
    let mut log = Log::new();
    let admin = signing(76);
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
    let binding = log.sign(
        &admin,
        1,
        vec![handoff],
        AuthorityOp::BindActor {
            authority_key: key_of(&admin),
            actor_ref: EntityId::from_bytes([0x22; 16]).expect("an id"),
            actor_class: "agent".to_owned(),
            epoch: 1,
        },
    );
    let successor = signing(77);
    let appointment = log.appoint(2, vec![binding, log.owner_root], &successor);
    let base_len = log.rows.len();
    let enrolment = log.sign(
        &successor,
        1,
        vec![appointment],
        AuthorityOp::EnrollDevice {
            device: device(key_of(&signing(78)), ROLE_AGENT),
        },
    );

    let (whole, resumed) = whole_and_resumed_folds(&log.rows, base_len, Some(&log.pin), 0);

    assert!(
        whole.valid_entries.contains(&appointment),
        "the appointment counts: {:?}",
        whole.issues
    );
    assert!(
        whole.valid_entries.contains(&enrolment),
        "{:?}",
        whole.issues
    );
    assert!(
        whole
            .issues
            .contains(&AuthorityFoldIssue::StaleRosterApproval(binding)),
        "the appointment revoked the binding's key, and the window passed: {:?}",
        whole.issues
    );
    assert!(!whole.valid_entries.contains(&binding));
    let resumed = resumed.expect("the agent's enrolment resumes from the base");
    assert!(
        !resumed.valid_entries.contains(&binding),
        "the resumed fold expires the binding too: {:?}",
        resumed.issues
    );
    assert_eq!(resumed.valid_entries, whole.valid_entries);
    assert_eq!(resumed.roster, whole.roster);
}

// The PLAN's tests 12 and 16 (adversarial reads: round 2 finding 5, round 1
// finding 11): what the recovered world keeps.

/// A federation confirmation; two that share a nonce collide.
fn confirmation(id: u8, nonce: u8) -> AuthorityOp {
    AuthorityOp::FederationConfirm(AuthorityConfirmAction {
        kind: AuthorityConfirmKind::Accept,
        confirm_id: [id; 32],
        peer_vault_id: [96; 32],
        epoch: 1,
        nonce: [nonce; 16],
    })
}

/// Whether `confirm` stands in `fold`: a valid entry, or a consumed
/// confirmation id and nonce.
fn confirm_stands(fold: &AuthorityFold, confirm: AuthorityEntryHash) -> bool {
    fold.valid_entries.contains(&confirm) || fold.federation_confirms.contains_key(&confirm)
}

/// PLAN v3 test 12 (round-2 finding 5): the genesis root key signs two
/// confirmations that share one nonce, and a handoff over each. Alone, one
/// of the two stands. The handoffs conflict, and each fences the other's
/// confirmation, so neither stands. The appointment over both handoffs
/// counts, with the world its ancestry's fold gave: neither confirmation
/// stands in the install's fold either, so no nonce contender comes back.
#[test]
fn the_recovered_world_is_the_ancestry_fold() {
    let mut log = Log::new();
    let root_key = log.root_key.clone();
    let first = log.sign(&root_key, 1, vec![log.owner_root], confirmation(1, 3));
    let second = log.sign(&root_key, 1, vec![log.owner_root], confirmation(2, 3));
    let alone = log.fold();
    assert_eq!(
        [first, second]
            .into_iter()
            .filter(|confirm| confirm_stands(&alone, *confirm))
            .count(),
        1,
        "alone, one of two confirmations that share a nonce stands: {:?}",
        alone.issues
    );
    let first_handoff = log.sign(
        &root_key,
        2,
        vec![first],
        AuthorityOp::ReRoot {
            new_device: device(
                key_of(&signing(FIRST_HANDOFF_SEED)),
                ROLE_OWNER | ROLE_ADMIN,
            ),
        },
    );
    let second_handoff = log.sign(
        &root_key,
        2,
        vec![second],
        AuthorityOp::ReRoot {
            new_device: device(
                key_of(&signing(SECOND_HANDOFF_SEED)),
                ROLE_OWNER | ROLE_ADMIN,
            ),
        },
    );
    let handoffs = [first_handoff, second_handoff];
    let fenced = log.fold();
    assert!(rootless(&fenced), "{:?}", fenced.issues);
    for confirm in [first, second] {
        assert!(
            !confirm_stands(&fenced, confirm),
            "the conflicting handoffs fence both confirmations: {:?}",
            fenced.issues
        );
    }

    let successor = signing(110);
    let appointment = log.appoint(2, log.witnesses(&handoffs), &successor);
    let binding = log.sign(
        &successor,
        1,
        vec![appointment],
        AuthorityOp::BindActor {
            authority_key: key_of(&successor),
            actor_ref: EntityId::from_bytes([0x11; 16]).expect("an id"),
            actor_class: "human".to_owned(),
            epoch: 1,
        },
    );
    let fold = log.fold();

    assert_eq!(
        verdict(&fold, appointment),
        Some(AppointmentVerdict::Valid),
        "{:?}",
        fold.issues
    );
    assert!(
        fold.valid_entries.contains(&binding),
        "the successor's binding stands: {:?}",
        fold.issues
    );
    assert!(live(&fold, &key_of(&successor)));
    assert!(!rootless(&fold), "{:?}", fold.issues);
    for confirm in [first, second] {
        assert!(
            !confirm_stands(&fold, confirm),
            "the recovered world keeps both confirmations refused: {:?}",
            fold.issues
        );
    }
    for handoff in handoffs {
        assert!(!fold.valid_entries.contains(&handoff));
    }
    assert!(
        !fold
            .issues
            .iter()
            .any(|issue| matches!(issue, AuthorityFoldIssue::UnsettledHandoff(_))),
        "the recovered line raises no unsettled handoff: {:?}",
        fold.issues
    );
}

/// PLAN v3 test 16 (round-1 finding 11): the genesis root key enrols the
/// anchor's public key as a cloud-custodial agent device, which takes no
/// possession of the anchor key, and the handoff fork follows. The roster
/// marks the anchor key as the host's, yet the successor the anchor appoints
/// starts its own custody line: no roster key admitted it, so the host's
/// custody does not reach it.
#[test]
fn the_successor_starts_its_own_custody_line() {
    let mut log = Log::new();
    let root_key = log.root_key.clone();
    let anchor = key_of(&log.anchor);
    let mut custodial = device(anchor.clone(), ROLE_AGENT);
    custodial.tier = AuthorityTier::CloudCustodial;
    let enrolment = log.sign(
        &root_key,
        1,
        vec![log.owner_root],
        AuthorityOp::EnrollDevice { device: custodial },
    );
    let handoffs: Vec<_> = [(2, FIRST_HANDOFF_SEED), (3, SECOND_HANDOFF_SEED)]
        .into_iter()
        .map(|(seq, seed)| {
            log.sign(
                &root_key,
                seq,
                vec![enrolment],
                AuthorityOp::ReRoot {
                    new_device: device(key_of(&signing(seed)), ROLE_OWNER | ROLE_ADMIN),
                },
            )
        })
        .collect();
    let before = log.fold();
    assert!(
        before.valid_entries.contains(&enrolment),
        "{:?}",
        before.issues
    );
    assert!(
        in_host_custody(&before, &anchor),
        "the roster marks the anchor key as the host's"
    );
    assert!(rootless(&before), "{:?}", before.issues);

    let successor = signing(111);
    let appointment = log.appoint(2, log.witnesses(&handoffs), &successor);
    let fold = log.fold();

    assert_eq!(
        verdict(&fold, appointment),
        Some(AppointmentVerdict::Valid),
        "{:?}",
        fold.issues
    );
    assert!(live(&fold, &key_of(&successor)));
    assert_eq!(
        fold.roster[&key_of(&successor)].roles,
        ROLE_OWNER | ROLE_ADMIN
    );
    assert!(
        in_host_custody(&fold, &anchor),
        "the anchor key's custody mark stays"
    );
    assert!(
        !in_host_custody(&fold, &key_of(&successor)),
        "no roster key admitted the successor, so the host's custody does not reach it"
    );
}
