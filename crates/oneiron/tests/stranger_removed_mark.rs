//! FIX [STRANGER-REMOVED-MARK-GLOBAL]: a stranger anchor's removal mark
//! removes no machine from what this install believes, while the owner's
//! own removal still does.
//!
//! The store gate's structure keeps one set of removed machines, and a frontier
//! join a removed machine carries is a stranger's (FIX 7908). The set took a
//! Removed mark from any anchor, a stranger's included: any fresh key
//! publishes an owner root, and its anchor marks any machine in its own
//! chain. So one mark by a root nobody pins made an honest machine's own
//! install joins strangers' rows: they counted against the one shared
//! stranger bound, and the peer settled gate (#9202) did not believe them.
//! The fold reads a foreign anchor's chains only under the pin, and the
//! owner's doors read a stranger's removal mark as no removal (FIX
//! [FOREIGN-ANCHOR-MARK-BLOCKS-MACHINE-DOORS]). The set now takes a removal
//! only when it files as this install's own: a slip issuer, one of this
//! install's own anchors, or an own carrier key signed it.
//!
//! T1 is the attack (red on main, green with the fix); T2 guards the owner's
//! own removal (green on both). T3 (REVIEW-9555 P1) is the owner's removal
//! a carrier machine carries, filed before the issuer's enrolment of that
//! carrier makes its key own: red at c6faec2e, where the removal stayed a
//! stranger's; green once the structure files it again as own. T4
//! (REVIEW-9555 round 2) is the owner's removal a carrier known only under a
//! stranger's anchor carries beside an owner key's proof. The fold admits a
//! carrier only from its machine's live roster chain (#8673, RULING
//! FOREIGN-ANCHOR-ADMIT-SIDE-P1 = B), so it refuses that removal, and the
//! structure must count none: red on main with stack #8714, where the
//! structure took any carried removal; green with the fix.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test
//! stranger_removed_mark`.

#![cfg(all(feature = "sync", feature = "test-support"))]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActAuthority, ActSurface, AuthorityEntryHash, AuthorityKey,
    AuthorityLogEntry, AuthorityOp, AuthoritySignature, AuthorityVaultId,
    MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass,
    MachineEncryptionKey, MachineEnrolmentRequest, MachineOwnership, MachineProfile, MachineRole,
    OwnerAct, OwnerActKind, OwnerKeyEnrollment, OwnerRootRecord, authority_entry_hash,
    authority_log_entity_id, authority_transcript, encode_authority_log_entry_body,
    machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::registry::ENTITY_TYPE_AUTHORITY_LOG;
use oneiron::store::GateDecisionId;
use oneiron::sync::client::ImportTier;
use oneiron::sync::peer_route::authority_fold_settled;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::world_keys::RecoveryRootSeed;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_authority::authority::{
    FrontierJoin, FrontierJoinFamily, FrontierJoinScope, HomeCandidacy,
};

/// The seed of the joining machine's machine key.
const JOINING_SEED: u8 = 68;
/// The seed of the carrier machine's machine key, its install key (T3, T4).
const CARRIER_SEED: u8 = 69;
/// The seed of the machine key of holder machine H, which holds the owner
/// key (T4).
const HOLDER_SEED: u8 = 70;
/// The seed of owner key K, which the owner enrols on H (T4).
const OWNER_KEY_SEED: u8 = 71;
/// How many timestamps T3 tries for a hand-signed row whose stored id must
/// sort before another row's.
const ORDER_TRIES: u64 = 1 << 26;
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
    signed_at(vault_id, seq, parent_hashes, op, signer, 1)
}

/// [`signed`] with the row's timestamp `ts`, which moves its hash.
fn signed_at(
    vault_id: AuthorityVaultId,
    seq: u64,
    parent_hashes: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
    signer: &SigningKey,
    ts: u64,
) -> AuthorityLogEntry {
    let mut row = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(vault_id),
        seq,
        parent_hashes,
        op,
        signer: signature_slot(key_of(signer)),
        cosigns: Vec::new(),
        ts,
    };
    let transcript = authority_transcript(&row).expect("the transcript signs");
    row.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    row
}

/// [`signed_at`] with one cosign by `cosigner`. Both keys are in the row
/// before either signs, so both sign the same transcript.
fn cosigned_at(
    vault_id: AuthorityVaultId,
    seq: u64,
    parent_hashes: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
    (signer, cosigner): (&SigningKey, &SigningKey),
    ts: u64,
) -> AuthorityLogEntry {
    let mut row = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(vault_id),
        seq,
        parent_hashes,
        op,
        signer: signature_slot(key_of(signer)),
        cosigns: vec![signature_slot(key_of(cosigner))],
        ts,
    };
    let transcript = authority_transcript(&row).expect("the transcript signs");
    row.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    row.cosigns[0].signature = cosigner.sign(&transcript).to_bytes().to_vec();
    row
}

fn hash(row: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(row).expect("a row hashes")
}

/// The stranger root's owner person, distinct from the vault's owner.
fn stranger_owner() -> EntityId {
    EntityId::from_bytes([0xA1; 16]).expect("an id parses")
}

/// A self-host vault as its own server starts one: this install serving and
/// profiled under the host root, and the owner bound and authenticated. It
/// pins no root, so a machine stands under the roster's head alone.
struct ServedVault {
    vault: Vault,
    owner: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

impl ServedVault {
    fn self_host() -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("self-host vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile under the host root")
            .roster
            .expect("guard: this install has a roster chain");
        let person = vault.ensure_embedded_owner_actor().expect("the owner");
        oneiron::test_support::bind_host_owner(&vault, &issuer, person)
            .expect("the owner's binding");
        let owner = vault
            .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
            .expect("the owner's proof");
        Self {
            vault,
            owner,
            _dir: dir,
        }
    }

    fn vault_id(&self) -> AuthorityVaultId {
        self.vault
            .authority_fold()
            .expect("authority fold reads")
            .vault_id
            .expect("the vault is rooted")
    }

    /// Machine M's request to join this vault, with its own proof.
    fn joining_machine(&self) -> MachineEnrolmentRequest {
        self.machine_request(0x76, JOINING_SEED)
    }

    /// The request of the machine with id bytes `id` and machine key seed
    /// `seed` to join this vault, with its own proof.
    fn machine_request(&self, id: u8, seed: u8) -> MachineEnrolmentRequest {
        let vault_id = self.vault_id();
        let machine = EntityId::from_bytes([id; 16]).expect("an id parses");
        let node = signing(seed);
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

    /// The owner enrols `owner_key` as an owner key held on `holder`,
    /// through the public owner key enrollment door under the host root.
    /// Returns the enrollment's entry.
    fn enrol_owner_key(&self, holder: EntityId, owner_key: &SigningKey) -> AuthorityEntryHash {
        let authority = ActAuthority::Owner(self.owner.clone(), ActSurface::ThisInstall);
        let public_key = owner_key.verifying_key().to_bytes();
        let challenge = self
            .vault
            .owner_key_enrollment_challenge_as(&authority, holder, &public_key)
            .expect("the enrollment's challenge");
        self.vault
            .enrol_owner_signing_key_as_host(
                &authority,
                OwnerKeyEnrollment {
                    machine: holder,
                    public_key,
                    proof: owner_key.sign(&challenge).to_bytes().to_vec(),
                },
                &oneiron::test_support::test_host_issuer(),
            )
            .expect("the owner enrols the owner key")
            .entry
    }

    /// The entry of M's live roster head.
    fn roster_head(&self, machine: EntityId) -> AuthorityEntryHash {
        let fold = self.vault.authority_fold().expect("authority fold reads");
        let roster = fold
            .machine(machine)
            .and_then(|folded| folded.roster.as_ref())
            .expect("guard: M has a roster chain");
        roster.entry
    }
}

/// A self-host vault with machine M enrolled as the owner's at roster
/// revision 1, its peer route settled.
fn enrolled_self_host() -> (ServedVault, MachineEnrolmentRequest) {
    let served = ServedVault::self_host();
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
    assert!(landing.held().is_none(), "guard: the enrolment is not held");
    let fold = served.vault.authority_fold().expect("authority fold reads");
    let roster = fold
        .machine(request.machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("guard: M has a roster chain");
    assert!(roster.is_live(), "guard: M's roster is live");
    assert!(
        authority_fold_settled(&served.vault).expect("the settled read"),
        "guard: the enrolment leaves the history whole"
    );
    (served, request)
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
            .expect("authority fold reads")
            .valid_entries
            .contains(&root_hash),
        "guard: the stranger's root is in valid_entries, so its anchor vouches"
    );
    (anchor, root_hash)
}

/// The stranger's anchor marks M removed under M's own keys and proof, on its
/// root row, and the mark is stored. Returns the mark's hash.
fn strangers_removal_mark(
    served: &ServedVault,
    request: &MachineEnrolmentRequest,
    anchor: &SigningKey,
    root_hash: AuthorityEntryHash,
) -> AuthorityEntryHash {
    let profile = MachineProfile {
        machine: request.machine,
        owner: stranger_owner(),
        machine_key: request.machine_key,
        device_class: request.device_class,
        encryption_key: request.encryption_key.clone(),
        role: MachineRole::Removed,
        revision: 1,
        machine_proof: request.machine_proof,
        seen_world_edits: BTreeSet::new(),
        carrier: None,
        act: None,
    };
    let entry = signed(
        served.vault_id(),
        2,
        vec![root_hash],
        AuthorityOp::MachineProfile(profile),
        anchor,
    );
    let mark = hash(&entry);
    served
        .vault
        .put_authority_log_entry(&entry, AT, 2)
        .expect("the stranger's removal mark is stored");
    mark
}

/// Delivers `entry` to `vault` through the replicated ingest door a sync peer's
/// row takes: the public explicit-tier replay (`sync::replay::replay_entity`
/// with `ImportTier::OwnDevice`), which runs the replicated authority
/// validator and the store door.
fn deliver_via_replicated(vault: &Vault, entry: &AuthorityLogEntry) -> oneiron::Result<()> {
    let body = encode_authority_log_entry_body(entry).expect("the row encodes");
    let id = authority_log_entity_id(entry).expect("the row's content id");
    replay_entity(
        vault,
        ReplicatedEntity {
            id,
            entity_type: ENTITY_TYPE_AUTHORITY_LOG,
            occurred: AT,
            learned_at: 2,
            row_version: 0,
            body: &body,
        },
        ImportTier::OwnDevice,
    )
}

/// M's own install join J of `head` and its home candidacy P, which rests on
/// `candidacy_parent` and which M keeps. Delivers J alone through replicated
/// ingest and checks that J stored with P missing. Returns P's hash.
fn deliver_join_over_withheld_candidacy(
    served: &ServedVault,
    machine: EntityId,
    head: AuthorityEntryHash,
    candidacy_parent: AuthorityEntryHash,
) -> AuthorityEntryHash {
    let vault_id = served.vault_id();
    let node = signing(JOINING_SEED);
    let declaration = HomeCandidacy {
        machine,
        node_id: 1,
        always_on: false,
        primary: false,
        macro_ready: true,
        cloud: false,
    };
    let withheld = signed(
        vault_id,
        1,
        vec![candidacy_parent],
        AuthorityOp::HomeCandidacy(declaration),
        &node,
    );
    let withheld_hash = hash(&withheld);
    let mut parents = vec![head, withheld_hash];
    parents.sort_unstable();
    let join = signed(
        vault_id,
        2,
        parents,
        AuthorityOp::FrontierJoin(FrontierJoin {
            family: FrontierJoinFamily::Install(machine),
            scope: FrontierJoinScope::Main,
        }),
        &node,
    );
    let join_id = authority_log_entity_id(&join).expect("J's content-derived id");
    deliver_via_replicated(&served.vault, &join).expect("J lands through replicated ingest");
    assert!(
        served
            .vault
            .get_authority_log_entry(&join_id)
            .expect("J reads back")
            .is_some(),
        "setup: J is stored, so M's join reached the log"
    );
    assert!(
        served
            .vault
            .authority_missing_history()
            .expect("the history read")
            .missing
            .contains(&withheld_hash),
        "setup: the fetch request names P, so delivery can fetch it"
    );
    withheld_hash
}

/// T1 the attack: a stranger's anchor marks the owner's machine M removed,
/// and M then delivers its own install join J over its withheld candidacy P.
/// J is M's row under M's live roster key, so this install believes it: the
/// believed history names P and the peer route stays unsettled. RED on main
/// (the stranger's mark made J a stranger's row: P is not believed missing
/// and the route reads settled), GREEN with the fix.
#[test]
fn a_strangers_removal_mark_leaves_the_machines_own_join_believed() {
    let (served, request) = enrolled_self_host();
    let machine = request.machine;
    let (anchor, root_hash) = publish_stranger_root(&served);
    let mark = strangers_removal_mark(&served, &request, &anchor, root_hash);
    let fold = served.vault.authority_fold().expect("authority fold reads");
    assert!(
        fold.valid_entries.contains(&mark),
        "guard: the stranger's removal mark is in valid_entries"
    );
    let roster = fold
        .machine(machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("guard: M has a roster chain");
    assert!(
        roster.is_live(),
        "guard: the stranger's mark leaves M's roster chain live"
    );
    assert!(
        authority_fold_settled(&served.vault).expect("the settled read"),
        "guard: the stranger's root and mark alone stall no peer route"
    );
    let head = served.roster_head(machine);
    let withheld = deliver_join_over_withheld_candidacy(&served, machine, head, mark);
    assert!(
        served
            .vault
            .authority_missing_believed_history()
            .expect("the believed history read")
            .missing
            .contains(&withheld),
        "a stranger's removal mark made M's own join a stranger's row: the history this \
         install believes it lacks leaves out P"
    );
    assert!(
        !authority_fold_settled(&served.vault).expect("the settled read"),
        "M's believed join over its withheld candidacy must keep peer serving unsettled"
    );
}

/// T2 the guard: the owner removes M through his own door, and M then
/// delivers its own install join J over its withheld candidacy P. The removal
/// is this install's own, so J is a removed machine's join, a stranger's row
/// (FIX 7908): the believed history leaves out P and the peer route stays
/// settled. GREEN on main and with the fix.
#[test]
fn the_owners_removal_makes_the_machines_join_a_strangers() {
    let (served, request) = enrolled_self_host();
    let machine = request.machine;
    let (_anchor, root_hash) = publish_stranger_root(&served);
    let landing = served
        .vault
        .set_machine_role(
            &served.owner,
            ActSurface::ThisInstall,
            machine,
            MachineRole::Removed,
            None,
        )
        .expect("the owner's removal of M lands");
    assert!(
        landing.held().is_none(),
        "guard: the removal stands, it is not held"
    );
    let fold = served.vault.authority_fold().expect("authority fold reads");
    let roster = fold
        .machine(machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("guard: M has a roster chain after the removal");
    assert_eq!(
        roster.profile.role,
        MachineRole::Removed,
        "guard: M's roster head is removed"
    );
    assert!(
        authority_fold_settled(&served.vault).expect("the settled read"),
        "guard: the removal leaves the history whole"
    );
    let head = served.roster_head(machine);
    let withheld = deliver_join_over_withheld_candidacy(&served, machine, head, root_hash);
    assert!(
        !served
            .vault
            .authority_missing_believed_history()
            .expect("the believed history read")
            .missing
            .contains(&withheld),
        "a machine the owner removed: its join is a stranger's row, so the history this \
         install believes it lacks leaves out P"
    );
    assert!(
        authority_fold_settled(&served.vault).expect("the settled read"),
        "a removed machine's withheld parent must stall no peer route"
    );
}

/// A row's place in the order the store lists AUTHORITY_LOG rows, and the
/// store gate's structure files them: its stored id, the first 16 bytes of
/// its hash.
fn stored_order(hash: &AuthorityEntryHash) -> u128 {
    u128::from_be_bytes(hash[..16].try_into().expect("16 bytes"))
}

/// The first row `row_at(ts)` builds, over timestamps from 1, whose stored
/// order `fits`.
fn row_in_order(
    row_at: impl Fn(u64) -> AuthorityLogEntry,
    fits: impl Fn(u128) -> bool,
) -> AuthorityLogEntry {
    (1..=ORDER_TRIES)
        .map(row_at)
        .find(|row| fits(stored_order(&hash(row))))
        .expect("FIXTURE: a timestamp puts the row in the stored order the case needs")
}

/// T3 (REVIEW-9555 P1): the issuer enrols carrier C. A stranger's anchor marks C
/// as its own, and C carries the owner's removal of M. The store gate's
/// structure files rows by stored id, and here the stranger's root, its
/// mark of C and C's removal of M all sort before the issuer's enrolment of
/// C. So the removal is filed while C's key still stands as a stranger's;
/// the enrolment then takes the key as own. The removal must count then: M
/// is removed, so M's install join J over its withheld candidacy P is a
/// stranger's row, and the believed history leaves out P. RED at c6faec2e
/// (the removal stayed a stranger's, so J was believed and P stalled the
/// peer route); GREEN once the structure files the removal again as own.
#[test]
fn a_carriers_removal_counts_once_its_key_is_taken_as_own() {
    let (served, request) = enrolled_self_host();
    let machine = request.machine;
    let vault_id = served.vault_id();
    let person = served
        .vault
        .ensure_embedded_owner_actor()
        .expect("the owner");
    let carrier = served.machine_request(0x77, CARRIER_SEED);
    served
        .vault
        .enroll_machine(
            &served.owner,
            ActSurface::ThisInstall,
            &carrier,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner's enrolment of carrier C lands");
    let enrolment = served.roster_head(carrier.machine);
    let head = served.roster_head(machine);
    let mut removal_parents = vec![head, enrolment];
    removal_parents.sort_unstable();

    // C's install key signs the owner's removal of M, carried, below the
    // enrolment in stored order.
    let removal = row_in_order(
        |ts| {
            let profile = MachineProfile {
                machine,
                owner: person,
                machine_key: request.machine_key,
                device_class: request.device_class,
                encryption_key: request.encryption_key.clone(),
                role: MachineRole::Removed,
                revision: 2,
                machine_proof: request.machine_proof,
                seen_world_edits: BTreeSet::new(),
                carrier: Some(carrier.machine),
                act: Some(OwnerAct::by_owner(
                    person,
                    OwnerActKind::MachineRemoval,
                    machine,
                    ActSurface::ThisInstall,
                    [0; 32],
                )),
            };
            signed_at(
                vault_id,
                1,
                removal_parents.clone(),
                AuthorityOp::MachineProfile(profile),
                &signing(CARRIER_SEED),
                ts,
            )
        },
        |order| order < stored_order(&enrolment),
    );
    let removal_order = stored_order(&hash(&removal));

    // A stranger's root, and its anchor's mark of C as its own, below the
    // removal in stored order, the root first.
    let seed = RecoveryRootSeed::generate().expect("a fresh stranger root seed");
    let root = seed
        .public(&vault_id)
        .expect("the stranger root's public half");
    let anchor = seed.anchor();
    let record = OwnerRootRecord {
        owner: stranger_owner(),
        root: root.id,
        recovery_key: MachineEncryptionKey {
            suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
            key: root.recovery_key.to_bytes(),
        },
        anchor_key: root.anchor_key,
    };
    let root_row = row_in_order(
        |ts| {
            signed_at(
                vault_id,
                1,
                vec![head],
                AuthorityOp::OwnerRoot(record.clone()),
                &anchor,
                ts,
            )
        },
        |order| order < removal_order / 2,
    );
    let root_order = stored_order(&hash(&root_row));
    let mark = row_in_order(
        |ts| {
            let profile = MachineProfile {
                machine: carrier.machine,
                owner: stranger_owner(),
                machine_key: carrier.machine_key,
                device_class: carrier.device_class,
                encryption_key: carrier.encryption_key.clone(),
                role: MachineRole::Owned(MachineOwnership::Yours),
                revision: 1,
                machine_proof: carrier.machine_proof,
                seen_world_edits: BTreeSet::new(),
                carrier: None,
                act: None,
            };
            signed_at(
                vault_id,
                2,
                vec![hash(&root_row)],
                AuthorityOp::MachineProfile(profile),
                &anchor,
                ts,
            )
        },
        |order| root_order < order && order < removal_order,
    );
    for row in [&removal, &root_row, &mark] {
        served
            .vault
            .put_authority_log_entry(row, AT, 2)
            .expect("FIXTURE: the row is stored");
    }
    let fold = served.vault.authority_fold().expect("authority fold reads");
    for row in [&removal, &root_row, &mark] {
        assert!(
            served
                .vault
                .get_authority_log_entry(&authority_log_entity_id(row).expect("the row's id"))
                .expect("the row reads back")
                .is_some(),
            "FIXTURE: the row is in the log"
        );
    }
    assert!(
        fold.valid_entries.contains(&hash(&root_row)),
        "FIXTURE: the stranger's root counts, so its anchor marks as a stranger's"
    );
    assert!(
        authority_fold_settled(&served.vault).expect("the settled read"),
        "FIXTURE: the stored rows alone stall no peer route"
    );

    let withheld = deliver_join_over_withheld_candidacy(&served, machine, head, hash(&root_row));
    assert!(
        !served
            .vault
            .authority_missing_believed_history()
            .expect("the believed history read")
            .missing
            .contains(&withheld),
        "the owner's removal C carried counts once the issuer's enrolment takes C's key as own: \
         M's join is a stranger's row, so the history this install believes it lacks leaves out P"
    );
    assert!(
        authority_fold_settled(&served.vault).expect("the settled read"),
        "a removed machine's withheld parent must stall no peer route"
    );
}

/// T4 (REVIEW-9555 round 2): the owner enrols owner key K on holder machine
/// H. Carrier C is known only under a stranger's anchor, whose mark of C
/// rests on its root; the owner never enrols C. C carries the owner's
/// removal of M beside K's proof, the mark and K's enrolment in its
/// ancestry. The fold admits a carrier only from its machine's live roster
/// chain (#8673, RULING FOREIGN-ANCHOR-ADMIT-SIDE-P1 = B) and C has none, so
/// it refuses the removal, the owner's proof notwithstanding, and M stays
/// live. The store gate's structure must count no removal either: M's
/// install join J over its withheld candidacy P is M's own row, so the
/// believed history names P and the peer route stays unsettled. RED on main
/// with stack #8714 (the structure took any carried removal, so J was a
/// stranger's row and the believed history left out P), GREEN with the fix
/// (a removal a stranger's carrier key carries files nothing).
#[test]
fn a_proven_removal_a_strangers_carrier_carries_removes_nothing() {
    let (served, request) = enrolled_self_host();
    let machine = request.machine;
    let vault_id = served.vault_id();
    let person = served
        .vault
        .ensure_embedded_owner_actor()
        .expect("the owner");
    let holder = served.machine_request(0x78, HOLDER_SEED);
    served
        .vault
        .enroll_machine(
            &served.owner,
            ActSurface::ThisInstall,
            &holder,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner's enrolment of holder H lands");
    let owner_key = signing(OWNER_KEY_SEED);
    let enrolment = served.enrol_owner_key(holder.machine, &owner_key);
    let head = served.roster_head(machine);
    let carrier = served.machine_request(0x77, CARRIER_SEED);

    // A stranger's root, and its anchor's mark of C as its own on it.
    let (anchor, root_hash) = publish_stranger_root(&served);
    let mark_profile = MachineProfile {
        machine: carrier.machine,
        owner: stranger_owner(),
        machine_key: carrier.machine_key,
        device_class: carrier.device_class,
        encryption_key: carrier.encryption_key.clone(),
        role: MachineRole::Owned(MachineOwnership::Yours),
        revision: 1,
        machine_proof: carrier.machine_proof,
        seen_world_edits: BTreeSet::new(),
        carrier: None,
        act: None,
    };
    let mark = signed(
        vault_id,
        2,
        vec![root_hash],
        AuthorityOp::MachineProfile(mark_profile),
        &anchor,
    );

    // C's install key signs the owner's removal of M, carried, beside K's
    // proof.
    let mut removal_parents = vec![head, enrolment, hash(&mark)];
    removal_parents.sort_unstable();
    let removal_profile = MachineProfile {
        machine,
        owner: person,
        machine_key: request.machine_key,
        device_class: request.device_class,
        encryption_key: request.encryption_key.clone(),
        role: MachineRole::Removed,
        revision: 2,
        machine_proof: request.machine_proof,
        seen_world_edits: BTreeSet::new(),
        carrier: Some(carrier.machine),
        act: Some(OwnerAct::by_owner(
            person,
            OwnerActKind::MachineRemoval,
            machine,
            ActSurface::ThisInstall,
            [0; 32],
        )),
    };
    let removal = cosigned_at(
        vault_id,
        1,
        removal_parents,
        AuthorityOp::MachineProfile(removal_profile),
        (&signing(CARRIER_SEED), &owner_key),
        1,
    );
    for row in [&mark, &removal] {
        served
            .vault
            .put_authority_log_entry(row, AT, 2)
            .expect("FIXTURE: the row is stored");
        assert!(
            served
                .vault
                .get_authority_log_entry(&authority_log_entity_id(row).expect("the row's id"))
                .expect("the row reads back")
                .is_some(),
            "FIXTURE: the row is in the log"
        );
    }
    let fold = served.vault.authority_fold().expect("authority fold reads");
    assert!(
        fold.valid_entries.contains(&hash(&mark)),
        "FIXTURE: the stranger's mark of C counts, so C's key stands as a stranger's"
    );
    assert!(
        !fold.valid_entries.contains(&hash(&removal)),
        "FIXTURE: the fold refuses a carrier known only under a stranger's anchor, even beside \
         K's proof"
    );
    let roster = fold
        .machine(machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("FIXTURE: M has a roster chain");
    assert!(
        roster.is_live(),
        "FIXTURE: the refused removal leaves M's roster chain live"
    );
    assert!(
        authority_fold_settled(&served.vault).expect("the settled read"),
        "FIXTURE: the stored rows alone stall no peer route"
    );

    let withheld = deliver_join_over_withheld_candidacy(&served, machine, head, root_hash);
    assert!(
        served
            .vault
            .authority_missing_believed_history()
            .expect("the believed history read")
            .missing
            .contains(&withheld),
        "a removal the fold refuses removes nothing here: M's join is M's own row, so the history \
         this install believes it lacks names P"
    );
    assert!(
        !authority_fold_settled(&served.vault).expect("the settled read"),
        "M's believed join over its withheld candidacy must keep peer serving unsettled"
    );
}
